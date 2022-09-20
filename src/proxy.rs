use socket2::{Socket, SockAddr};
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::{net, io, ops};
use super::sql_session::{RequestBasicType, ResponseBasicType, SqlRequest, SqlResponse, SqlProxySession};

use super::validator::SqlValidator;
use super::token::SqlToken;



struct PacketInfo { // PacketOverview? PacketHeader?
    is_malicious: bool,
    query: Option<String>,
}



/// The possible connection states of a `Proxy`.
#[derive(PartialEq,Eq)]
enum ConnectionState {
    // ClientTLSHandshake, // unimplemented
    DatabaseTCPHandshake, // called connect() to database, awaiting completed connection
    // DatabaseTLSHandshake, // unimplemented
    Connected,
}

/// Enumerates the read/write events that a socket cannot send/receive data for
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IOEvent { 
    /// Indicates that no read or write events on the socket have failed
    None,
    /// Indicates that data could not be read from the socket without blocking
    Read,
    /// Indicates that data could not be written to the socket without blocking
    Write,
    /// Indicates that data could be neither read from nor written to the socket without blocking
    ReadWrite, 
}

impl ops::BitOr for IOEvent {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (IOEvent::ReadWrite, _) | (_, IOEvent::None) => self,
            (_, IOEvent::ReadWrite) | (IOEvent::None, _) => rhs,
            (IOEvent::Read, IOEvent::Write) | (IOEvent::Write, IOEvent::Read) => IOEvent::ReadWrite,
            _ => self // can only be (Write, Write) or (Read, Read)
        }
    }
}

impl ops::BitOrAssign for IOEvent {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs // TODO: does this actually work?
    }
}



// With 'send' and 'recv' buffers (along with 'process' queues of maximum sizes) 
// large enough to hold multiple requests but small enough to avoid consuming all memory

/// Handles and proxies a single SQL connection between an incoming client connection 
/// and the backend database.
/// 
pub struct Proxy<T: SqlToken, P: SqlProxySession<Socket, Socket>> {
    client_read_closed: bool,
    client_key: usize,
    db_address: SockAddr,
    db_read_closed: bool,
    db_write_closed: bool,
    db_key: usize,
    request_queue: VecDeque<PacketInfo>,
    incoming_data: VecDeque<P::RequestType>,
    outgoing_data: VecDeque<P::ResponseType>,
    sql_session: P,
    /// The current connectivity state of the proxy
    state: ConnectionState, 
    _sqltoken_type: PhantomData<T>,
}

// STEPS TO REMOVE INDIVIDUAL PACKETS:
// 1. read_packet_raw() -> returns Packet (with length) or nothing. When it returns a packet, it advances the readable index by the length of the packet.
// 1b. both Proxy and PostgresSession keep track of packet sizes using a Vec<usize>
// 2. write_raw() -> returns a usize indicating number of bytes written. Proxy and Session decrement/remove packet length from Vec based on usize returned.
// 3. When read_packet_raw() returns a packet that has a malicious query, mark it as a packet to be discarded in the Vec<usize> and start using write_packet_raw(), 
// removing packets from the VecDeque<usize>
// 4. Once the packet to remove is reached, use the `advance_read()` function in the Buffer to completely remove the packet
// 5. Go back to write_raw() after done for efficiency

impl<T: SqlToken, P: SqlProxySession<Socket, Socket>> Proxy<T, P> {
    pub fn new(client_socket: Socket, database_socket: Socket, database_address: SockAddr, client_key: usize, db_key: usize) -> Self {
        Proxy {
            client_read_closed: false,
            client_key: client_key,
            db_address: database_address,
            db_read_closed: false,
            db_write_closed: false,
            db_key: db_key,
            request_queue: VecDeque::new(),
            incoming_data: VecDeque::new(),
            outgoing_data: VecDeque::new(),
            state: ConnectionState::DatabaseTCPHandshake,
            sql_session: P::new(client_socket, database_socket),
            _sqltoken_type: PhantomData,
        }
    }

    /// Returns the polling key associated with the client socket of the given proxy.
    pub fn get_client_key(&self) -> usize {
        self.client_key
    }

    /// Returns the client socket of the given proxy connection.
    pub fn get_client_socket(&self) -> &Socket {
        self.sql_session.get_client_io_ref()
    }


    /// Returns the polling key associated with the database socket of the given proxy.
    pub fn get_db_key(&self) -> usize {
        self.db_key
    }

    pub fn incoming_closed(&self) -> bool {
        self.client_read_closed && self.db_write_closed
    }


    /// Returns the database socket of the given proxy.
    pub fn get_db_socket(&self) -> &Socket {
        self.sql_session.get_server_io_ref()
    }

    /// Progresses the state of the given proxy connection by attempting each of the following operations once, 
    /// in order:
    /// 
    /// 1. Connecting to the database via TCP (if not connected)
    /// 2. Processing any data received from the client and validating any SQL query contained within it using `validator` (if connected)
    /// 3. Forwarding data received from the client to the backend database (if connected)
    ///
    /// Returns a tuple indicating the read/write events needed on the proxy's client socket and database socket (in that order).
    /// 
    pub fn process_incoming(&mut self, validator: &mut SqlValidator<T>) -> io::Result<(IOEvent,IOEvent)> {
        let (mut client_ev, mut db_ev) = (IOEvent::None, IOEvent::None);

        /*
        if self.state == State::ClientTLSHandshake {
            client_ev |= self.connect_client_tls()?;
        }
        */

        if self.state == ConnectionState::DatabaseTCPHandshake {
            db_ev |= self.connect_database()?;
        }

        /*
        if self.state == State::DatabaseTLSHandshake {
            db_ev |= self.connect_db_tls()?;
        }
        */

        if self.state == ConnectionState::Connected {
            // Only go through one round of each phase to ensure fairness at the EventHandler layer

            client_ev |= match self.process_client_packet(validator) {
                Ok(()) => IOEvent::None,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => IOEvent::Read,
                    _ => return Err(e)
                }
            };

            db_ev |= match self.proxy_client_packet() {
                Ok(()) => IOEvent::None,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => IOEvent::Write,
                    _ => return Err(e)
                }
            };
        }

        Ok((client_ev, db_ev))
    }

    /// Progresses the state of the given proxy connection by attempting each of the following operations once, 
    /// in order:
    /// 
    /// 1. Connecting to the database via TCP (if not connected)
    /// 2. Processing any data received from the backend database and updating `validator` based on SQL query response (if connected)
    /// 3. Forwarding data received from the database to the client (if connected)
    ///
    /// Returns a tuple indicating the read/write events needed on the proxy's client socket and database socket (in that order).
    /// 
    pub fn process_outgoing(&mut self, validator: &mut SqlValidator<T>) -> io::Result<(IOEvent,IOEvent)> {
        let (mut client_ev, mut db_ev) = (IOEvent::None, IOEvent::None);

        /*
        if self.state == State::ClientTLSHandshake {
            client_ev |= self.connect_client_tls()?;
        }
        */

        if self.state == ConnectionState::DatabaseTCPHandshake {
            db_ev |= self.connect_database()?;
        }

        /*
        if self.state == State::DatabaseTLSHandshake {
            db_ev |= self.connect_db_tls()?;
        }
        */
        
        if self.state == ConnectionState::Connected {
            // Only go through one round of each phase to ensure fairness at the EventHandler layer

            db_ev |= match self.process_db_packet() {
                Ok(()) => IOEvent::None,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => IOEvent::Read,
                    _ => return Err(e)
                }
            };

            client_ev |= match self.proxy_db_packet(validator) {
                Ok(()) => IOEvent::None,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => IOEvent::Write,
                    _ => return Err(e)
                }
            };
        }

        Ok((client_ev, db_ev))
    }

    /// Attempts to establish a proxy connection to the backend database.
    /// 
    fn connect_database(&mut self) -> io::Result<IOEvent> {
        match self.get_db_socket().connect(&self.db_address) {
            Ok(_) => {
                self.state = ConnectionState::Connected;
                Ok(IOEvent::None)
            },
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(IOEvent::Read), // TODO: check which event to poll for
            Err(e) => Err(e)
        }
    }

    fn process_client_packet(&mut self, validator: &mut SqlValidator<T>) -> io::Result<()> {
        if self.client_read_closed {
            if !self.db_write_closed && self.incoming_data.len() == 0 {
                self.get_db_socket().shutdown(net::Shutdown::Write)?; // No more data to process, so close other half of the incoming stream
                self.db_write_closed = true;
            }
            return Ok(())
        }

        let request = match self.sql_session.server_receive_request() {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                self.client_read_closed = true; // TODO: make sure that the socket actually has `shutdown()` called on it in the appropriate location
                return Ok(())
            },
            Err(e) => return Err(e)
        };

        match request.get_basic_type() {
            RequestBasicType::AdditionalInformation => self.incoming_data.push_back(request), // No corresponding response will be returned by server
            RequestBasicType::Query(query) => match validator.check_query(query) {
                Err(_) => self.request_queue.push_back(PacketInfo { query: Some(query.clone()), is_malicious: true }), // Don't forward request data, don't want the db to run a malicious query
                Ok(()) => {
                    self.request_queue.push_back(PacketInfo { query: Some(query.clone()), is_malicious: false });
                    self.incoming_data.push_back(request);
                },
            },
            _ => { // Any other data type is transparently proxied
                self.request_queue.push_back(PacketInfo { query: None, is_malicious: false });
                self.incoming_data.push_back(request);
            }
        };

        Ok(())
    }
        
    fn proxy_client_packet(&mut self) -> io::Result<()> {
        assert!(!self.db_write_closed); // NOTE: this should never be reached based on how we've architected our event handler

        if let Some(request) = self.incoming_data.pop_front() {
            match self.sql_session.client_send_request(&request) {
                Ok(()) => self.sql_session.recycle_request(request),
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                    self.db_write_closed = true; // TODO: make sure that the socket actually has `shutdown()` called on it in the appropriate location
                    self.client_read_closed = true;
                    return self.get_client_socket().shutdown(net::Shutdown::Read);
                    // No sense pushing the incoming request back onto the stack--there'll be no way to send it anyways
                    // TODO: make sure the number of responses we expect from the server are correct in this edge case
                },
                Err(e) => {
                    self.incoming_data.push_front(request); // Could be a recoverable error, such as EWOULDBLOCK
                    return Err(e)
                }
            }
        }

        Ok(())
    }

    fn process_db_packet(&mut self) -> io::Result<()> {
        // If we have no more data to receive and none to to send, we should close the connection
        if self.incoming_closed() && self.request_queue.is_empty() && self.outgoing_data.is_empty() {
            self.get_client_socket().shutdown(net::Shutdown::Write)?;
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "connection gracefully terminated (no more packets to read in from client or process)"))
            // TODO: do we want to notify the proxy to stop through a ConnectionAborted error here, even though it was a graceful termination?
        }

        if self.db_read_closed {
            return Ok(()) // We're not going to receive any new packets, so stop here
        }

        while let Some(request_info) = self.request_queue.pop_front() {
            if request_info.is_malicious {
                // TODO: inject artificial error packet to output queue here
            } else {
                self.request_queue.push_front(request_info);
                break
            }
        }

        // TODO: if not too many packets in outgoing_data queue
        self.outgoing_data.push_back(match self.sql_session.client_receive_response() {
            Ok(resp) => resp,
            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                self.db_read_closed = true;
                self.db_write_closed = true;
                self.client_read_closed = true; // If we can't get data from our db, no sense in accepting new data from our client
                self.get_client_socket().shutdown(net::Shutdown::Read)?; // TODO: make sure we close the write end of our db socket regardless of failure here??
                self.get_db_socket().shutdown(net::Shutdown::Write)?;
                return Ok(())
            },
            Err(e) => return Err(e)
        });

        Ok(())
    }

    fn proxy_db_packet(&mut self, validator: &mut SqlValidator<T>) -> io::Result<()> {   


        while let Some(response) = self.outgoing_data.pop_front() {
            match self.sql_session.server_send_response(&response) {
                Ok(()) => (),
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                    // Close proxy gracefully
                    self.get_db_socket().shutdown(net::Shutdown::Write)?;
                    self.get_db_socket().shutdown(net::Shutdown::Read)?;
                    self.get_client_socket().shutdown(net::Shutdown::Read)?;
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "client unexpectedly closed connection despite data remaining to be returned"))
                },
                Err(e) => {
                    self.outgoing_data.push_front(response); // Could be a recoverable error, such as EWOULDBLOCK
                    return Err(e)
                }
            }

            if *response.basic_type() == ResponseBasicType::AdditionalInformation {
                self.sql_session.recycle_response(response);
                return Ok(())
            }

            if let Some(request_info) = self.request_queue.pop_front() {
                // We presume that no SQL queries coming from an application will trigger errors by default.
                // Thus, the presence of an error potentially indicates the introduction of additional command syntax (i.e. SQL Injection)
                match (request_info.query, response.basic_type()) {
                    (Some(query), ResponseBasicType::RequestCompleted) => validator.update_good_query(query),
                    (Some(query), _) => validator.update_bad_query(query),
                    _ => ()
                }

                self.sql_session.recycle_response(response);
            } else {
                // Somehow, we received one more response from the database than what we were expecting. This is BAD (as it could lead to erroneous data and errors being passed to the application, not to mention request smuggling...)
                return Err(io::Error::new(io::ErrorKind::InvalidData, "proxy request/response flow became desynchronized--aborting connection"))
                // TODO: make sure this errorkind (InvalidData) doesn't conflict with others
            }
        }

        // Successfully wrote all remaining data from buffers, so connection can be closed
        if self.db_read_closed {
            self.get_client_socket().shutdown(net::Shutdown::Write)?; // TODO: here, or in SqlSession?
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "connection gracefully terminated (no more packets from database)"))
        }

        Ok(())
    }
}