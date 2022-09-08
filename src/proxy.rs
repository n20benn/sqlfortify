use socket2::{Socket, SockAddr};
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::{net, io, ops};
use super::validator::SqlValidator;
use super::token::SqlToken;
use super::wire::{Buffer, Packet, PacketType, Wire, WireDirection};

/// The default number of bytes 
//const DEFAULT_BUFFER_SIZE: usize = 65536;


struct PacketInfo { // PacketOverview? PacketHeader?
    is_query: bool,
    is_malicious: bool,
    remaining_bytes: usize,
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
pub struct Proxy<T: SqlToken, S: Wire<Socket>> {
    client: S,
    client_read_closed: bool,
    client_key: usize,
    db: S,
    db_address: SockAddr,
    db_read_closed: bool,
    db_write_closed: bool,
    db_key: usize,
    processing_malicious: bool,
    query_queue: VecDeque<PacketInfo>,
    incoming_data: <S as Wire<Socket>>::BufferType,
    incoming_packets: VecDeque<PacketInfo>,
    outgoing_data: <S as Wire<Socket>>::BufferType,
    outgoing_packets: VecDeque<PacketInfo>,
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

impl<T: SqlToken, S: Wire<Socket>> Proxy<T, S> {
    pub fn new(client_socket: Socket, database_socket: Socket, database_address: SockAddr, client_key: usize, db_key: usize) -> Self {
        Proxy {
            client: S::new(client_socket, WireDirection::ServerSide), // BufReader::new(client_socket),
            client_read_closed: false,
            client_key: client_key,
            db: S::new(database_socket, WireDirection::ClientSide), // BufReader::new(database_socket),
            db_address: database_address,
            db_read_closed: false,
            db_write_closed: false,
            db_key: db_key,
            processing_malicious: false,
            incoming_data: <S as Wire<Socket>>::BufferType::new(),
            incoming_packets: VecDeque::new(),
            outgoing_data: <S as Wire<Socket>>::BufferType::new(),
            outgoing_packets: VecDeque::new(),
            state: ConnectionState::DatabaseTCPHandshake,
            // wire: W::new(),
            _sqltoken_type: PhantomData,
        }
    }

    /// Returns the polling key associated with the client socket of the given proxy.
    pub fn get_client_key(&self) -> usize {
        self.client_key
    }

    /// Returns the client socket of the given proxy connection.
    pub fn get_client_socket(&self) -> &Socket {
        self.client.get_io_ref()
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
        self.db.get_io_ref()
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

            db_ev |= match self.process_db_packet(validator) {
                Ok(()) => IOEvent::None,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => IOEvent::Read,
                    _ => return Err(e)
                }
            };

            client_ev |= match self.proxy_db_packet() {
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
        match self.db.get_io_ref().connect(&self.db_address) {
            Ok(_) => {
                self.state = ConnectionState::Connected;
                Ok(IOEvent::None)
            },
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(IOEvent::ReadWrite),
            Err(e) => Err(e)
        }
    }

    fn process_client_packet(&mut self, validator: &mut SqlValidator<T>) -> io::Result<()> {
        if self.client_read_closed {
            if !self.db_write_closed && self.incoming_packets.len() == 0 {
                self.db.get_io_ref().shutdown(net::Shutdown::Write)?; // No more data to process, so close other half of the incoming stream
                self.db_write_closed = true;
            }
            return Ok(())
        }

        let packets = match self.client.read_raw(&mut self.incoming_data) {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                self.client_read_closed = true; // TODO: make sure that the socket actually has `shutdown()` called on it in the appropriate location
                return Ok(())
            },
            Err(e) => return Err(e)
        };

        for packet in packets {
            let packet_info = match packet.get_query() {
                Some(query) => match validator.check_query(&query) {
                    Ok(()) => PacketInfo { is_query: true, is_malicious: false, remaining_bytes: packet.len() },
                    Err(_) => {
                        self.processing_malicious = true;
                        PacketInfo { is_query: true, is_malicious: true, remaining_bytes: packet.len() }
                    },
                },
                None => PacketInfo { is_query: false, is_malicious: false, remaining_bytes: packet.len() }, // Not a query, so we don't validate it
            };

            self.incoming_packets.push_back(packet_info);
        }

        Ok(())
    }
        
    fn proxy_client_packet(&mut self) -> io::Result<()> {
        assert!(!self.db_write_closed);
        if self.db_write_closed {
            return Ok(()) // NOTE: this should never be reached based on how we've set up our event handler
        }
        
        if self.processing_malicious { // Proxy packets one at a time so that we can remove the malicious query packet
            match self.incoming_packets.front() {
                Some(p) if p.is_malicious => {
                    self.incoming_data.advance_read(p.remaining_bytes); // Discard packet from buffer
                    // TODO: inject an error packet sequence into the outgoing_data stream (or rather queue it up to do so)
                    self.incoming_packets.pop_front();
                    self.processing_malicious = self.incoming_packets.iter().any(|p| p.is_malicious);
                },
                Some(_) => (),
                None => {
                    self.processing_malicious = false; // False alarm TODO: log--this shouldn't happen unless something was coded wrong
                    return Ok(()) // There won't be any packets to write from `incoming_data` anyway
                }
            }

            match self.db.write_packet_raw(&self.incoming_data) {
                Ok(()) => { self.incoming_packets.pop_front(); },
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                    self.db_write_closed = true;
                    self.client_read_closed = true;
                    self.client.get_io_ref().shutdown(net::Shutdown::Read)?; // Stop receiving from client if DB disconnects // TODO: should this happen within the write_packet() call?
                    return Ok(())
                },
                Err(e) => return Err(e)
            }

        } else {
            let written = match self.db.write_raw(&self.incoming_data) {
                Ok(len) => len,
                Err(e) => match e.kind() {
                    io::ErrorKind::ConnectionAborted => {
                        self.db_write_closed = true;
                        self.client_read_closed = true;
                        self.client.get_io_ref().shutdown(net::Shutdown::Read)?; // Stop receiving from client if DB disconnects // TODO: should this happen within the write_packet() call?
                        return Ok(())
                    },
                    _ => return Err(e)
                }
            };

            while let Some(packet_data) = self.incoming_packets.front_mut() {
                if written == 0 {
                    break
                } else if written >= packet_data.remaining_bytes {
                    written -= packet_data.remaining_bytes;
                    self.incoming_packets.pop_front();
                } else {
                    packet_data.remaining_bytes -= written;
                    written = 0;
                }
            }
        }

        Ok(())
    }

    fn process_db_packet(&mut self, validator: &mut SqlValidator<T>) -> io::Result<()> {
        // If we have no more data to receive and none to to send, we should close the connection
        if self.incoming_closed() && self.query_queue.is_empty() && self.outgoing_packets.is_empty() {
            self.client.get_io_ref().shutdown(net::Shutdown::Write)?;
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "connection gracefully terminated (no more packets from client to read in/process)"))
        }

        if self.db_read_closed {
            return Ok(()) // We're not going to receive any new packets, so stop here
        }

        if self.processing_malicious {
            
        } else {
            let packets = match self.db.read_raw(&mut self.outgoing_data) {
                Ok(p) => p,
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                    self.db_read_closed = true;
                    return Ok(())
                },
                Err(e) => return Err(e)
            };

            for packet in packets {

            }
        }

        let packet = match self.db.read_packet_raw(&mut self.outgoing_data) {
            Ok(p) => p,
            Err(e) => match e.kind() {
                io::ErrorKind::ConnectionAborted => {
                    self.db_read_closed = true; // TODO: make sure that the socket actually has `shutdown()` called on it in the appropriate location
                    return Ok(())
                },
                _ => return Err(e)
            }
        };

        /*
        // Handles malicious queues specially--they won't have any wire data coming from the DB
        while let Some(SqlQuery::Malicious(_)) = self.queries.get(0) {
            self.queries.pop_front();

            // Inject an error into the stream of SQL responses
            let error_packets = S::generate_server_error();
            self.resp_proxy_queue.extend(error_packets);
        }

        // Now handle packets from the database socket
        let mut packet = match self.resp_receive_queue.pop_front() {
            Some(pkt) => pkt,
            None => { 
                if self.resp_buffer_cnt < MAX_BUFFER_CNT {
                    self.resp_buffer_cnt += 1; // Add a new buffer to the mix--we haven't reached the limit on number of buffers
                    S::new_packet()
                } else {
                    return Ok(()) // No buffers available to store packet in--defer until database gets done reading
                }
            }
        };
        
        match self.db.read_packet(&mut packet) {
            Ok(true) => {},
            Ok(false) => {
                self.req_receive_queue.push_front(packet);
                return Ok(())
            },
            Err(e) => {
                self.req_receive_queue.push_front(packet);
                return Err(e);
            }
        };

        /*
        let packet = match self.receive_server_packet(&mut buffer) {
            Ok(p) => p,
            Err(e) => {
                self.req_receive_buffers.push_front(buffer); // Put buffer back where we got it from for now
                return Err(e)
            }
        };
        */


        match packet.get_type() {
            PacketType::DataResponse => {
                // Invariant: SqlQuery::Malicious(_) will never occur here--we've already popped all of them from the front
                if let Some(SqlQuery::Benign(query)) = self.queries.pop_front() {
                    validator.update_good_query(query);
                }
            },
            PacketType::ErrorResponse => {
                // Invariant: SqlQuery::Malicious(_) will never occur here--we've already popped all of them from the front
                if let Some(SqlQuery::Benign(query)) = self.queries.pop_front() {
                    validator.update_bad_query(query);
                }
            },
            _ => ()
        }

        self.resp_proxy_queue.push_back(packet);

        */
        Ok(())
    }

    fn proxy_db_packet(&mut self) -> io::Result<()> {




        while let Some(mut packet) = self.resp_proxy_queue.pop_front() {
            match self.client.write_packet(&mut packet) {
                Ok(false) => {
                    self.resp_proxy_queue.push_front(packet);
                    return Ok(())
                }
                Ok(true) => {
                    if (self.resp_proxy_queue.len() + self.resp_receive_queue.len()) < MAX_BUFFER_CNT {
                        if packet.is_oversized() {
                            packet = S::new_packet();
                        } else {
                            packet.clear();
                        }

                        self.resp_receive_queue.push_back(packet);
                    }
                    // else we have too many buffers and should just drop this one
                },
                Err(e) => {
                    // if ConnectionAborted or InvalidData, then just return the error and shut down the entire proxy
                    self.resp_proxy_queue.push_front(packet); // Return the buffer to where it was
                    return Err(e)
                }
            };
        }

        // Successfully wrote all remaining data from buffers, so connection can be closed
        if self.db_read_closed {
            self.client.get_io_ref().shutdown(net::Shutdown::Write)?; // TODO: here, or in SqlSession?
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "connection gracefully terminated (no more packets from database)"))
        }

        Ok(())
    }
}