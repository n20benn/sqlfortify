use crate::sqli_detector;

use super::sql_session::{ClientMessage, ProxySession, ServerMessage};
use socket2::{SockAddr, Socket};
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::{io, net, ops};

use super::validator::SqlValidator;

/// The maximum number of requests or responses to buffer in each direction
const REQUEST_QUEUE_SOFT_LIMIT: usize = 10;
const RESPONSE_QUEUE_SOFT_LIMIT: usize = 10;

const CODE_EINPROGRESS: i32 = 115;
const CODE_EISCONNECTED: i32 = 106;

struct RequestMetadata {
    is_malicious: bool,
    query: Option<String>,
}

/// The possible connection states of a `Proxy`.
#[derive(PartialEq, Eq)]
enum ConnectionState {
    // ClientTLSHandshake, // unimplemented
    /// The backend is performing a TCP handshake
    DatabaseTCPHandshake, // called connect() to database, awaiting completed connection
    // DatabaseTLSHandshake, // unimplemented
    /// The frontend and backend are fully connected and transferring data
    Connected,
}

/// Enumerates the read/write events that a socket cannot send/receive data for
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IONeed {
    /// Indicates that no read or write events on the socket have failed
    None,
    /// Indicates that data could not be read from the socket without blocking
    Read,
    /// Indicates that data could not be written to the socket without blocking
    Write,
    /// Indicates that data could be neither read from nor written to the socket without blocking
    ReadWrite,
}

impl ops::BitOr for IONeed {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (IONeed::ReadWrite, _) | (_, IONeed::None) => self,
            (_, IONeed::ReadWrite) | (IONeed::None, _) => rhs,
            (IONeed::Read, IONeed::Write) | (IONeed::Write, IONeed::Read) => IONeed::ReadWrite,
            _ => self, // can only be (Write, Write) or (Read, Read)
        }
    }
}

impl ops::BitOrAssign for IONeed {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs // Uses bitor() function to properly assign left-hand side
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProxyResult {
    pub frontend: IONeed,
    pub backend: IONeed,
    pub should_retry: bool,
}

impl ProxyResult {
    fn none() -> Self {
        ProxyResult {
            frontend: IONeed::None,
            backend: IONeed::None,
            should_retry: false,
        }
    }
}

impl ops::BitOr for ProxyResult {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        ProxyResult {
            frontend: self.frontend | rhs.frontend,
            backend: self.backend | rhs.backend,
            should_retry: self.should_retry | rhs.should_retry,
        }
    }
}

impl ops::BitOrAssign for ProxyResult {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs
    }
}

/// Handles and proxies a single SQL connection between an incoming client connection
/// and the backend database.
///
pub struct Proxy<D: sqli_detector::Detector, P: ProxySession<Socket, Socket>> {
    backend_address: SockAddr,
    backend_key: usize,
    backend_read_closed: bool,
    backend_write_closed: bool,
    frontend_address: String,
    frontend_key: usize,
    frontend_read_closed: bool,
    incoming_data: VecDeque<P::RequestType>,
    outgoing_data: VecDeque<P::ResponseType>,
    request_queue: VecDeque<RequestMetadata>,
    sql_session: P,
    /// The current connectivity state of the proxy
    state: ConnectionState,
    _sqli_detector_type: PhantomData<D>,
}

// STEPS TO REMOVE INDIVIDUAL PACKETS:
// 1. read_packet_raw() -> returns Packet (with length) or nothing. When it returns a packet, it advances the readable index by the length of the packet.
// 1b. both Proxy and PostgresSession keep track of packet sizes using a Vec<usize>
// 2. write_raw() -> returns a usize indicating number of bytes written. Proxy and Session decrement/remove packet length from Vec based on usize returned.
// 3. When read_packet_raw() returns a packet that has a malicious query, mark it as a packet to be discarded in the Vec<usize> and start using write_packet_raw(),
// removing packets from the VecDeque<usize>
// 4. Once the packet to remove is reached, use the `advance_read()` function in the Buffer to completely remove the packet
// 5. Go back to write_raw() after done for efficiency

impl<D: sqli_detector::Detector, P: ProxySession<Socket, Socket>> Proxy<D, P> {
    pub fn new(
        backend_address: SockAddr,
        backend_key: usize,
        backend_socket: Socket,
        frontend_address: String,
        frontend_key: usize,
        frontend_socket: Socket,
    ) -> Self {
        Proxy {
            backend_address,
            backend_key,
            backend_read_closed: false,
            backend_write_closed: false,
            frontend_address: frontend_address,
            frontend_key,
            frontend_read_closed: false,
            incoming_data: VecDeque::new(),
            outgoing_data: VecDeque::new(),
            request_queue: VecDeque::new(),
            sql_session: P::new(backend_socket, frontend_socket),
            state: ConnectionState::DatabaseTCPHandshake,
            _sqli_detector_type: PhantomData {},
        }
    }

    /// Returns the polling key associated with the database socket of the given proxy.
    pub fn get_backend_key(&self) -> usize {
        self.backend_key
    }

    /// Returns the client socket of the given proxy connection.
    pub fn get_backend_socket(&self) -> &Socket {
        self.sql_session.get_backend_io_ref()
    }

    pub fn get_frontend_address<'a>(&'a self) -> &'a str {
        self.frontend_address.as_str()
    }

    /// Returns the polling key associated with the client socket of the given proxy.
    pub fn get_frontend_key(&self) -> usize {
        self.frontend_key
    }

    /// Returns the database socket of the given proxy.
    pub fn get_frontend_socket(&self) -> &Socket {
        self.sql_session.get_frontend_io_ref()
    }

    /// Returns `true` if no more packets remain to be sent to the backend and the frontend client has closed its write end
    pub fn no_more_incoming(&self) -> bool {
        self.frontend_read_closed && self.backend_write_closed
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
    pub fn process_incoming(&mut self, validator: &mut SqlValidator<D>) -> io::Result<ProxyResult> {
        let mut res = ProxyResult::none();

        /*
        if self.state == State::ClientTLSHandshake {
            client_ev |= self.connect_client_tls()?;
        }
        */

        if self.state == ConnectionState::DatabaseTCPHandshake {
            res |= self.connect_backend()?;
        }

        /*
        if self.state == State::DatabaseTLSHandshake {
            db_ev |= self.connect_db_tls()?;
        }
        */

        if self.state == ConnectionState::Connected {
            // Only go through one round of each phase to ensure fairness at the EventHandler layer
            res |= match self.process_frontend_data(validator) {
                Ok(needs) => needs,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => ProxyResult {
                        frontend: IONeed::Read,
                        backend: IONeed::None,
                        should_retry: false,
                    },
                    _ => return Err(e),
                },
            };

            res |= match self.proxy_data_to_backend() {
                Ok(needs) => needs,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => ProxyResult {
                        frontend: IONeed::None,
                        backend: IONeed::Write,
                        should_retry: false,
                    },
                    _ => return Err(e),
                },
            };
        }

        Ok(res)
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
    pub fn process_outgoing(&mut self, validator: &mut SqlValidator<D>) -> io::Result<ProxyResult> {
        let mut res = ProxyResult::none();

        /*
        if self.state == State::ClientTLSHandshake {
            client_ev |= self.connect_client_tls()?;
        }
        */

        /*
        if self.state == ConnectionState::DatabaseTCPHandshake {
            backend_ev |= self.connect_backend()?;
        }
        */

        /*
        if self.state == State::DatabaseTLSHandshake {
            db_ev |= self.connect_db_tls()?;
        }
        */

        if self.state == ConnectionState::Connected {
            // Only go through one round of each phase to ensure fairness at the EventHandler layer

            res |= match self.process_backend_data(validator) {
                Ok(needs) => needs,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => ProxyResult {
                        frontend: IONeed::None,
                        backend: IONeed::Read,
                        should_retry: false,
                    },
                    _ => return Err(e),
                },
            };

            res |= match self.proxy_data_to_frontend() {
                Ok(needs) => needs,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => ProxyResult {
                        frontend: IONeed::Write,
                        backend: IONeed::None,
                        should_retry: false,
                    },
                    _ => return Err(e),
                },
            };
        }

        Ok(res)
    }

    /// Attempts to establish a proxy connection to the backend database.
    fn connect_backend(&mut self) -> io::Result<ProxyResult> {
        match self.get_backend_socket().connect(&self.backend_address) {
            Ok(()) => {
                log::debug!(
                    "Connection to database completed for socket with key {}",
                    self.get_backend_key()
                );
                self.state = ConnectionState::Connected;
                Ok(ProxyResult {
                    frontend: IONeed::Read,
                    backend: IONeed::Read,
                    should_retry: false,
                })
            }
            Err(e) if e.raw_os_error() == Some(CODE_EISCONNECTED) => {
                log::debug!(
                    "EISCONNECTED error on connect() for socket with key {}",
                    self.get_backend_key()
                );
                self.state = ConnectionState::Connected;
                Ok(ProxyResult {
                    frontend: IONeed::Read,
                    backend: IONeed::Read,
                    should_retry: false,
                })
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(CODE_EINPROGRESS) =>
            {
                log::debug!("Connection to database blocked");
                Ok(ProxyResult {
                    frontend: IONeed::None,
                    backend: IONeed::Write,
                    should_retry: false,
                })
            }
            Err(e) => Err(e),
        }
    }

    fn process_frontend_data(
        &mut self,
        validator: &mut SqlValidator<D>,
    ) -> io::Result<ProxyResult> {
        if self.frontend_read_closed {
            log::debug!("Not reading any new requests as frontend read end is closed");
            if !self.backend_write_closed && self.incoming_data.len() == 0 {
                log::info!("No more packets to forward to backend and frontend read closed--closing backend write for {}", self.frontend_address.as_str());
                self.get_backend_socket().shutdown(net::Shutdown::Write)?; // No more data to process, so close other half of the incoming stream
                self.backend_write_closed = true;
            }
            return Ok(ProxyResult::none());
        }

        if self.incoming_data.len() >= REQUEST_QUEUE_SOFT_LIMIT {
            log::debug!("Deferring reading additional packets as incoming stream has filled its buffer allowance");
            return Ok(ProxyResult::none()); // Defer receiving requests until the buffer has had time to be drained
        }

        let mut request = match self.sql_session.frontend_receive_request() {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                log::info!("Frontend read closed--no more new incoming packets for {}", self.frontend_address.as_str());
                self.frontend_read_closed = true;
                return Ok(ProxyResult::none());
            }
            Err(e) => return Err(e),
        };

        log::debug!("Successfully received request from frontend");

        let mut io_needs = ProxyResult {
            frontend: IONeed::None,
            backend: IONeed::None,
            should_retry: true,
        };
        if request.get_basic_info().gssenc_requested {
            log::warn!("Frontend attempted to encrypt stream with GSSAPI (not supported)--session encryption downgraded");
            if let Some(resp) = self.sql_session.frontend_downgrade_gssenc(&mut request) {
                self.outgoing_data.push_back(resp);
                io_needs.frontend |= IONeed::Write; // To ensure that the frontend gets this packet written out
            }

            if !request.is_valid() {
                // if is_valid set to `false` then the request is not to be forwarded
                return Ok(io_needs);
            }
        }

        if request.get_basic_info().ssl_requested {
            log::warn!("Frontend attempted to encrypt stream with SSL (not supported)--session encryption downgraded");
            if let Some(resp) = self.sql_session.frontend_downgrade_ssl(&mut request) {
                self.outgoing_data.push_back(resp);
                io_needs.frontend |= IONeed::Write; // To ensure that the frontend gets this packet written out
            }

            if !request.is_valid() {
                // if is_valid set to `false` then the request is not to be forwarded
                return Ok(io_needs);
            }
        }

        if let Some(query) = request.get_basic_info().query.as_ref() {
            log::info!("SQL query received from frontend for {}--checking for SQL injection attempts...", self.frontend_address.as_str());
            match validator.check_query(query.as_str()) {
                Err(e) => {
                    log::warn!("SQL injection detected in query: {}", e);
                    self.request_queue.push_back(RequestMetadata {
                        query: Some(query.clone()),
                        is_malicious: true,
                    });

                    io_needs.frontend |= IONeed::Write; // To ensure that the frontend gets this packet written out
                }
                Ok(()) => {
                    log::info!("SQL query was benign");
                    self.request_queue.push_back(RequestMetadata {
                        query: Some(query.clone()),
                        is_malicious: false,
                    });
                    self.incoming_data.push_back(request);
                }
            }
        } else {
            log::debug!("Received request was not a SQL query");
            if request.get_basic_info().is_request {
                self.request_queue.push_back(RequestMetadata {
                    query: None,
                    is_malicious: false,
                });
            }

            self.incoming_data.push_back(request);
        }

        Ok(io_needs)
    }

    fn proxy_data_to_backend(&mut self) -> io::Result<ProxyResult> {
        if self.backend_write_closed {
            return Ok(ProxyResult::none());
        }

        // NOTE: chould change these while loops to `if` and return ProxyResult { frontend: IONeed::None, backend: IONeed::None, do_again: self.incoming_data.len() > 0 }
        // But only if we feel like this while loop could be enough for one client to starve others of resources (very unlikely if even at all possible)
        while let Some(request) = self.incoming_data.pop_front() {
            log::debug!("Proxying next request in queue to backend");
            match self.sql_session.backend_send_request(&request) {
                Ok(()) => self.sql_session.recycle_request(request),
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                    log::info!("Backend write end closed--closing frontend read end and backend for {}", self.frontend_address.as_str());
                    if !self.frontend_read_closed {
                        self.frontend_read_closed = true;
                        match self.get_frontend_socket().shutdown(net::Shutdown::Read) {
                            Ok(_) => (),
                            Err(e) => {
                                return Err(io::Error::new(
                                    io::ErrorKind::ConnectionAborted,
                                    format!(
                                "error when attempting to close {} frontend socket read end: {}",
                                self.frontend_address.as_str(),
                                e.to_string()
                            ),
                                ))
                            }
                        };
                    }

                    // No sense pushing the incoming request back onto the stack--there'll be no way to send it anyways
                    // TODO: make sure the number of responses we expect from the server are correct in this edge case
                }
                Err(e) => {
                    self.incoming_data.push_front(request); // Could be a recoverable error, such as EWOULDBLOCK, so we add the request back to our queue
                    return Err(e);
                }
            }
        }

        if self.frontend_read_closed {
            self.backend_write_closed = true;
            match self.get_backend_socket().shutdown(net::Shutdown::Write) {
                Ok(_) => (),
                Err(e) => log::info!(
                    "error when closing {} backend socket write end: {}",
                    self.frontend_address.as_str(),
                    e.to_string()
                ),
            }
        }

        Ok(ProxyResult::none())
    }

    fn process_backend_data(&mut self, validator: &mut SqlValidator<D>) -> io::Result<ProxyResult> {
        // If we have no more data to receive and none to to send, we should close the connection
        if self.no_more_incoming() && self.request_queue.is_empty() && self.outgoing_data.is_empty()
        {
            if !self.backend_write_closed {
                match self.get_backend_socket().shutdown(net::Shutdown::Write) {
                    Ok(_) => (),
                    Err(e) => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, format!("connection otherwise gracefully terminated, but error when attempting to close backend socket write end: {}", e.to_string()))),
                }
            }
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "connection gracefully terminated (no more packets to read in from client or process)"));
        }

        if self.backend_read_closed {
            log::debug!("Not reading any new responses as backend read end for {} is closed", self.frontend_address.as_str());
            return Ok(ProxyResult::none()); // We're not going to receive any new packets, so stop here
        }

        // Remove any requests from the queue that are to be spoofed with error responses
        while let Some(request_info) = self.request_queue.pop_front() {
            if request_info.is_malicious {
                log::debug!("Error response packets injected into stream for malicious query");
                self.outgoing_data
                    .push_back(self.sql_session.error_response());
            } else {
                self.request_queue.push_front(request_info);
                break;
            }
        }

        if self.outgoing_data.len() >= RESPONSE_QUEUE_SOFT_LIMIT {
            log::debug!("Deferring reading additional responses as outgoing stream has filled its buffer allowance");
            return Ok(ProxyResult::none()); // Defer receiving responses until the buffer has had time to be drained
        }

        log::debug!("Reading in data from backend...");

        let response = match self.sql_session.backend_receive_response() {
            Ok(resp) => resp,
            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                log::info!("Backend write end closed--closing incoming stream for {} (read end of frontend and write end of backend)", self.frontend_address.as_str());
                self.backend_read_closed = true;
                if !self.frontend_read_closed {
                    self.frontend_read_closed = true; // If we can't get data from our db, no sense in accepting new data from our client
                    match self.get_frontend_socket().shutdown(net::Shutdown::Read) {
                        Ok(_) => (),
                        Err(e) => {
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                format!(
                                    "error when closing {} frontend socket read end: {}",
                                    self.frontend_address.as_str(),
                                    e.to_string()
                                ),
                            ))
                        }
                    }
                }
                if !self.backend_write_closed {
                    self.backend_write_closed = true;
                    match self.get_backend_socket().shutdown(net::Shutdown::Write) {
                        Ok(_) => (),
                        Err(e) => log::warn!(
                            "error when attempting to close {} backend socket write end: {}",
                            self.frontend_address.as_str(),
                            e.to_string()
                        ),
                    };
                }

                return Ok(ProxyResult::none());
            }
            Err(e) => return Err(e),
        };

        if let Some(was_successful) = response.get_basic_info().result {
            if let Some(request_info) = self.request_queue.pop_front() {
                // We presume that no SQL queries coming from an application will trigger errors by default.
                // Thus, the presence of an error potentially indicates the introduction of additional command syntax (i.e. SQL Injection)
                match (request_info.query, was_successful) {
                    (Some(query), true) => {
                        log::debug!("SQL success response detected from backend--updating query as good: ({})", query.as_str());
                        validator.update_good_query(query.as_str())
                    }
                    (Some(query), false) => {
                        log::warn!("SQL error response detected from backend--updating query as malicious: ({})", query.as_str());
                        validator.update_bad_query(query.as_str())
                    }
                    _ => log::debug!("SQL response detected for some non-query request"), // some other non-query request (e.g. a FunctionCall)
                }
            } else {
                // Somehow, we received one more response from the database than what we were expecting. This is BAD (as it could lead to erroneous data and errors being passed to the application, not to mention request smuggling...)
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("proxy request/response flow became desynchronized for {}", self.frontend_address.as_str()),
                ));
            }
        }

        self.outgoing_data.push_back(response);

        log::debug!("Successfully received response data from backend");

        Ok(ProxyResult {
            frontend: IONeed::None,
            backend: IONeed::None,
            should_retry: true,
        })
    }

    fn proxy_data_to_frontend(&mut self) -> io::Result<ProxyResult> {
        while let Some(response) = self.outgoing_data.pop_front() {
            match self.sql_session.frontend_send_response(&response) {
                Ok(()) => log::debug!("Successfully forwarded response to frontend"),
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                    log::info!("Frontend write end closed--closing all sockets for {} and freeing proxy resources", self.frontend_address.as_str());
                    // Close proxy according to TCP spec
                    self.get_frontend_socket().shutdown(net::Shutdown::Write)?;
                    self.get_frontend_socket().shutdown(net::Shutdown::Read)?;
                    self.get_backend_socket().shutdown(net::Shutdown::Read)?;
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, format!("{} client unexpectedly closed connection despite data remaining to be returned", self.frontend_address.as_str())));
                }
                Err(e) => {
                    self.outgoing_data.push_front(response); // we assume this could be a recoverable error, such as EWOULDBLOCK
                    return Err(e);
                }
            }

            self.sql_session.recycle_response(response);
            return Ok(ProxyResult::none());
        }

        // Successfully wrote all remaining data from buffers, so connection can be closed
        if self.backend_read_closed {
            match self.get_frontend_socket().shutdown(net::Shutdown::Write) {
                Ok(_) => (),
                Err(e) => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, format!("connection otherwise gracefully terminated, but error when closing {} frontend socket write end: {}", self.frontend_address.as_str(), e.to_string()))),
            }
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("{} connection gracefully terminated (no more packets from database)", self.frontend_address.as_str()),
            ));
        }

        Ok(ProxyResult::none())
    }
}
