use log;
use nohash_hasher;
use polling::{Event, Poller};
use socket2::{Domain, SockAddr, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;
use std::{error, fmt, io};

use crate::sql;
use crate::sql_wire;

use super::connection::{Connection, IONeed};
use super::key_pool::KeyPool;
use super::validator;

pub struct Parameters {
    pub validator_params: validator::Parameters,
}

impl Parameters {
    pub fn default() -> Self {
        Parameters {
            validator_params: validator::Parameters::default(),
        }
    }
}

#[derive(Debug)]
pub struct HandlerError {
    reason: String,
}

impl fmt::Display for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.reason)
    }
}

impl error::Error for HandlerError {}

impl std::convert::From<std::io::Error> for HandlerError {
    fn from(e: std::io::Error) -> Self {
        HandlerError {
            reason: e.to_string(),
        }
    }
}

pub struct EventHandler<D: sql::Detector, P: sql_wire::Proxy<Socket, Socket>> {
    db_addr: SockAddr,
    db_key_map: HashMap<usize, usize, nohash_hasher::BuildNoHashHasher<usize>>,
    key_pool: KeyPool,
    listener: Socket,
    listener_key: usize,
    poller: Poller,
    connections: HashMap<usize, Connection<D, P>, nohash_hasher::BuildNoHashHasher<usize>>,
    validator: validator::SqlValidator<D>,
}

impl<D: sql::Detector, P: sql_wire::Proxy<Socket, Socket>> EventHandler<D, P> {
    pub fn new(
        listen_address: SockAddr,
        db_address: SockAddr,
        params: Parameters,
    ) -> Result<Self, HandlerError> {
        let listener = create_listener(&listen_address)?;
        let poller = match Poller::new() {
            Ok(p) => p,
            Err(e) => {
                return Err(HandlerError {
                    reason: format!("failed to initialize poller: {}", e.to_string()),
                })
            }
        };
        let mut pool = KeyPool::new();
        let listener_key = pool.take_key();

        match poller.add(&listener, Event::none(listener_key)) {
            Ok(_) => (),
            Err(e) => {
                return Err(HandlerError {
                    reason: format!(
                        "failed to add listening socket to poller: {}",
                        e.to_string()
                    ),
                })
            }
        };

        Ok(EventHandler::<D, P> {
            db_addr: db_address,
            key_pool: pool,
            listener: listener,
            listener_key: listener_key,
            poller: poller,
            connections: HashMap::with_hasher(nohash_hasher::BuildNoHashHasher::default()),
            db_key_map: HashMap::with_hasher(nohash_hasher::BuildNoHashHasher::default()),
            validator: validator::SqlValidator::new(params.validator_params),
        })
    }

    pub fn handle_loop(&mut self) -> Result<(), HandlerError> {
        let mut new_events = Vec::new();
        let mut event_keys = HashMap::with_hasher(nohash_hasher::BuildNoHashHasher::default());

        loop {
            // If we still have connections to service in the queue, return additional connections immediately
            let timeout = if event_keys.len() > 0 {
                log::debug!("Temporarily polling for new socket events");
                Some(Duration::ZERO)
            } else {
                log::debug!("Polling for new socket events indefinitely...");
                None
            };

            // We always want our listening socket to be polled
            match self
                .poller
                .modify(&self.listener, Event::readable(self.listener_key))
            {
                Ok(_) => (),
                Err(e) => {
                    return Err(HandlerError {
                        reason: format!(
                            "failed to poll read events on listening socket: {}",
                            e.to_string()
                        ),
                    })
                }
            };

            match self.poller.wait(&mut new_events, timeout) {
                Ok(_) => (),
                Err(e) => {
                    return Err(HandlerError {
                        reason: format!("poller error while awaiting events: {}", e.to_string()),
                    })
                }
            };

            while let Some(ev) = new_events.pop() {
                // No need to call events.clear(); this does it
                let (key, mut incoming, mut outgoing) = match self.db_key_map.get(&ev.key) {
                    Some(key) => (*key, ev.writable, ev.readable), // The original key was for a database-facing socket
                    None => (ev.key, ev.readable, ev.writable), // The key is for a client-facing socket
                };

                (incoming, outgoing) = match event_keys.get(&key) {
                    Some((i, o)) => ((incoming || *i), (outgoing || *o)),
                    None => (incoming, outgoing),
                };

                if key == self.listener_key {
                    self.handle_listener_event(&mut event_keys)?;
                } else {
                    event_keys.insert(
                        key,
                        match event_keys.get(&key) {
                            Some((old_incoming, old_outgoing)) => {
                                (old_incoming | incoming, old_outgoing | outgoing)
                            }
                            None => (incoming, outgoing),
                        },
                    );
                }
            }

            self.handle_queue(&mut event_keys)?;
        }
    }

    fn handle_listener_event(
        &mut self,
        event_keys: &mut HashMap<usize, (bool, bool), nohash_hasher::BuildNoHashHasher<usize>>,
    ) -> Result<(), HandlerError> {
        // We could loop here, calling accept() as many times as it will return, but
        // that could have the potential to starve existing connections.

        match self.listener.accept() {
            Ok((new_client, new_client_addr)) => {
                let client_addr_name = match new_client_addr.as_socket() {
                    Some(socket_addr) => socket_addr.to_string(),
                    None => "<unknown_addr_type>".to_string(),
                };

                log::info!("Received new connection from client {}", client_addr_name);

                match new_client.set_nonblocking(true) {
                    Ok(_) => (),
                    Err(e) => {
                        log::error!(
                            "Failed to set {} client socket to nonblocking: {}",
                            client_addr_name,
                            e
                        );
                        return Ok(());
                    }
                }

                let backend_socket =
                    match create_backend_socket(Domain::from(self.db_addr.family() as i32)) {
                        Ok(sock) => sock,
                        Err(e) => {
                            log::error!("{}", e.reason);
                            return Ok(()); // Fail gracefully in this case--we don't want an influx of new connections causing a db error to crash existing connections, that would be DOS
                        }
                    };
                let client_key = self.key_pool.take_key();
                let backend_key = self.key_pool.take_key();

                match self.poller.add(&new_client, Event::none(client_key)) {
                    Ok(_) => (),
                    Err(e) => {
                        log::error!(
                            "Failed to add {} client socket to poller: {}",
                            client_addr_name,
                            e
                        );
                        return Ok(());
                    }
                }
                match self.poller.add(&backend_socket, Event::none(backend_key)) {
                    Ok(_) => (),
                    Err(e) => {
                        log::error!(
                            "Failed to add {} client socket to poller: {}",
                            client_addr_name,
                            e
                        );
                        return Ok(());
                    }
                }

                log::info!(
                    "Successfully initialized connection for client {}",
                    client_addr_name
                );

                self.connections.insert(
                    client_key,
                    Connection::new(
                        self.db_addr.clone(),
                        backend_key,
                        backend_socket,
                        client_addr_name,
                        client_key,
                        new_client,
                    ),
                );

                self.db_key_map.insert(backend_key, client_key);
                event_keys.insert(client_key, (true, false)); // Necessary to call `connect` on db_socket
            }
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
                | io::ErrorKind::Interrupted => (),
                // io::ErrorKind::ConnectionAborted | io::ErrorKind::PermissionDenied => { }
                // Permission denied means that Linux firewall blocked connection
                _ => log::info!("Listener failed to accept new connection: {}", e),
            },
        }

        Ok(())
    }

    fn connection_cleanup(&mut self, connection_key: usize) {
        let connection = match self.connections.remove(&connection_key) {
            Some(conn) => conn,
            None => {
                log::warn!("Wrong key passed to event handler to clean up connection resources: key {} had no associated connection information", connection_key);
                return;
            }
        };

        self.key_pool.return_key(connection_key);
        self.key_pool.return_key(connection.get_backend_key());

        self.db_key_map.remove(&connection.get_backend_key());
        self.connections.remove(&connection_key); // Allows `connection` to be freed up
        match self.poller.delete(connection.get_frontend_socket()) {
            Ok(()) => (),
            Err(e) => log::warn!(
                "Frontend socket for {} couldn't be removed from poller during cleanup: {}",
                connection.get_frontend_address(),
                e
            ),
        }
        match self.poller.delete(connection.get_backend_socket()) {
            Ok(()) => (),
            Err(e) => log::warn!(
                "Backend socket for {} couldn't be removed from poller during cleanup: {}",
                connection.get_frontend_address(),
                e
            ),
        }
    }

    fn handle_queue(
        &mut self,
        events: &mut HashMap<usize, (bool, bool), nohash_hasher::BuildNoHashHasher<usize>>,
    ) -> Result<(), HandlerError> {
        let mut queue = VecDeque::from_iter(events.drain());

        while let Some((frontend_key, (incoming, outgoing))) = queue.pop_front() {
            let connection = match self.connections.get_mut(&frontend_key) {
                Some(c) => c,
                None => {
                    // This should never happen
                    log::warn!(
                        "Connection information missing for event key {}",
                        frontend_key
                    );
                    log::debug!(
                        "Event key had incoming flag set to {}, outgoing flag set to {}",
                        incoming,
                        outgoing
                    );
                    continue;
                }
            };

            log::debug!(
                "Handling event for client {} with event key {}",
                connection.get_frontend_address(),
                frontend_key
            );

            let mut still_incoming = false;
            let mut still_outgoing = false;

            let mut frontend_events = IONeed::None;
            let mut backend_events = IONeed::None;

            if outgoing {
                log::debug!(
                    "Processing outgoing packets for client {} with event key {}",
                    connection.get_frontend_address(),
                    frontend_key,
                );
                match connection.process_outgoing(&mut self.validator) {
                    Ok(res) => {
                        still_outgoing = res.should_retry;
                        frontend_events |= res.frontend;
                        backend_events |= res.backend;
                    }
                    Err(e) => {
                        log::info!(
                            "Client {} closed while processing outgoing packets - {}",
                            frontend_key,
                            e.to_string()
                        );

                        self.connection_cleanup(frontend_key);
                        continue; // Error was unrecoverable, so no sense processing incoming or re-adding socket to polling
                    }
                };
            }

            if incoming {
                log::debug!(
                    "Processing incoming packets for client {} with event key {}",
                    connection.get_frontend_address(),
                    frontend_key
                );
                match connection.process_incoming(&mut self.validator) {
                    Ok(res) => {
                        still_incoming = res.should_retry;
                        frontend_events |= res.frontend;
                        backend_events |= res.backend;
                    }
                    Err(e) => {
                        log::info!(
                            "Client {} closed while processing incoming packets - {}",
                            connection.get_frontend_address(),
                            e.to_string()
                        );

                        self.connection_cleanup(frontend_key);
                        continue; // Error was unrecoverable, so no sense processing incoming or re-adding socket to polling
                    }
                };
            }

            if still_incoming || still_outgoing {
                log::debug!("Connection was still_incoming or still_outgoing--put back into event_keys for next iteration");
                match events.insert(frontend_key, (still_incoming, still_outgoing)) {
                    Some(_) => log::warn!("event inserted into queue that already contained it (connection state likely corrupted)"),
                    None => (),
                }
                // Re-add key to event keys so that it will be handled immediately
            }

            if frontend_events != IONeed::None {
                log::debug!("Frontend events were not none--adding frontend socket to poller");
                self.poller.modify(
                    connection.get_frontend_socket(),
                    match_event(frontend_events, connection.get_frontend_key()),
                )?;
            }

            if backend_events != IONeed::None {
                log::debug!("Backend events were not none--adding backend socket to poller");
                self.poller.modify(
                    connection.get_backend_socket(),
                    match_event(backend_events, connection.get_backend_key()),
                )?;
            }
        }

        Ok(())
    }
}

fn match_event(res: IONeed, key: usize) -> Event {
    match res {
        IONeed::Read => Event::readable(key),
        IONeed::Write => Event::writable(key),
        IONeed::ReadWrite => Event::all(key),
        IONeed::None => Event::none(key),
    }
}

fn create_listener(listen_address: &SockAddr) -> Result<Socket, HandlerError> {
    let family = match listen_address.family() as i32 {
        libc::AF_INET => Domain::IPV4,
        libc::AF_INET6 => Domain::IPV6,
        _ => {
            return Err(HandlerError {
                reason: format!(
                    "unrecognized family '{}' for specified listener address",
                    listen_address.family()
                ),
            })
        }
    };

    let listener = match Socket::new(family, Type::STREAM, None) {
        Ok(sock) => sock,
        Err(e) => {
            return Err(HandlerError {
                reason: format!("socket creation for listener failed: {}", e.to_string()),
            })
        }
    };

    match listener.set_nonblocking(true) {
        Ok(_) => (),
        Err(e) => {
            return Err(HandlerError {
                reason: format!(
                    "listening socket could not be set to nonblocking: {}",
                    e.to_string()
                ),
            })
        }
    };

    match listener.bind(&listen_address) {
        Ok(_) => (),
        Err(e) => {
            return Err(HandlerError {
                reason: format!(
                    "listening socket could not be bound to the desired address: {}",
                    e.to_string()
                ),
            })
        }
    };
    match listener.listen(4096) {
        // Maximum number of backlogged connections
        Ok(_) => (),
        Err(e) => {
            return Err(HandlerError {
                reason: format!(
                    "server socket failed to listen for new connections: {}",
                    e.to_string()
                ),
            })
        }
    };
    Ok(listener)
}

fn create_backend_socket(family: Domain) -> Result<Socket, HandlerError> {
    let db_socket = match Socket::new(family, Type::STREAM, None) {
        Ok(sock) => sock,
        Err(e) => {
            return Err(HandlerError {
                reason: format!(
                    "failed to create new socket to connect to backend: {}",
                    e.to_string()
                ),
            })
        }
    };

    match db_socket.set_nonblocking(true) {
        Ok(_) => (),
        Err(e) => {
            return Err(HandlerError {
                reason: format!(
                    "failed to make database socket nonblocking: {}",
                    e.to_string()
                ),
            })
        }
    };

    Ok(db_socket)
}
