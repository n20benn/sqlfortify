use log;
use polling::{Event, Poller};
use socket2::{Domain, SockAddr, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;
use std::{error, fmt, io};

use crate::sqli_detector;

use super::key_pool::KeyPool;
use super::proxy::{IOEvent, Proxy};
use super::validator;

use super::sql_session::ProxySession;

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

pub struct EventHandler<D: sqli_detector::Detector, P: ProxySession<Socket, Socket>> {
    db_addr: SockAddr,
    db_key_map: HashMap<usize, usize>,
    key_pool: KeyPool,
    listener: Socket,
    listener_key: usize,
    poller: Poller,
    proxies: HashMap<usize, Proxy<D, P>>,
    validator: validator::SqlValidator<D>,
}

impl<D: sqli_detector::Detector, P: ProxySession<Socket, Socket>> EventHandler<D, P> {
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
            proxies: HashMap::new(),
            db_key_map: HashMap::new(),
            validator: validator::SqlValidator::new(params.validator_params),
        })
    }

    pub fn handle_loop(&mut self) -> Result<(), HandlerError> {
        let mut new_events = Vec::new();
        let mut event_keys = HashMap::new();

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
                    Some(key) => (*key, ev.writable, ev.readable), // The key is for a database-facing socket
                    None => (ev.key, ev.readable, ev.writable), // The key is for a client-facing socket
                };

                (incoming, outgoing) = match event_keys.get(&key) {
                    Some((i, o)) => ((incoming || *i), (outgoing || *o)),
                    None => (incoming, outgoing),
                };

                if key == self.listener_key {
                    self.handle_listener_event(&mut event_keys)?;
                } else {
                    event_keys.insert(key, (incoming, outgoing));
                }
            }

            self.handle_queue(&mut event_keys)?;
        }
    }

    fn handle_listener_event(
        &mut self,
        event_keys: &mut HashMap<usize, (bool, bool)>,
    ) -> Result<(), HandlerError> {
        // We could loop here, calling accept() as many times as it will return, but
        // that could have the potential to starve existing connections.

        match self.listener.accept() {
            Ok((new_client, new_client_addr)) => {
                match new_client_addr.as_socket() {
                    Some(socket_addr) => {
                        log::info!("Received new connection from client {}", socket_addr)
                    }
                    None => log::info!("Received new connection from client {:?}", new_client_addr),
                }

                match new_client.set_nonblocking(true) {
                    Ok(_) => (),
                    Err(e) => {
                        log::error!("Failed to set incoming client socket to nonblocking: {}", e);
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
                        log::error!("Failed to add client socket to poller: {}", e);
                        return Ok(());
                    }
                }
                match self.poller.add(&backend_socket, Event::none(backend_key)) {
                    Ok(_) => (),
                    Err(e) => {
                        log::error!("Failed to add client socket to poller: {}", e);
                        return Ok(());
                    }
                }

                self.proxies.insert(
                    client_key,
                    Proxy::new(
                        self.db_addr.clone(),
                        backend_key,
                        backend_socket,
                        new_client_addr.clone(),
                        client_key,
                        new_client,
                    ),
                );

                self.db_key_map.insert(backend_key, client_key);
                event_keys.insert(client_key, (true, false)); // Necessary to call `connect` on db_socket

                match new_client_addr.as_socket() {
                    Some(socket_addr) => log::info!(
                        "Successfully initialized connection for client {}",
                        socket_addr
                    ),
                    None => log::info!(
                        "Successfully initialized connection for client {:?}",
                        new_client_addr
                    ),
                }
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

    fn handle_queue(
        &mut self,
        event_keys: &mut HashMap<usize, (bool, bool)>,
    ) -> Result<(), HandlerError> {
        let mut queue = VecDeque::from_iter(event_keys.drain());

        while let Some((frontend_key, (incoming, outgoing))) = queue.pop_front() {
            let proxy = match self.proxies.get_mut(&frontend_key) {
                Some(c) => c,
                None => {
                    // This should never happen
                    log::warn!("Proxy information missing for event key {}", frontend_key);
                    log::debug!(
                        "Event key had incoming flag set to {}, outgoing flag set to {}",
                        incoming,
                        outgoing
                    );
                    continue;
                }
            };

            let client_name = match proxy.get_frontend_address().as_socket() {
                Some(socket_addr) => socket_addr.to_string(),
                None => "<unknown_addr_type>".to_string(),
            };

            log::debug!(
                "Handling event for client proxy {} with event key {}",
                client_name,
                frontend_key
            );

            let mut still_incoming = false;
            let mut still_outgoing = false;

            let mut frontend_events = IOEvent::None;
            let mut backend_events = IOEvent::None;

            if outgoing {
                log::debug!(
                    "Processing outgoing packets for client proxy {} with event key {}",
                    client_name,
                    frontend_key
                );
                match proxy.process_outgoing(&mut self.validator) {
                    Ok((IOEvent::None, IOEvent::None)) => still_outgoing = true,
                    Ok((client_need, db_need)) => {
                        frontend_events |= client_need;
                        backend_events |= db_need;
                    }
                    Err(e) => {
                        log::info!(
                            "Proxy for client {} closed while processing outgoing packets - {}",
                            client_name,
                            e.to_string()
                        );
                        // Clean up proxy's resources
                        self.key_pool.return_key(proxy.get_frontend_key());
                        self.key_pool.return_key(proxy.get_backend_key());

                        self.db_key_map.remove(&proxy.get_backend_key());
                        self.proxies.remove(&frontend_key); // Allows `proxy` to be freed up
                        continue; // Error was unrecoverable, so no sense processing incoming or re-adding socket to polling
                    }
                };
            }

            if incoming {
                log::debug!(
                    "Processing incoming packets for client proxy {} with event key {}",
                    client_name,
                    frontend_key
                );
                match proxy.process_incoming(&mut self.validator) {
                    Ok((IOEvent::None, IOEvent::None)) => {
                        still_incoming = !proxy.no_more_incoming()
                    } // If incoming sockets are closed, don't continue trying to process incoming packets
                    Ok((frontend_need, backend_need)) => {
                        frontend_events |= frontend_need;
                        backend_events |= backend_need;
                    }
                    Err(e) => {
                        log::info!(
                            "Proxy for client {} closed while processing incoming packets - {}",
                            client_name,
                            e.to_string()
                        );
                        // Clean up proxy's resources
                        self.key_pool.return_key(proxy.get_frontend_key());
                        self.key_pool.return_key(proxy.get_backend_key());

                        self.db_key_map.remove(&proxy.get_backend_key());
                        self.proxies.remove(&frontend_key); // Allows `proxy` to be freed up
                        continue; // Error was unrecoverable, so no sense processing incoming or re-adding socket to polling
                    }
                };
            }

            if still_incoming || still_outgoing {
                log::debug!("Proxy was still_incoming or still_outgoing--put back into event_keys");
                event_keys.insert(frontend_key, (still_incoming, still_outgoing));
                // Re-add key to event keys so that it will be handled immediately
            }

            if !still_incoming && !proxy.no_more_incoming() {
                frontend_events |= IOEvent::Read;
            }

            if !still_outgoing {
                backend_events |= IOEvent::Read;
            }

            if frontend_events != IOEvent::None {
                log::debug!("Frontend events were not none--adding proxy frontend to poller");
                self.poller.modify(
                    proxy.get_frontend_socket(),
                    match_event(frontend_events, proxy.get_frontend_key()),
                )?;
            }

            if backend_events != IOEvent::None {
                log::debug!("Backend events were not none--adding proxy backend to poller");
                self.poller.modify(
                    proxy.get_backend_socket(),
                    match_event(backend_events, proxy.get_backend_key()),
                )?;
            }
        }

        Ok(())
    }
}

fn match_event(res: IOEvent, key: usize) -> Event {
    match res {
        IOEvent::Read => Event::readable(key),
        IOEvent::Write => Event::writable(key),
        IOEvent::ReadWrite => Event::all(key),
        IOEvent::None => Event::none(key),
    }
}

fn create_listener(listen_address: &SockAddr) -> Result<Socket, HandlerError> {
    let family = match listen_address.family() as i32 {
        libc::AF_INET => Domain::IPV4,
        libc::AF_INET6 => Domain::IPV6,
        _ => {
            return Err(HandlerError {
                reason: format!(
                    "unrecognized family for specified listener address {}",
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
