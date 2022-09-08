//use log::{debug, error, info, trace, warn};
use polling::{Event, Poller};
use socket2::{Socket, SockAddr, Domain, Type};
use std::collections::{HashMap, VecDeque};
use std::{error, fmt, io};
use std::time::Duration;
use log::info;

use super::key_pool::KeyPool;
use super::proxy::{Proxy, IOEvent};
use super::token::SqlToken;
use super::wire::Wire;
use super::validator::SqlValidator;


// TODO: WARNING: unsafe code. Replace as soon as API replacement arrives
// Fixed by: https://github.com/rust-lang/socket2/pull/311
use libc::sockaddr_storage;
fn copy_sockaddr(addr: &SockAddr) -> SockAddr {
    unsafe {
        let sockaddr_storage_ref = addr.as_ptr().cast::<sockaddr_storage>().as_ref().unwrap();
        SockAddr::new(sockaddr_storage_ref.clone(), addr.len())
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

impl error::Error for HandlerError { }

impl std::convert::From<std::io::Error> for HandlerError {
    fn from(e: std::io::Error) -> Self {
        HandlerError { reason: e.to_string() }
    }
}



pub struct EventHandler<T: SqlToken, S: Wire<Socket>> {
    db_addr: SockAddr,
    db_key_map: HashMap<usize, usize>,
    key_pool: KeyPool,
    listener: Socket,
    listener_key: usize,
    poller: Poller,
    proxies: HashMap<usize, Proxy<T, S>>,
    validator: SqlValidator<T>,
}



impl<T: SqlToken, S: Wire<Socket>> EventHandler<T, S> {
    pub fn new(listen_address: SockAddr, db_address: SockAddr) -> Result<Self, HandlerError> {
        let listener = create_listener(&listen_address)?;
        let poller = Poller::new()?;
        let mut pool = KeyPool::new();
        let listener_key = pool.take_key();

        Ok(EventHandler::<T, S> {
            db_addr: db_address,
            key_pool: pool,
            listener: listener,
            listener_key: listener_key,
            poller: poller,
            proxies: HashMap::new(),
            db_key_map: HashMap::new(),
            validator: SqlValidator::new(),
        })
    }

    pub fn handle_loop(&mut self) -> Result<(),HandlerError> {
        let mut new_events = Vec::new();
        let mut event_keys = HashMap::new();

        loop {
            // If we still have connections to service in the queue, return additional connections immediately
            let timeout = if event_keys.len() > 0 { Some(Duration::ZERO) } else { None };
            
            // We always want our listening socket to be polled
            self.poller.modify(&self.listener, Event::readable(self.listener_key))?; // TODO: error handling here
            self.poller.wait(&mut new_events, timeout)?; 
            
            while let Some(ev) = new_events.pop() { // No need to call events.clear(); this does it
                let (key, mut incoming, mut outgoing) = match self.db_key_map.get(&ev.key) {
                    Some(key) => (*key, ev.writable, ev.readable), // The key is for a database-facing socket
                    None => (ev.key, ev.readable, ev.writable) // The key is for a client-facing socket
                };

                (incoming, outgoing) = match event_keys.get(&key) {
                    Some((i, o)) => ((incoming || *i), (outgoing || *o)),
                    None => (incoming, outgoing)
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

    fn handle_listener_event(&mut self, event_keys: &mut HashMap<usize, (bool, bool)>) -> Result<(), HandlerError> {
        // We could loop here, calling accept() as many times as it will return, but 
        // that could have the potential to starve existing connections.

        match self.listener.accept() {
            Ok((new_client, new_client_addr)) => {
                info!("Received new connection from client {:?}", new_client_addr);

                let db_socket = create_db_socket(Domain::from(self.db_addr.family() as i32))?;
                let db_key = self.key_pool.take_key();
                let client_key = self.key_pool.take_key();
                
                self.proxies.insert(client_key, Proxy::new(new_client, db_socket, copy_sockaddr(&self.db_addr), client_key, db_key));
                event_keys.insert(client_key, (true, false)); // Necessary to call `connect()` on db_socket
            },
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => (),
                io::ErrorKind::ConnectionAborted | io::ErrorKind::PermissionDenied => {
                    info!("Listener failed to accept new connection: {}", e);
                    // Permission denied means that Linux firewall blocked connection
                },
                _ => return Err(HandlerError::from(e)) // Unrecoverable error on listener (very rare)
            }
        }

        Ok(())
    }

    fn handle_queue(&mut self, event_keys: &mut HashMap<usize, (bool, bool)>) -> Result<(),HandlerError> {
        let mut queue = VecDeque::from_iter(event_keys.drain());

        while let Some((key,(incoming, outgoing))) = queue.pop_front() {
            let proxy = match self.proxies.get_mut(&key) {
                Some(c) => c,
                None => continue // Shouldn't really happen
            };

            let mut still_incoming = false;
            let mut still_outgoing = false;

            let mut client_events = IOEvent::None;
            let mut db_events = IOEvent::None;

            if outgoing {
                match proxy.process_outgoing(&mut self.validator) {
                    Ok((IOEvent::None, IOEvent::None)) => still_outgoing = true,
                    Ok((client_need, db_need)) => {
                        client_events |= client_need;
                        db_events |= db_need;
                    },
                    Err(_) => { // TODO: log socket's error `e` here
                        // Clean up proxy's resources
                        self.key_pool.return_key(proxy.get_client_key());
                        self.key_pool.return_key(proxy.get_db_key());

                        self.db_key_map.remove(&proxy.get_db_key());
                        self.proxies.remove(&key); // Allows `proxy` to be freed up 
                        // TODO: log errors in `remove()` calls here
                        continue // Error was unrecoverable, so no sense processing incoming or re-adding socket to polling
                    }
                };
            }
            
            if incoming {
                match proxy.process_incoming(&mut self.validator) {
                    Ok((IOEvent::None, IOEvent::None)) => still_incoming = !proxy.incoming_closed(), // If incoming sockets are closed, don't continue trying to process incoming packets
                    Ok((client_need, db_need)) => {
                        client_events |= client_need;
                        db_events |= db_need;
                    },
                    Err(_) => { // TODO: log socket's error `e` here
                        // Clean up proxy's resources
                        self.key_pool.return_key(proxy.get_client_key());
                        self.key_pool.return_key(proxy.get_db_key());

                        self.db_key_map.remove(&proxy.get_db_key());
                        self.proxies.remove(&key); // Allows `proxy` to be freed up 
                        // TODO: log errors in `remove()` calls here
                        continue // Error was unrecoverable, so no sense processing incoming or re-adding socket to polling
                    }
                };
            }

            if still_outgoing || still_incoming {
                event_keys.insert(key, (still_incoming, still_outgoing)); // Re-add key to event keys so that it will be handled immediately
            }

            if client_events != IOEvent::None {
                self.poller.modify(proxy.get_client_socket(), match_event(client_events, proxy.get_client_key()))?;
            }

            if db_events != IOEvent::None {
                self.poller.modify(proxy.get_db_socket(), match_event(db_events, proxy.get_db_key()))?;
            }
        };

        Ok(())
    }
}

fn match_event(res: IOEvent, key: usize) -> Event {
    match res {
        IOEvent::Read => Event::readable(key),
        IOEvent::Write => Event::writable(key),
        IOEvent::ReadWrite => Event::all(key),
        IOEvent::None => Event::none(key)
    }
}

fn create_listener(listen_address: &SockAddr) -> io::Result<Socket> {
    let listener = Socket::new(Domain::IPV4, Type::STREAM, None)?; // TODO: support IPv6; add error checks
    listener.set_nonblocking(true)?;
    listener.bind(&listen_address)?;
    listener.listen(4096)?; // Maximum number of backlogged connections
    Ok(listener)
}

fn create_db_socket(family: Domain) -> io::Result<Socket> {
    let db_socket = Socket::new(family, Type::STREAM, None)?;
    // TODO: future support for IPV6, Unix Domain sockets here...
    db_socket.set_nonblocking(true)?; // TODO: error handling here

    Ok(db_socket)
}

