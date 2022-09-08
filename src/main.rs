//#[feature(nll)] // Enforced breakage with non-lexical lifetimes (going to be a thing soon in Rust)
// #![allow(unused)] // TODO: remove once ready to refine code
// #![allow(dead_code)]
// #![forbid(unsafe_code)]

mod matcher;
mod validator;
mod token;
mod proxy;
mod wire;
mod postgres_wire;
mod session;
mod postgres_session;
mod key_pool;
//mod iso_token;
//mod postgres_token;
mod cockroach_token;
mod event_handler;
mod mysql_wire;
mod base_session;
mod ring_buffer;
mod wire_reader;

use log::{error, info, trace};
use socket2::{Socket,SockAddr};
use std::{panic, process, thread};
use std::net::SocketAddr;

use event_handler::EventHandler;
use token::SqlToken;
use wire::Wire;
use cockroach_token::CockroachToken;
use postgres_wire::PostgresWire;


fn main() {
    env_logger::init(); // Logging to stderr by default

    // TODO: Someday we'll have per-thread handling of crashes... but not today.
    // If any thread panics, we kill the entire process so that the system's 
    // service handler (systemd or sc, for instance) can handle the shutdown
    // and potentially reload the service.
    panic::set_hook(Box::new(|info| {
        trace!("Thread panicked--entered custom panic handler");
        let thread = thread::current();
        let thread_name = thread.name().unwrap_or("<unnamed thread>");

        let msg = match info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match info.payload().downcast_ref::<String>() {
                Some(s) => &s[..],
                None => "<reason unspecified>",
            },
        };

        error!("An unexpected crash occurred in thread '{}': {}", thread_name, msg);

        if let Some(location) = info.location() {
            info!("Panic occurred in file '{}' at line {}", location.file(), location.line());
        } else {
            info!("Panic occurred at an unspecified location.");
        }

        error!("Forcing process termination with exit code 1");
        process::exit(1); // Important part--kills all threads if any one dies
    }));

    /*

    // Required arguments:
    // - Configuration file location
    let mut args:Vec<String> = env::args().collect();
    if args.len() < 1 || args.len() > 2 {
        error!("Invalid arguments supplied to command. Exiting...");
        process::exit(1);
    }

    
    let config_path = String::from("config.toml"); // Default configuration path
    if let Some(s) = args.drain(1..).next() {
        let config_path = s;
    }
    */

    // TODO: parse configuration here

    let listen:SocketAddr = "127.0.0.1:8080".parse().unwrap(); // TODO: remove unwrap
    let db:SocketAddr = "127.0.0.1:8081".parse().unwrap(); // TODO: remove unwrap

    let listen = SockAddr::from(listen);
    let db = SockAddr::from(db);

    // Both 'parse' and 'from' support IPv4 and IPv6, but not Unix domain sockets. Do this:
    // #[cfg(target_family="unix")]
    // SockAddr::unix(String::from("Path"));

    create_thread::<CockroachToken, PostgresWire<Socket>>(listen, db);
    
    loop {
        thread::park(); // Not guaranteed to block forever, so we loop
    }
}

fn create_thread<T, S>(listen_address: SockAddr, db_address: SockAddr) 
where T: SqlToken, S: Wire<Socket> {
    let _ = thread::Builder::new().name("CockroachDB".to_string()).spawn(move || {
        let mut handler: EventHandler<T, S>;

        match EventHandler::new(listen_address, db_address) {
            Ok(h) => handler = h,
            Err(e) => {
                error!("Unrecoverable error occurred while initializing event handler: {}", e);
                return
            }
        };

        match handler.handle_loop() {
            Ok(()) => error!("An unknown error occurred that caused the event loop to return"), // Invariant: should never happen (event loop is infinite loop)
            Err(e) => error!("Unrecoverable error caused event loop to crash: {}", e),
        }
    });
}


