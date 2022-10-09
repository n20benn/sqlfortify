mod connection;
mod event_handler;
mod key_pool;
mod matcher;
mod validator;

mod sql;
mod sql_wire;

use socket2::{SockAddr, Socket};
use sql::cockroach_detector::CockroachDetector;
use std::{fs, io::Read, net::SocketAddr, path};
//use toml::{self, Deserializer};

use sql_wire::postgres_session::PostgresProxySession;

#[macro_use]
extern crate enum_display_derive;

fn main() {
    env_logger::init(); // Logging to stderr by default

    /*
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

        error!(
            "An unexpected crash occurred in thread '{}': {}",
            thread_name, msg
        );

        if let Some(location) = info.location() {
            info!(
                "Panic occurred in file '{}' at line {}",
                location.file(),
                location.line()
            );
        } else {
            info!("Panic occurred at an unspecified location.");
        }

        error!("Forcing process termination with exit code 1");
        process::exit(1); // Important part--kills all threads if any one dies
    }));
    */

    /*
    let config_path = path::Path::new("/home/nathaniel/Code/sqlfortify/default_config.toml");
    let mut file = match fs::File::open(&config_path) {
        Ok(file) => file,
        Err(e) => panic!(
            "Couldn't open configuration file {}: {}",
            config_path.display(),
            e
        ),
    };

    let mut config = String::new();
    match file.read_to_string(&mut config) {
        Ok(_) => (),
        Err(e) => panic!(
            "Configuration file located at {} had malformed data: {}",
            config_path.display(),
            e
        ),
    }

    let mut des = Deserializer::new(config.as_str());
    */

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

    let listen: SocketAddr = "127.0.0.1:8080".parse().unwrap(); // TODO: remove unwrap
    let db: SocketAddr = "127.0.0.1:5432".parse().unwrap(); // TODO: remove unwrap

    let listen = SockAddr::from(listen);
    let db = SockAddr::from(db);

    // This will get populated by the config file
    let params = event_handler::Parameters::default();

    // Both 'parse' and 'from' support IPv4 and IPv6, but not Unix domain sockets. Do this:
    // #[cfg(target_family="unix")]
    // SockAddr::unix(String::from("Path"));

    /*
    create_thread::<CockroachDetector, PostgresProxySession<Socket, Socket>>(listen, db, params);

    loop {
        thread::park(); // Not guaranteed to block forever, so we loop
    }
    */

    let mut handler: event_handler::EventHandler<
        CockroachDetector,
        PostgresProxySession<Socket, Socket>,
    >;

    match event_handler::EventHandler::new(listen, db, params) {
        Ok(h) => handler = h,
        Err(e) => {
            log::error!(
                "Unrecoverable error occurred while initializing event handler ({})",
                e
            );
            return;
        }
    };

    match handler.handle_loop() {
        Ok(()) => log::error!("An unknown error occurred that caused the event loop to return"), // Invariant: should never happen (event loop is infinite loop)
        Err(e) => log::error!("Unrecoverable error caused event loop to crash ({})", e),
    }
}

/*
fn create_thread<D, P>(
    listen_address: SockAddr,
    db_address: SockAddr,
    params: event_handler::Parameters,
)
// NOTE: could add C, S generics here that impl io::read and io::write to extend functionality beyond inet sockets
where
    D: sqli_detector::Detector,
    P: ProxySession<Socket, Socket>,
{
    let _ = std::thread::Builder::new()
        .name("CockroachDB".to_string())
        .spawn(move || {
            let mut handler: event_handler::EventHandler<D, P>;

            match event_handler::EventHandler::new(listen_address, db_address, params) {
                Ok(h) => handler = h,
                Err(e) => {
                    log::error!(
                        "Unrecoverable error occurred while initializing event handler: {}",
                        e
                    );
                    return;
                }
            };

            match handler.handle_loop() {
                Ok(()) => log::error!("An unknown error occurred that caused the event loop to return"), // Invariant: should never happen (event loop is infinite loop)
                Err(e) => log::error!("Unrecoverable error caused event loop to crash: {}", e),
            }
        });
}
*/
