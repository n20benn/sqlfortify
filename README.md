# sqlfortify

SQLFortify - pluggable, self-learning defense in depth against SQL injection attacks

SQLFortify is a database extension that provides advanced intrusion prevention capabilities against SQL injection (SQLI) attacks.
In addition to detecting individual attempts at SQL injection, SQLFortify is capable of determining what query parameter is the most likely source of SQLI, and can use this to block any further injection attempts via that parameter.

## Building

To build the project, first make sure you [have rust installed](https://www.rust-lang.org/tools/install).
Then, run the following to download and compile the code:

```bash
git clone https://github.com/n20benn/sqlfortify
cd sqlfortify
cargo build --release
```

Once this is done, you can either use `cargo run` or the `sqlfortify` executable found in `/target` to run SQLFortify.

## Running

If I wanted to start a SQLFortify instance that would proxy packets for a postgres server running at 127.0.0.1:8888 and I wanted the proxy to accept connections at 0.0.0.0:5432, I would run the following:

```bash
sqlfortify 0.0.0.0 5432 127.0.0.1 8888 
```

Note that both the listening address/port and the database address/port need to be specified for SQLFortify to run.

## Project goals

The following are listed in order of priority, though not necessarily in the order that they will be complete.

Near future:
- Add additional rules for SQLI detection
- Add support for MySQL wire format
- Support for configuration file options

Later:
- Custom rule specification
- Benchmarks on performance
- Support plugin mode of operation (running as a MySQL or PostgreSQL plugin rather than a daemon)


