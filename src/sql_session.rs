use std::io;

// Requests and responses have a 1-to-1 mapping


#[derive(PartialEq, Eq)]
pub enum RequestBasicType {
    /// The initial packet sequence that connects the client to a particular db. Parameters: (username, database)
    Startup(String, String),
    /// Packet sequences pertaining to the client and server authenticating each other
    Authentication,
    /// A packet sequence containing a SQL statement that will be executed by the database.
    Query(String),
    /// (not seen yet) A packet sequence containing several consecutive SQL statements.
    /// Queries(Vec<String>),
    /// A packet sequence indicating a request to change the username currently logged into. Parameters: username
    ChangeUser(String),
    /// A packet sequence indicating a request to change the database (and potentially username) currently connected to. Parameters: (database, username)
    ChangeDatabase(String, Option<String>),
    /// Packet sequences that do not involve SQL, but nonetheless execute actions on the database. Includes functions (such as \copy for postgres)
    Command,
    /// Indicates an attempt to initiate SSL encryption
    SSLEncryption,
    /// Information transferred to the server that doesn't constitute a distinct request (requests of this type should not be kept track of in upper layers)
    AdditionalInformation,
    /// Catch-all for sequences of packets that don't fit any other RequestType, but are nonetheless still considered direct requests (see `AdditionalInformation` for packet sequences that aren't considered requests)
    Other
}

#[derive(PartialEq, Eq)]
pub enum ResponseBasicType {
    /// An error that immediately invalidates the current session (thus requiring the client to reconnect)
    UnrecoverableError(String),
    /// A recoverable error reported for a single request.
    IndividualError(String),
    /// Indicates success in completing a given request.
    RequestCompleted,
    /// Information transferred back to the client that doesn't constitute a distinct response (responses of this type should not be kept track of in upper layers)
    AdditionalInformation,
}


pub trait SqlRequest {
    fn get_basic_type<'a>(&'a self) -> &'a RequestBasicType;

    fn as_slice<'a>(&'a self) -> &'a[u8];
}

pub trait SqlResponse {
    fn basic_type<'a>(&'a self) -> &'a ResponseBasicType;

    fn as_slice<'a>(&'a self) -> &'a[u8];
}


pub trait SqlClientSession<T: io::Read + io::Write> {
    type RequestType: SqlRequest;
    type ResponseType: SqlResponse;

    fn new(io: T) -> Self;

    fn receive_response(&mut self) -> io::Result<Self::ResponseType>;

    fn send_request(&mut self, request: &Self::RequestType) -> io::Result<()>;


    /// Safely reuses the allocated structures and buffers of the given response, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_response(&mut self, response: Self::ResponseType);

    fn get_io_ref(&self) -> &T;
}

pub trait SqlServerSession<T: io::Read + io::Write> {
    type RequestType: SqlRequest;
    type ResponseType: SqlResponse;

    fn new(io: T) -> Self;

    fn receive_request(&mut self) -> io::Result<Self::RequestType>;

    fn send_response(&mut self, response: &Self::ResponseType) -> io::Result<()>;

    /// Safely reuses the allocated structures and buffers of the given request, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_request(&mut self, request: Self::RequestType);

    fn get_io_ref(&self) -> &T;
}


pub trait SqlProxySession<C: io::Read + io::Write, S: io::Read + io::Write> {
    type RequestType: SqlRequest;
    type ResponseType: SqlResponse;

    fn new(client_io: C, server_io: S) -> Self;

    fn server_receive_request(&mut self) -> io::Result<Self::RequestType>;

    fn server_send_response(&mut self, response: &Self::ResponseType) -> io::Result<()>;

    fn client_receive_response(&mut self) -> io::Result<Self::ResponseType>;

    fn client_send_request(&mut self, request: &Self::RequestType) -> io::Result<()>;


    /// Safely reuses the allocated structures and buffers of the given request, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_request(&mut self, request: Self::RequestType);

    /// Safely reuses the allocated structures and buffers of the given response, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_response(&mut self, request: Self::ResponseType);

    fn get_client_io_ref(&self) -> &C;

    fn get_server_io_ref(&self) -> &S;
}