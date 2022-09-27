use std::io;

// Requests and responses have a 1-to-1 mapping

pub struct MessageInfo {
    /// If set, indicates that the given username should be used for subsequent SQL queries.
    pub username: Option<String>,
    /// If set, indicates that the given database should be used for subsequent SQL queries.
    pub database: Option<String>,
    /// If set, indicates that the message contains the given SQL query that will be executed by the SQL server
    pub query: Option<String>,
    /// If true, indicates that the message is requesting information from the other side that should be met with a corresponding 'result' message.
    pub is_request: bool,
    /// If set, indicates that the message is a definitive result for a corresponding request in the message stream with either a successful (true) or failed (false) outcome.
    pub result: Option<bool>,
    /// If true, the given packet is attempting to indicate or request SSL encryption support with the other side.
    pub ssl_requested: bool,
    /// If true, the given packet is attempting to indicate or request GSSAPI encryption support with the other side.
    pub gssenc_requested: bool,
    /// If true, the protocol requested by the given packet is not supported by the current version of this library.
    pub unsupported_version: bool,
}

impl MessageInfo {
    /// Creates a default message that does not convey any significant information to the upper layer.
    pub fn new() -> Self {
        MessageInfo {
            username: None,
            database: None,
            query: None,
            is_request: false,
            result: None,
            ssl_requested: false,
            gssenc_requested: false,
            unsupported_version: false,
        }
    }
}

pub trait ClientMessage {
    fn get_basic_info<'a>(&'a self) -> &'a MessageInfo;
//    fn get_basic_type<'a>(&'a self) -> &'a ClientMessageType;

    fn as_slice<'a>(&'a self) -> &'a[u8];
}

pub trait ServerMessage {
    fn get_basic_info<'a>(&'a self) -> &'a MessageInfo;
//    fn get_basic_type<'a>(&'a self) -> &'a ServerMessageType;

    fn as_slice<'a>(&'a self) -> &'a[u8];
}


pub trait ClientSession<T: io::Read + io::Write> {
    type RequestType: ClientMessage;
    type ResponseType: ServerMessage;

    fn new(io: T) -> Self;

    fn receive_response(&mut self) -> io::Result<Self::ResponseType>;

    fn send_request(&mut self, request: &Self::RequestType) -> io::Result<()>;


    /// Safely reuses the allocated structures and buffers of the given response, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_response(&mut self, response: Self::ResponseType);

    fn get_io_ref(&self) -> &T;
}

pub trait ServerSession<T: io::Read + io::Write> {
    type RequestType: ClientMessage;
    type ResponseType: ServerMessage;

    fn new(io: T) -> Self;

    fn receive_request(&mut self) -> io::Result<Self::RequestType>;

    fn send_response(&mut self, response: &Self::ResponseType) -> io::Result<()>;

    /// Safely reuses the allocated structures and buffers of the given request, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_request(&mut self, request: Self::RequestType);

    fn get_io_ref(&self) -> &T;
}


pub trait ProxySession<C: io::Read + io::Write, S: io::Read + io::Write> {
    type RequestType: ClientMessage;
    type ResponseType: ServerMessage;

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

    fn client_downgrade_ssl(ssl_request: &mut Self::RequestType) -> Option<Self::ResponseType>;

    fn server_downgrade_ssl(ssl_response: &mut Self::ResponseType) -> Option<Self::RequestType>;

    fn client_downgrade_gssenc(gssenc_request: &mut Self::RequestType) -> Option<Self::ResponseType>;

    fn client_downgrade_protocol(proto_request: &mut Self::RequestType) -> Option<Self::ResponseType>;
}