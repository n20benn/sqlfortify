pub mod mysql_session;
pub mod postgres_session;

mod mysql_packet;
mod postgres_packet;
mod wire_reader;

use std::io;

// Requests and responses have a 1-to-1 mapping

pub struct PacketInfo {
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

impl PacketInfo {
    /// Creates a default message that does not convey any significant information to the upper layer.
    pub fn new() -> Self {
        PacketInfo {
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

pub trait ClientPacket {
    fn get_basic_info<'a>(&'a self) -> &'a PacketInfo;

    fn as_slice<'a>(&'a self) -> &'a [u8];

    fn is_valid(&self) -> bool;
}

pub trait ServerPacket {
    fn get_basic_info<'a>(&'a self) -> &'a PacketInfo;

    fn as_slice<'a>(&'a self) -> &'a [u8];

    fn is_valid(&self) -> bool;
}

pub trait Client<T: io::Read + io::Write> {
    type RequestType: ClientPacket;
    type ResponseType: ServerPacket;

    fn new(io: T) -> Self;

    fn receive_response(&mut self) -> io::Result<Self::ResponseType>;

    fn send_request(&mut self, request: &Self::RequestType) -> io::Result<()>;

    /// Safely reuses the allocated structures and buffers of the given response, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_response(&mut self, response: Self::ResponseType);

    fn get_io_ref(&self) -> &T;
}

pub trait Server<T: io::Read + io::Write> {
    type RequestType: ClientPacket;
    type ResponseType: ServerPacket;

    fn new(io: T) -> Self;

    fn receive_request(&mut self) -> io::Result<Self::RequestType>;

    fn send_response(&mut self, response: &Self::ResponseType) -> io::Result<()>;

    /// Safely reuses the allocated structures and buffers of the given request, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_request(&mut self, request: Self::RequestType);

    fn get_io_ref(&self) -> &T;
}

pub trait Proxy<C: io::Read + io::Write, S: io::Read + io::Write> {
    type RequestType: ClientPacket;
    type ResponseType: ServerPacket;

    fn new(backend_io: C, frontend_io: S) -> Self;

    fn frontend_receive_request(&mut self) -> io::Result<Self::RequestType>;

    fn frontend_send_response(&mut self, response: &Self::ResponseType) -> io::Result<()>;

    fn backend_receive_response(&mut self) -> io::Result<Self::ResponseType>;

    fn backend_send_request(&mut self, request: &Self::RequestType) -> io::Result<()>;

    /// Safely reuses the allocated structures and buffers of the given request, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_request(&mut self, request: Self::RequestType);

    /// Safely reuses the allocated structures and buffers of the given response, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_response(&mut self, request: Self::ResponseType);

    fn get_backend_io_ref(&self) -> &C;

    fn get_frontend_io_ref(&self) -> &S;

    fn frontend_downgrade_ssl(
        &mut self,
        ssl_request: &mut Self::RequestType,
    ) -> Option<Self::ResponseType>;

    fn backend_downgrade_ssl(
        &mut self,
        ssl_response: &mut Self::ResponseType,
    ) -> Option<Self::RequestType>;

    fn frontend_downgrade_gssenc(
        &mut self,
        gssenc_request: &mut Self::RequestType,
    ) -> Option<Self::ResponseType>;

    fn backend_downgrade_protocol(
        &mut self,
        proto_request: &mut Self::ResponseType,
    ) -> Option<Self::RequestType>;

    fn error_response(&mut self) -> Self::ResponseType;
}
