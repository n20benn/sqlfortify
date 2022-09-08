use std::io;

use super::wire::Buffer;

pub enum RequestType<'a> {
    /// (username, database)
    Startup(&'a str, &'a str),
    Authentication,
    Query(&'a str),
    /// username
    ChangeUser(&'a str),
    /// (username, database)
    ChangeDatabase(&'a str, &'a str),
    Command, // Includes functions
    SSLEncryption,
}

pub enum ResponseType<'a> {
    UnrecoverableError(&'a str),
    RecoverableError(&'a str),
    RequestCompleted,
    //AdditionalInformation,
}


pub trait Request<'a> {
    fn get_type(&self) -> RequestType<'a>;
}

pub trait Response<'a> {
    fn get_type(&self) -> ResponseType<'a>;
}



pub trait ServerSession<T: io::Read + io::Write> {
    type BufferType: Buffer;
    type RequestType: Request;
    type ResponseType: Response;

    fn new(io: T) -> Self;

    // fn receive_request(&mut self) -> io::Result<Self::RequestType>;

    fn receive_request_raw(&mut self, buffer: &mut Self::BufferType) -> io::Result<Self::RequestType>; // -> io::Result<RequestType>;

    fn receive_raw(&mut self, buffer: &mut Self::BufferType) -> io::Result<Vec<Self::RequestType>>;

    // fn send_response(&mut self, response: &Self::ResponseType) -> io::Result<()>;

    fn send_response_raw(&mut self, buffer: &mut Self::BufferType, response: &Self::ResponseType) -> io::Result<()>;

    fn send_raw(&mut self, buffer: &mut Self::BufferType) -> io::Result<()>;

    fn get_io_ref(&self) -> &T;
}

pub trait ClientSession<T: io::Read + io::Write> {
    type BufferType: Buffer;
    type RequestType: Request;
    type ResponseType: Response;

    fn new(io: T) -> Self;

    // fn send_request(&mut self, request: &Self::RequestType) -> io::Result<()>;

    fn send_request_raw(&mut self, buffer: &mut Self::BufferType, request: &Self::RequestType) -> io::Result<()>;

    fn send_raw(&mut self, buffer: &mut Self::BufferType) -> io::Result<()>;

    // fn receive_response(&mut self) -> io::Result<Self::ResponseType>;

    fn receive_response_raw(&mut self, buffer: &mut Self::BufferType) -> io::Result<Self::ResponseType>;

    fn receive_raw(&mut self, buffer: &mut Self::BufferType) -> io::Result<Vec<Self::ResponseType>>;

    fn get_io_ref(&self) -> &T;
}

