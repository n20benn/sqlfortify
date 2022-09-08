use std::{io};
use std::io::Read;
use std::hash::{Hasher};


/// Which end of the Session is being represented by the socket (client-side vs server-side).
pub enum WireDirection {
    /// The session represents a local client communicating with a remote server.
    ClientSide,
    /// The session represents a local database server communicating with a remote client.
    ServerSide,
}



pub trait Buffer {
    fn new() -> Self;

    fn get_writable_vectored<'a>(&'a mut self) -> &mut [io::IoSliceMut<'a>];

    fn advance_written(&mut self, num_bytes_written: usize);

    fn advance_readable(&mut self, num_bytes_readable: usize);

    fn get_readable_vectored<'a>(&'a self) -> &[io::IoSlice<'a>];

    fn advance_read(&mut self, num_bytes_read: usize);

    /// Expands the writable capacity of the buffer by at least `num_bytes` bytes.
    /// Note that this function may expand the capacity of the buffer by an arbitrarily 
    /// greater amount than `num_bytes`.
    fn expand(&mut self, num_bytes: usize);

    fn get_subslice_checked<'a>(slice: &'a [io::IoSlice<'a>], end: usize) -> Option<&'a [io::IoSlice<'a>]> {
        let mut truncated = false;

        for s in slice.iter_mut() {
            match s.get(..end) {
                Some(subslice) => *s = io::IoSlice::new(&subslice),
                None => ()
            }
            end -= s.len();
        }

        if end == 0 {
            Some(slice.into_iter().filter(|s| s.len() > 0).map(|s| *s).collect::<Vec<io::IoSlice<'_>>>().as_slice())
        } else {
            None
        }
    }

}

// There's no guarantee that a given SQL wire implementation will send a query in the form of a single packet


// This should really be named 'Wire' because it handles data at the wire in terms of packets. Nothing more than that.
/// Uses InvalidData for any error
pub trait Wire<T: io::Read + io::Write> {
    type PacketType: Packet;
    type BufferType: Buffer;

    /// Creates a new SQL Session object using the given io device.
    fn new(io: T, session_type: WireDirection) -> Self;

    // TODO: not sure I need this anymore
    fn new_packet() -> Self::PacketType;


    // TODO: FUTURE: implement below methods to complete API
    /* 
    fn read_packet(&mut self) -> io::Result<Self::PacketType>;

    /// Can only use `read_packet`/`write_packet` or `read_packet_raw`/`write_packet_raw`; these method calls 
    /// cannot be mixed. Attempts to mix them will result in a `Data` error and the session will be unusable 
    /// afterwards.
    fn write_packet(&mut self, packet: &Self::PacketType) -> io::Result<()>;
    */


    /// Reads a single packet from the io device being wrapped by this session. 
    /// The SqlSession automatically checks the validity of packets (both in terms 
    /// of contents and ordering); any invalid packets being read in will result in 
    /// an error of type `InvalidData` being returned. Once invalid data is detected 
    /// in the io device, any subsequent calls will likewise return `InvalidData`; no 
    /// error recovery will be attempted, and the session should be closed after this 
    /// error is first received.
    /// 
    /// If a nonblocking io device is passed in, this function may return an error 
    /// of kind `WouldBlock`; in this case, the io device should be polled until 
    /// it can be read again and then this function must be called again with 
    /// the same packet object as before. Failure to do so will result in permanent 
    /// internal state failure, and the session object will no longer work (i.e. it 
    /// will return an error of type `InvalidData`).
    /// 
    /// On success, a boolean value is returned. If the value is `true`, then a complete
    /// packet was read to the `packet` parameter. If the value is `false`, then no 
    /// packet can or should be read from the Session in its current state (most likely 
    /// because a packet needs to be written to the Session).
    fn read_packet_raw(&mut self, buffer: &mut Self::BufferType) -> io::Result<Self::PacketType>;


    fn read_raw(&mut self, buffer: &mut Self::BufferType) -> io::Result<Vec<Self::PacketType>>;

    // fn read_packet(&mut self) -> io::Result<Self::PacketType>;


    /// Writes a single packet to the io device being wrapped by this session. 
    /// The SqlSession automatically checks the validity of packets (both in terms 
    /// of contents and ordering); any invalid packets being written will result in 
    /// an error of type `InvalidData` being returned. Once invalid data is detected 
    /// in the io device, any subsequent calls will likewise return `InvalidData`; no 
    /// error recovery will be attempted, and the session should be closed after this 
    /// error is first received.
    /// 
    /// If a nonblocking io device is passed in, this function may return an error 
    /// of type `WouldBlock`; in this case, the io device should be polled until 
    /// it can be read again and then this function must be called again with 
    /// the same packet object as before. Failure to do so will result in permanent 
    /// internal state failure, and the session object will no longer work (i.e. it 
    /// will return an error of type `InvalidData`).
    /// 
    /// On success, a boolean value is returned. If the value is `true`, then a complete
    /// packet was written from the `packet` parameter. If the value is `false`, then no 
    /// packet can or should be written to the Session in its current state (most likely 
    /// because a packet needs to be read from the  in its current state (most likely 
    /// because a packet needs to be read from the Session).
    fn write_packet_raw(&mut self, buffer: &Self::BufferType) -> io::Result<()>;

    // fn write_packet(&mut self, packet: &Self::PacketType) -> io::Result<()>;

    /// Writes as much data from `buffer` as possible to the internal I/O device. 
    /// 
    /// Returns the number of bytes written on success, or an `io::Error` if no data 
    /// could be written.
    fn write_raw(&mut self, buffer: &Self::BufferType) -> io::Result<usize>;

    // fn write_packet(&mut self, packet: &Self::PacketType) -> io::Result<()>;

    
    /// Generates a sequence of packets that adequately conveys a server parse error 
    /// to a client for its last sent SQL query.
    fn generate_server_error() -> Vec<Self::PacketType>;

    /// Gets a reference to the underlying io device.
    /// 
    /// It is inadvisable to directly read from or write to the underlying io device; 
    /// this should only be used to poll the io device for events.
    fn get_io_ref(&self) -> &T;
}


// TODO: Might need to be a struct instead...
pub trait Packet {
    fn get_query<'a>(&'a self) -> Option<&'a str>;

    // fn get_raw(&self) -> &[u8];

    fn get_type(&self) -> PacketType;

    fn len(&self) -> usize;
}




// TODO: remove this enum
#[derive(Clone, Copy, Debug)]
pub enum PacketType {
    Query,
    DataResponse,
    ErrorResponse,
    Other,
}

