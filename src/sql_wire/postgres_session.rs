use std::collections::VecDeque;
use std::{cmp, io};

use super::postgres_packet::*;

use crate::sql_wire::*;

// Minimum number of bytes needed to extract 'length' field from packet
const STARTUP_PKT_HDRLEN: usize = 4;
const STANDARD_PKT_HDRLEN: usize = 5;
const SSL_RESPONSE_PKT_HDRLEN: usize = 1;

const DEFAULT_REQ_RESP_BUFLEN: usize = 1 * 1024; // 1KB

// ErrorResponse packet is 58 bytes long: \x00\x00\x00\x3A
const ERROR_PACKET_BYTES: &'static [u8] = b"E\x00\x00\x00\x3ASERROR\x00C42000\x00MMalformed input blocked by SQLFortify\x00\x00Z\x00\x00\x00\x05I";
// TODO: this always assumes not in a transaction block. Will that cause issues???
// I => idle (not in Transaction block)
// T => in transaction block
// E => in failed transaction block
// Realistically, we'd only ever be in 'I' or 'E'. It seems like always returning 'I' would be preferable to always returning 'E'?

#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionState {
    Startup,
    SslRequested,
    GssRequested,
    Normal,
    ExtendedQuery,
    CopyIn,
    ExtendedCopyIn,
}

pub struct PostgresRequest {
    basic_info: PacketInfo,
    is_valid: bool,
    data: Vec<u8>,
    pkt_len: usize,
}

impl PostgresRequest {
    fn new() -> Self {
        PostgresRequest {
            basic_info: PacketInfo::new(),
            is_valid: false,
            data: Vec::from([0; DEFAULT_REQ_RESP_BUFLEN]),
            pkt_len: 0,
        }
    }
}

impl ClientPacket for PostgresRequest {
    fn get_basic_info<'a>(&'a self) -> &'a PacketInfo {
        &self.basic_info // TODO: stub
    }

    fn as_slice<'a>(&'a self) -> &'a [u8] {
        &self.data.as_slice()
    }

    fn is_valid(&self) -> bool {
        self.is_valid
    }
}

pub struct PostgresResponse {
    basic_info: PacketInfo,
    is_valid: bool,
    raw_data: Vec<u8>,
    pkt_len: usize,
}

impl PostgresResponse {
    fn new() -> Self {
        PostgresResponse {
            basic_info: PacketInfo::new(),
            is_valid: false,
            raw_data: Vec::from([0; DEFAULT_REQ_RESP_BUFLEN]), // TODO: is this inefficient? is there a better way?
            pkt_len: 0,
        }
    }
}

impl ServerPacket for PostgresResponse {
    fn get_basic_info<'a>(&'a self) -> &'a PacketInfo {
        &self.basic_info // TODO: stub
    }

    fn as_slice<'a>(&'a self) -> &'a [u8] {
        &self.raw_data.as_slice()
    }

    fn is_valid(&self) -> bool {
        self.is_valid
    }
}

pub struct PostgresClientSession<T: io::Read + io::Write> {
    state: SessionState,
    io: T,
    recycled_responses: VecDeque<PostgresResponse>,
    request_failure: Option<bool>,
    request_part_idx: Option<usize>,
}

impl<T: io::Read + io::Write> Client<T> for PostgresClientSession<T> {
    type RequestType = PostgresRequest;
    type ResponseType = PostgresResponse;

    fn new(io: T) -> Self {
        PostgresClientSession {
            state: SessionState::Startup,
            io: io,
            recycled_responses: VecDeque::new(),
            request_failure: None,
            request_part_idx: None,
        }
    }

    fn send_request(&mut self, request: &Self::RequestType) -> io::Result<()> {
        send_request(
            &mut self.io,
            request,
            &mut self.state,
            &mut self.request_part_idx,
        )
    }

    fn receive_response(&mut self) -> io::Result<Self::ResponseType> {
        let mut response = match self.recycled_responses.pop_front() {
            // TODO: handle case where buffers grow too big
            Some(req) => req,
            None => PostgresResponse::new(),
        };

        match receive_response(
            &mut self.io,
            &mut response,
            &mut self.state,
            &mut self.request_failure,
        ) {
            Ok(()) => Ok(response),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.recycled_responses.push_front(response);
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Safely reuses the allocated structures and buffers of the given response, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_response(&mut self, response: Self::ResponseType) {
        self.recycled_responses.push_back(response);
    }

    fn get_io_ref(&self) -> &T {
        &self.io
    }
}

pub struct PostgresServerSession<T: io::Read + io::Write> {
    io_device: T,
    recycled_requests: VecDeque<PostgresRequest>,
    response_part_idx: Option<usize>,
    state: SessionState,
}

impl<T: io::Read + io::Write> Server<T> for PostgresServerSession<T> {
    type RequestType = PostgresRequest;
    type ResponseType = PostgresResponse;

    fn new(io: T) -> Self {
        PostgresServerSession {
            io_device: io,
            recycled_requests: VecDeque::new(),
            response_part_idx: None,
            state: SessionState::Startup,
        }
    }

    fn receive_request(&mut self) -> io::Result<Self::RequestType> {
        let mut request = match self.recycled_requests.pop_front() {
            Some(req) => req,
            None => PostgresRequest::new(),
        };

        match receive_request(&mut self.io_device, &mut request, &mut self.state) {
            Ok(()) => Ok(request),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.recycled_requests.push_front(request);
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    fn send_response(&mut self, response: &Self::ResponseType) -> io::Result<()> {
        send_response(
            &mut self.io_device,
            response,
            &mut self.state,
            &mut self.response_part_idx,
        )
    }

    /// Safely reuses the allocated structures and buffers of the given request, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_request(&mut self, request: Self::RequestType) {
        self.recycled_requests.push_back(request);
    }

    fn get_io_ref(&self) -> &T {
        &self.io_device
    }
}

pub struct PostgresProxySession<C: io::Read + io::Write, S: io::Read + io::Write> {
    client_io: C,
    recycled_requests: VecDeque<PostgresRequest>,
    recycled_responses: VecDeque<PostgresResponse>,
    request_failure: Option<bool>,
    request_part_idx: Option<usize>,
    response_part_idx: Option<usize>,
    server_io: S,
    state: SessionState,
}

impl<C: io::Read + io::Write, S: io::Read + io::Write> Proxy<C, S> for PostgresProxySession<C, S> {
    type RequestType = PostgresRequest;
    type ResponseType = PostgresResponse;

    fn new(client_io: C, server_io: S) -> Self {
        PostgresProxySession {
            client_io: client_io,
            request_part_idx: None,
            response_part_idx: None,
            recycled_requests: VecDeque::new(),
            recycled_responses: VecDeque::new(),
            request_failure: None,
            server_io: server_io,
            state: SessionState::Startup,
        }
    }

    fn frontend_receive_request(&mut self) -> io::Result<Self::RequestType> {
        let mut request = match self.recycled_requests.pop_front() {
            Some(req) => req,
            None => PostgresRequest::new(),
        };

        log::debug!("Receiving request...");
        match receive_request(&mut self.server_io, &mut request, &mut self.state) {
            Ok(()) => {
                log::debug!("Request received");
                Ok(request)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                log::debug!("Request needs more bytes to be received");
                self.recycled_requests.push_front(request);
                Err(e)
            }
            Err(e) => {
                log::debug!(
                    "Receiving request failed with other error: {}",
                    e.to_string()
                );
                Err(e)
            }
        }
    }

    fn frontend_send_response(&mut self, response: &Self::ResponseType) -> io::Result<()> {
        send_response(
            &mut self.server_io,
            response,
            &mut self.state,
            &mut self.response_part_idx,
        )
    }

    fn backend_receive_response(&mut self) -> io::Result<Self::ResponseType> {
        let mut response = match self.recycled_responses.pop_front() {
            Some(req) => req,
            None => PostgresResponse::new(),
        };

        log::debug!("Receiving response...");

        match receive_response(
            &mut self.client_io,
            &mut response,
            &mut self.state,
            &mut self.request_failure,
        ) {
            Ok(()) => {
                log::debug!("Response received");
                Ok(response)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                log::debug!("Response needs more bytes to be received");
                self.recycled_responses.push_front(response);
                Err(e)
            }
            Err(e) => {
                log::debug!(
                    "Receiving response failed with other error: {}",
                    e.to_string()
                );
                Err(e)
            }
        }
    }

    fn backend_send_request(&mut self, request: &Self::RequestType) -> io::Result<()> {
        send_request(
            &mut self.client_io,
            request,
            &mut self.state,
            &mut self.request_part_idx,
        )
    }

    /// Safely reuses the allocated structures and buffers of the given request, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_request(&mut self, mut request: Self::RequestType) {
        request.basic_info = PacketInfo::new();
        request.pkt_len = 0;
        request.is_valid = false;
        self.recycled_requests.push_back(request);
    }

    /// Safely reuses the allocated structures and buffers of the given response, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_response(&mut self, mut response: Self::ResponseType) {
        response.basic_info = PacketInfo::new();
        response.pkt_len = 0;
        response.is_valid = false;
        self.recycled_responses.push_back(response);
    }

    fn get_backend_io_ref(&self) -> &C {
        &self.client_io
    }

    fn get_frontend_io_ref(&self) -> &S {
        &self.server_io
    }

    fn frontend_downgrade_ssl(
        &mut self,
        ssl_request: &mut Self::RequestType,
    ) -> Option<Self::ResponseType> {
        // Label the request packet as invalid so that it won't be forwarded
        ssl_request.is_valid = false;
        if self.state == SessionState::SslRequested {
            // TODO: if this doesn't hold, should we throw an error??
            self.state = SessionState::Startup;
        }

        Some(PostgresResponse {
            basic_info: PacketInfo::new(),
            is_valid: true,
            raw_data: Vec::from([b'N']),
            pkt_len: SSL_RESPONSE_PKT_HDRLEN,
        })
    }

    fn backend_downgrade_ssl(
        &mut self,
        _ssl_response: &mut Self::ResponseType,
    ) -> Option<Self::RequestType> {
        todo!() // TODO: stub
    }

    fn frontend_downgrade_gssenc(
        &mut self,
        gssenc_request: &mut Self::RequestType,
    ) -> Option<Self::ResponseType> {
        // Label the request packet as invalid so that it won't be forwarded
        gssenc_request.is_valid = false;
        if self.state == SessionState::GssRequested {
            // TODO: if this doesn't hold, should we throw an error??
            self.state = SessionState::Startup;
        }

        Some(PostgresResponse {
            basic_info: PacketInfo::new(),
            is_valid: true,
            raw_data: Vec::from([b'N']),
            pkt_len: 1,
        })
    }

    fn backend_downgrade_protocol(
        &mut self,
        _proto_request: &mut Self::ResponseType,
    ) -> Option<Self::RequestType> {
        todo!() // TODO: stub
    }

    fn error_response(&mut self) -> Self::ResponseType {
        let mut basic_info = PacketInfo::new();
        basic_info.result = Some(false);

        PostgresResponse {
            basic_info: basic_info,
            is_valid: true,
            raw_data: Vec::from(ERROR_PACKET_BYTES),
            pkt_len: ERROR_PACKET_BYTES.len(),
        }
    }
}

fn read_packet<'a, T: io::Read>(
    io: &mut T,
    buf: &'a mut Vec<u8>,
    buf_len: &mut usize, // 0 <= buf_len <= buf.len()
    pkt_len: usize,      // Could be *anything*--passed in from client
) -> io::Result<&'a mut [u8]> {
    let mut buffer_length = buf.len();
    let mut truncated_end_idx = cmp::min(pkt_len, buffer_length);

    if *buf_len > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Internal error while reading in packet--write index exceeded buffer length",
        ));
    } // Thus, *buf_len <= buf.len()

    loop {
        while let Some(remaining_buffer) = buf.get_mut(*buf_len..truncated_end_idx) {
            if remaining_buffer.len() == 0 {
                break;
            }

            match io.read(remaining_buffer) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "I/O device unexpectedly closed while reading data",
                    ))
                }
                Ok(len) => {
                    *buf_len += len; // Invariant: *buf_len + len <= buf.len() because we're reading into a buffer of size (buf.len() - *buf_len) or less
                    log::debug!("Read {} bytes into buffer", len);
                }
                Err(e) => return Err(e),
            }
        }

        if *buf_len >= pkt_len {
            break;
        } else {
            log::debug!("Packet contents exceeded available space--increasing buffer size");
            buf.extend(std::iter::repeat(0).take(cmp::min(buffer_length, pkt_len - buffer_length))); // We need more buffer--at most double the current one

            buffer_length = buf.len();
            truncated_end_idx = cmp::min(pkt_len, buffer_length);
        }
    }

    return Ok(&mut buf[..pkt_len]); // Invariant: pkt_len <= *buf_len <= buf.len(), so this will never index out of bounds
}

fn receive_request<T: io::Read>(
    io: &mut T,
    request: &mut PostgresRequest,
    state: &mut SessionState,
) -> io::Result<()> {
    // TODO: make sure that input reading comes from buffered I/O

    match state {
        SessionState::Startup => {
            log::debug!("Reading startup request header...");
            let header_bytes = read_packet(
                io,
                &mut request.data,
                &mut request.pkt_len,
                STARTUP_PKT_HDRLEN,
            )?;
            log::debug!("Request header read.");
            let pkt_len = match read_startup_packet_len(header_bytes) {
                Ok(l) => l,
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            };

            log::debug!("Reading startup request body...");
            let pkt = read_packet(io, &mut request.data, &mut request.pkt_len, pkt_len)?;

            log::debug!("Request body read.");
            request.is_valid = true;

            match parse_startup_req_packet(pkt) {
                Ok(RequestPacket::SSLRequest) => {
                    request.basic_info.ssl_requested = true;
                    *state = SessionState::SslRequested;
                }
                Ok(RequestPacket::GSSENCRequest) => {
                    request.basic_info.gssenc_requested = true;
                    *state = SessionState::GssRequested;
                }
                Ok(RequestPacket::CancelRequest(_, _)) => (), // TODO: this should close the connection
                Ok(RequestPacket::StartupMessage(version, user, params)) => {
                    request.basic_info.username = Some(user.to_string());
                    request.basic_info.database =
                        Some(params.get("database").unwrap_or(&user).to_string());
                    request.basic_info.is_request = true;
                    if version != PostgresWireVersion::V3_0 {
                        request.basic_info.unsupported_version = true;
                    }
                    *state = SessionState::Normal;
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected packet received during connection startup",
                    ))
                }
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            }
        }
        _ => {
            log::debug!("Reading request header...");
            let header_bytes = read_packet(
                io,
                &mut request.data,
                &mut request.pkt_len,
                STANDARD_PKT_HDRLEN,
            )?;
            log::debug!("Request header read.");

            let pkt_len = match read_standard_packet_len(header_bytes) {
                Ok((_, l)) => l,
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            };

            log::debug!("Reading request body...");
            let pkt = read_packet(io, &mut request.data, &mut request.pkt_len, pkt_len)?;
            request.is_valid = true;
            log::debug!("Request body read.");

            match (*state, parse_standard_req_packet(pkt)) {
                (SessionState::Normal, Ok(RequestPacket::Query(q))) => {
                    request.basic_info.query = Some(q.to_string());
                    request.basic_info.is_request = true;
                },
                (SessionState::Normal, Ok(RequestPacket::FunctionCall(_,_,_,_))) => request.basic_info.is_request = true,
                (SessionState::Normal, Ok(RequestPacket::Parse(_,_,_) | RequestPacket::Bind(_,_,_,_,_) | RequestPacket::Execute(_,_) | RequestPacket::DescribePortal(_) | RequestPacket::DescribePrepared(_) | RequestPacket::ClosePortal(_) | RequestPacket::ClosePrepared(_) | RequestPacket::Flush)) => *state = SessionState::ExtendedQuery,
                (SessionState::Normal, Ok(RequestPacket::Sync)) => {
                    request.basic_info.is_request = true;
                    *state = SessionState::ExtendedQuery;
                },
                (SessionState::Normal, Ok(_)) => (),
                (SessionState::CopyIn, Ok(RequestPacket::CopyData(_) | RequestPacket::Flush | RequestPacket::Sync)) => (),
                (SessionState::CopyIn, Ok(_)) => *state = SessionState::Normal,
                (SessionState::ExtendedQuery, Ok(RequestPacket::Sync)) => {
                    request.basic_info.is_request = true;
                    *state = SessionState::ExtendedQuery;
                },
                (SessionState::ExtendedQuery, Ok(_)) => (),
                (SessionState::ExtendedCopyIn, Ok(RequestPacket::CopyData(_) | RequestPacket::Flush | RequestPacket::Sync)) => (),
                (SessionState::ExtendedCopyIn, Ok(_)) => *state = SessionState::ExtendedQuery, // includes CopyDone and CopyFail
                (SessionState::Startup, _) => (),
                (SessionState::GssRequested | SessionState::SslRequested, _) => return Err(io::Error::new(io::ErrorKind::InvalidData, "erroneous (and potentially malicious) data detected after encryption request")),
                (_, Err(e)) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            }
        }
    }

    Ok(())
}

fn receive_response<T: io::Read>(
    io: &mut T,
    response: &mut PostgresResponse,
    state: &mut SessionState,
    request_failure: &mut Option<bool>,
) -> io::Result<()> {
    log::debug!("Reading response header...");
    let header_bytes = read_packet(
        io,
        &mut response.raw_data,
        &mut response.pkt_len,
        STANDARD_PKT_HDRLEN,
    )?;
    log::debug!("Response header read.");

    let pkt_len = match read_standard_packet_len(header_bytes) {
        Ok((_, l)) => l,
        Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    };

    log::debug!("Reading response body...");
    let pkt = read_packet(io, &mut response.raw_data, &mut response.pkt_len, pkt_len)?;
    response.is_valid = true;

    log::debug!("Response body read.");

    match (*state, parse_standard_resp_packet(pkt)) {
        (_, Ok(ResponsePacket::ErrorResponse(_))) => *request_failure = Some(true),
        (SessionState::Normal, Ok(ResponsePacket::ReadyForQuery(_))) => {
            response.basic_info.result = Some(!request_failure.unwrap_or(false));
            *request_failure = None;
        }
        (
            SessionState::Normal,
            Ok(ResponsePacket::CopyInResponse(_, _) | ResponsePacket::CopyBothResponse(_, _)),
        ) => *state = SessionState::CopyIn,
        (SessionState::Normal, Ok(_)) => (),

        (SessionState::ExtendedQuery, Ok(ResponsePacket::ReadyForQuery(_))) => {
            *state = SessionState::Normal;
            response.basic_info.result = Some(!request_failure.unwrap_or(false));
            *request_failure = None;
        }
        (
            SessionState::ExtendedQuery,
            Ok(ResponsePacket::CopyInResponse(_, _) | ResponsePacket::CopyBothResponse(_, _)),
        ) => *state = SessionState::ExtendedCopyIn,
        (_, Ok(_)) => (),
        (_, Err(e)) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    }

    Ok(())
}

fn advance_up_to<'a, T>(buf: &'a [T], amount: usize) -> &'a [T] {
    match buf.get(amount..) {
        Some(b) => b,
        None => &mut [],
    }
}

fn send_request<T: io::Write>(
    io: &mut T,
    request: &PostgresRequest,
    _state: &mut SessionState,
    start: &mut Option<usize>,
) -> io::Result<()> {
    let mut total_written = start.unwrap_or(0);

    log::debug!("Writing request...");

    if !request.is_valid {
        log::error!("Invalid request sent")
    }

    let mut buf = match request.as_slice().get(total_written..request.pkt_len) {
        Some(b) => b,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected request packet sent out of order (invalid length)",
            ))
        }
    };

    while buf.len() > 0 {
        let num_written = match io.write(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "I/O device unexpectedly closed while writing data",
                ))
            }
            Ok(num_written) => num_written,
            Err(e) => return Err(e),
        };

        total_written += num_written;
        *start = Some(total_written);
        buf = advance_up_to(buf, num_written);
    }

    log::debug!("Successfully wrote request.");
    return Ok(());
}

fn send_response<T: io::Write>(
    io: &mut T,
    response: &PostgresResponse,
    _state: &mut SessionState,
    start: &mut Option<usize>,
) -> io::Result<()> {
    let mut total_written = start.unwrap_or(0);

    log::debug!("Writing response...");

    if !response.is_valid {
        log::error!("Invalid response sent")
    }

    let mut buf = match response.as_slice().get(total_written..response.pkt_len) {
        Some(buf) => buf,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected response packet sent out of order (invalid length)",
            ))
        }
    };

    while buf.len() > 0 {
        let num_written = match io.write(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "I/O device unexpectedly closed while writing data",
                ))
            }
            Ok(num_written) => num_written,
            Err(e) => return Err(e),
        };

        total_written += num_written;
        *start = Some(total_written);
        buf = advance_up_to(buf, num_written);
    }

    log::debug!("Successfully wrote response.");
    return Ok(());
}
