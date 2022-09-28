use std::collections::VecDeque;
use std::{cmp, io};

use super::postgres_packet::*;

use super::sql_session::*;

// Minimum number of bytes needed to extract 'length' field from packet
const STARTUP_PKT_HDRLEN: usize = 4;
const STANDARD_PKT_HDRLEN: usize = 5;
const SSL_RESPONSE_PKT_HDRLEN: usize = 1;

const DEFAULT_REQ_RESP_BUFLEN: usize = 1 * 1024 * 1024; // 1MB

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
    basic_info: MessageInfo,
    is_valid: bool,
    packet_start: usize,
    raw_data: Vec<u8>,
    raw_len: usize,
}

impl PostgresRequest {
    fn new() -> Self {
        PostgresRequest {
            basic_info: MessageInfo::new(),
            is_valid: false,
            packet_start: 0,
            raw_data: Vec::from_iter(std::iter::repeat(0).take(DEFAULT_REQ_RESP_BUFLEN)), // TODO: is this inefficient? is there a better way?
            raw_len: 0,
        }
    }
}

impl ClientMessage for PostgresRequest {
    fn get_basic_info<'a>(&'a self) -> &'a MessageInfo {
        &self.basic_info // TODO: stub
    }

    fn as_slice<'a>(&'a self) -> &'a [u8] {
        &self.raw_data.as_slice()
    }

    fn is_valid(&self) -> bool {
        self.is_valid
    }
}

pub struct PostgresResponse {
    basic_info: MessageInfo,
    is_valid: bool,
    packet_start: usize,
    raw_data: Vec<u8>,
    raw_len: usize,
}

impl PostgresResponse {
    fn new() -> Self {
        PostgresResponse {
            basic_info: MessageInfo::new(),
            is_valid: false,
            packet_start: 0,
            raw_data: Vec::from_iter(std::iter::repeat(0).take(DEFAULT_REQ_RESP_BUFLEN)), // TODO: is this inefficient? is there a better way?
            raw_len: 0,
        }
    }
}

impl ServerMessage for PostgresResponse {
    fn get_basic_info<'a>(&'a self) -> &'a MessageInfo {
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

impl<T: io::Read + io::Write> ClientSession<T> for PostgresClientSession<T> {
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

impl<T: io::Read + io::Write> ServerSession<T> for PostgresServerSession<T> {
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

impl<C: io::Read + io::Write, S: io::Read + io::Write> ProxySession<C, S>
    for PostgresProxySession<C, S>
{
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

        match receive_request(&mut self.server_io, &mut request, &mut self.state) {
            Ok(()) => Ok(request),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.recycled_requests.push_front(request);
                Err(e)
            }
            Err(e) => Err(e),
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

        match receive_response(
            &mut self.client_io,
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

    fn backend_send_request(&mut self, request: &Self::RequestType) -> io::Result<()> {
        send_request(
            &mut self.client_io,
            request,
            &mut self.state,
            &mut self.request_part_idx,
        )
    }

    /// Safely reuses the allocated structures and buffers of the given request, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_request(&mut self, request: Self::RequestType) {
        self.recycled_requests.push_back(request);
    }

    /// Safely reuses the allocated structures and buffers of the given response, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_response(&mut self, response: Self::ResponseType) {
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
            basic_info: MessageInfo::new(),
            is_valid: true,
            packet_start: 0,
            raw_data: Vec::from_iter([b'N']),
            raw_len: SSL_RESPONSE_PKT_HDRLEN,
        })
    }

    fn backend_downgrade_ssl(
        &mut self,
        ssl_response: &mut Self::ResponseType,
    ) -> Option<Self::RequestType> {
        None // TODO: stub
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
            basic_info: MessageInfo::new(),
            is_valid: true,
            packet_start: 0,
            raw_data: Vec::from_iter([b'N']),
            raw_len: 1,
        })
    }

    fn backend_downgrade_protocol(
        &mut self,
        proto_request: &mut Self::ResponseType,
    ) -> Option<Self::RequestType> {
        None // TODO: stub
    }

    fn error_response(&mut self) -> Self::ResponseType {
        let mut basic_info = MessageInfo::new();
        basic_info.result = Some(false);

        PostgresResponse {
            basic_info: basic_info,
            is_valid: true,
            packet_start: 0,
            raw_data: Vec::new(), // TODO: stub; add error bytes here
            raw_len: 0,           // TODO: stub. length of raw_data here
        }
    }
}

fn move_up_to<'a>(buf: &'a mut [u8], amount: usize) -> &'a mut [u8] {
    match buf.get_mut(amount..) {
        Some(b) => b,
        None => &mut [],
    }
}

fn read_packet<'a, T: io::Read>(
    io: &mut T,
    buf: &'a mut Vec<u8>,
    raw_len: usize,
    pkt_start_idx: usize,
    pkt_len: usize,
) -> io::Result<&'a mut [u8]> {
    // avoid usize overflow here
    if usize::MAX - pkt_len > pkt_start_idx {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packet received exceeded max packet processing size",
        ));
    }

    if pkt_start_idx + pkt_len > buf.len() {
        let extension_len = cmp::max(buf.len(), pkt_start_idx + pkt_len); // We need more buffer--at least double the current one
        buf.extend(std::iter::repeat(0).take(extension_len));
    }

    let packet_buffer = &mut buf[pkt_start_idx..pkt_start_idx + pkt_len];

    let initially_read = cmp::max(raw_len - pkt_start_idx, 0);
    let mut remaining_buffer = move_up_to(packet_buffer, initially_read);

    loop {
        if remaining_buffer.len() == 0 {
            return Ok(packet_buffer);
        }

        match io.read(remaining_buffer) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "I/O device unexpectedly had no more data",
                ))
            }
            Ok(len) => remaining_buffer = move_up_to(remaining_buffer, len),
            Err(e) => return Err(e),
        }
    }
}

fn receive_request<T: io::Read>(
    io: &mut T,
    request: &mut PostgresRequest,
    state: &mut SessionState,
) -> io::Result<()> {
    // TODO: make sure that input reading comes from buffered I/O

    match state {
        SessionState::Startup => {
            let header_bytes = read_packet(
                io,
                &mut request.raw_data,
                request.raw_len,
                request.packet_start,
                STARTUP_PKT_HDRLEN,
            )?;
            let pkt_len = match read_startup_packet_len(header_bytes) {
                Ok(l) => l,
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            };

            let pkt = read_packet(
                io,
                &mut request.raw_data,
                request.raw_len,
                request.packet_start,
                pkt_len,
            )?;
            request.packet_start += pkt_len;

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
            let header_bytes = read_packet(
                io,
                &mut request.raw_data,
                request.raw_len,
                request.packet_start,
                STANDARD_PKT_HDRLEN,
            )?;
            let pkt_len = match read_standard_packet_len(header_bytes) {
                Ok((c, l)) => l,
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            };

            let pkt = read_packet(
                io,
                &mut request.raw_data,
                request.raw_len,
                request.packet_start,
                pkt_len,
            )?;
            request.packet_start += pkt_len;

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
    let header_bytes = read_packet(
        io,
        &mut response.raw_data,
        response.raw_len,
        response.packet_start,
        STANDARD_PKT_HDRLEN,
    )?;
    let pkt_len = match read_standard_packet_len(header_bytes) {
        Ok((c, l)) => l,
        Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    };

    let pkt = read_packet(
        io,
        &mut response.raw_data,
        response.raw_len,
        response.packet_start,
        pkt_len,
    )?;
    response.packet_start += pkt_len;
    response.is_valid = true;

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

fn send_request<T: io::Write>(
    io: &mut T,
    request: &PostgresRequest,
    state: &mut SessionState,
    start: &mut Option<usize>,
) -> io::Result<()> {
    let mut total_written = start.unwrap_or(0);

    let buf = match request.as_slice().get(total_written..) {
        Some(b) => b,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected request packet sent out of order (invalid length)",
            ))
        }
    };

    loop {
        *start = Some(total_written);
        match io.write(buf) {
            Ok(num_written) => total_written += num_written,
            Err(e) => return Err(e),
        }

        if total_written == request.as_slice().len() {
            *start = None;
            return Ok(());
        }
    }
}

fn send_response<T: io::Write>(
    io: &mut T,
    response: &PostgresResponse,
    state: &mut SessionState,
    start: &mut Option<usize>,
) -> io::Result<()> {
    let mut total_written = start.unwrap_or(0);

    if start.is_some() && response.as_slice().len() <= total_written {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected response packet sent out of order (invalid length)",
        ));
    }

    loop {
        *start = Some(total_written);
        match io.write(&response.as_slice()[total_written..]) {
            Ok(num_written) => total_written += num_written,
            Err(e) => return Err(e),
        }

        if total_written == response.as_slice().len() {
            *start = None;
            return Ok(());
        }
    }
}
