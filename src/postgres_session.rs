use std::{cmp, io};
use std::collections::{HashMap, VecDeque};

use super::wire_reader::WireReader;
use super::sql_session::*;

// Minimum number of bytes needed to extract 'length' field from packet
const STARTUP_PKT_HDRLEN: usize = 4;
const STANDARD_PKT_HDRLEN: usize = 5;

const DEFAULT_REQ_RESP_BUFLEN: usize = 1*1024*1024; // 1MB

const MAX_PACKET_SIZE: u32 = u32::MAX / 2; // Packets very rarely get this big in Postgres

enum SessionState {
    Startup,
    SSLRequestSent,
    StartupSent,
    Authentication,
    AuthenticationSent,
    ReadyForData,
    SimpleQuerySent,

    PermError,
}


enum RequestPacket<'a> {
    /// Encapsulates SASLResponse,
    AuthDataResponse(&'a [u8]),
    /// Indicates a Bind command
    /// (destination portal, source prepared statement, parameter format codes, parameters, result-column format codes)
    Bind(&'a str, &'a str, Vec<bool>, Vec<Option<&'a [u8]>>, Vec<bool>),
    /// Indicates that a request should be cancelled TODO: update documentation
    CancelRequest(i32, i32),
    /// Requests that the given portal be closed
    ClosePortal(&'a str),
    /// Requests that the given prepared statement be closed
    ClosePrepared(&'a str),
    /// Carries data being copied using a COPY command
    CopyData(&'a [u8]),
    /// Indicates a COPY command has finished sending data
    CopyDone,
    /// Indicates a COPY command has failed
    CopyFail(&'a str),
    /// Requests that the given portal be described
    DescribePortal(&'a str),
    /// Requests that the given prepared statement be described
    DescribePrepared(&'a str),
    /// Requests the given portal be executed
    /// (name of portal, maximum number of rows to return--0 means no limit)
    Execute(&'a str, i32),
    /// Requests a flush command be performed
    Flush,
    /// Requests a function be called
    /// (object ID of function, argument format codes--is_text, arguments, format code for function result)
    FunctionCall(i32, Vec<bool>, Vec<Option<&'a [u8]>>, bool),
    /// Requests GSSAPI Encryption
    GSSENCRequest,
    /*
    /// Sends GSSAPI/SSAPI authentication data in the form of bytes
    GSSResponse(&'a [u8]),
    */
    /// Requests a command be parsed
    /// (prepared statement name, query string, parameter data types)
    Parse(&'a str, &'a str, Vec<i32>),
    /*
    /// Indicates a password is being sent, and contains the given password string
    PasswordMessage(&'a str),
    */
    /// Requests that he given smple SQL query be executed
    Query(&'a str),
    /*
    /// An initial SASL response, or else data for a GSSAPI, SSAPI or password response
    /// (selected SASL authentication mechanism, SASL mechanism specific "initial Response")
    SASLInitialResponse(&'a str, Option<&'a [u8]>),
    
    /// A SASL response, or else data for a GSSAPI, SSAPI or password response containing 
    /// SASL mechanism specific message data
    SASLResponse(&'a [u8]),
    */
    /// Requests the connection be encrypted with SSL
    SSLRequest,
    /// Requests a particular user be connected to the database
    StartupMessage(PostgresWireVersion, &'a str, HashMap<&'a str, &'a str>),
    /// Requests a Sync command be performed
    Sync,
    /// Identifies the message as a termination
    Terminate,
}


enum ResponsePacket<'a> {
    /// Indicates successful authentication
    AuthenticationOk,
    /// Indicates that Kerberos V5 authentication is required
    AuthenticationKerberosV5,
    /// Indicates that a cleartext password is required
    AuthenticationCleartextPassword,
    /// Indicates that an MD5 hash of the password with the given 4-byte salt should be sent for authentication
    AuthenticationMD5Password(&'a [u8; 4]),
    /// Indicates that SCM credentials are required
    AuthenticationSCMCredential,
    /// Indicates that GSSAPI authentication is required
    AuthenticationGSS,
    /// Indicates that additional GSSAPI or SSPI authentication data is required
    AuthenticationGSSContinue(&'a [u8]),
    /// Indicates that SSPI authentication is required
    AuthenticationSSPI,
    /// Indicates SASL authentication is required; contains the server's list of authentication mechanisms ordered by preference
    AuthenticationSASL(Vec<&'a str>),
    /// Interim SASL authentication message containing SASL data specific to the SASL mechanism being used
    AuthenticationSASLContinue(&'a [u8]),
    /// Final SASL message containing "additional data" specific to the SASL mechanism being used
    AuthenticationSASLFinal(&'a [u8]),
    /// Provides cancellation key data (process ID and a secret key) that the frontend must use to issue CancelRequest messages later
    BackendKeyData(i32, i32),
    /// Indicates that a Bind request has completed successfully
    BindComplete,
    /// Indicates that a close request was successful
    CloseComplete,
    /// Indicates that the command specified by the given tag was completed
    CommandComplete(&'a str),
    /// Carries data being copied using a COPY command
    CopyData(&'a [u8]),
    /// Indicates a COPY command has finished sending data
    CopyDone,
    /// Indicates the beginning of a COPY from the client to the server
    /// (is_binary, format codes for each column (and number of columns))
    CopyInResponse(bool, Vec<bool>),
    /// Indicates the beginning of a COPY from the server to the client 
    /// (is_binary, format codes for each column (and number of columns))
    CopyOutResponse(bool, Vec<bool>),
    /// Indicates the beginning of a copy that uses Streaming Replication
    CopyBothResponse(bool, Vec<bool>),
    /// Indicates the given message is a data row containing a number of columns with values (None = null)
    DataRow(Vec<Option<&'a [u8]>>),
    /// Response to an empty query string (substitues for CommandComplete)
    EmptyQueryResponse,
    /// Indicates an error has occurred
    ErrorResponse(HashMap<u8, &'a str>),
    /// Response to a given FunctionCall containing a result value--None means null
    FunctionCallResponse(Option<&'a [u8]>),
    /// Indicates protocol version must be negotiated.
    /// (newest minor protocol version supported, protocol options not recognized by server)
    NegotiateProtocolVersion(i32, Vec<&'a str>),
    /// Indicates that no data could be sent
    NoData,
    /// A response that asynchronously conveys information to the client
    NoticeResponse(HashMap<u8, &'a str>),
    /// Indicates a notification has been raised from a backend process
    /// (process ID, name of channel, payload string notification)
    NotificationResponse(i32, &'a str, &'a str),
    /// The message describes parameters for a query, with each `u32` specifying the object ID of the parameter at the given index
    ParameterDescription(Vec<i32>),
    /// A one-time parameter status report
    /// (parameter being reported, current value for parameter)
    ParameterStatus(&'a str, &'a str),
    /// Indicates a Parse command has been completed
    ParseComplete,
    /// Indicates an Execute message's row-count limit was reached, so the portal was suspended
    PortalSuspended,
    /// Indicates the backend is ready for its next query, with the given `char` specifying either 
    /// 'I' if idle (not in any transaction block), 'T' if in a transaction block, or 'E' if 
    /// a failed instruction occurred in the current transaction block.
    ReadyForQuery(TransactionStatus),
    /// Returns data for a single row
    /// (field name, table ID, column ID, data type object ID, data type size, type modifier, is_binary)
    RowDescription(Vec<(&'a str, i32, i16, i32, i16, i32, bool)>),
}

enum TransactionStatus {
    /// Not in a transaction block
    Idle,
    /// Currently in a transaction block
    Transaction,
    /// In a failed transaction block (queries will be rejected until block is ended)
    FailedTransaction,
}

enum PostgresWireVersion {
    V3_0,
}


pub struct PostgresRequest {
    basic_type: RequestBasicType,
    is_valid: bool,
    packet_start: usize,
    raw_data: Vec<u8>,
    raw_len: usize,
}

impl PostgresRequest {
    fn new() -> Self {
        PostgresRequest {
            basic_type: RequestBasicType::AdditionalInformation,
            is_valid: false,
            packet_start: 0,
            raw_data: Vec::from_iter(std::iter::repeat(0).take(DEFAULT_REQ_RESP_BUFLEN)), // TODO: is this inefficient? is there a better way?
            raw_len: 0,
        }
    }
}

impl SqlRequest for PostgresRequest {
    fn get_basic_type<'a>(&'a self) -> &'a RequestBasicType {
        &self.basic_type // TODO: stub
    }

    fn as_slice<'a>(&'a self) -> &'a[u8] {
        &self.raw_data.as_slice()
    }
}

pub struct PostgresResponse {
    basic_type: ResponseBasicType,
    is_valid: bool,
    packet_start: usize,
    raw_data: Vec<u8>,
    raw_len: usize,
}

impl PostgresResponse {
    fn new() -> Self {
        PostgresResponse {
            basic_type: ResponseBasicType::AdditionalInformation,
            is_valid: false,
            packet_start: 0,
            raw_data: Vec::from_iter(std::iter::repeat(0).take(DEFAULT_REQ_RESP_BUFLEN)), // TODO: is this inefficient? is there a better way?
            raw_len: 0,
        }
    }
}

impl SqlResponse for PostgresResponse {
    fn basic_type<'a>(&'a self) -> &'a ResponseBasicType {
        &self.basic_type // TODO: stub
    }

    fn as_slice<'a>(&'a self) -> &'a[u8] {
        &self.raw_data.as_slice()
    }
}


pub struct PostgresClientSession<T: io::Read + io::Write> {
    client_state: SessionState,
    io: T,
    recycled_responses: VecDeque<PostgresResponse>,
    request_part_idx: Option<usize>,
}

impl<T: io::Read + io::Write> SqlClientSession<T> for PostgresClientSession<T> {
    type RequestType = PostgresRequest;
    type ResponseType = PostgresResponse;

    fn new(io: T) -> Self {
        PostgresClientSession {
            client_state: SessionState::Startup,
            io: io,
            recycled_responses: VecDeque::new(),
            request_part_idx: None,
        }
    }

    fn send_request(&mut self, request: &Self::RequestType) -> io::Result<()> {
        send_request(&mut self.io, request, &mut self.client_state, &mut self.request_part_idx)
    }

    fn receive_response(&mut self) -> io::Result<Self::ResponseType> {
        let mut response = match self.recycled_responses.pop_front() {
            Some(req) => req,
            None => PostgresResponse::new()
        };

        match receive_response(&mut self.io, &mut response, &mut self.client_state) {
            Ok(()) => Ok(response),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.recycled_responses.push_front(response);
                Err(e)
            },
            Err(e) => Err(e)
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
    server_state: SessionState,
}

impl<T: io::Read + io::Write> SqlServerSession<T> for PostgresServerSession<T> {

    type RequestType = PostgresRequest;
    type ResponseType = PostgresResponse;

    fn new(io: T) -> Self {
        PostgresServerSession {
            io_device: io,
            recycled_requests: VecDeque::new(),
            response_part_idx: None,
            server_state: SessionState::Startup,
        }
    }

    fn receive_request(&mut self) -> io::Result<Self::RequestType> {
        let mut request = match self.recycled_requests.pop_front() {
            Some(req) => req,
            None => PostgresRequest::new()
        };


        match receive_request(&mut self.io_device, &mut request, &mut self.server_state) {
            Ok(()) => Ok(request),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.recycled_requests.push_front(request);
                Err(e)
            },
            Err(e) => Err(e)
        }
    }

    fn send_response(&mut self, response: &Self::ResponseType) -> io::Result<()> {
        send_response(&mut self.io_device, response, &mut self.server_state, &mut self.response_part_idx)
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
    client_state: SessionState,
    recycled_requests: VecDeque<PostgresRequest>,
    recycled_responses: VecDeque<PostgresResponse>,
    request_part_idx: Option<usize>,
    response_part_idx: Option<usize>,
    server_io: S,
    server_state: SessionState,
}

impl<C: io::Read + io::Write, S: io::Read + io::Write> SqlProxySession<C, S> for PostgresProxySession<C, S> {
    type RequestType = PostgresRequest;
    type ResponseType = PostgresResponse;

    fn new(client_io: C, server_io: S) -> Self {
        PostgresProxySession {
            client_io: client_io,
            client_state: SessionState::Startup,
            server_io: server_io,
            request_part_idx: None,
            response_part_idx: None,
            recycled_requests: VecDeque::new(),
            recycled_responses: VecDeque::new(),
            server_state: SessionState::Startup,
        }
    }

    fn server_receive_request(&mut self) -> io::Result<Self::RequestType> {
        let mut request = match self.recycled_requests.pop_front() {
            Some(req) => req,
            None => PostgresRequest::new()
        };


        match receive_request(&mut self.server_io, &mut request, &mut self.server_state) {
            Ok(()) => Ok(request),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.recycled_requests.push_front(request);
                Err(e)
            },
            Err(e) => Err(e)
        }
    }

    fn server_send_response(&mut self, response: &Self::ResponseType) -> io::Result<()> {
        send_response(&mut self.server_io, response, &mut self.server_state, &mut self.response_part_idx)
    }

    fn client_receive_response(&mut self) -> io::Result<Self::ResponseType> {
        let mut response = match self.recycled_responses.pop_front() {
            Some(req) => req,
            None => PostgresResponse::new()
        };

        match receive_response(&mut self.client_io, &mut response, &mut self.client_state) {
            Ok(()) => Ok(response),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.recycled_responses.push_front(response);
                Err(e)
            },
            Err(e) => Err(e)
        }
    }

    fn client_send_request(&mut self, request: &Self::RequestType) -> io::Result<()> {
        send_request(&mut self.client_io, request, &mut self.client_state, &mut self.request_part_idx)
    }

    /// Safely reuses the allocated structures and buffers of the given request, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_request(&mut self, request: Self::RequestType) {
        self.recycled_requests.push_back(request);
    }

    /// Safely reuses the allocated structures and buffers of the given response, thereby resulting in fewer repeated allocations of large buffers
    fn recycle_response(&mut self, response: Self::ResponseType) {
        self.recycled_responses.push_back(response);
    }

    fn get_client_io_ref(&self) -> &C {
        &self.client_io
    }

    fn get_server_io_ref(&self) -> &S {
        &self.server_io
    }
}

fn move_up_to<'a>(buf: &'a mut [u8] , amount: usize) -> &'a mut [u8] {
    match buf.get_mut(amount..) {
        Some(b) => b,
        None => &mut []
    }
}

fn read_packet<'a, T: io::Read>(io: &mut T, buf: &'a mut Vec<u8>, raw_len: usize, pkt_start_idx: usize, pkt_len: usize) -> io::Result<&'a mut [u8]> {
    // avoid usize overflow here
    if usize::MAX - pkt_len > pkt_start_idx {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "packet received exceeded max packet processing size"))
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
            return Ok(packet_buffer)
        }

        match io.read(remaining_buffer) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "I/O device unexpectedly had no more data")),
            Ok(len) => remaining_buffer = move_up_to(remaining_buffer, len),
            Err(e) => return Err(e)
        }
    }
}

fn receive_request<T: io::Read>(io: &mut T, request: &mut PostgresRequest, state: &mut SessionState) -> io::Result<()> {
    // TODO: make sure that input reading comes from buffered I/O

    match state {
        SessionState::Startup => {
            // Read first header bytes of the packet
            let header_bytes = read_packet(io, &mut request.raw_data, request.raw_len, request.packet_start, STARTUP_PKT_HDRLEN)?;
            let packet_len = match read_startup_packet_len(header_bytes) {
                Ok(l) => l,
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            };

            let packet_bytes = read_packet(io, &mut request.raw_data, request.raw_len, request.packet_start, packet_len)?;
            request.packet_start += packet_len;
            match parse_startup_req_packet(packet_bytes) {
                Ok(RequestPacket::SSLRequest) => (),
                Ok(RequestPacket::GSSENCRequest) => ()
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            }
        },
        _ => {

        }
    }
    Err(io::Error::new(io::ErrorKind::Other, "unimplemented"))
}

fn receive_response<T: io::Read>(io: &mut T, response: &mut PostgresResponse, state: &mut SessionState) -> io::Result<()> {



    Err(io::Error::new(io::ErrorKind::Other, "unimplemented"))
}

fn send_request<T: io::Write>(io: &mut T, request: &PostgresRequest, state: &mut SessionState, start: &mut Option<usize>) -> io::Result<()> {
    let mut total_written = start.unwrap_or(0);

    let buf = match request.as_slice().get(total_written..) {
        Some(b) => b,
        None => return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected request packet sent out of order (invalid length)"))
    };

    loop {
        *start = Some(total_written);
        match io.write(buf) {
            Ok(num_written) => total_written += num_written,
            Err(e) => return Err(e)
        }

        if total_written == request.as_slice().len() {
            *start = None;
            return Ok(())
        }
    }
}

fn send_response<T: io::Write>(io: &mut T, response: &PostgresResponse, state: &mut SessionState, start: &mut Option<usize>) -> io::Result<()> {
    let mut total_written = start.unwrap_or(0);

    if start.is_some() && response.as_slice().len() <= total_written {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected response packet sent out of order (invalid length)"))
    }

    loop {
        *start = Some(total_written);
        match io.write(&response.as_slice()[total_written..]) {
            Ok(num_written) => total_written += num_written,
            Err(e) => return Err(e)
        }

        if total_written == response.as_slice().len() {
            *start = None;
            return Ok(())
        }
    }
}


fn read_startup_packet_len(buffer: &[u8]) -> Result<usize, &'static str> {
    let mut reader = WireReader::new(buffer);
    let packet_length = reader.read_int32()?;
    if packet_length < 0 {
        Err("packet length field was a negative value")
    } else {
        Ok(packet_length as usize)
    }
}

fn read_standard_packet_len(buffer: &[u8]) -> Result<(u8, usize), &'static str> {
    let mut reader = WireReader::new(buffer);
    let identifier = reader.read_byte()?;
    let packet_length = match reader.read_int32()? {
        len if len < 0 => return Err("packet length field was a negative value"),
        len => (len as usize).checked_add(1).ok_or("packet length field too large")?,
    };

    Ok((identifier, packet_length))
}

fn parse_startup_req_packet<'a>(buffer: &'a [u8]) -> Result<RequestPacket, &'static str> {
    let packet_length = read_startup_packet_len(buffer)?;
    let mut reader = WireReader::new(buffer);
    reader.advance_up_to(4);

    let protocol_field = reader.read_int32()?;

    if (protocol_field == 80877103 || protocol_field == 80877104) && !reader.empty() {
        return Err("startup packet contained more data than expected")
    }

    let protocol_version = match protocol_field {
        196608 => PostgresWireVersion::V3_0, // TODO: allow all minor versions to use this major version as well...?
        80877102 => return Ok(RequestPacket::CancelRequest(reader.read_int32()?, reader.read_int32_and_finalize()?)),
        80877103 => return Ok(RequestPacket::SSLRequest),
        80877104 => return Ok(RequestPacket::GSSENCRequest),
        _ => return Err("startup packet contained unrecognized protocol version")
    };

    let params = reader.read_utf8_string_string_map()?;

    if let Some(user) = params.get("user") {
        Ok(RequestPacket::StartupMessage(protocol_version, user, params))
    } else {
        Err("startup packet missing required 'user' parameter")
    }
}

fn parse_standard_req_packet<'a>(buffer: &'a [u8]) -> Result<RequestPacket, &'static str> {
    let (packet_identifier, packet_length) = read_standard_packet_len(buffer)?;
    let mut reader = WireReader::new(buffer);
    reader.advance_up_to(5);

    match packet_identifier {
        b'c' | b'H' | b'S' => reader.finalize()?,
        _ => ()
    }

    match packet_identifier {
        b'B' => parse_bind_packet(packet_length, reader),
        b'C' => match reader.read_byte()? {
            b'S' => Ok(RequestPacket::ClosePrepared(reader.read_utf8_c_str_and_finalize()?)),
            b'P' => Ok(RequestPacket::ClosePortal(reader.read_utf8_c_str_and_finalize()?)),
            _ => Err("packet contained invalid Close type parameter"),
        },
        b'd' => Ok(RequestPacket::CopyData(reader.read_remaining_bytes())),
        b'c' => Ok(RequestPacket::CopyDone),
        b'f' => Ok(RequestPacket::CopyFail(reader.read_utf8_c_str_and_finalize()?)),
        b'D' => match reader.read_byte()? {
            b'S' => Ok(RequestPacket::DescribePrepared(reader.read_utf8_c_str_and_finalize()?)),
            b'P' => Ok(RequestPacket::DescribePortal(reader.read_utf8_c_str_and_finalize()?)),
            _ => Err("packet contained invalid Describe type parameter"),
        },
        b'E' => Ok(RequestPacket::Execute(reader.read_utf8_c_str()?, reader.read_int32_and_finalize()?)),
        b'H' => Ok(RequestPacket::Flush),
        b'F' => parse_function_req_packet(packet_length, reader),
        b'p' => Ok(RequestPacket::AuthDataResponse(reader.read_remaining_bytes())),
        b'P' => {
            let prepared_stmt_name = reader.read_utf8_c_str()?;
            let query_name = reader.read_utf8_c_str()?;
            let parameters_cnt = reader.read_int16_length()?;
            Ok(RequestPacket::Parse(prepared_stmt_name, query_name, reader.read_int32_list_and_finalize(parameters_cnt)?))
        },
        b'Q' => Ok(RequestPacket::Query(reader.read_utf8_c_str_and_finalize()?)),
        b'S' => Ok(RequestPacket::Sync),
        b'X' => Ok(RequestPacket::Terminate),
        _ => Err("packet contained unrecognized packet identifier")
    }
}

fn parse_standard_resp_packet<'a>(buffer: &'a [u8]) -> Result<ResponsePacket, &'static str> {
    let (packet_identifier, packet_length) = read_standard_packet_len(buffer)?;
    let mut reader = WireReader::new(buffer);
    reader.advance_up_to(5);

    match packet_identifier {
        b'2' | b'3' | b'c' | b'I' | b'n' | b'1' | b's' => reader.finalize()?,
        _ => ()
    }

    match packet_identifier {
        b'K' => Ok(ResponsePacket::BackendKeyData(reader.read_int32()?, reader.read_int32_and_finalize()?)),
        b'R' => parse_auth_resp_packet(packet_length, reader),
        b'2' => Ok(ResponsePacket::BindComplete),
        b'3' => Ok(ResponsePacket::CloseComplete),
        b'C' => Ok(ResponsePacket::CommandComplete(reader.read_utf8_c_str_and_finalize()?)),
        b'd' => Ok(ResponsePacket::CopyData(reader.read_remaining_bytes())),
        b'c' => Ok(ResponsePacket::CopyDone),
        b'G' => parse_copyin_response_packet(packet_length, reader),
        b'H' => parse_copyout_response_packet(packet_length, reader),
        b'W' => parse_copyboth_response_packet(packet_length, reader),
        b'D' => parse_datarow_response_packet(packet_length, reader),
        b'I' => Ok(ResponsePacket::EmptyQueryResponse),
        b'E' => Ok(ResponsePacket::ErrorResponse(reader.read_term_utf8_byte_string_map_and_finalize()?)),
        b'V' => Ok(ResponsePacket::FunctionCallResponse(match reader.read_nullable_int32_length()? {
            Some(length) => Some(reader.read_bytes_and_finalize(length)?),
            None => None
        })),
        b'v' => {
            let newest_minor_proto = reader.read_int32()?;
            let options_cnt = reader.read_int32_length()?;
            Ok(ResponsePacket::NegotiateProtocolVersion(newest_minor_proto, reader.read_utf8_c_strs_and_finalize(options_cnt)?))
        },
        b'n' => Ok(ResponsePacket::NoData),
        b'N' => Ok(ResponsePacket::NoticeResponse(reader.read_term_utf8_byte_string_map_and_finalize()?)),
        b'A' => Ok(ResponsePacket::NotificationResponse(reader.read_int32()?, reader.read_utf8_c_str()?, reader.read_utf8_c_str_and_finalize()?)),
        b't' => {
            let parameters_cnt = reader.read_int16_length()?;
            Ok(ResponsePacket::ParameterDescription(reader.read_int32_list_and_finalize(parameters_cnt)?))
        },
        b'S' => Ok(ResponsePacket::ParameterStatus(reader.read_utf8_c_str()?, reader.read_utf8_c_str_and_finalize()?)),
        b'1' => Ok(ResponsePacket::ParseComplete),
        b's' => Ok(ResponsePacket::PortalSuspended),
        b'Z' => Ok(ResponsePacket::ReadyForQuery(match reader.read_byte()? {
            b'I' => TransactionStatus::Idle,
            b'T' => TransactionStatus::Transaction,
            b'E' => TransactionStatus::FailedTransaction,
            _ => return Err("packet contained unrecognized transaction status indicator")
        })),
        b'T' => parse_rowdescription_resp_packet(packet_length, reader),
        _ => Err("packet contained unrecognized packet identifier")
    }
}


fn parse_rowdescription_resp_packet<'a>(packet_length: usize, mut reader: WireReader<'a>) -> Result<ResponsePacket, &'static str> {
    let field_cnt = reader.read_int16_length()?;
    let mut fields = Vec::new();
    for _ in 0..field_cnt {
        let field_name = reader.read_utf8_c_str()?;
        let table_object_id = reader.read_int32()?;
        let attribute_number = reader.read_int16()?;
        let data_type_id = reader.read_int32()?;
        let data_type_size = reader.read_int16()?;
        let type_modifier = reader.read_int32()?;
        let format_code = match reader.read_int16()? {
            1 => true,
            0 => false,
            _ => return Err("packet contained invalid boolean value for format code")
        };
        fields.push((field_name, table_object_id, attribute_number, data_type_id, data_type_size, type_modifier, format_code));
    }

    Ok(ResponsePacket::RowDescription(fields))
}

fn parse_function_req_packet<'a>(packet_length: usize, mut reader: WireReader<'a>) -> Result<RequestPacket, &'static str> {
    let object_id = reader.read_int32()?;
    let arg_format_code_cnt = reader.read_int16_length()?;
    let mut arg_format_codes = Vec::new();
    for _ in 0..arg_format_code_cnt {
        arg_format_codes.push(match reader.read_int16()? {
            1 => true,
            0 => false,
            _ =>return Err("packet contains invalid value for boolean format code field")
        });
    }

    let argument_cnt = reader.read_int16_length()?;
    let mut arguments = Vec::new();
    for _ in 0..argument_cnt {
        arguments.push(match reader.read_nullable_int32_length()? {
            Some(param_length) => Some(reader.read_bytes(param_length)?),
            None => None,
        });
    }

    let function_result_format = match reader.read_int16_and_finalize()? {
        1 => true,
        0 => false,
        _ => return Err("packet contains invalid value for boolean format code field")
    };

    Ok(RequestPacket::FunctionCall(object_id, arg_format_codes, arguments, function_result_format))
}

fn parse_datarow_response_packet<'a>(packet_length: usize, mut reader: WireReader<'a>) -> Result<ResponsePacket, &'static str> {
    let column_cnt = reader.read_int16_length()?;
    let mut column_values = Vec::new();
    for _ in 0..column_cnt {
        column_values.push(match reader.read_nullable_int32_length()? {
            Some(column_length) => Some(reader.read_bytes(column_length)?),
            None => None,
        });
    }
    reader.finalize()?;

    Ok(ResponsePacket::DataRow(column_values))
}

fn parse_copyin_response_packet<'a>(packet_length: usize, reader: WireReader<'a>) -> Result<ResponsePacket, &'static str> {
    let (is_binary, format_codes) = parse_copy_response_fields(packet_length, reader)?;
    Ok(ResponsePacket::CopyInResponse(is_binary, format_codes))
}

fn parse_copyout_response_packet<'a>(packet_length: usize, reader: WireReader<'a>) -> Result<ResponsePacket, &'static str> {
    let (is_binary, format_codes) = parse_copy_response_fields(packet_length, reader)?;
    Ok(ResponsePacket::CopyOutResponse(is_binary, format_codes))
}

fn parse_copyboth_response_packet<'a>(packet_length: usize, reader: WireReader<'a>) -> Result<ResponsePacket, &'static str> {
    let (is_binary, format_codes) = parse_copy_response_fields(packet_length, reader)?;
    Ok(ResponsePacket::CopyBothResponse(is_binary, format_codes))
}

fn parse_copy_response_fields<'a>(packet_length: usize, mut reader: WireReader<'a>) -> Result<(bool, Vec<bool>), &'static str> {
    let is_binary = match reader.read_byte()? {
        b'1' => true,
        b'0' => false,
        _ => return Err("packet contains invalid value for boolean copy format field")
    };

    let format_codes_cnt = reader.read_int16_length()?;
    let mut format_codes = Vec::new();
    for _ in 0..format_codes_cnt {
        format_codes.push(match reader.read_int16()? {
            1 => true,
            0 => false,
            _ => return Err("packet contains invalid value for boolean format code field")
        });
    }
    reader.finalize()?;
    Ok((is_binary, format_codes))
}

fn parse_auth_resp_packet<'a>(packet_length: usize, mut reader: WireReader<'a>) -> Result<ResponsePacket, &'static str> {
    let auth_mechanism = reader.read_int32()?;
    match auth_mechanism {
        0 | 2 | 6 | 7 | 9  => reader.finalize()?,
        _ => ()
    }

    match auth_mechanism {
        0 => Ok(ResponsePacket::AuthenticationOk),
        2 => Ok(ResponsePacket::AuthenticationKerberosV5),
        3 => Ok(ResponsePacket::AuthenticationCleartextPassword),
        5 => Ok(ResponsePacket::AuthenticationMD5Password(reader.read_4_bytes_and_finalize()?)),
        6 => Ok(ResponsePacket::AuthenticationSCMCredential),
        7 => Ok(ResponsePacket::AuthenticationGSS),
        8 => Ok(ResponsePacket::AuthenticationGSSContinue(reader.read_remaining_bytes())),
        9 => Ok(ResponsePacket::AuthenticationSSPI),
        10 => Ok(ResponsePacket::AuthenticationSASL(reader.read_term_utf8_c_strs_and_finalize()?)),
        11 => Ok(ResponsePacket::AuthenticationSASLContinue(reader.read_remaining_bytes())),
        12 => Ok(ResponsePacket::AuthenticationSASLFinal(reader.read_remaining_bytes())),
        _ => Err("")
    }
}

fn parse_bind_packet<'a>(packet_length: usize, mut reader: WireReader<'a>) -> Result<RequestPacket, &'static str> {
    let dest_portal = reader.read_utf8_c_str()?;
    let prepared_stmt = reader.read_utf8_c_str()?;
    let format_codes_cnt = reader.read_int16_length()?;
    let mut format_codes = Vec::new();
    for _ in 0..format_codes_cnt {
        format_codes.push(match reader.read_int16()? {
            0 => false,
            1 => true,
            _ => return Err("packet contained invalid parameter format code")
        });
    }

    let parameters_cnt = reader.read_int16_length()?;
    let mut parameters = Vec::new();
    for _ in 0..parameters_cnt {
        parameters.push(match reader.read_nullable_int32_length()? {
            Some(param_length) => Some(reader.read_bytes(param_length)?),
            None => None,
        });
    }

    let result_format_codes_cnt = reader.read_int16_length()?;
    let mut result_format_codes = Vec::new();
    for _ in 0..result_format_codes_cnt {
        result_format_codes.push(match reader.read_int16()? {
            1 => true,
            0 => false,
            _ => return Err("packet contained invalid result-column format code")
        });
    }

    Ok(RequestPacket::Bind(dest_portal, prepared_stmt, format_codes, parameters, result_format_codes))
}