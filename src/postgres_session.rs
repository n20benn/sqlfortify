use std::io;
use std::collections::HashMap;

use crate::wire::Buffer;
use super::wire_reader::WireReader;

use super::ring_buffer::RingBuffer;
use super::session::{ClientSession, Request, RequestType, Response, ResponseType, ServerSession};


const MAX_PACKET_SIZE: u32 = u32::MAX / 2; // Packets don't get this big in postgres


struct RequestPacket<'a> {
    length: usize,
    content: ReqPacketType<'a>,
}

enum ReqPacketType<'a> {
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
    StartupMessage(PostgresWireProtocol, &'a str, HashMap<&'a str, &'a str>),
    /// Requests a Sync command be performed
    Sync,
    /// Identifies the message as a termination
    Terminate,
}

struct ResponsePacket<'a> {
    length: usize,
    content: RespPacketType<'a>,
}

enum RespPacketType<'a> {
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
    RowDescription(Vec<(&'a str, i32, i16, i32, i16, i32, bool)>)
}

enum TransactionStatus {
    /// Not in a transaction block
    Idle,
    /// Currently in a transaction block
    Transaction,
    /// In a failed transaction block (queries will be rejected until block is ended)
    FailedTransaction
}



enum PostgresWireProtocol {
    V3_0
}



pub struct PostgresRequest<'a> {

}

impl<'a> PostgresRequest<'a> {
    pub fn get_content(&self) -> PostgresRequestContent<'a> {

    }
}

impl Request for PostgresRequest<'a> {
    fn get_type<'a>(&'a self) -> RequestType<'a> {
        RequestType::<'a>::Authentication
    }
}

pub struct PostgresResponse<'a> {

}

impl Response for PostgresResponse {
    fn get_type<'a>(&'a self) -> ResponseType<'a> {
        ResponseType::<'a>::UnrecoverableError("")
    }
}



pub struct PostgresServer<T: io::Read + io::Write> {
    io_device: T,
}

impl<T: io::Read + io::Write> ServerSession<T> for PostgresServer<T> {
    type BufferType = RingBuffer;
    type RequestType = PostgresRequest;
    type ResponseType = PostgresResponse;

    fn new(io: T) -> Self {
        PostgresServer {
            io_device: io,
        }
    }

    // fn receive_request(&mut self) -> io::Result<Self::RequestType>;

    fn receive_request_raw(&mut self, buffer: &mut Self::BufferType) -> io::Result<Self::RequestType> {
        Err(io::Error::new(io::ErrorKind::Other, "unimplemented"))
    }

    fn receive_raw(&mut self, buffer: &mut Self::BufferType) -> io::Result<Vec<Self::RequestType>> {
        Err(io::Error::new(io::ErrorKind::Other, "unimplemented"))
    }

    // fn send_response(&mut self, response: &Self::ResponseType) -> io::Result<()>;

    fn send_response_raw(&mut self, buffer: &mut Self::BufferType, response: &Self::ResponseType) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Other, "unimplemented"))
    }

    fn send_raw(&mut self, buffer: &mut Self::BufferType) -> io::Result<()> {
        write_underlying_io(&mut self.io_device, buffer.get_readable_vectored())?;
        Ok(())
    }

    fn get_io_ref(&self) -> &T {
        &self.io_device
    }
}


pub struct PostgresClient<T: io::Read + io::Write> {
    io_device: T,
}

impl<T: io::Read + io::Write> ClientSession<T> for PostgresClient<T> {
    type BufferType = RingBuffer;
    type RequestType = PostgresRequest;
    type ResponseType = PostgresResponse;

    fn new(io: T) -> Self {
        PostgresClient { 
            io_device: io,
        }
    }

    // fn send_request(&mut self, request: &Self::RequestType) -> io::Result<()>;

    fn send_request_raw(&mut self, buffer: &mut Self::BufferType, request: &Self::RequestType) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Other, "unimplemented"))
    }

    fn send_raw(&mut self, buffer: &mut Self::BufferType) -> io::Result<()> {
        // TODO: we still need to parse packet types/lengths and keep track of our current state
        write_underlying_io(&mut self.io_device, buffer.get_readable_vectored())?;
        Ok(())
    }

    // fn receive_response(&mut self) -> io::Result<Self::ResponseType>;

    fn receive_response_raw(&mut self, buffer: &mut Self::BufferType) -> io::Result<Self::ResponseType> {
        Err(io::Error::new(io::ErrorKind::Other, "unimplemented"))
    }

    fn receive_raw(&mut self, buffer: &mut Self::BufferType) -> io::Result<Vec<Self::ResponseType>> {
        //read_underlying_io(&mut self.io_device, buffer.get_writable_vectored())?;
        Err(io::Error::new(io::ErrorKind::Other, "unimplemented"))
    }

    fn get_io_ref(&self) -> &T {
        &self.io_device
    }
}

fn read_underlying_io<'a, T: io::Read + io::Write>(io: &mut T, buffer: &mut [io::IoSliceMut<'a>]) -> io::Result<usize> {
    match io.read_vectored(buffer) {
        Ok(0) => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "I/O device had no more bytes to read (read connection closed)")),
        Ok(w) => Ok(w),
        Err(e) => match e.kind() {
            io::ErrorKind::ConnectionAborted => return Err(io::Error::new(io::ErrorKind::Other, e.to_string())), // Unlikely (and not specified by POSIX), but this will prevent error confusion
            _ => return Err(e)
        }
    }
}

fn write_underlying_io<'a, T: io::Read + io::Write>(io: &mut T, buffer: &[io::IoSlice<'a>]) -> io::Result<usize> {
    match io.write_vectored(buffer) {
        Ok(0) => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "I/O device refused to write any bytes (write connection closed)")),
        Ok(w) => Ok(w),
        Err(e) => match e.kind() {
            io::ErrorKind::ConnectionAborted => return Err(io::Error::new(io::ErrorKind::Other, e.to_string())), // Unlikely (and not specified by POSIX), but this will prevent error confusion
            _ => return Err(e)
        }
    }
}

fn read_startup_header(buffer: &[u8]) -> Result<usize, &'static str> {
    let reader = WireReader::new(buffer);
    let packet_length = reader.read_int32()?;
    if packet_length < 0 {
        Err("packet length field was a negative value")
    } else {
        Ok(packet_length as usize)
    }
}

fn read_standard_header(buffer: &[u8]) -> Result<(u8, usize), &'static str> {
    let reader = WireReader::new(buffer);
    let identifier = reader.read_byte()?;
    let packet_length = match reader.read_int32()? {
        len if len < 0 => return Err("packet length field was a negative value"),
        len => (len as usize).checked_add(1).ok_or("packet length field too large")?,
    };

    Ok((identifier, packet_length))
}

fn parse_startup_req_packet<'a>(buffer: &'a [u8]) -> Result<RequestPacket, &'static str> {
    let packet_length = read_startup_header(buffer)?;
    let reader = WireReader::new(buffer);
    reader.advance_up_to(4);

    let protocol_field = reader.read_int32()?;

    if (protocol_field == 80877103 || protocol_field == 80877104) && !reader.empty() {
        return Err("startup packet contained more data than expected")
    }

    let protocol_version = match protocol_field {
        196608 => PostgresWireProtocol::V3_0, // TODO: allow all minor versions to use this major version as well...?
        80877102 => return Ok(RequestPacket { length: packet_length as usize, content: ReqPacketType::CancelRequest(reader.read_int32()?, reader.finalize_after(reader.read_int32())?) }),
        80877103 => return Ok(RequestPacket { length: packet_length as usize, content: ReqPacketType::SSLRequest }),
        80877104 => return Ok(RequestPacket { length: packet_length as usize, content: ReqPacketType::GSSENCRequest }),
        _ => return Err("startup packet contained unrecognized protocol version")
    };

    let params = reader.read_utf8_string_string_map_term()?;

    if let Some(user) = params.get("user") {
        Ok(RequestPacket { 
            length: packet_length as usize, 
            content: ReqPacketType::StartupMessage(protocol_version, user, params)
        })
    } else {
        Err("startup packet missing required 'user' parameter")
    }
}

fn parse_standard_req_packet<'a>(buffer: &'a [u8]) -> Result<RequestPacket, &'static str> {
    let (packet_identifier, packet_length) = read_standard_header(buffer)?;
    let reader = WireReader::new(buffer);
    reader.advance_up_to(5);

    match packet_identifier {
        b'c' | b'H' | b'S' => reader.finalize()?,
        _ => ()
    }

    match packet_identifier {
        b'B' => parse_bind_packet(packet_length, reader),
        b'C' => Ok(RequestPacket { length: packet_length, content: match reader.read_byte()? {
            b'S' => ReqPacketType::ClosePrepared(reader.finalize_after(reader.read_utf8_c_str())?),
            b'P' => ReqPacketType::ClosePortal(reader.finalize_after(reader.read_utf8_c_str())?),
            _ => return Err("packet contained invalid Close type parameter"),
        }}),
        b'd' => Ok(RequestPacket { length: packet_length, content: ReqPacketType::CopyData(reader.read_remaining_bytes()) }),
        b'c' => Ok(RequestPacket { length: packet_length, content: ReqPacketType::CopyDone }),
        b'f' => Ok(RequestPacket { length: packet_length, content: ReqPacketType::CopyFail(reader.finalize_after(reader.read_utf8_c_str())?) }),
        b'D' => Ok(RequestPacket { length: packet_length, content: match reader.read_byte()? {
            b'S' => ReqPacketType::DescribePrepared(reader.finalize_after(reader.read_utf8_c_str())?),
            b'P' =>ReqPacketType::DescribePortal(reader.finalize_after(reader.read_utf8_c_str())?),
            _ => return Err("packet contained invalid Describe type parameter"),
        }}),
        b'E' => Ok(RequestPacket { length: packet_length, content: ReqPacketType::Execute(reader.read_utf8_c_str()?, reader.finalize_after(reader.read_int32())?) }),
        b'H' => Ok(RequestPacket { length: packet_length, content: ReqPacketType::Flush }),
        b'F' => parse_function_req_packet(packet_length, reader),
        b'p' => Ok(RequestPacket { length: packet_length, content: ReqPacketType::AuthDataResponse(reader.read_remaining_bytes()) }),
        b'P' => Ok(RequestPacket { length: packet_length, content: ReqPacketType::Parse(reader.read_utf8_c_str()?, reader.read_utf8_c_str()?, reader.finalize_after(reader.read_int32_list(reader.read_int16_length()?))?) }),
        b'Q' => Ok(RequestPacket { length: packet_length, content: ReqPacketType::Query(reader.finalize_after(reader.read_utf8_c_str())?) }),
        b'S' => Ok(RequestPacket { length: packet_length, content: ReqPacketType::Sync }),
        b'X' => Ok(RequestPacket { length: packet_length, content: ReqPacketType::Terminate }),
        _ => Err("packet contained unrecognized packet identifier")
    }
}

fn parse_standard_resp_packet<'a>(buffer: &'a [u8]) -> Result<ResponsePacket, &'static str> {
    let (packet_identifier, packet_length) = read_standard_header(buffer)?;
    let reader = WireReader::new(buffer);
    reader.advance_up_to(5);

    match packet_identifier {
        b'2' | b'3' | b'c' | b'I' | b'n' | b'1' | b's' => reader.finalize()?,
        _ => ()
    }

    match packet_identifier {
        b'K' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::BackendKeyData(reader.read_int32()?, reader.finalize_after(reader.read_int32())?) }),
        b'R' => parse_auth_resp_packet(packet_length, reader),
        b'2' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::BindComplete }),
        b'3' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::CloseComplete }),
        b'C' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::CommandComplete(reader.finalize_after(reader.read_utf8_c_str())?) }),
        b'd' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::CopyData(reader.read_remaining_bytes()) }),
        b'c' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::CopyDone }),
        b'G' => parse_copyin_response_packet(packet_length, reader),
        b'H' => parse_copyout_response_packet(packet_length, reader),
        b'W' => parse_copyboth_response_packet(packet_length, reader),
        b'D' => parse_datarow_response_packet(packet_length, reader),
        b'I' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::EmptyQueryResponse }),
        b'E' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::ErrorResponse(reader.finalize_after(reader.read_utf8_byte_string_map_term())?) }),
        b'V' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::FunctionCallResponse(match reader.read_nullable_int32_length()? {
            Some(length) => Some(reader.finalize_after(reader.read_bytes(length))?),
            None => None
        }) }),
        b'v' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::NegotiateProtocolVersion(reader.read_int32()?, reader.finalize_after(reader.read_utf8_c_strs(reader.read_int32_length()?))?) }),
        b'n' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::NoData }),
        b'N' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::NoticeResponse(reader.finalize_after(reader.read_utf8_byte_string_map_term())?) }),
        b'A' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::NotificationResponse(reader.read_int32()?, reader.read_utf8_c_str()?, reader.finalize_after(reader.read_utf8_c_str())?) }),
        b't' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::ParameterDescription(reader.finalize_after(reader.read_int32_list(reader.read_int16_length()?))?) }),
        b'S' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::ParameterStatus(reader.read_utf8_c_str()?, reader.finalize_after(reader.read_utf8_c_str())?) }),
        b'1' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::ParseComplete }),
        b's' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::PortalSuspended }),
        b's' => Ok(ResponsePacket { length: packet_length, content: RespPacketType::ReadyForQuery(match reader.read_byte()? {
            b'I' => TransactionStatus::Idle,
            b'T' => TransactionStatus::Transaction,
            b'E' => TransactionStatus::FailedTransaction,
            _ => return Err("packet contained unrecognized transaction status indicator")
        }) }),
        b'T' => parse_rowdescription_resp_packet(packet_length, reader),
        _ => Err("packet contained unrecognized packet identifier")
    }
}


fn parse_rowdescription_resp_packet<'a>(packet_length: usize, reader: WireReader<'a>) -> Result<ResponsePacket, &'static str> {
    let field_cnt = reader.read_int16_length()?;
    let fields = Vec::new();
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

    Ok(ResponsePacket { length: packet_length, content: RespPacketType::RowDescription(fields) })
}

fn parse_function_req_packet<'a>(packet_length: usize, reader: WireReader<'a>) -> Result<RequestPacket, &'static str> {
    let object_id = reader.read_int32()?;
    let arg_format_code_cnt = reader.read_int16_length()?;
    let arg_format_codes = Vec::new();
    for _ in 0..arg_format_code_cnt {
        arg_format_codes.push(match reader.read_int16()? {
            1 => true,
            0 => false,
            _ =>return Err("packet contains invalid value for boolean format code field")
        });
    }

    let argument_cnt = reader.read_int16_length()?;
    let arguments = Vec::new();
    for _ in 0..argument_cnt {
        arguments.push(match reader.read_nullable_int32_length()? {
            Some(param_length) => Some(reader.read_bytes(param_length)?),
            None => None,
        });
    }

    let function_result_format = match reader.finalize_after(reader.read_int16())? {
        1 => true,
        0 => false,
        _ => return Err("packet contains invalid value for boolean format code field")
    };

    Ok(RequestPacket {
        length: packet_length,
        content: ReqPacketType::FunctionCall(object_id, arg_format_codes, arguments, function_result_format)
    })
}

fn parse_datarow_response_packet<'a>(packet_length: usize, reader: WireReader<'a>) -> Result<ResponsePacket, &'static str> {
    let column_cnt = reader.read_int16_length()?;
    let column_values = Vec::new();
    for _ in 0..column_cnt {
        column_values.push(match reader.read_nullable_int32_length()? {
            Some(column_length) => Some(reader.read_bytes(column_length)?),
            None => None,
        });
    }
    reader.finalize()?;

    Ok(ResponsePacket {
        length: packet_length,
        content: RespPacketType::DataRow(column_values)
    })
}

fn parse_copyin_response_packet<'a>(packet_length: usize, reader: WireReader<'a>) -> Result<ResponsePacket, &'static str> {
    let (is_binary, format_codes) = parse_copy_response_fields(packet_length, reader)?;
    Ok(ResponsePacket { length: packet_length, content: RespPacketType::CopyInResponse(is_binary, format_codes) })
}

fn parse_copyout_response_packet<'a>(packet_length: usize, reader: WireReader<'a>) -> Result<ResponsePacket, &'static str> {
    let (is_binary, format_codes) = parse_copy_response_fields(packet_length, reader)?;
    Ok(ResponsePacket { length: packet_length, content: RespPacketType::CopyOutResponse(is_binary, format_codes) })
}

fn parse_copyboth_response_packet<'a>(packet_length: usize, reader: WireReader<'a>) -> Result<ResponsePacket, &'static str> {
    let (is_binary, format_codes) = parse_copy_response_fields(packet_length, reader)?;
    Ok(ResponsePacket { length: packet_length, content: RespPacketType::CopyBothResponse(is_binary, format_codes) })
}

fn parse_copy_response_fields<'a>(packet_length: usize, reader: WireReader<'a>) -> Result<(bool, Vec<bool>), &'static str> {
    let is_binary = match reader.read_byte()? {
        b'1' => true,
        b'0' => false,
        _ => return Err("packet contains invalid value for boolean copy format field")
    };

    let format_codes_cnt = reader.read_int16_length();
    let format_codes = Vec::new();
    for _ in format_codes_cnt {
        format_codes.push(match reader.read_int16()? {
            1 => true,
            0 => false,
            _ => return Err("packet contains invalid value for boolean format code field")
        });
    }
    reader.finalize()?;
    Ok((is_binary, format_codes))
}

fn parse_auth_resp_packet<'a>(packet_length: usize, reader: WireReader<'a>) -> Result<ResponsePacket, &'static str> {
    let auth_mechanism = reader.read_int32()?;
    match auth_mechanism {
        0 | 2 | 6 | 7 | 9  => reader.finalize()?,
        _ => ()
    }

    Ok(ResponsePacket {
        length: packet_length,
        content: match auth_mechanism {
            0 => RespPacketType::AuthenticationOk,
            2 => RespPacketType::AuthenticationKerberosV5,
            3 => RespPacketType::AuthenticationCleartextPassword,
            5 => RespPacketType::AuthenticationMD5Password(reader.finalize_after(reader.read_bytes_exact_4())?),
            6 => RespPacketType::AuthenticationSCMCredential,
            7 => RespPacketType::AuthenticationGSS,
            8 => RespPacketType::AuthenticationGSSContinue(reader.read_remaining_bytes()),
            9 => RespPacketType::AuthenticationSSPI,
            10 => RespPacketType::AuthenticationSASL(reader.finalize_after(reader.read_utf8_c_strs_term())?),
            11 => RespPacketType::AuthenticationSASLContinue(reader.read_remaining_bytes()),
            12 => RespPacketType::AuthenticationSASLFinal(reader.read_remaining_bytes()),
            _ => return Err("")
        }
    })
}

fn parse_bind_packet<'a>(packet_length: usize, reader: WireReader<'a>) -> Result<RequestPacket, &'static str> {
    let dest_portal = reader.read_utf8_c_str()?;
    let prepared_stmt = reader.read_utf8_c_str()?;
    let format_codes_cnt = reader.read_int16_length()?;
    let format_codes = Vec::new();
    for _ in 0..format_codes_cnt {
        format_codes.push(match reader.read_int16()? {
            0 => false,
            1 => true,
            _ => return Err("packet contained invalid parameter format code")
        });
    }

    let parameters_cnt = reader.read_int16_length()?;
    let parameters = Vec::new();
    for _ in 0..parameters_cnt {
        parameters.push(match reader.read_nullable_int32_length()? {
            Some(param_length) => Some(reader.read_bytes(param_length)?),
            None => None,
        });
    }

    let result_format_codes_cnt = reader.read_int16_length()?;
    let result_format_codes = Vec::new();
    for _ in 0..result_format_codes_cnt {
        result_format_codes.push(match reader.read_int16()? {
            1 => true,
            0 => false,
            _ => return Err("packet contained invalid result-column format code")
        });
    }

    Ok(RequestPacket { 
        length: packet_length, 
        content: ReqPacketType::Bind(dest_portal, prepared_stmt, format_codes, parameters, result_format_codes)
    })
}