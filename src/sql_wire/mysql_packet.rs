use std::collections::HashMap;
use std::cmp;
use std::ops;

use super::wire_reader::WireReader;

pub enum RequestPacket<'a> {
    ///
    /// 
    /// Fields: capability_flags, max_packet_size, charset, username, auth_response, database, auth_plugin_name, client_connect_attrs
    HandshakeResponse41(u32, u32, u8,&'a str, &'a [u8], Option<&'a str>, Option<&'a str>, Option<HashMap<&'a str, &'a str>>, u8),
    ///
    /// 
    /// Fields: capability_flags, max_packet_size, username, auth_response, database
    HandshakeResponse320(u32, u32, &'a str, &'a [u8], Option<&'a str>),
    ///
    /// 
    /// Fields: capability flags (CLIENT_SSL set), max_packet_size, charset
    SSLRequest(u32, u32, Option<u8>),
    ///
    /// 
    /// Fields: auth_plugin_response
    AuthSwitchResponse(&'a [u8]),
    ///
    /// 
    /// Fields: plugin_name, plugin_data
    AuthNextFactor(&'a str, &'a [u8]),
    ///
    /// 
    /// Fields: query, (parameter_type_and_flag, parameter_name, parameter_value)
    ComQuery(&'a str, Vec<(u16, &'a str, &'a [u8])>),
    ///
    ComQuit,
    ///
    /// 
    /// Fields: schema_name
    ComInitDb(&'a str),
    ///
    /// 
    /// Fields: table, wildcard
    ComFieldList(&'a str, &'a str),
    ComRefresh(u8),
    ComStatistics,
    ComProcessInfo,
    ///
    /// 
    /// Fields: connection_id
    ComProcessKill(u32),
    ComDebug,
    ComPing,
    ///
    /// 
    /// Fields: username, auth_plugin_data, database, charset, auth_plugin_name connection_attrs // TODO: are connection_attrs strings or bytes?
    ComChangeUser(&'a str, &'a [u8], &'a str, Option<u16>, Option<&'a str>, HashMap<&'a str, &'a str>),
    ComResetConnection,
    ///
    /// 
    /// Fields: option_operation
    ComSetOption(u16),
    ///
    /// 
    /// Fields: query
    ComStmtPrepare(&'a str),
    ///
    /// 
    /// Fields: statement_id, flags, iteration_count, (null_bit, parameter_type, parameter_name, parameter_value)
    ComStmtExecute(u32, u8, u32, Vec<(bool, u16, &'a str, &'a [u8])>),
}

pub enum ResponsePacket<'a> {
    ///
    /// 
    /// Fields: server_version, connection_id, auth_plugin_data_part_1, capability_flags_1, charset, status_flags, capability_flags_2, auth_plugin_data_part_2, auth_plugin_name
    HandshakeV10(&'a str, u32, &'a [u8; 8], u32, u8, u16, &'a [u8], Option<&'a str>),
    ///
    /// 
    /// Fields: server_version, connection_id, auth_data_stramble
    HandshakeV9(&'a str, u32, &'a str),
    ///
    /// 
    /// Fields: plugin_name, auth_plugin_data
    AuthSwitchRequest(&'a str, &'a [u8]),
    OldAuthSwitchRequest,
    ///
    /// 
    /// Fields: additional_authentication_data
    AuthMoreData(&'a [u8]),
    ///
    /// 
    /// Fields: plugin_name, plugin_data
    AuthNextFactor(&'a str, &'a [u8]),
    ///
    /// 
    /// Fields: affected_rows, last_insert_id, status_flags, warnings, status_info, session_state_info
    OKPacket(u64, u64, Option<u16>, Option<u16>, &'a str, Option<&'a str>),
    ///
    /// 
    /// Fields: error_code, (sql_state_marker, sql_state), error_message
    ERRPacket(u16, Option<(&'a str, &'a str)>, &'a str),
    ///
    /// 
    /// Fields: catalog, schema, table, org_table, name, org_name, charset, column_length, column_type, flags, max_decimal_digits
    ColumnDefinition41(&'a str, &'a str, &'a str, &'a str, &'a str, &'a str, u16, u32, u8, u16, u8),
    ///
    /// 
    /// Fields: table, name, column_type, flags, decimals, default_values
    ColumnDefinition320(&'a str, &'a str, u8, u16, u8, Option<&'a str>),
    ///
    /// 
    /// Fields: statement_id, num_columns, num_params, warning_count, metadata_follows
    ComStmtPrepareOk(u32, u16, u16, Option<u16>, Option<bool>),
}

pub mod ClientCapabilities {
pub const LONG_PASSWORD: u32 = 1 << 0;
pub const FOUND_ROWS: u32 = 1 << 1;
pub const LONG_FLAG:u32 = 1 << 2;
pub const CONNECT_WITH_DB: u32 = 1 << 3;
pub const NO_SCHEMA: u32 = 1 << 4;
pub const COMPRESS: u32 = 1 << 5;
pub const ODBC: u32 = 1 << 6;
pub const LOCAL_FILES: u32 = 1 << 7;
pub const IGNORE_SPACE: u32 = 1 << 8;
pub const PROTOCOL_41: u32 = 1 << 9;
pub const INTERACTIVE: u32 = 1 << 10;
pub const SSL: u32 = 1 << 11;
pub const IGNORE_SIGPIPE: u32 = 1 << 12;
pub const TRANSACTIONS: u32 = 1 << 13;
pub const RESERVED: u32 = 1 << 14;
pub const RESERVED2: u32 = 1 << 15;
pub const MULTI_STATEMENTS: u32 = 1 << 16;
pub const MULTI_RESULTS: u32 = 1 << 17;
pub const PS_MULTI_RESULTS: u32 = 1 << 18;
pub const PLUGIN_AUTH: u32 = 1 << 19;
pub const CONNECT_ATTRS: u32 = 1 << 20;
pub const PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 1 << 21;
pub const CAN_HANDLE_EXPIRED_PASSWORDS: u32 = 1 << 22;
pub const SESSION_TRACK: u32 = 1 << 23;
pub const DEPRECATE_EOF: u32 = 1 << 24;
pub const OPTIONAL_RESULTSET_METADATA: u32 = 1 << 25;
pub const ZSTD_COMPRESSION_ALGORITHM: u32 = 1 << 26;
pub const QUERY_ATTRIBUTES: u32 = 1 << 27;
pub const MULTI_FACTOR_AUTHENTICATION: u32 = 1 << 28;
pub const CAPABILITY_EXTENSION: u32 = 1 << 29;
pub const SSL_VERIFY_SERVER_CERT: u32 = 1 << 30;
pub const REMEMBER_OPTIONS: u32 = 1 << 31;
}

#[derive(PartialEq, Eq)]
pub enum TransactionStatus {
    /// Not in a transaction block
    Idle,
    /// Currently in a transaction block
    Transaction,
    /// In a failed transaction block (queries will be rejected until block is ended)
    FailedTransaction,
}

pub fn read_lenenc_integer<'a>(reader: &mut WireReader<'a>) -> Result<u64, &'static str> {
    let first_byte: u8 = reader.read()?;
    match first_byte {
        0..=0xFB => Ok(first_byte as u64),
        OxFC => Ok(reader.read::<u16>()? as u64),
        0xFD => Ok(reader.read_u32_3byte()? as u64),
        0xFE => Ok(reader.read::<u64>()?),
        0xFF => Err("invalid length-encoded integer 0xFF")
    }
}

pub fn read_header<'a>(
    mut reader: WireReader<'a>,
) -> Result<(u32, u8), &'static str> {
    Ok((reader.read_u32_3byte()?, reader.read()?))
}

pub fn parse_server_handshake<'a>(buffer: &'a [u8]) -> Result<ResponsePacket, &'static str> {
    let mut reader = WireReader::new(buffer);
    reader.advance_up_to(4);

    
    let protocol_version = reader.read()?;
    let server_version = reader.read_str()?;
    let thread_id = reader.read()?;

    match protocol_version {
        9u8 => Ok(ResponsePacket::HandshakeV9(server_version, thread_id, reader.read_str_and_finalize()?)),
        10u8 => {
            let auth_data_part1 = reader.read_bytearray()?;
            reader.advance_up_to(1); // empty 0x00 byte
            let capabilities_flags_1: u32 = reader.read::<u16>()? as u32;
            let charset = reader.read()?;
            let status_flags = reader.read()?;
            let capabilities_flags = (capabilities_flags_1) & ((reader.read::<u16>()? as u32) << 16);
            
            let auth_data_len: u8 = if (capabilities_flags & ClientCapabilities::PLUGIN_AUTH) != 0 {
                reader.read()?
            } else {
                reader.advance_up_to(1);
                0
            };
            
            reader.advance_up_to(10); // Reserved field
            let adjusted_auth_len = match auth_data_len.checked_sub(8) {
                Some(l) => cmp::max(13, l as usize),
                None => 13
            };

            let auth_data_part2 = reader.read_bytes(adjusted_auth_len)?;
            let auth_plugin_name = if (capabilities_flags & ClientCapabilities::PLUGIN_AUTH) != 0 {
                Some(reader.read_str()?)
            } else {
                None
            };
            reader.finalize()?;

            Ok(ResponsePacket::HandshakeV10(server_version, thread_id, auth_data_part1, capabilities_flags, charset, status_flags, auth_data_part2, auth_plugin_name))
        },
        _ => Err("unsupported protocol version in startup packet")
    }
}

fn parse_client_handshake<'a>(buffer: &'a [u8]) -> Result<RequestPacket, &'static str> {
    let mut reader = WireReader::new(buffer);
    reader.advance_up_to(4);

    let client_flags1: u32 = reader.read::<u16>()? as u32;
    if (client_flags1 & ClientCapabilities::SSL) != 0 {
        if (client_flags1 & ClientCapabilities::PROTOCOL_41) != 0 {
            let capabilities_flags = (client_flags1) & ((reader.read::<u16>()? as u32) << 16);
            Ok(RequestPacket::SSLRequest(capabilities_flags, reader.read()?, Some(reader.read_and_finalize()?)))
        } else {
            Ok(RequestPacket::SSLRequest(client_flags1, reader.read_u32_3byte_and_finalize()?, None))
        }
    } else if (client_flags1 & ClientCapabilities::PROTOCOL_41) != 0 {
        let client_flags = (client_flags1) | ((reader.read::<u16>()? as u32) << 16);
        let max_packet_size = reader.read::<u32>()?;
        let charset = reader.read()?;
        reader.advance_up_to(23);
        let username = reader.read_str()?;
        let resp_len = if (client_flags & ClientCapabilities::PLUGIN_AUTH_LENENC_CLIENT_DATA) != 0 {
            read_lenenc_integer(&mut reader)?
        } else {
            reader.read::<u8>()? as u64
        };
        let auth_response = reader.read_bytes(resp_len as usize)?;

        let database = if (client_flags & ClientCapabilities::CONNECT_WITH_DB) != 0 {
            Some(reader.read_str()?)
        } else {
            None
        };

        let client_plugin_name = if (client_flags & ClientCapabilities::PLUGIN_AUTH) != 0 {
            Some(reader.read_str()?)
        } else {
            None
        };

        let connect_attrs = if (client_flags & ClientCapabilities::CONNECT_ATTRS) != 0 {
            let map_len = read_lenenc_integer(&mut reader)? as usize;
            Some(reader.read_str_str_map_sized(map_len)?)
        } else {
            None
        };

        let zstd_level = reader.read_and_finalize()?;
        Ok(RequestPacket::HandshakeResponse41(client_flags, max_packet_size, charset, username, auth_response, database, client_plugin_name, connect_attrs, zstd_level))

    } else { // CLIENT_PROTOCOL_320
        let max_packet_size = reader.read_u32_3byte()?;
        let username = reader.read_str()?;
        let (auth_response, database) = if (client_flags1 & ClientCapabilities::CONNECT_WITH_DB) != 0 {
            (reader.read_bytes_term()?, Some(reader.read_str_and_finalize()?))
        } else {
            (reader.read_bytes_term_and_finalize()?, None)
        };
        Ok(RequestPacket::HandshakeResponse320(client_flags1, max_packet_size, username, auth_response, database))
    }
}

/* 
pub fn parse_startup_req_packet<'a>(buffer: &'a [u8]) -> Result<RequestPacket, &'static str> {
    let packet_length = read_startup_packet_len(buffer)?;
    if buffer.len() != packet_length {
        return Err("startup packet length field mismatch (internal error)");
    }

    let mut reader = WireReader::new(buffer);
    reader.advance_up_to(4);

    let protocol_field = reader.read_int32()?;

    if (protocol_field == 80877103 || protocol_field == 80877104) && !reader.empty() {
        return Err("startup packet contained more data than expected");
    }

    let protocol_version = match protocol_field {
        196608 => PostgresWireVersion::V3_0, // TODO: allow all minor versions to use this major version as well...?
        80877102 => {
            return Ok(RequestPacket::CancelRequest(
                reader.read_int32()?,
                reader.read_int32_and_finalize()?,
            ))
        },
        80877103 => return Ok(RequestPacket::SSLRequest),
        80877104 => return Ok(RequestPacket::GSSENCRequest),
        _ => return Err("startup packet contained unrecognized protocol version"),
    };

    let params = reader.read_utf8_string_string_map()?;

    if let Some(user) = params.get("user") {
        Ok(RequestPacket::StartupMessage(
            protocol_version,
            user,
            params,
        ))
    } else {
        Err("startup packet missing required 'user' parameter")
    }
}

pub fn parse_standard_req_packet<'a>(buffer: &'a [u8]) -> Result<RequestPacket, &'static str> {
    let (packet_identifier, packet_length) = read_standard_packet_len(buffer)?;
    if buffer.len() - 1 != packet_length {
        return Err("request packet length field mismatch (internal error)");
    }

    let mut reader = WireReader::new(buffer);
    reader.advance_up_to(5);

    match packet_identifier {
        b'c' | b'H' | b'S' => reader.finalize()?,
        _ => (),
    }

    match packet_identifier {
        b'B' => parse_bind_packet(reader),
        b'C' => match reader.read_byte()? {
            b'S' => Ok(RequestPacket::ClosePrepared(
                reader.read_utf8_c_str_and_finalize()?,
            )),
            b'P' => Ok(RequestPacket::ClosePortal(
                reader.read_utf8_c_str_and_finalize()?,
            )),
            _ => Err("packet contained invalid Close type parameter"),
        },
        b'd' => Ok(RequestPacket::CopyData(reader.read_remaining_bytes())),
        b'c' => Ok(RequestPacket::CopyDone),
        b'f' => Ok(RequestPacket::CopyFail(
            reader.read_utf8_c_str_and_finalize()?,
        )),
        b'D' => match reader.read_byte()? {
            b'S' => Ok(RequestPacket::DescribePrepared(
                reader.read_utf8_c_str_and_finalize()?,
            )),
            b'P' => Ok(RequestPacket::DescribePortal(
                reader.read_utf8_c_str_and_finalize()?,
            )),
            _ => Err("packet contained invalid Describe type parameter"),
        },
        b'E' => Ok(RequestPacket::Execute(
            reader.read_utf8_c_str()?,
            reader.read_int32_and_finalize()?,
        )),
        b'H' => Ok(RequestPacket::Flush),
        b'F' => parse_function_req_packet(reader),
        b'p' => Ok(RequestPacket::AuthDataResponse(
            reader.read_remaining_bytes(),
        )),
        b'P' => {
            let prepared_stmt_name = reader.read_utf8_c_str()?;
            let query_name = reader.read_utf8_c_str()?;
            let parameters_cnt = reader.read_int16_length()?;
            Ok(RequestPacket::Parse(
                prepared_stmt_name,
                query_name,
                reader.read_int32_list_and_finalize(parameters_cnt)?,
            ))
        }
        b'Q' => Ok(RequestPacket::Query(reader.read_utf8_c_str_and_finalize()?)),
        b'S' => Ok(RequestPacket::Sync),
        b'X' => Ok(RequestPacket::Terminate),
        _ => Err("packet contained unrecognized packet identifier"),
    }
}

pub fn parse_standard_resp_packet<'a>(buffer: &'a [u8]) -> Result<ResponsePacket, &'static str> {
    let (packet_identifier, packet_length) = read_standard_packet_len(buffer)?;
    if buffer.len() - 1 != packet_length {
        return Err("response packet length field mismatch (internal error)");
    }
    let mut reader = WireReader::new(buffer);
    reader.advance_up_to(5);

    match packet_identifier {
        b'2' | b'3' | b'c' | b'I' | b'n' | b'1' | b's' => reader.finalize()?,
        _ => (),
    }

    match packet_identifier {
        b'K' => Ok(ResponsePacket::BackendKeyData(
            reader.read_int32()?,
            reader.read_int32_and_finalize()?,
        )),
        b'R' => parse_auth_resp_packet(reader),
        b'2' => Ok(ResponsePacket::BindComplete),
        b'3' => Ok(ResponsePacket::CloseComplete),
        b'C' => Ok(ResponsePacket::CommandComplete(
            reader.read_utf8_c_str_and_finalize()?,
        )),
        b'd' => Ok(ResponsePacket::CopyData(reader.read_remaining_bytes())),
        b'c' => Ok(ResponsePacket::CopyDone),
        b'G' => parse_copyin_response_packet(reader),
        b'H' => parse_copyout_response_packet(reader),
        b'W' => parse_copyboth_response_packet(reader),
        b'D' => parse_datarow_response_packet(reader),
        b'I' => Ok(ResponsePacket::EmptyQueryResponse),
        b'E' => Ok(ResponsePacket::ErrorResponse(
            reader.read_term_utf8_byte_string_map_and_finalize()?,
        )),
        b'V' => Ok(ResponsePacket::FunctionCallResponse(
            match reader.read_nullable_int32_length()? {
                Some(length) => Some(reader.read_bytes_and_finalize(length)?),
                None => None,
            },
        )),
        b'v' => {
            let newest_minor_proto = reader.read_int32()?;
            let options_cnt = reader.read_int32_length()?;
            Ok(ResponsePacket::NegotiateProtocolVersion(
                newest_minor_proto,
                reader.read_utf8_c_strs_and_finalize(options_cnt)?,
            ))
        }
        b'n' => Ok(ResponsePacket::NoData),
        b'N' => Ok(ResponsePacket::NoticeResponse(
            reader.read_term_utf8_byte_string_map_and_finalize()?,
        )),
        b'A' => Ok(ResponsePacket::NotificationResponse(
            reader.read_int32()?,
            reader.read_utf8_c_str()?,
            reader.read_utf8_c_str_and_finalize()?,
        )),
        b't' => {
            let parameters_cnt = reader.read_int16_length()?;
            Ok(ResponsePacket::ParameterDescription(
                reader.read_int32_list_and_finalize(parameters_cnt)?,
            ))
        }
        b'S' => Ok(ResponsePacket::ParameterStatus(
            reader.read_utf8_c_str()?,
            reader.read_utf8_c_str_and_finalize()?,
        )),
        b'1' => Ok(ResponsePacket::ParseComplete),
        b's' => Ok(ResponsePacket::PortalSuspended),
        b'Z' => Ok(ResponsePacket::ReadyForQuery(match reader.read_byte()? {
            b'I' => TransactionStatus::Idle,
            b'T' => TransactionStatus::Transaction,
            b'E' => TransactionStatus::FailedTransaction,
            _ => return Err("packet contained unrecognized transaction status indicator"),
        })),
        b'T' => parse_rowdescription_resp_packet(reader),
        _ => Err("packet contained unrecognized packet identifier"),
    }
}

fn parse_rowdescription_resp_packet<'a>(
    mut reader: WireReader<'a>,
) -> Result<ResponsePacket, &'static str> {
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
            _ => return Err("packet contained invalid boolean value for format code"),
        };
        fields.push((
            field_name,
            table_object_id,
            attribute_number,
            data_type_id,
            data_type_size,
            type_modifier,
            format_code,
        ));
    }

    Ok(ResponsePacket::RowDescription(fields))
}

fn parse_function_req_packet<'a>(
    mut reader: WireReader<'a>,
) -> Result<RequestPacket, &'static str> {
    let object_id = reader.read_int32()?;
    let arg_format_code_cnt = reader.read_int16_length()?;
    let mut arg_format_codes = Vec::new();
    for _ in 0..arg_format_code_cnt {
        arg_format_codes.push(match reader.read_int16()? {
            1 => true,
            0 => false,
            _ => return Err("packet contains invalid value for boolean format code field"),
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
        _ => return Err("packet contains invalid value for boolean format code field"),
    };

    Ok(RequestPacket::FunctionCall(
        object_id,
        arg_format_codes,
        arguments,
        function_result_format,
    ))
}

fn parse_datarow_response_packet<'a>(
    mut reader: WireReader<'a>,
) -> Result<ResponsePacket, &'static str> {
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

fn parse_copyin_response_packet<'a>(
    reader: WireReader<'a>,
) -> Result<ResponsePacket, &'static str> {
    let (is_binary, format_codes) = parse_copy_response_fields(reader)?;
    Ok(ResponsePacket::CopyInResponse(is_binary, format_codes))
}

fn parse_copyout_response_packet<'a>(
    reader: WireReader<'a>,
) -> Result<ResponsePacket, &'static str> {
    let (is_binary, format_codes) = parse_copy_response_fields(reader)?;
    Ok(ResponsePacket::CopyOutResponse(is_binary, format_codes))
}

fn parse_copyboth_response_packet<'a>(
    reader: WireReader<'a>,
) -> Result<ResponsePacket, &'static str> {
    let (is_binary, format_codes) = parse_copy_response_fields(reader)?;
    Ok(ResponsePacket::CopyBothResponse(is_binary, format_codes))
}

fn parse_copy_response_fields<'a>(
    mut reader: WireReader<'a>,
) -> Result<(bool, Vec<bool>), &'static str> {
    let is_binary = match reader.read_byte()? {
        b'1' => true,
        b'0' => false,
        _ => return Err("packet contains invalid value for boolean copy format field"),
    };

    let format_codes_cnt = reader.read_int16_length()?;
    let mut format_codes = Vec::new();
    for _ in 0..format_codes_cnt {
        format_codes.push(match reader.read_int16()? {
            1 => true,
            0 => false,
            _ => return Err("packet contains invalid value for boolean format code field"),
        });
    }
    reader.finalize()?;
    Ok((is_binary, format_codes))
}

fn parse_auth_resp_packet<'a>(mut reader: WireReader<'a>) -> Result<ResponsePacket, &'static str> {
    let auth_mechanism = reader.read_int32()?;
    match auth_mechanism {
        0 | 2 | 6 | 7 | 9 => reader.finalize()?,
        _ => (),
    }

    match auth_mechanism {
        0 => Ok(ResponsePacket::AuthenticationOk),
        2 => Ok(ResponsePacket::AuthenticationKerberosV5),
        3 => Ok(ResponsePacket::AuthenticationCleartextPassword),
        5 => Ok(ResponsePacket::AuthenticationMD5Password(
            reader.read_4_bytes_and_finalize()?,
        )),
        6 => Ok(ResponsePacket::AuthenticationSCMCredential),
        7 => Ok(ResponsePacket::AuthenticationGSS),
        8 => Ok(ResponsePacket::AuthenticationGSSContinue(
            reader.read_remaining_bytes(),
        )),
        9 => Ok(ResponsePacket::AuthenticationSSPI),
        10 => Ok(ResponsePacket::AuthenticationSASL(
            reader.read_term_utf8_c_strs_and_finalize()?,
        )),
        11 => Ok(ResponsePacket::AuthenticationSASLContinue(
            reader.read_remaining_bytes(),
        )),
        12 => Ok(ResponsePacket::AuthenticationSASLFinal(
            reader.read_remaining_bytes(),
        )),
        _ => Err(""),
    }
}

fn parse_bind_packet<'a>(mut reader: WireReader<'a>) -> Result<RequestPacket, &'static str> {
    let dest_portal = reader.read_utf8_c_str()?;
    let prepared_stmt = reader.read_utf8_c_str()?;
    let format_codes_cnt = reader.read_int16_length()?;
    let mut format_codes = Vec::new();
    for _ in 0..format_codes_cnt {
        format_codes.push(match reader.read_int16()? {
            0 => false,
            1 => true,
            _ => return Err("packet contained invalid parameter format code"),
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
            _ => return Err("packet contained invalid result-column format code"),
        });
    }

    Ok(RequestPacket::Bind(
        dest_portal,
        prepared_stmt,
        format_codes,
        parameters,
        result_format_codes,
    ))
}
*/