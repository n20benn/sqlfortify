use super::wire::{Packet, Wire};






// Packet Format:
// int<3> payload_length (length of payload beyond 4 initial header bytes)
// int<1> sequence_id
// string<var> payload
//
// if payload_length = 0x ff ff ff, it indicates there will be another packet
// sequence_id starts at 0, is reset to 0 when a new command begins in the Command Phase.
//
// Server responses:
//
// 1. OK_Packet
// int<1> header (0x00 or 0xfe)
// int<lenenc> affected_rows
// int<lenenc> last_insert_id
// if capabilities & CLIENT_PROTOCOL_41 {
// int<2> 	status_flags 	SERVER_STATUS_flags_enum
// int<2> 	warnings 	number of warnings
// } else if capabilities & CLIENT_TRANSACTIONS {
// int<2> 	status_flags 	SERVER_STATUS_flags_enum
// }
// if capabilities & CLIENT_SESSION_TRACK
// string<lenenc> 	info 	human readable status information
// if status_flags & SERVER_SESSION_STATE_CHANGED {
// string<lenenc> 	session state info 	Session State Information
// }
// } else {
// string<EOF> 	info 	human readable status information
// } 

// Packet is OK if header = 0x00 and payload_length > 7
// Packet is EOF if header = 0xfe and payload_length < 9
// ^ only applies if CLIENT_DEPRECATE_EOF flag is sent by client
// 






/* 


pub struct MysqlWire {
    startup_packet_read: bool,
    protocol_version: u32,
    user: String,
    database: String,
}

impl MysqlWire {

}

impl SqlWire for MysqlWire {
    fn new() -> Self {
        MysqlWire {
            user: String::new(),
            database: String::new(),
            startup_packet_read: false,
            protocol_version: 0,
        }
    }

    fn read_client_packet(&mut self, wire: &[u8]) -> Result<Packet, WireError> {
        /*
        if !self.startup_packet_read {
            self.read_startup_header(wire)
        } else {
            Err(WireError::Truncated(9))
        }
        */

        Err(WireError::Truncated(9))
    }

    fn read_server_packet(&mut self, wire: &[u8]) -> Result<Packet, WireError> {
        /*
        if !self.startup_packet_read {
            self.read_startup_header(wire)
        } else {
            Err(WireError::Truncated(9))
        }
        */

        Err(WireError::Truncated(9))
    }

    fn write_server_error(&self, buffer: &mut [u8]) -> Result<(), usize> {

        Ok(())
    }

    /* 
    fn read_header(&mut self, wire: &[u8]) -> Result<Header, WireError> {
        
    }

    fn parse_query(&mut self, wire: &[u8]) -> Result<String, WireError> {
        Err(WireError::Truncated)
    }
    */

    // read_client() and read_server()?
}

*/


// Simple Query
// Client -- 'Q' --> Server (Single Query message)
// Server -- <Response message> --> Client (one or more)
// Server -- 'E' <ErrorMessage> --> Client (potential)
// Server -- 'Z' <ReadyForQuery> --> Client (indicates next command)


// Exception to return: 22018 | invalid_character_value_for_cast