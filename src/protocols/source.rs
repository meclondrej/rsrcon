use std::{
    io::{Read, Write},
    net::TcpStream,
    str,
};

use crate::{
    protocol::Protocol,
    tcp_util::{fatal_with_stream_shutdown, is_errorkind_timeout, shutdown_stream},
    util::fatal,
};

#[allow(non_camel_case_types)]
pub enum PacketType {
    SERVERDATA_AUTH,
    SERVERDATA_EXECCOMMAND,
    SERVERDATA_AUTH_RESPONSE,
    SERVERDATA_RESPONSE_VALUE,
}

impl PacketType {
    pub fn to_numeric(&self) -> i32 {
        match self {
            Self::SERVERDATA_AUTH => 3,
            Self::SERVERDATA_EXECCOMMAND => 2,
            Self::SERVERDATA_AUTH_RESPONSE => 2,
            Self::SERVERDATA_RESPONSE_VALUE => 0,
        }
    }
    pub fn from_incoming_numeric(numeric: i32) -> Option<Self> {
        match numeric {
            2 => Some(Self::SERVERDATA_AUTH_RESPONSE),
            0 => Some(Self::SERVERDATA_RESPONSE_VALUE),
            _ => None,
        }
    }
}

pub struct Packet {
    pub id: i32,
    pub packet_type: PacketType,
    pub body: String,
}

pub enum PacketToBytesError {
    TooLarge,
}

pub enum PacketFromBytesError {
    MalformedPacket,
    Utf8Error,
    InvalidPacketType,
}

const MINIMAL_PACKET_SIZE: usize = size_of::<i32>() // the packet id
    + size_of::<i32>() // the packet type
    + 2 * size_of::<u8>(); // the two null terminators

impl Packet {
    pub fn to_bytes(&self) -> Result<Vec<u8>, PacketToBytesError> {
        let packet_type = self.packet_type.to_numeric();
        let body: &[u8] = self.body.as_bytes();
        let size: usize = size_of::<i32>() // the packet id
            + size_of::<i32>() // the packet type
            + body.len() // the packet body
            + 2; // the two null terminators
        if size > 4096 {
            return Err(PacketToBytesError::TooLarge);
        }
        let packet_size: usize = size + size_of::<i32>();
        let mut bytes: Vec<u8> = Vec::with_capacity(packet_size);
        bytes.extend_from_slice(&(size as i32).to_le_bytes());
        bytes.extend_from_slice(&self.id.to_le_bytes());
        bytes.extend_from_slice(&packet_type.to_le_bytes());
        bytes.extend_from_slice(body);
        bytes.extend_from_slice(&[0, 0]);
        Ok(bytes)
    }
    pub fn from_incoming_bytes(bytes: &[u8]) -> Result<Self, PacketFromBytesError> {
        if bytes.len() < MINIMAL_PACKET_SIZE {
            return Err(PacketFromBytesError::MalformedPacket);
        }
        let id: i32 = i32::from_le_bytes(bytes[0..size_of::<i32>()].try_into().unwrap());
        let packet_type: i32 = i32::from_le_bytes(
            bytes[size_of::<i32>()..2 * size_of::<i32>()]
                .try_into()
                .unwrap(),
        );
        let body: &str = match std::str::from_utf8(
            &bytes[2 * size_of::<i32>()..bytes.len() - (2 * size_of::<u8>())],
        ) {
            Ok(body) => body,
            Err(_) => return Err(PacketFromBytesError::Utf8Error),
        };
        Ok(Self {
            id,
            packet_type: match PacketType::from_incoming_numeric(packet_type) {
                Some(packet_type) => packet_type,
                None => return Err(PacketFromBytesError::InvalidPacketType),
            },
            body: body.to_owned(),
        })
    }
}

pub fn send_packet(stream: &mut TcpStream, packet: &Packet) -> Result<(), PacketToBytesError> {
    let bytes: Vec<u8> = match packet.to_bytes() {
        Ok(bytes) => bytes,
        Err(PacketToBytesError::TooLarge) => return Err(PacketToBytesError::TooLarge),
    };
    match stream.write_all(&bytes) {
        Err(err) if is_errorkind_timeout(err.kind()) => {
            fatal_with_stream_shutdown(stream, "write to stream timed out")
        }
        Err(err) => fatal_with_stream_shutdown(stream, &format!("write to stream failed: {}", err)),
        _ => Ok(()),
    }
}

pub fn stream_read(stream: &mut TcpStream, data: &mut [u8]) {
    match stream.read_exact(data) {
        Err(err) if is_errorkind_timeout(err.kind()) => {
            fatal_with_stream_shutdown(stream, "read from stream timed out")
        }
        Err(err) => {
            fatal_with_stream_shutdown(stream, &format!("read from stream failed: {}", err))
        }
        _ => (),
    };
}

pub fn receive_packet(stream: &mut TcpStream) -> Packet {
    let mut size: [u8; size_of::<i32>()] = [0; size_of::<i32>()];
    stream_read(stream, &mut size);
    let size: i32 = i32::from_le_bytes(size);
    if size < 0 {
        fatal_with_stream_shutdown(stream, "negative size received");
    }
    let mut incoming_bytes: Vec<u8> = vec![0; size as usize];
    stream_read(stream, &mut incoming_bytes);
    match Packet::from_incoming_bytes(&incoming_bytes) {
        Ok(packet) => packet,
        Err(err) => fatal_with_stream_shutdown(
            stream,
            match err {
                PacketFromBytesError::MalformedPacket => "received malformed packet",
                PacketFromBytesError::Utf8Error => "received non-utf8 text",
                PacketFromBytesError::InvalidPacketType => "received invalid response packet type",
            },
        ),
    }
}

pub struct Source {
    pub stream: TcpStream,
}

impl Protocol for Source {
    fn connect(params: crate::protocol::ConnectionParameters) -> Self {
        let mut stream: TcpStream = TcpStream::connect_timeout(&params.dest, params.timeout)
            .unwrap_or_else(|err| fatal(&format!("cannot connect to the server: {}", err)));
        stream
            .set_read_timeout(Some(params.timeout))
            .unwrap_or_else(|err| {
                fatal_with_stream_shutdown(
                    &stream,
                    &format!("cannot set stream read timeout: {}", err),
                )
            });
        stream
            .set_write_timeout(Some(params.timeout))
            .unwrap_or_else(|err| {
                fatal_with_stream_shutdown(
                    &stream,
                    &format!("cannot set stream write timeout: {}", err),
                )
            });
        let auth_request_packet: Packet = Packet {
            id: 1,
            packet_type: PacketType::SERVERDATA_AUTH,
            body: params.password.to_owned(),
        };
        if let Err(PacketToBytesError::TooLarge) = send_packet(&mut stream, &auth_request_packet) {
            fatal_with_stream_shutdown(&stream, "auth request packet too large");
        }
        receive_packet(&mut stream);
        let auth_response_packet: Packet = receive_packet(&mut stream);
        if auth_response_packet.id == -1 {
            fatal_with_stream_shutdown(&stream, "incorrect password");
        }
        Self { stream }
    }
    fn transmission(&mut self, command: String) -> Option<String> {
        let empty_packet: Packet = Packet {
            id: 1,
            packet_type: PacketType::SERVERDATA_RESPONSE_VALUE,
            body: String::new(),
        };
        let packet: Packet = Packet {
            id: 1,
            packet_type: PacketType::SERVERDATA_EXECCOMMAND,
            body: command,
        };
        if let Err(PacketToBytesError::TooLarge) = send_packet(&mut self.stream, &packet) {
            println!("packet too large");
            return None;
        }
        if let Err(PacketToBytesError::TooLarge) = send_packet(&mut self.stream, &empty_packet) {
            fatal_with_stream_shutdown(&self.stream, "blank packet is too large");
        }
        let mut packet_counter: u32 = 0;
        let mut response_segments: Vec<String> = Vec::new();
        loop {
            let packet: Packet = receive_packet(&mut self.stream);
            if packet_counter > 0 && packet.body.is_empty() {
                break;
            }
            response_segments.push(packet.body);
            packet_counter += 1;
        }
        receive_packet(&mut self.stream);
        Some(response_segments.join(""))
    }
    fn disconnect(&mut self) {
        shutdown_stream(&self.stream);
    }
}
