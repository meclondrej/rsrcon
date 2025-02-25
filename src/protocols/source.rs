use std::{
    io::{self, Write},
    net::{self, TcpStream},
    str,
};

use thiserror::Error;

use crate::{
    protocol::{Protocol, TransmissionResult},
    tcp_util::{is_errorkind_timeout, stream_read, StreamReadError},
};

#[allow(non_camel_case_types)]
#[derive(PartialEq)]
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

#[derive(Error, Debug)]
pub enum PacketToBytesError {
    #[error("the packet is too large")]
    TooLarge,
}

#[derive(Error, Debug)]
pub enum PacketFromBytesError {
    #[error("the packet is malformed")]
    MalformedPacket,
    #[error("the packet contains non-utf8 text")]
    Utf8Error,
    #[error("the packet is of invalid type")]
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
        let body: &str =
            std::str::from_utf8(&bytes[2 * size_of::<i32>()..bytes.len() - (2 * size_of::<u8>())])
                .map_err(|_| PacketFromBytesError::Utf8Error)?;
        Ok(Self {
            id,
            packet_type: PacketType::from_incoming_numeric(packet_type)
                .ok_or(PacketFromBytesError::InvalidPacketType)?,
            body: body.to_owned(),
        })
    }
}

#[derive(Error, Debug)]
pub enum SendPacketError {
    #[error("failed to convert packet to bytes: {0}")]
    PacketToBytesError(PacketToBytesError),
    #[error("write to stream timed out")]
    Timeout,
    #[error("failed to write to stream: {0}")]
    StreamWriteFailure(io::Error),
}

pub fn send_packet(stream: &mut TcpStream, packet: &Packet) -> Result<(), SendPacketError> {
    let bytes: Vec<u8> = packet
        .to_bytes()
        .map_err(SendPacketError::PacketToBytesError)?;
    match stream.write_all(&bytes) {
        Err(err) if is_errorkind_timeout(err.kind()) => Err(SendPacketError::Timeout),
        Err(err) => Err(SendPacketError::StreamWriteFailure(err)),
        _ => Ok(()),
    }
}

#[derive(Error, Debug)]
pub enum ReceivePacketError {
    #[error("failed to read from stream")]
    StreamReadError(StreamReadError),
    #[error("negative size received")]
    NegativeSizeReceived,
    #[error("failed to convert packet to bytes: {0}")]
    PacketFromBytesError(PacketFromBytesError),
}

pub fn receive_packet(stream: &mut TcpStream) -> Result<Packet, ReceivePacketError> {
    let mut size: [u8; size_of::<i32>()] = [0; size_of::<i32>()];
    stream_read(stream, &mut size).map_err(ReceivePacketError::StreamReadError)?;
    let size: i32 = i32::from_le_bytes(size);
    if size < 0 {
        return Err(ReceivePacketError::NegativeSizeReceived);
    }
    let mut incoming_bytes: Vec<u8> = vec![0; size as usize];
    stream_read(stream, &mut incoming_bytes).map_err(ReceivePacketError::StreamReadError)?;
    Packet::from_incoming_bytes(&incoming_bytes).map_err(ReceivePacketError::PacketFromBytesError)
}

pub struct Source {
    pub stream: TcpStream,
}

#[derive(Error, Debug)]
pub enum ConnectError {
    #[error("cannot connect to the server: {0}")]
    ServerConnectionFailure(io::Error),
    #[error("failed to set stream read timeout: {0}")]
    ReadTimeoutSetFailure(io::Error),
    #[error("failed to set stream write timeout: {0}")]
    WriteTimeoutSetFailure(io::Error),
    #[error("failed to send packet: {0}")]
    SendPacketError(SendPacketError),
    #[error("failed to receive packet: {0}")]
    ReceivePacketError(ReceivePacketError),
    #[error("failed to authenticate, incorrect password")]
    IncorrectPassword,
}

#[derive(Error, Debug)]
pub enum TransmissionError {
    #[error("the packet is too large")]
    PacketTooLarge,
}

#[derive(Error, Debug)]
pub enum TransmissionFatal {
    #[error("failed to send packet: {0}")]
    SendPacketError(SendPacketError),
    #[error("failed to receive packet: {0}")]
    ReceivePacketError(ReceivePacketError),
}

impl Source {
    pub fn connect(params: crate::protocol::ConnectionParameters) -> anyhow::Result<Self> {
        let mut stream: TcpStream = TcpStream::connect_timeout(&params.dest, params.timeout)
            .map_err(ConnectError::ServerConnectionFailure)?;
        stream
            .set_read_timeout(Some(params.timeout))
            .map_err(ConnectError::ReadTimeoutSetFailure)?;
        stream
            .set_write_timeout(Some(params.timeout))
            .map_err(ConnectError::WriteTimeoutSetFailure)?;
        let auth_request_packet: Packet = Packet {
            id: 1,
            packet_type: PacketType::SERVERDATA_AUTH,
            body: params.password.to_owned(),
        };
        send_packet(&mut stream, &auth_request_packet).map_err(ConnectError::SendPacketError)?;
        let auth_response_packet: Packet;
        loop {
            let received_packet: Packet =
                receive_packet(&mut stream).map_err(ConnectError::ReceivePacketError)?;
            if received_packet.packet_type == PacketType::SERVERDATA_AUTH_RESPONSE {
                auth_response_packet = received_packet;
                break;
            }
        }
        if auth_response_packet.id == -1 {
            return Err(ConnectError::IncorrectPassword.into());
        }
        Ok(Self { stream })
    }
}

impl Protocol for Source {
    fn transmission(&mut self, command: String) -> TransmissionResult {
        let empty_packet: Packet = Packet {
            id: 2,
            packet_type: PacketType::SERVERDATA_EXECCOMMAND,
            body: String::new(),
        };
        let packet: Packet = Packet {
            id: 1,
            packet_type: PacketType::SERVERDATA_EXECCOMMAND,
            body: command,
        };
        match send_packet(&mut self.stream, &packet) {
            Err(SendPacketError::PacketToBytesError(PacketToBytesError::TooLarge)) => {
                return TransmissionResult::Error(TransmissionError::PacketTooLarge.into())
            }
            Err(err) => {
                return TransmissionResult::Fatal(TransmissionFatal::SendPacketError(err).into())
            }
            _ => (),
        }
        if let Err(err) = send_packet(&mut self.stream, &empty_packet) {
            return TransmissionResult::Fatal(TransmissionFatal::SendPacketError(err).into());
        }
        let mut response_segments: Vec<String> = Vec::new();
        loop {
            let packet: Packet = match receive_packet(&mut self.stream) {
                Ok(packet) => packet,
                Err(err) => {
                    return TransmissionResult::Fatal(
                        TransmissionFatal::ReceivePacketError(err).into(),
                    )
                }
            };
            if packet.id == 2 {
                break;
            }
            response_segments.push(packet.body);
        }
        TransmissionResult::Success {
            response: response_segments.join(""),
        }
    }
    fn disconnect(&mut self) -> anyhow::Result<()> {
        self.stream
            .shutdown(net::Shutdown::Both)
            .map_err(anyhow::Error::from)
    }
}
