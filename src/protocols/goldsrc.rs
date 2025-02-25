use core::str;
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    str::Utf8Error,
};

use thiserror::Error;

use crate::{
    protocol::{Protocol, TransmissionResult},
    tcp_util::is_errorkind_timeout,
};

const PREFIX: [u8; 4] = [0xFF; 4];
const CHALLENGE: &[u8; 20] = b"\xFF\xFF\xFF\xFFchallenge rcon\n\0";

#[derive(Error, Debug)]
pub enum ChallengeIdExtractionError {
    #[error("challenge contains non-utf8 text")]
    Utf8(Utf8Error),
    #[error("the challenge is malformed")]
    MalformedChallenge,
}

pub fn extract_challenge_id(mut challenge: &[u8]) -> Result<&str, ChallengeIdExtractionError> {
    challenge = challenge
        .strip_prefix(&PREFIX)
        .ok_or(ChallengeIdExtractionError::MalformedChallenge)?;
    challenge = challenge
        .strip_prefix(b"challenge rcon ")
        .ok_or(ChallengeIdExtractionError::MalformedChallenge)?;
    challenge = challenge
        .strip_suffix(b"\n\0")
        .ok_or(ChallengeIdExtractionError::MalformedChallenge)?;
    str::from_utf8(challenge).map_err(ChallengeIdExtractionError::Utf8)
}

pub fn make_command_packet(command: &str, password: &str, challenge_id: &str) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();
    packet.extend_from_slice(&PREFIX);
    packet
        .append(&mut format!("rcon {} \"{}\" {}\0", challenge_id, password, command).into_bytes());
    packet
}

#[derive(Error, Debug)]
pub enum ResponseExtractionError {
    #[error("payload contains non-utf8 text")]
    Utf8(Utf8Error),
    #[error("the payload is malformed")]
    MalformedPayload,
}

pub fn extract_response(mut payload: &[u8]) -> Result<&str, ResponseExtractionError> {
    payload = payload
        .strip_prefix(&PREFIX)
        .ok_or(ResponseExtractionError::MalformedPayload)?;
    payload = payload
        .strip_prefix(b"l")
        .ok_or(ResponseExtractionError::MalformedPayload)?;
    payload = payload
        .strip_suffix(b"\0\0")
        .ok_or(ResponseExtractionError::MalformedPayload)?;
    str::from_utf8(payload).map_err(ResponseExtractionError::Utf8)
}

pub struct Goldsrc {
    pub socket: UdpSocket,
    pub password: String,
}

pub const RECV_BUFFER_SIZE: usize = 65535;

#[derive(Error, Debug)]
pub enum DataSendError {
    #[error("failed to send to socket: {0}")]
    SendFailure(io::Error),
    #[error("send to socket timed out")]
    Timeout,
}

#[derive(Error, Debug)]
pub enum DataReceiveError {
    #[error("read from socket timed out")]
    Timeout,
    #[error("failed to receive from socket: {0}")]
    RecvFailure(io::Error),
    #[error("failed to receive packet, buffer overflow")]
    BufferOverflow {
        buffer_size: usize,
        payload_size: usize,
    },
}

#[derive(Error, Debug)]
pub enum ChallengeError {
    #[error("failed to send data: {0}")]
    DataSend(DataSendError),
    #[error("failed to receive data: {0}")]
    DataReceive(DataReceiveError),
    #[error("failed to extract challenge id: {0}")]
    ChallengeIdExtraction(ChallengeIdExtractionError),
}

#[derive(Error, Debug)]
pub enum InvokeCommandError {
    #[error("failed to send data: {0}")]
    DataSend(DataSendError),
    #[error("failed to receive data: {0}")]
    DataReceive(DataReceiveError),
    #[error("failed to extract response: {0}")]
    ResponseExtraction(ResponseExtractionError),
}

impl Goldsrc {
    pub fn send_data(&self, data: &[u8]) -> Result<(), DataSendError> {
        match self.socket.send(data) {
            Ok(_) => Ok(()),
            Err(err) if is_errorkind_timeout(err.kind()) => Err(DataSendError::Timeout),
            Err(err) => Err(DataSendError::SendFailure(err)),
        }
    }
    pub fn receive_data(&self) -> Result<Vec<u8>, DataReceiveError> {
        let mut buffer: Vec<u8> = vec![0; RECV_BUFFER_SIZE];
        let size: usize = match self.socket.recv(&mut buffer) {
            Ok(size) => size,
            Err(err) if is_errorkind_timeout(err.kind()) => return Err(DataReceiveError::Timeout),
            Err(err) => return Err(DataReceiveError::RecvFailure(err)),
        };
        if size > RECV_BUFFER_SIZE {
            return Err(DataReceiveError::BufferOverflow {
                buffer_size: RECV_BUFFER_SIZE,
                payload_size: size,
            });
        }
        buffer.truncate(size);
        Ok(buffer)
    }
    pub fn challenge(&self) -> Result<String, ChallengeError> {
        self.send_data(CHALLENGE)
            .map_err(ChallengeError::DataSend)?;
        let raw_challenge: Vec<u8> = self.receive_data().map_err(ChallengeError::DataReceive)?;
        let challenge_id: &str =
            extract_challenge_id(&raw_challenge).map_err(ChallengeError::ChallengeIdExtraction)?;
        Ok(challenge_id.to_owned())
    }
    pub fn invoke_command(
        &self,
        command: &str,
        challenge_id: &str,
    ) -> Result<String, InvokeCommandError> {
        let packet: Vec<u8> = make_command_packet(command, &self.password, challenge_id);
        self.send_data(&packet)
            .map_err(InvokeCommandError::DataSend)?;
        let raw_response: Vec<u8> = self
            .receive_data()
            .map_err(InvokeCommandError::DataReceive)?;
        let response: &str =
            extract_response(&raw_response).map_err(InvokeCommandError::ResponseExtraction)?;
        Ok(response.to_owned())
    }
}

#[derive(Error, Debug)]
pub enum ConnectError {
    #[error("failed to bind socket: {0}")]
    SocketBindFailure(io::Error),
    #[error("failed to set read timeout: {0}")]
    ReadTimeoutSetFailure(io::Error),
    #[error("failed to set write timeout: {0}")]
    WriteTimeoutSetFailure(io::Error),
    #[error("failed to set socket as blocking: {0}")]
    SetBlockingFailure(io::Error),
    #[error("encountered a transmission error while testing connection: {0}")]
    TransmissionErrorWhileTesting(anyhow::Error),
    #[error("encountered a transmission fatal while testing connection: {0}")]
    TransmissionFatalWhileTesting(anyhow::Error),
    #[error("incorrect password")]
    IncorrectPassword,
    #[error("rcon disabled on the server")]
    RconDisabledServerside,
    #[error("this client is banned on the server")]
    BanIssuedServerside,
}

#[derive(Error, Debug)]
pub enum TransmissionError {}

#[derive(Error, Debug)]
pub enum TransmissionFatal {
    #[error("failed to get challenge id: {0}")]
    Challenge(ChallengeError),
    #[error("failed to invoke command: {0}")]
    InvokeCommand(InvokeCommandError),
}

impl Goldsrc {
    pub fn connect(params: crate::protocol::ConnectionParameters) -> anyhow::Result<Self> {
        let socket: UdpSocket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .map_err(ConnectError::SocketBindFailure)?;
        socket
            .set_nonblocking(false)
            .map_err(ConnectError::SetBlockingFailure)?;
        socket
            .set_read_timeout(Some(params.timeout))
            .map_err(ConnectError::ReadTimeoutSetFailure)?;
        socket
            .set_write_timeout(Some(params.timeout))
            .map_err(ConnectError::WriteTimeoutSetFailure)?;
        socket
            .connect(params.dest)
            .map_err(ConnectError::SocketBindFailure)?;
        let mut goldsrc: Goldsrc = Self {
            socket,
            password: params.password,
        };
        match goldsrc.transmission("".to_string()) {
            TransmissionResult::Success { response } => match response.as_str() {
                "Bad rcon_password.\n" => Err(ConnectError::IncorrectPassword.into()),
                "Bad rcon_password.\nNo password set for this server.\n" => {
                    Err(ConnectError::RconDisabledServerside.into())
                }
                "You have been banned from this server.\n" => {
                    Err(ConnectError::BanIssuedServerside.into())
                }
                _ => Ok(goldsrc),
            },
            TransmissionResult::Error(err) => {
                Err(ConnectError::TransmissionErrorWhileTesting(err).into())
            }
            TransmissionResult::Fatal(err) => {
                Err(ConnectError::TransmissionFatalWhileTesting(err).into())
            }
        }
    }
}

impl Protocol for Goldsrc {
    fn transmission(&mut self, command: String) -> TransmissionResult {
        let challenge_id: String = match self.challenge() {
            Ok(id) => id,
            Err(err) => return TransmissionResult::Fatal(TransmissionFatal::Challenge(err).into()),
        };
        TransmissionResult::Success {
            response: match self.invoke_command(&command, &challenge_id) {
                Ok(response) => response,
                Err(err) => {
                    return TransmissionResult::Fatal(TransmissionFatal::InvokeCommand(err).into())
                }
            },
        }
    }
    fn disconnect(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
