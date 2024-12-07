use std::{
    io::{self, Read},
    net::TcpStream,
};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StreamReadError {
    #[error("read from stream timed out")]
    Timeout,
    #[error("read from stream failed: {0}")]
    StreamReadFailure(io::Error),
}

pub fn is_errorkind_timeout(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
}

pub fn stream_read(stream: &mut TcpStream, data: &mut [u8]) -> Result<(), StreamReadError> {
    match stream.read_exact(data) {
        Err(err) if is_errorkind_timeout(err.kind()) => Err(StreamReadError::Timeout),
        Err(err) => Err(StreamReadError::StreamReadFailure(err)),
        _ => Ok(()),
    }
}
