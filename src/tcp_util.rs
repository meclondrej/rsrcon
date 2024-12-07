use std::{
    io,
    net::{self, TcpStream},
};

use crate::util::fatal;

pub fn is_errorkind_timeout(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
}

pub fn shutdown_stream(stream: &TcpStream) {
    if let Err(err) = stream.shutdown(net::Shutdown::Both) {
        eprintln!("cannot shutdown stream: {}", err);
    };
}

pub fn fatal_with_stream_shutdown(stream: &TcpStream, msg: &str) -> ! {
    shutdown_stream(stream);
    fatal(msg);
}
