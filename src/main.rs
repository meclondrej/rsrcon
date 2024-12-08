use std::{
    fmt::Display,
    io::{self, stdin, stdout, BufRead, StdinLock, StdoutLock, Write},
    net::SocketAddr,
    process::exit,
    time::Duration,
};

use clap::{value_parser, Arg, ArgMatches, Command};
use protocol::{ConnectionParameters, Protocol, TransmissionResult};
use protocols::{goldsrc::Goldsrc, source::Source};
use thiserror::Error;
use util::fatal;

mod protocol;
mod protocols;
mod tcp_util;
mod util;

#[derive(Error, Debug)]
pub enum ReadCommandError {
    #[error("cannot write to stdout")]
    StdoutWriteError(io::Error),
    #[error("cannot read from stdin")]
    StdinReadError(io::Error),
}

pub fn read_command() -> Result<String, ReadCommandError> {
    let mut stdout: StdoutLock<'_> = stdout().lock();
    if let Err(err) = stdout.write_all(b"> ") {
        return Err(ReadCommandError::StdoutWriteError(err));
    }
    if let Err(err) = stdout.flush() {
        return Err(ReadCommandError::StdoutWriteError(err));
    }
    let mut input: String = String::new();
    let mut stdin: StdinLock<'_> = stdin().lock();
    if let Err(err) = stdin.read_line(&mut input) {
        return Err(ReadCommandError::StdinReadError(err));
    }
    Ok(input.trim().to_owned())
}

pub fn print_response(response: &str) {
    for line in response.lines() {
        println!("< {}", line);
    }
}

pub enum ProtocolType {
    Source,
    Goldsrc
}

impl ProtocolType {
    pub fn from_string(string: &str) -> Option<Self> {
        match string {
            "source" => Some(Self::Source),
            "goldsrc" => Some(Self::Goldsrc),
            _ => None,
        }
    }
    pub fn connect(&self, params: ConnectionParameters) -> anyhow::Result<Box<dyn Protocol>> {
        Ok(match self {
            Self::Source => Box::new(Source::connect(params)?),
            Self::Goldsrc => Box::new(Goldsrc::connect(params)?),
        })
    }
}

impl Display for ProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Source => "source",
                Self::Goldsrc => "goldsrc",
            }
        )
    }
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_PROTOCOL_TYPE: ProtocolType = ProtocolType::Source;

pub fn main() {
    let args: ArgMatches = Command::new("rsrcon")
        .about("A simple RCON client written in rust")
        .arg(
            Arg::new("dest")
                .help("address of the server to connect to")
                .required(true),
        )
        .arg(
            Arg::new("protocol")
                .help(format!(
                    "protocol to use (default: {})",
                    DEFAULT_PROTOCOL_TYPE
                ))
                .required(false)
                .short('P')
                .long("protocol"),
        )
        .arg(
            Arg::new("password")
                .help("password set on the server")
                .required(false)
                .short('p')
                .long("password"),
        )
        .arg(
            Arg::new("timeout")
                .help(format!(
                    "timeout of the connection stream in ms (default: {} ms)",
                    DEFAULT_TIMEOUT.as_millis()
                ))
                .required(false)
                .short('t')
                .long("timeout")
                .value_parser(value_parser!(u64)),
        )
        .get_matches();
    let dest: SocketAddr = args
        .get_one::<String>("dest")
        .unwrap()
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| fatal("cannot parse server address"));
    let protocol_type: ProtocolType = args
        .get_one::<String>("protocol")
        .map(|protocol_type_str: &String| {
            ProtocolType::from_string(protocol_type_str).unwrap_or_else(|| {
                fatal(&format!("Invalid protocol passed: {}", protocol_type_str))
            })
        })
        .unwrap_or(DEFAULT_PROTOCOL_TYPE);
    let password: String = args
        .get_one::<String>("password")
        .map(|pwd: &String| pwd.to_owned())
        .unwrap_or_else(|| rpassword::prompt_password("Enter password: ").unwrap());
    let timeout: Duration = args
        .get_one::<u64>("timeout")
        .map(|timeout_ms: &u64| Duration::from_millis(*timeout_ms))
        .unwrap_or(DEFAULT_TIMEOUT);
    let mut protocol: Box<dyn Protocol> = protocol_type
        .connect(ConnectionParameters {
            dest,
            timeout,
            password,
        })
        .unwrap_or_else(|err| fatal(&format!("{err}")));
    println!("Type your command or \"disconnect\" to disconnect");
    loop {
        let command: String = read_command().unwrap_or_else(|err| fatal(&format!("{err}")));
        if command == "disconnect" {
            protocol
                .disconnect()
                .unwrap_or_else(|err| fatal(&format!("{err}")));
            exit(0);
        }
        match protocol.transmission(command) {
            TransmissionResult::Success { response } => print_response(&response),
            TransmissionResult::Error(err) => eprintln!("{err}"),
            TransmissionResult::Fatal(err) => fatal(&format!("{err}")),
        }
    }
}
