use std::{
    io::{self, stdin, stdout, BufRead, Read, StdinLock, StdoutLock, Write},
    net::{self, SocketAddr, TcpStream},
    process::exit,
    time::Duration,
};

use clap::{value_parser, Arg, ArgMatches, Command};
use packet::{Packet, PacketFromBytesError, PacketToBytesError, PacketType};

mod packet;

fn fatal(msg: &str) -> ! {
    eprintln!("FATAL: {}", msg);
    exit(1);
}

const STDOUT_WRITE_FAILURE_MSG: &str = "cannot write to stdout";
const STDIN_WRITE_FAILURE_MSG: &str = "cannot read from stdin";

fn read_command() -> String {
    let mut stdout: StdoutLock<'_> = stdout().lock();
    stdout
        .write_all(b"> ")
        .unwrap_or_else(|_| fatal(STDOUT_WRITE_FAILURE_MSG));
    stdout
        .flush()
        .unwrap_or_else(|_| fatal(STDOUT_WRITE_FAILURE_MSG));
    let mut input: String = String::new();
    let mut stdin: StdinLock<'_> = stdin().lock();
    stdin
        .read_line(&mut input)
        .unwrap_or_else(|_| fatal(STDIN_WRITE_FAILURE_MSG));
    input.trim().to_owned()
}

fn print_response(response: &str) {
    for line in response.lines() {
        println!("< {}", line);
    }
}

fn is_errorkind_timeout(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
}

fn shutdown_stream(stream: &TcpStream) {
    if let Err(err) = stream.shutdown(net::Shutdown::Both) {
        eprintln!("cannot shutdown stream: {}", err);
    };
}

fn fatal_with_stream_shutdown(stream: &TcpStream, msg: &str) -> ! {
    shutdown_stream(stream);
    fatal(msg);
}

fn send_packet(stream: &mut TcpStream, packet: &Packet) -> Result<(), PacketToBytesError> {
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

fn stream_read(stream: &mut TcpStream, data: &mut [u8]) {
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

fn receive_packet(stream: &mut TcpStream) -> Packet {
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

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

fn main() {
    let args: ArgMatches = Command::new("rsrcon")
        .about("A simple Source RCON client written in rust")
        .arg(
            Arg::new("dest")
                .help("address of the server to connect to")
                .required(true),
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
    let password: String = args
        .get_one::<String>("password")
        .map(|pwd: &String| pwd.to_owned())
        .unwrap_or_else(|| rpassword::prompt_password("Enter password: ").unwrap());
    let timeout: Duration = args
        .get_one::<u64>("timeout")
        .map(|timeout_ms: &u64| Duration::from_millis(*timeout_ms))
        .unwrap_or(DEFAULT_TIMEOUT);
    let mut stream: TcpStream = TcpStream::connect_timeout(&dest, timeout)
        .unwrap_or_else(|err| fatal(&format!("cannot connect to the server: {}", err)));
    stream
        .set_read_timeout(Some(timeout))
        .unwrap_or_else(|err| {
            fatal_with_stream_shutdown(&stream, &format!("cannot set stream read timeout: {}", err))
        });
    stream
        .set_write_timeout(Some(timeout))
        .unwrap_or_else(|err| {
            fatal_with_stream_shutdown(
                &stream,
                &format!("cannot set stream write timeout: {}", err),
            )
        });
    let auth_request_packet: Packet = Packet {
        id: 1,
        packet_type: PacketType::SERVERDATA_AUTH,
        body: password.to_owned(),
    };
    if let Err(PacketToBytesError::TooLarge) = send_packet(&mut stream, &auth_request_packet) {
        fatal_with_stream_shutdown(&stream, "auth request packet too large");
    }
    receive_packet(&mut stream);
    let auth_response_packet: Packet = receive_packet(&mut stream);
    if auth_response_packet.id == -1 {
        fatal_with_stream_shutdown(&stream, "incorrect password");
    }
    let empty_packet: Packet = Packet {
        id: 1,
        packet_type: PacketType::SERVERDATA_RESPONSE_VALUE,
        body: String::new(),
    };
    println!("Type your command or \"disconnect\" to disconnect");
    loop {
        loop {
            let command: String = read_command();
            if command == "disconnect" {
                shutdown_stream(&stream);
                exit(0);
            }
            let packet: Packet = Packet {
                id: 1,
                packet_type: PacketType::SERVERDATA_EXECCOMMAND,
                body: command,
            };
            if let Err(PacketToBytesError::TooLarge) = send_packet(&mut stream, &packet) {
                println!("packet too large");
                continue;
            }
            break;
        }
        if let Err(PacketToBytesError::TooLarge) = send_packet(&mut stream, &empty_packet) {
            fatal_with_stream_shutdown(&stream, "blank packet is too large");
        }
        let mut packet_counter: u32 = 0;
        let mut response_segments: Vec<String> = Vec::new();
        loop {
            let packet: Packet = receive_packet(&mut stream);
            if packet_counter > 0 && packet.body.is_empty() {
                break;
            }
            response_segments.push(packet.body);
            packet_counter += 1;
        }
        receive_packet(&mut stream);
        print_response(&response_segments.join(""));
    }
}
