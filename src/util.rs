use std::process::exit;

pub fn fatal(msg: &str) -> ! {
    eprintln!("FATAL: {}", msg);
    exit(1);
}
