use std::{net::SocketAddr, time::Duration};

use anyhow::Error;

pub struct ConnectionParameters {
    pub dest: SocketAddr,
    pub timeout: Duration,
    pub password: String,
}

pub enum TransmissionResult {
    Success { response: String },
    Error(Error),
    Fatal(Error),
}

pub trait Protocol {
    fn connect(params: ConnectionParameters) -> anyhow::Result<Self>
    where
        Self: Sized;
    fn transmission(&mut self, command: String) -> TransmissionResult;
    fn disconnect(&mut self) -> anyhow::Result<()>;
}
