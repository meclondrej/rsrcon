use std::{net::SocketAddr, time::Duration};

pub struct ConnectionParameters {
    pub dest: SocketAddr,
    pub timeout: Duration,
    pub password: String,
}

pub trait Protocol {
    fn connect(params: ConnectionParameters) -> Self
    where
        Self: Sized;
    fn transmission(&mut self, command: String) -> Option<String>;
    fn disconnect(&mut self);
}
