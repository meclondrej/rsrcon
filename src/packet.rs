use std::str;

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
