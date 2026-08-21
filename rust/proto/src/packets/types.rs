use bytes::Bytes;

pub const MAX_PAYLOAD_LENGTH: usize = 1_048_576;
pub const IDENTITY_LENGTH: usize = 32;

#[derive(Debug)]
pub struct Packet {
    pub kind: PacketKind,
    pub identity: [u8; IDENTITY_LENGTH],
    pub payload: Bytes,
}

impl Packet {
    pub fn new(kind: PacketKind, payload: Bytes) -> Self {
        Self {
            kind,
            identity: [0u8; IDENTITY_LENGTH],
            payload,
        }
    }

    pub fn new_with_identity(kind: PacketKind, identity: [u8; IDENTITY_LENGTH], payload: Bytes) -> Self {
        Self { kind, identity, payload }
    }

    pub fn new_empty(kind: PacketKind) -> Self {
        Self {
            kind,
            identity: [0u8; IDENTITY_LENGTH],
            payload: Bytes::new(),
        }
    }

    pub fn new_empty_with_identity(kind: PacketKind, identity: [u8; IDENTITY_LENGTH]) -> Self {
        Self {
            kind,
            identity,
            payload: Bytes::new(),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, num_enum::TryFromPrimitive)]
pub enum PacketKind {
    Ping = 1,
    Pong = 2,
    Ok = 3,
    Err = 4,

    GetSpace = 6,
    WriteBlock = 7,
    ReadBlock = 8,
}
