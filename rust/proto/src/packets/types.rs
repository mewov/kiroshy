pub const MAX_PAYLOAD_LENGTH: usize = 1_048_576;
pub const IDENTITY_LENGTH: usize = 32;

#[derive(Debug)]
pub struct Packet {
    pub kind: PacketKind,
    pub identity: [u8; IDENTITY_LENGTH],
    pub payload: Vec<u8>,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, num_enum::TryFromPrimitive)]
pub enum PacketKind {
    Ping = 1,
    Pong = 2,
}
