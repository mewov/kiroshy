use rand::{RngExt};

pub mod frame_client;
pub mod frame_node;

pub const HS_SIGNATURE: [u8; 4] = *b"KSv1";
pub const VERSION_SIZE: usize = 3;
pub const CHALLENGE_SIZE: usize = 32;

pub fn generate_challenge() -> [u8; CHALLENGE_SIZE] {
    rand::rng().random()
}