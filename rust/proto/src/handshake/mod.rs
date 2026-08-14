use rand::{RngExt};

pub mod frame_client;
pub mod frame_node;

pub const VERSION_SIZE: usize = 3;
pub const CHALLENGE_SIZE: usize = 32;

pub fn generate_challenge() -> [u8; CHALLENGE_SIZE] {
    rand::rng().random()
}