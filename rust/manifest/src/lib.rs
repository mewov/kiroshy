use serde::{Deserialize, Serialize};

pub mod creator;
pub mod parser;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub password_hash: [u8; 32],
    pub blocks_length: u32,
    pub payload: Vec<Block>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub block_idx: u32,
    pub block_id: [u8; 32],
    pub nodes: Vec<NodeInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub addr: String,
    pub public_key: [u8; 32],
}
