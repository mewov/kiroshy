pub mod serialization;
pub use serialization::ManifestWriter;

#[derive(Debug)]
pub struct Manifest {
    pub filename: String,
    pub password_hash: [u8; 32],
    pub blocks_length: u32,
    pub payload: Vec<Block>,
}

#[derive(Debug)]
pub struct Block {
    pub block_idx: u32,
    pub block_id: [u8; 32],
    pub nodes: Vec<NodeInfo>,
}

#[derive(Debug)]
pub struct NodeInfo {
    pub addr: String,
    pub public_key: [u8; 32],
}
