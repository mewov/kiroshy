use crate::{Block, NodeInfo};
use std::fs::File;
use std::io::{self, BufReader, Error, ErrorKind, Read};

pub struct ManifestReader {
    blocks: u32,
    manifest_name: String,
    filename: String,
    password_hash: [u8; 32],
    reader: BufReader<File>,
    blocks_read: u32,
}

impl ManifestReader {
    pub fn new(manifest_name: &str) -> io::Result<Self> {
        let file = File::open(manifest_name)?;
        let mut reader = BufReader::new(file);

        let blocks = read_u32_be(&mut reader)?;
        let filename_len = read_u16_be(&mut reader)? as usize;
        let filename_bytes = read_exact_vec(&mut reader, filename_len)?;

        let filename = String::from_utf8(filename_bytes).map_err(|e| Error::new(ErrorKind::InvalidData, format!("Invalid UTF-8 in filename: {e}")))?;

        let password_hash = read_array_32(&mut reader)?;

        Ok(Self {
            blocks,
            manifest_name: manifest_name.to_string(),
            filename,
            password_hash,
            reader,
            blocks_read: 0,
        })
    }

    pub fn blocks(&self) -> u32 {
        self.blocks
    }

    pub fn filename(&self) -> &str {
        &self.filename
    }

    pub fn password_hash(&self) -> &[u8; 32] {
        &self.password_hash
    }

    pub fn read_block(&mut self) -> io::Result<Option<Block>> {
        if self.blocks_read >= self.blocks {
            return Ok(None);
        }

        let block_idx = read_u32_be(&mut self.reader)?;
        let block_id = read_array_32(&mut self.reader)?;
        let nodes_len = read_u8(&mut self.reader)? as usize;

        let mut nodes = Vec::with_capacity(nodes_len);
        for _ in 0..nodes_len {
            let addr_len = read_u16_be(&mut self.reader)? as usize;
            let addr_bytes = read_exact_vec(&mut self.reader, addr_len)?;

            let addr = String::from_utf8(addr_bytes).map_err(|e| Error::new(ErrorKind::InvalidData, format!("Invalid UTF-8 in node address: {e}")))?;

            let public_key = read_array_32(&mut self.reader)?;

            nodes.push(NodeInfo { addr, public_key });
        }

        self.blocks_read += 1;

        Ok(Some(Block { block_idx, block_id, nodes }))
    }

    pub fn read_all(mut self) -> io::Result<Vec<Block>> {
        let mut blocks = Vec::with_capacity(self.blocks as usize);
        while let Some(block) = self.read_block()? {
            blocks.push(block);
        }

        Ok(blocks)
    }

    pub fn manifest_name(&self) -> &str {
        &self.manifest_name
    }
}

fn read_u8<R: Read>(reader: &mut R) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u16_be<R: Read>(reader: &mut R) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

fn read_u32_be<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn read_array_32<R: Read>(reader: &mut R) -> io::Result<[u8; 32]> {
    let mut buf = [0u8; 32];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_exact_vec<R: Read>(reader: &mut R, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}
