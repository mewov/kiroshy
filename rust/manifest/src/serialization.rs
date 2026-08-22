use std::fs::File;
use std::io::{BufWriter, Error, Result, Seek, Write};

pub struct ManifestWriter {
    blocks: u32,
    manifest_name: String,
    writer: BufWriter<File>,
}

impl ManifestWriter {
    pub fn new(manifest_name: &str, filename: &str, password_hash: &[u8; 32]) -> Result<Self> {
        let filename_bytes = filename.as_bytes();
        let filename_len = u16::try_from(filename_bytes.len()).map_err(|_| Error::other("Filename is too large"))?;

        let file = File::create(manifest_name)?;
        let mut writer = BufWriter::new(file);

        let mut header = Vec::with_capacity(filename_bytes.len() + 38);
        header.extend_from_slice(&[0u8; 4]);
        header.extend_from_slice(&filename_len.to_be_bytes());
        header.extend_from_slice(filename_bytes);
        header.extend_from_slice(password_hash);

        writer.write_all(&header)?;

        Ok(Self {
            blocks: 0,
            manifest_name: manifest_name.to_string(),
            writer,
        })
    }

    pub fn push_block(&mut self, block: &crate::Block) -> Result<()> {
        let nodes_len = u8::try_from(block.nodes.len()).map_err(|_| Error::other("Too many nodes"))?;

        let mut buffer = Vec::new();
        buffer.extend_from_slice(&block.block_idx.to_be_bytes());
        buffer.extend_from_slice(&block.block_id);
        buffer.push(nodes_len);

        for node in &block.nodes {
            let addr_bytes = node.addr.as_bytes();
            let addr_len = u16::try_from(addr_bytes.len()).map_err(|_| Error::other("Node address is too large"))?;

            buffer.extend_from_slice(&addr_len.to_be_bytes());
            buffer.extend_from_slice(addr_bytes);
            buffer.extend_from_slice(&node.public_key);
        }

        self.writer.write_all(&buffer)?;
        self.blocks += 1;

        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        self.writer.flush()?;
        self.writer.seek(std::io::SeekFrom::Start(0))?;
        self.writer.write_all(&self.blocks.to_be_bytes())?;
        self.writer.flush()?;
        Ok(())
    }

    pub fn remove(self) -> Result<()> {
        std::fs::remove_file(&self.manifest_name)
    }
}
