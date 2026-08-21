use std::io::Result;

pub struct ManifestParser {
    manifest: crate::Manifest,
}

impl ManifestParser {
    pub fn new(filename: &str) -> Result<Self> {
        let source = std::fs::File::open(filename)?;
        let manifest: crate::Manifest = serde_json::from_reader(source)?;
        Ok(Self { manifest })
    }

    pub fn get_password(&self) -> [u8; 32] {
        self.manifest.password_hash
    }

    pub fn get_blocks_length(&self) -> u32 {
        self.manifest.blocks_length
    }

    pub fn pop_block(&mut self) -> Option<crate::Block> {
        self.manifest.payload.pop()
    }
}
