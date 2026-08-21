use std::io::{Result, Write};

pub struct ManifestCreator {
    file: std::fs::File,
    manifest: crate::Manifest,
}

impl ManifestCreator {
    pub fn new(filename: &str, password_hash: [u8; 32]) -> Result<Self> {
        let file = std::fs::File::create(filename)?;
        let manifest = crate::Manifest {
            password_hash,
            blocks_length: 0,
            payload: Vec::new(),
        };

        Ok(Self { file, manifest })
    }

    pub fn push_block(&mut self, block: crate::Block) {
        self.manifest.blocks_length += 1;
        self.manifest.payload.push(block);
    }

    pub fn save(mut self) -> Result<()> {
        let manifest_vec = serde_json::to_vec(&self.manifest)?;
        self.file.write_all(&manifest_vec)?;
        Ok(())
    }
}
