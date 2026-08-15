use std::{io::Read, path::PathBuf};
use anyhow::Result;
use ed25519_dalek::{SECRET_KEY_LENGTH, SigningKey};

pub fn initial(path: &PathBuf) -> Result<SigningKey> {
    if path.exists() {
        let mut buffer = [0u8; SECRET_KEY_LENGTH];
        std::fs::File::open(path)?.read_exact(&mut buffer)?;
        return Ok(SigningKey::from_bytes(&buffer))
    }

    let mut rng = rand::rngs::OsRng;
    let signing = SigningKey::generate(&mut rng);

    std::fs::write(path, signing.to_bytes())?;
    Ok(signing)
}