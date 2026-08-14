use anyhow::Result;
use ed25519_dalek::{SIGNATURE_LENGTH, Signer, SigningKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::handshake::{CHALLENGE_SIZE, VERSION_SIZE};

pub async fn initial<R: AsyncRead + Unpin>(r: &mut R) -> Result<(VerifyStep, (u8, u8, u8))> {
    let mut buffer = [0u8; VERSION_SIZE + CHALLENGE_SIZE];
    r.read_exact(&mut buffer).await?;

    let version = (buffer[0], buffer[1], buffer[2]);
    let challenge = buffer[VERSION_SIZE..].try_into()?;

    Ok((VerifyStep { challenge, }, version))
}

pub struct VerifyStep {
    challenge: [u8; CHALLENGE_SIZE]
}

impl VerifyStep {
    pub async fn verify<W: AsyncWrite + Unpin>(self, w: &mut W, signing: &SigningKey, version: (u8, u8, u8)) -> Result<()> {
        let mut buffer = [0u8; VERSION_SIZE + SIGNATURE_LENGTH];
        buffer[0] = version.0;
        buffer[1] = version.1;
        buffer[2] = version.2;

        let signature = signing.sign(&self.challenge);
        buffer[VERSION_SIZE..VERSION_SIZE+SIGNATURE_LENGTH].copy_from_slice(&signature.to_bytes());

        w.write_all(&buffer).await?;
        w.flush().await?;
        Ok(())
    }
}