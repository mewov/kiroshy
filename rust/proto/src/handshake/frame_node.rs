use crate::handshake::{CHALLENGE_SIZE, HS_SIGNATURE, VERSION_SIZE};
use anyhow::Result;
use ed25519_dalek::{SIGNATURE_LENGTH, Signer, SigningKey};
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

pub async fn initial<R: AsyncRead + Unpin>(r: &mut R, read_timeout: Duration) -> Result<(VerifyStep, (u8, u8, u8))> {
    let mut buffer = [0u8; VERSION_SIZE + CHALLENGE_SIZE];
    timeout(read_timeout, r.read_exact(&mut buffer)).await??;

    let version = (buffer[0], buffer[1], buffer[2]);
    let challenge = buffer[VERSION_SIZE..].try_into()?;

    Ok((VerifyStep { challenge }, version))
}

pub struct VerifyStep {
    challenge: [u8; CHALLENGE_SIZE],
}

impl VerifyStep {
    pub async fn verify<W: AsyncWrite + Unpin>(self, w: &mut W, peer: &[u8], write_timeout: Duration, signing: &SigningKey, version: (u8, u8, u8)) -> Result<()> {
        let mut buffer = [0u8; VERSION_SIZE + SIGNATURE_LENGTH];
        buffer[0] = version.0;
        buffer[1] = version.1;
        buffer[2] = version.2;

        let mut message: Vec<u8> = Vec::with_capacity(HS_SIGNATURE.len() + peer.len() + self.challenge.len());
        message.extend_from_slice(&HS_SIGNATURE);
        message.extend_from_slice(peer);
        message.extend_from_slice(&self.challenge);

        let signature = signing.sign(&message);
        buffer[VERSION_SIZE..VERSION_SIZE + SIGNATURE_LENGTH].copy_from_slice(&signature.to_bytes());

        timeout(write_timeout, w.write_all(&buffer)).await??;
        Ok(())
    }
}
