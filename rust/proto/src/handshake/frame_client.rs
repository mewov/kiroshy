use std::time::Duration;

use anyhow::Result;
use ed25519_dalek::{SIGNATURE_LENGTH, Signature, Verifier, VerifyingKey};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, time::timeout};
use crate::handshake::{CHALLENGE_SIZE, VERSION_SIZE, generate_challenge};

pub async fn initial<W: AsyncWrite + Unpin>(w: &mut W, write_timeout: Duration, version: &(u8, u8, u8)) -> Result<VerifyStep> {
    let mut buffer = [0u8; VERSION_SIZE + CHALLENGE_SIZE];
    buffer[0] = version.0;
    buffer[1] = version.1;
    buffer[2] = version.2;

    let challenge = generate_challenge();
    buffer[VERSION_SIZE..VERSION_SIZE+CHALLENGE_SIZE].copy_from_slice(&challenge);

    timeout(write_timeout, w.write_all(&buffer)).await??;
    Ok(VerifyStep { challenge })
}

pub struct VerifyStep {
    challenge: [u8; CHALLENGE_SIZE]
}

impl VerifyStep {
    pub async fn verify<R: AsyncRead + Unpin>(self, r: &mut R, read_timeout: Duration, verifying: &VerifyingKey) -> Result<(u8, u8, u8)> {
        let mut buffer = [0u8; VERSION_SIZE + SIGNATURE_LENGTH];
        timeout(read_timeout, r.read_exact(&mut buffer)).await??;

        let version = (buffer[0], buffer[1], buffer[2]);
        let signature = Signature::from_bytes(buffer[VERSION_SIZE..VERSION_SIZE+SIGNATURE_LENGTH].try_into()?);

        verifying.verify(&self.challenge, &signature)?;
        Ok(version)
    }
}