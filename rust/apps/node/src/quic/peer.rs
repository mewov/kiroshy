use quinn::Connection;
use rustls::pki_types::CertificateDer;

pub fn get_peer_cert_bytes(connection: &Connection) -> Option<Vec<u8>> {
    let identity = connection.peer_identity()?;
    let certs = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let leaf = certs.first()?;

    Some(leaf.as_ref().to_vec())
}