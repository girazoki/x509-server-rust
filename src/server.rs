use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

use crate::errors::ServerError;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;

// We need to own the der bytes long enough, that is why we created this struct
#[derive(Debug)]
pub struct OwnedX509Certificate {
    pub der: Arc<Vec<u8>>,
    pub cert: X509Certificate<'static>,
}

/// Run the server with a given socket path and a certificate directory path
pub async fn run_server_with_cert_dir(
    cert_path: &std::path::Path,
    socket_path: &std::path::Path,
) -> Result<(), ServerError> {
    let trusted_certs: Vec<OwnedX509Certificate> = if cert_path.is_dir() {
        load_certificates_from_dir(cert_path)?
    } else {
        let data = std::fs::read(cert_path)?;
        let cert = load_certificate_from_file(&data)?;
        vec![cert]
    };

    if trusted_certs.is_empty() {
        return Err(ServerError::NoCertificatesFound);
    }

    log::info!("Loaded {} trusted certificate(s)", trusted_certs.len());

    run(socket_path.to_str().unwrap(), trusted_certs).await
}

/// Run the server with a given socket path and a set of already loaded certificates
pub async fn run(
    socket_path: &str,
    trusted_certs: Vec<OwnedX509Certificate>,
) -> Result<(), ServerError> {
    // Remove old socket if exists
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;

    // Wrap the certificate set in Arc for cheap cloning across tasks
    let trusted_certs = Arc::new(trusted_certs);

    loop {
        let (mut stream, _) = listener.accept().await?;
        let certs = trusted_certs.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(&mut stream, certs).await {
                eprintln!("Connection error: {:?}", e);
            }
        });
    }
}

/// Handles an incoming connection
pub async fn handle_connection<S>(
    stream: &mut S,
    trusted_certs: Arc<Vec<OwnedX509Certificate>>,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read until EOF or max 64k
    let mut buf = vec![0u8; 65536];
    let n = stream.read(&mut buf).await.map_err(ServerError::IoError)?;
    buf.truncate(n);

    if buf.is_empty() {
        // No data received; respond gracefully
        let response = format!("STATUS: INVALID\n{}", ServerError::EmptyRequest);
        stream
            .write_all(response.as_bytes())
            .await
            .map_err(ServerError::IoError)?;
        return Ok(());
    }

    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();

    // Try to read the first line
    let sig_line = match lines.next() {
        Some(line) => line,
        None => {
            let response = format!("STATUS: INVALID\n{}", ServerError::EmptyFile);
            stream
                .write_all(response.as_bytes())
                .await
                .map_err(ServerError::IoError)?;
            return Ok(());
        }
    };

    // Try to get the signature from the first line
    let signature = match sig_line.strip_prefix("# SIGNATURE:") {
        Some(sig) => sig.trim(),
        None => {
            let response = format!("STATUS: INVALID\n{}", ServerError::MissingSignatureLine);
            stream
                .write_all(response.as_bytes())
                .await
                .map_err(ServerError::IoError)?;
            return Ok(());
        }
    };

    // The rest is our body
    let body = lines.collect::<Vec<_>>().join("\n");

    let result = verify_script_against_cert_store(&trusted_certs, signature, body.as_bytes());

    let response = match result {
        Ok(_) => match std::process::Command::new("bash")
            .arg("-c")
            .arg(&body)
            .output()
        {
            Ok(out) => format!("STATUS: OK\n{}", String::from_utf8_lossy(&out.stdout)),
            Err(_) => format!("STATUS: ERROR\n{}", ServerError::ScriptExecutionFailed),
        },
        Err(e) => format!("STATUS: INVALID\n{}", e),
    };

    stream
        .write_all(response.as_bytes())
        .await
        .map_err(ServerError::IoError)?;

    Ok(())
}

// Verify a given signature against all certificates in store
pub fn verify_script_against_cert_store(
    certs: &[OwnedX509Certificate],
    signature_b64: &str,
    message: &[u8],
) -> Result<(), ServerError> {
    for cert in certs {
        if crate::crypto::verify_signature(&cert.cert, signature_b64, message).is_ok() {
            return Ok(());
        }
    }
    Err(ServerError::SignatureVerificationFailed)
}

/// Load the cerificate from a file
pub fn load_certificate_from_file(data: &[u8]) -> Result<OwnedX509Certificate, ServerError> {
    // Early return if we cannot parse the x509 pem
    let (_, pem) = x509_parser::pem::parse_x509_pem(data).map_err(|e| {
        log::debug!("error parsing x509 pem {:?}", e);
        ServerError::InvalidPem
    })?;
    let der_bytes = Arc::new(pem.contents.to_vec());

    // Early return if we cannot derive the cert from
    let (_, cert) = X509Certificate::from_der(&der_bytes).map_err(|e| {
        log::debug!("error loading certificate from der {:?}", e);
        ServerError::InvalidCertificate
    })?;
    // This is safe to do now, as we return and own der_bytes for as long as the server runs
    let cert_static: X509Certificate<'static> = unsafe { std::mem::transmute(cert) };

    // Check if certificate is sef_signed
    if !is_self_signed(&cert_static) {
        return Err(ServerError::UntrustedCertificate);
    }

    // Check if certificate is valid for code signing
    if !has_code_signing_eku(&cert_static) {
        return Err(ServerError::CodeSigningNotEnabled);
    }

    Ok(OwnedX509Certificate {
        der: der_bytes,
        cert: cert_static,
    })
}

/// Load cerificates from directory
/// Files that are not valid certificates are not loaded
pub fn load_certificates_from_dir<P: AsRef<Path>>(
    dir: P,
) -> Result<Vec<OwnedX509Certificate>, ServerError> {
    let mut certs = Vec::new();

    for entry in fs::read_dir(dir).map_err(|e| ServerError::IoError(e))? {
        let entry = entry.map_err(|e| ServerError::IoError(e))?;
        let path = entry.path();

        // Skip if whatever we find is not a file itself
        if !path.is_file() {
            continue;
        }

        let data = fs::read(&path).map_err(|e| ServerError::IoError(e))?;

        // Try to load only those files that parse correctly to a x509 cert
        if let Ok(cert) = load_certificate_from_file(&data) {
            log::debug!("Loading certifiate in path {:?} DER {:?}", path, cert.der);
            certs.push(cert);
        }
    }

    Ok(certs)
}

/// Verify the certificate is selg-signed. We only support self-signed certificates in this server.
fn is_self_signed(cert: &X509Certificate) -> bool {
    // Issuer == Subject
    if cert.tbs_certificate.subject != cert.tbs_certificate.issuer {
        return false;
    }

    // Verify cert signature with its own public key
    cert.verify_signature(None).is_ok()
}

/// Verify the certificate is inteded for code signing
fn has_code_signing_eku(cert: &X509Certificate) -> bool {
    if let Ok(Some(eku)) = cert.extended_key_usage() {
        if eku.value.code_signing {
            return true;
        }
    }
    false
}
