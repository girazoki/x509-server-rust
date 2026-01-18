use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

use crate::errors::ServerError;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;
use x509_parser::prelude::parse_x509_pem;

pub async fn run_server_with_cert_dir(
    cert_path: &std::path::Path,
    socket_path: &std::path::Path,
) -> Result<(), ServerError> {
    let trusted_certs: Vec<X509Certificate<'static>> = if cert_path.is_dir() {
        load_certificates_from_dir(cert_path)?
    } else {
        let data = std::fs::read(cert_path)?;
        load_certificates_from_file(&data)?
    };

    if trusted_certs.is_empty() {
        return Err(ServerError::NoCertificatesFound);
    }

    println!("Loaded {} trusted certificate(s)", trusted_certs.len());

    run(socket_path.to_str().unwrap(), trusted_certs).await
}

pub async fn run(
    socket_path: &str,
    trusted_certs: Vec<X509Certificate<'static>>,
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
/// Handles a single incoming connection
pub async fn handle_connection<S>(
    stream: &mut S,
    trusted_certs: Arc<Vec<X509Certificate<'static>>>,
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
        let response = format!("STATUS: INVALID INPUT\n");
        stream
            .write_all(response.as_bytes())
            .await
            .map_err(ServerError::IoError)?;
        return Ok(());
    }

    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();

    let sig_line = match lines.next() {
        Some(line) => line,
        None => {
            let response = format!("STATUS: INVALID\n{}", ServerError::MissingSignatureLine);
            stream
                .write_all(response.as_bytes())
                .await
                .map_err(ServerError::IoError)?;
            return Ok(());
        }
    };

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

pub fn verify_script_against_cert_store(
    certs: &[X509Certificate<'static>],
    signature_b64: &str,
    message: &[u8],
) -> Result<(), ServerError> {
    for cert in certs {
        if crate::crypto::verify_signature(cert, signature_b64, message).is_ok() {
            return Ok(());
        }
    }
    Err(ServerError::SignatureVerificationFailed)
}

pub fn load_certificates_from_file(
    data: &[u8],
) -> Result<Vec<X509Certificate<'static>>, ServerError> {
    let mut certs = Vec::new();
    if let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(data) {
        if let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(&pem.contents) {
            let cert_static: X509Certificate<'static> = unsafe { std::mem::transmute(cert) };
            certs.push(cert_static);
        }
    }
    Ok(certs)
}

pub fn load_certificates_from_dir<P: AsRef<Path>>(
    dir: P,
) -> Result<Vec<X509Certificate<'static>>, ServerError> {
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
        if let Ok((_, pem)) = parse_x509_pem(&data) {
            if let Ok((_, cert)) = X509Certificate::from_der(&pem.contents) {
                // Convert to 'static by leaking data (simplest way for example)
                let cert_static: X509Certificate<'static> = unsafe { std::mem::transmute(cert) };
                certs.push(cert_static);
            }
        }
    }

    Ok(certs)
}
