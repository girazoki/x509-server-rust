mod crypto;
mod errors;
mod server;

use crate::errors::ServerError;
use clap::Parser;
use std::fs;
use std::path::Path;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;
use x509_parser::prelude::parse_x509_pem;

/// Server to verify signed bash scripts
#[derive(Parser)]
struct Args {
    /// Path to certificate file or directory
    #[arg(short, long)]
    cert_path: std::path::PathBuf,

    /// Path for the Unix socket
    #[arg(short, long)]
    socket_path: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), ServerError> {
    // Parse CLI args using Clap
    let args = Args::parse();

    // Load certificates from the given path
    let trusted_certs: Vec<X509Certificate<'static>> = if args.cert_path.is_dir() {
        load_certificates_from_dir(&args.cert_path)?
    } else {
        let data = std::fs::read(&args.cert_path)?;
        load_certificates_from_file(&data)?
    };

    if trusted_certs.is_empty() {
        return Err(ServerError::NoCertificatesFound);
    }

    println!("Loaded {} trusted certificate(s)", trusted_certs.len());

    // Run the server with the loaded certificate set
    server::run(args.socket_path.to_str().unwrap(), trusted_certs).await
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
