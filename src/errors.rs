use std::fmt;

#[derive(Debug)]
pub enum ServerError {
    InvalidPem,
    InvalidCertificate,
    InvalidSignatureEncoding,
    SignatureVerificationFailed,
    UnsupportedKeyAlgorithm,
    ScriptExecutionFailed,
    UnsupportedCurve,
    NoCertificatesFound,
    MissingSignatureLine,
    EmptyFile,
    EmptyRequest,
    UntrustedCertificate,
    IoError(std::io::Error),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::InvalidPem => write!(f, "Invalid PEM certificate"),
            ServerError::InvalidCertificate => write!(f, "Invalid X.509 certificate"),
            ServerError::InvalidSignatureEncoding => write!(f, "Invalid signature encoding"),
            ServerError::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            ServerError::UnsupportedKeyAlgorithm => write!(f, "Unsupported public key algorithm"),
            ServerError::ScriptExecutionFailed => write!(f, "Script execution failed"),
            ServerError::UnsupportedCurve => write!(f, "Unsupported curve for ECC verification"),
            ServerError::NoCertificatesFound => write!(f, "No certificates found"),
            ServerError::MissingSignatureLine => {
                write!(f, "Missing signature line, not reading further")
            }
            ServerError::EmptyFile => {
                write!(f, "Received an empty file")
            }
            ServerError::EmptyRequest => {
                write!(f, "Received an empty request")
            }
            ServerError::UntrustedCertificate => {
                write!(f, "We dont trust any non-self-signed certificate")
            }
            ServerError::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl From<std::io::Error> for ServerError {
    fn from(e: std::io::Error) -> Self {
        ServerError::IoError(e)
    }
}
