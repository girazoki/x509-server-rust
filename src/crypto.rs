use base64::Engine;
use ring::signature;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;
use x509_parser::pem::parse_x509_pem;
use x509_parser::oid_registry::*;
use ring::signature::{ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, VerificationAlgorithm};
use crate::errors::ServerError;

pub fn verify_signature(
    cert_pem: &[u8],
    signature_b64: &str,
    script_body: &[u8],
) -> Result<(), ServerError> {
    // 1. Parse PEM
    let (_, pem) = parse_x509_pem(cert_pem)
        .map_err(|_| ServerError::InvalidPem)?;

    // 2. Parse DER
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|_| ServerError::InvalidCertificate)?;

    let spki = cert.public_key();

    // Decode signature
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim()).map_err(|_| ServerError::InvalidSignatureEncoding)?;

    // Hash script body
    let digest = Sha256::digest(script_body);

    // Verify, We verify against a small set of crypto algorithms, in the case of more we should add more here
    let verification_alg: &dyn VerificationAlgorithm = match cert.signature_algorithm.algorithm.clone() {
        oid if oid == OID_PKCS1_SHA1WITHRSA || oid == OID_SHA1_WITH_RSA => {
            &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
        }
        oid if oid == OID_PKCS1_SHA256WITHRSA => &signature::RSA_PKCS1_2048_8192_SHA256,
        oid if oid == OID_PKCS1_SHA384WITHRSA => &signature::RSA_PKCS1_2048_8192_SHA384,
        oid if oid == OID_PKCS1_SHA512WITHRSA => &signature::RSA_PKCS1_2048_8192_SHA512,
        oid if oid == OID_PKCS1_RSASSAPSS => {
           return Err(ServerError::UnsupportedKeyAlgorithm)
        }
        oid if oid == OID_SIG_ECDSA_WITH_SHA256 => get_ec_curve_sha(&spki.algorithm, 256)
            .ok_or(ServerError::UnsupportedCurve)?,
        oid if oid == OID_SIG_ECDSA_WITH_SHA384 => get_ec_curve_sha(&spki.algorithm, 384)
            .ok_or(ServerError::UnsupportedCurve)?,
        oid if oid == OID_SIG_ED25519 => &signature::ED25519,
        _ => return Err(ServerError::UnsupportedKeyAlgorithm),
    };

    // Load the verifier with the selected algo
    let verifier = signature::UnparsedPublicKey::new(verification_alg, spki.raw);
    verifier
        .verify(digest.as_slice(), &signature)
        .map_err(|_| ServerError::SignatureVerificationFailed)
}

fn get_ec_curve_sha(spki_alg: &AlgorithmIdentifier, bits: u16) -> Option<&'static dyn VerificationAlgorithm> {
    let curve_oid = spki_alg
        .parameters
        .as_ref()
        .and_then(|p| p.clone().oid().ok())?;

    if curve_oid == OID_EC_P256 && bits == 256 {
        Some(&ECDSA_P256_SHA256_ASN1)
    } else if curve_oid == OID_NIST_EC_P384 && bits == 384 {
        Some(&ECDSA_P384_SHA384_ASN1)
    } else {
        None
    }
}