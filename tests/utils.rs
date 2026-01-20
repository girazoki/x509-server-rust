use base64::Engine as _;
use rcgen::SigningKey;
use rcgen::{
    CertificateParams, ExtendedKeyUsagePurpose, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PKCS_ED25519, PKCS_RSA_SHA256,
};
/// Supported algorithms
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TestAlgo {
    Rsa2048,
    EcdsaP256,
    EcdsaP384,
    Ed25519,
}

/// Generates a self-signed certificate, DER bytes, and a signature for a message
pub fn generate_cert_and_signature(algo: TestAlgo, message: &[u8]) -> (Vec<u8>, String) {
    // Generate KeyPair for the requested algorithm
    let key_pair = match algo {
        TestAlgo::Rsa2048 => KeyPair::generate_for(&PKCS_RSA_SHA256).unwrap(),
        TestAlgo::EcdsaP256 => KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
        TestAlgo::EcdsaP384 => KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap(),
        TestAlgo::Ed25519 => KeyPair::generate_for(&PKCS_ED25519).unwrap(),
    };

    // Create certificate params with the generated key
    let mut cert_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();

    cert_params.insert_extended_key_usage(ExtendedKeyUsagePurpose::CodeSigning);
    let cert = cert_params.self_signed(&key_pair).unwrap();

    // DER bytes of the certificate
    let der_bytes: Vec<u8> = cert.der().to_vec();

    // Sign the message using the KeyPair directly
    let sig_bytes = key_pair.sign(message).unwrap();

    // Base64-encode the signature
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

    (der_bytes, sig_b64)
}

/// Generates a leaf certificate signed by the given CA
#[allow(dead_code)]
pub fn generate_leaf_cert_signed_by_ca() -> Vec<u8> {
    // We first generate the CA key. this for now will be RSA
    let ca_key_pair = KeyPair::generate_for(&PKCS_RSA_SHA256).unwrap();
    // Create certificate params with the generated ca key
    let cert_ca = CertificateParams::new(vec!["CA".to_string()])
        .unwrap()
        .self_signed(&ca_key_pair)
        .unwrap();

    let ca = Issuer::from_ca_cert_pem(&cert_ca.pem(), &ca_key_pair).unwrap();

    // now we generate a certificate signed by the CA
    let leaf_key_pair = KeyPair::generate_for(&PKCS_RSA_SHA256).unwrap();

    let leaf_cert = CertificateParams::new(vec!["Leaf Cert".to_string()])
        .unwrap()
        .signed_by(&leaf_key_pair, &ca)
        .unwrap();

    // PEM bytes of the certificate
    let pem = leaf_cert.pem();

    pem.as_bytes().to_vec()
}
