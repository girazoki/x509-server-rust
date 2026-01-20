mod utils;
use base64::Engine;
use utils::{TestAlgo, generate_cert_and_signature};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_server_rust::crypto::verify_signature;
#[test]
fn test_verify_all_algorithms() {
    let message = b"hello world";

    for &algo in &[
        TestAlgo::Rsa2048,
        TestAlgo::EcdsaP256,
        TestAlgo::EcdsaP384,
        TestAlgo::Ed25519,
    ] {
        let (der_bytes, sig_b64) = generate_cert_and_signature(algo, message);
        let (_, cert) = X509Certificate::from_der(&der_bytes).unwrap();
        // Verify
        let result = verify_signature(&cert, &sig_b64, message);
        assert!(result.is_ok(), "Signature failed for {:?}", algo);
    }
}

#[test]
fn test_verify_invalid_signatures() {
    let message = b"hello world";

    for &algo in &[
        TestAlgo::Rsa2048,
        TestAlgo::EcdsaP256,
        TestAlgo::EcdsaP384,
        TestAlgo::Ed25519,
    ] {
        let (der_bytes, sig_b64) = generate_cert_and_signature(algo, message);
        let (_, cert) = X509Certificate::from_der(&der_bytes).unwrap();

        // Let's make sure that if we generate a wrong signature, the test fails
        let mut sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap();
        sig_bytes[0] ^= 0xFF; // flip bits
        let sig_b64_tampered = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        let result = verify_signature(&cert, &sig_b64_tampered, message);
        assert!(
            result.is_err(),
            "Tampered signature should fail for {:?}",
            algo
        );

        // Let's make sure that verifying wrong message does not work
        let wrong_message = b"goodbye world";
        let result = verify_signature(&cert, &sig_b64, wrong_message);
        assert!(
            result.is_err(),
            "Using wrong message should fail for {:?}",
            algo
        );

        // Let's make sure we have an invalid encoding
        let sig_b64_invalid = "%%%INVALID%%%";
        let result = verify_signature(&cert, sig_b64_invalid, message);
        assert!(result.is_err(), "Invalid Base64 should fail for {:?}", algo);

        // Let's make sure that if we truncate it does nto work
        if sig_bytes.len() > 1 {
            let sig_b64_truncated =
                base64::engine::general_purpose::STANDARD.encode(&sig_bytes[..sig_bytes.len() - 1]);
            let result = verify_signature(&cert, &sig_b64_truncated, message);
            assert!(
                result.is_err(),
                "Truncated signature should fail for {:?}",
                algo
            );
        }
    }
}

#[test]
fn test_different_verifying_with_different_cert_errors() {
    let message = b"hello world";
    for &algo in &[
        TestAlgo::Rsa2048,
        TestAlgo::EcdsaP256,
        TestAlgo::EcdsaP384,
        TestAlgo::Ed25519,
    ] {
        let (_der_bytes1, sig_b64) = generate_cert_and_signature(algo, message);
        let (der_bytes2, _) = generate_cert_and_signature(algo, message);
        let (_, cert_wrong) = X509Certificate::from_der(&der_bytes2).unwrap();

        let result = verify_signature(&cert_wrong, &sig_b64, message);
        assert!(
            result.is_err(),
            "Signature should fail if verified with a different certificate"
        );
    }
}
