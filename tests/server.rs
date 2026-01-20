mod utils;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use utils::{TestAlgo, generate_cert_and_signature};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_server_rust::errors::ServerError;
use x509_server_rust::server::{OwnedX509Certificate, handle_connection};

#[tokio::test]
async fn test_invalid_signature() {
    let (mut client, mut server) = duplex(1024);
    let certs: Arc<Vec<OwnedX509Certificate>> = Arc::new(vec![]);

    let server_task = tokio::spawn(async move {
        handle_connection(&mut server, certs).await.unwrap();
    });

    let request = "# SIGNATURE: bogus\necho hello";
    client.write_all(request.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);

    assert!(response.starts_with("STATUS: INVALID"));
    server_task.await.unwrap();
}

#[tokio::test]
async fn test_invalid_utf8_input() {
    let (mut client, mut server) = duplex(1024);
    let certs: Arc<Vec<OwnedX509Certificate>> = Arc::new(vec![]);

    let server_task = tokio::spawn(async move {
        handle_connection(&mut server, certs).await.unwrap();
    });

    // Send invalid UTF-8 bytes
    let request = b"# SIGNATURE: sig\n\xff\xfe\xfd";
    client.write_all(request).await.unwrap();

    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);

    // Server should mark as invalid rather than panicking
    assert!(response.starts_with("STATUS: INVALID"));
    server_task.await.unwrap();
}

#[tokio::test]
async fn test_broken_stream() {
    let (client, mut server) = duplex(1024);
    let certs: Arc<Vec<OwnedX509Certificate>> = Arc::new(vec![]);

    let server_task = tokio::spawn(async move {
        let result = handle_connection(&mut server, certs).await;
        assert!(matches!(result, Err(ServerError::IoError(_))));
    });

    // Drop client immediately to simulate broken pipe
    drop(client);

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_script_execution_failure() {
    let (mut client, mut server) = duplex(1024);
    let certs: Arc<Vec<OwnedX509Certificate>> = Arc::new(vec![]);

    let server_task = tokio::spawn(async move {
        handle_connection(&mut server, certs).await.unwrap();
    });

    // Valid-ish signature line but script is invalid command
    let request = "# SIGNATURE: \ncommand_that_does_not_exist";
    client.write_all(request.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);

    assert!(response.starts_with("STATUS: INVALID") || response.starts_with("STATUS: ERROR"));
    server_task.await.unwrap();
}

#[tokio::test]
async fn test_missing_signature_line() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let certs = Arc::new(Vec::new());

    let script = b"echo hello world\n";
    client.write_all(script).await.unwrap();
    client.shutdown().await.unwrap(); // EOF

    let server_task = tokio::spawn(async move {
        handle_connection(&mut server, certs).await.unwrap();
    });

    // Read response from client
    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);

    assert!(response.contains("STATUS: INVALID"));
    assert!(response.contains("Missing signature line"));

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_server_with_valid_signature() {
    // script containing simple hello world
    let script = r#"echo "Hello world from valid script""#;
    let script_bytes = script.as_bytes();

    // testing algo culd be anything here
    let algo = TestAlgo::EcdsaP256;

    // Getting a static reference here, we are in tests so this is ok
    let (der_bytes, sig_b64) = generate_cert_and_signature(algo, script_bytes);
    let der_static: &'static [u8] = Box::leak(der_bytes.clone().into_boxed_slice());
    let (_, cert) = X509Certificate::from_der(der_static).unwrap();
    let certs: Arc<Vec<OwnedX509Certificate>> = Arc::new(vec![OwnedX509Certificate {
        cert,
        der: der_bytes.into(),
    }]);

    // Let's build the signature
    let input = format!("# SIGNATURE: {}\n{}", sig_b64, script);
    let (mut client, mut server) = duplex(1024);
    client.write_all(input.as_bytes()).await.unwrap();
    client.shutdown().await.unwrap();

    // Run handle_connection
    let server_task = tokio::spawn(async move {
        handle_connection(&mut server, certs).await.unwrap();
    });

    // Read server response
    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);

    // 7. Check that server executed the script
    assert!(response.contains("STATUS: OK"));
    assert!(response.contains("Hello world from valid script"));

    server_task.await.unwrap();
}
