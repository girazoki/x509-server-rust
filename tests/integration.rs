use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[tokio::test]
async fn test_server_with_scripts_in_process_succesful() {
    let cert_dir = "./example_certs";
    let succesful_scripts_dir = "./example_bash_scripts";
    let unsuccesful_scripts_dir = "./example_unsuccesful_bash_scripts";

    let socket_path = "/tmp/test_x509_server.sock";

    // Remove old socket
    let _ = std::fs::remove_file(socket_path);

    // Run server in background task
    let server_task = tokio::spawn(async move {
        x509_server_rust::server::run_server_with_cert_dir(
            Path::new(cert_dir),
            Path::new(socket_path),
        )
        .await
        .unwrap();
    });

    // Give server time to start
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Connect to server and send scripts
    for entry in std::fs::read_dir(succesful_scripts_dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }

        let script = std::fs::read(&path).unwrap();
        let mut stream = tokio::net::UnixStream::connect(socket_path).await.unwrap();
        stream.write_all(&script).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        println!("{} => {}", path.display(), response);

        assert!(
            response.contains("STATUS: OK"),
            "Unexpected server response"
        );
    }

    // Connect to server and send scripts
    for entry in std::fs::read_dir(unsuccesful_scripts_dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }

        let script = std::fs::read(&path).unwrap();
        let mut stream = tokio::net::UnixStream::connect(socket_path).await.unwrap();
        stream.write_all(&script).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        println!("{} => {}", path.display(), response);

        assert!(
            response.contains("STATUS: INVALID"),
            "Unexpected server response"
        );
    }

    // Stop server
    server_task.abort();
}
