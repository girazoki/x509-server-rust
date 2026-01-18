use tokio::net::UnixListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::crypto::verify_signature;
use crate::errors::ServerError;

pub async fn run(socket_path: &str, cert_pem: Vec<u8>) -> Result<(), ServerError> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;

    loop {
        // Listen in a loop to incoming streams
        let (mut stream, _) = listener.accept().await?;
        // TODO: change this to a folder where we read certificates from there
        let cert = cert_pem.clone();

        tokio::spawn(async move {
            let mut buf = Vec::new();
            if stream.read_to_end(&mut buf).await.is_err() {
                return;
            }

            // Read the buf
            let text = String::from_utf8_lossy(&buf);
            let mut lines = text.lines();

            // Retrieve the signature in the first line (if it exists)
            // Here: more descriptive errors, but the server cannot wait, we probably want to log
            let sig_line = lines.next().unwrap_or("");
            // I am sure this is wrong
            let signature = sig_line
                .strip_prefix("# SIGNATURE:")
                .unwrap_or("")
                .trim();

            // Retrieve the rest of the bash script
            let body = lines.collect::<Vec<_>>().join("\n");

            // Let's check if the signature verification was valid
            let result = verify_signature(&cert, signature, body.as_bytes());

            let response = match result {
                Ok(_) => {
                    // The expect should be removed here. We should use proper errors
                    match std::process::Command::new("bash")
                        .arg("-c")
                        .arg(body)
                        .output()
                    {
                        Ok(out) => format!(
                            "STATUS: OK\n{}",
                            String::from_utf8_lossy(&out.stdout)
                        ),
                        Err(_) => format!(
                            "STATUS: ERROR\n{}\n",
                            ServerError::ScriptExecutionFailed
                        ),
                    }
                }
                Err(e) => format!("STATUS: INVALID\n{}\n", e),
            };

            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}
