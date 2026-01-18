mod crypto;
mod server;
mod errors;

use crate::errors::ServerError;
#[tokio::main]
async fn main() -> Result<(), ServerError> {
    let cert_pem = std::fs::read("cert.pem")?;
    server::run("/tmp/signed-script.sock", cert_pem).await
}