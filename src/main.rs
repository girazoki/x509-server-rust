mod crypto;
mod errors;
mod server;

use crate::errors::ServerError;
use clap::Parser;

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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    server::run_server_with_cert_dir(&args.cert_path, &args.socket_path).await
}
