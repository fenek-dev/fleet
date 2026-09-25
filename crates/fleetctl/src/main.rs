//! `fleetctl mcp` — stdio MCP server forwarding to the Fleet app.
#![forbid(unsafe_code)]

use fleetctl::client::{AppClient, default_socket_path};
use std::process::ExitCode;
use std::sync::Arc;

const USAGE: &str = "usage: fleetctl mcp | fleetctl --version";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("mcp") if args.len() == 1 => {}
        Some("--version") | Some("-V") => {
            println!("fleetctl {}", fleetctl::VERSION);
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    }
    let Some(path) = default_socket_path() else {
        eprintln!("fleetctl: HOME is not set");
        return ExitCode::FAILURE;
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fleetctl: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    // stdout carries MCP; diagnostics go to stderr only.
    match rt.block_on(fleetctl::server::run_stdio(Arc::new(AppClient::new(path)))) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fleetctl: {e}");
            ExitCode::FAILURE
        }
    }
}
