//! Fleet server agent. Modes: gate | exec | bridge | install | revert.
//! Every mode runs on a single-threaded tokio runtime.
#![forbid(unsafe_code)]

use fleet_agent::cli::{self, InstallArgs, Mode};
use fleet_agent::exec::{self, ExecConfig};
use fleet_agent::gate::{self, GateConfig};
use fleet_agent::install::{self, GATE_USER, InstallInput};
use fleet_agent::paths::Paths;
use fleet_agent::pending::{ChangeId, PendingDir};
use fleet_agent::revert::{self, RevertOutcome};
use fleet_agent::{bridge, fsutil, now_ms};
use fleet_proto::ServerId;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cli) = cli::parse_cli(&args) else {
        eprintln!("{}", cli::USAGE);
        return ExitCode::from(2);
    };
    let dev = cli.root.is_some();
    let paths = cli.root.map_or_else(Paths::system, Paths::under);
    let result = match cli.mode {
        Mode::Bridge(m) => run_bridge(&paths, m),
        Mode::Gate => {
            run_async(gate::run(GateConfig::new(paths), terminate())).map_err(|e| e.to_string())
        }
        Mode::Exec => run_exec(paths, dev),
        Mode::Install(args) => run_install(&paths, &args),
        Mode::Revert(id) => run_revert(&paths, id),
        Mode::Uninstall(opts) => run_uninstall(&paths, opts, dev),
        Mode::UserKeys(op, home) => {
            fleet_agent::userkeys::helper_main(op, &home).map_err(|e| format!("user-keys: {e}"))
        }
        Mode::Version => {
            let target = fleet_proto::AgentTarget::current().map_or("unknown", |t| t.as_str());
            println!("{} {target}", fleet_agent::AGENT_VERSION_STR);
            Ok(())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fleet-agent: {e}");
            ExitCode::from(1)
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime init failed".to_owned())
}

fn run_async<T>(fut: impl Future<Output = T>) -> T {
    match runtime() {
        Ok(rt) => rt.block_on(fut),
        Err(e) => {
            eprintln!("fleet-agent: {e}");
            std::process::exit(1)
        }
    }
}

/// Completes on SIGTERM or SIGINT.
async fn terminate() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        return std::future::pending().await;
    };
    tokio::select! {
        _ = term.recv() => {},
        _ = int.recv() => {},
    }
}

fn run_exec(paths: Paths, dev: bool) -> Result<(), String> {
    // With --root (development) the gate runs as the same user.
    let gate_uid = if dev {
        fsutil::current_uid().map_err(|e| e.to_string())?
    } else {
        fsutil::lookup_uid(&paths.passwd, GATE_USER)
            .ok_or_else(|| format!("user {GATE_USER} not found"))?
    };
    run_async(exec::run(ExecConfig::new(paths, gate_uid), terminate())).map_err(|e| e.to_string())
}

fn run_install(paths: &Paths, a: &InstallArgs) -> Result<(), String> {
    let genesis = std::fs::read(&a.genesis).map_err(|e| format!("genesis: {e}"))?;
    let input = InstallInput {
        genesis: install::parse_genesis(&genesis).map_err(|e| e.to_string())?,
        policy_toml: std::fs::read_to_string(&a.policy).map_err(|e| format!("policy: {e}"))?,
        server_id: ServerId::new(a.server_id.clone()).map_err(|_| "invalid --server-id")?,
        admin_user: a.admin_user.clone(),
    };
    let out = install::install(paths, &input).map_err(|e| e.to_string())?;
    println!("noise_static={}", hex::encode(out.noise_static.0));
    println!("signing_key={}", hex::encode(out.signing_key.0));
    Ok(())
}

fn run_uninstall(
    paths: &Paths,
    opts: fleet_agent::uninstall::UninstallOpts,
    dev: bool,
) -> Result<(), String> {
    use fleet_agent::userkeys::{AsUser, Direct, UserKeys};
    let runner = fleet_ops::SystemRunner;
    // With --root (development) users' homes are handled in-process.
    let as_user = AsUser(&runner);
    let users: &dyn UserKeys = if dev { &Direct } else { &as_user };
    let log = fleet_agent::uninstall::run_uninstall(paths, opts, &runner, users)
        .map_err(|e| e.to_string())?;
    for l in log {
        println!("{l}");
    }
    Ok(())
}

fn run_revert(paths: &Paths, id: ChangeId) -> Result<(), String> {
    let dir = PendingDir::from_paths(paths);
    // Kinds without a restore module fail loudly rather than claim success.
    let reverter = revert::RegistryRevert::for_paths(paths);
    match revert::run_revert(&dir, id, &reverter, now_ms()).map_err(|e| e.to_string())? {
        RevertOutcome::Reverted | RevertOutcome::Kept { .. } |RevertOutcome::NotPending => Ok(()),
        RevertOutcome::Failed => Err("restore failed".into()),
    }
}

fn run_bridge(paths: &Paths, mode: bridge::BridgeMode) -> Result<(), String> {
    let rt = runtime()?;
    // Set by sshd; an untrusted hint (design §4.7).
    let hint = std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|c| bridge::ssh_client_ip(&c));
    let result = rt.block_on(bridge::run(
        &paths.agent_sock,
        mode,
        hint,
        tokio::io::stdin(),
        tokio::io::stdout(),
    ));
    // Stdin reads park a blocking-pool thread; don't wait for it on exit.
    rt.shutdown_background();
    result.map_err(|_| "bridge connection failed".to_owned())
}
