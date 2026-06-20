//! `izba` — daemon-first microVM sandboxes. Arg parsing + dispatch only;
//! all behavior lives in `commands/`.

mod commands;
mod name;
mod terminal;

use clap::{Args, Parser, Subcommand};
use izba_core::paths::Paths;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "izba",
    version = short_version(),
    about = "Run coding agents in microVM sandboxes"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// `izba --version` one-liner: `0.1.0 (de57bb5)`. clap needs a `&'static str`,
/// so the allocated short string is computed once and leaked behind a OnceLock.
fn short_version() -> &'static str {
    use std::sync::OnceLock;
    static V: OnceLock<String> = OnceLock::new();
    V.get_or_init(|| izba_core::build_info::BuildInfo::current().short())
        .as_str()
}

/// Options shared by `create` and `run`.
#[derive(Debug, Args)]
struct SandboxOpts {
    /// Container image to boot
    #[arg(long, default_value = "ubuntu:24.04")]
    image: String,
    /// Number of virtual CPUs
    #[arg(long, default_value_t = 2)]
    cpus: u32,
    /// Memory in MiB
    #[arg(long, default_value_t = 4096)]
    mem: u32,
    /// Size of the writable scratch disk in GiB
    #[arg(long, default_value_t = 8)]
    rw_size_gb: u64,
    /// Sandbox name (default: derived from the workspace directory name)
    #[arg(long)]
    name: Option<String>,
    /// Publish a host port to the guest: [BIND:]HOST:GUEST (repeatable)
    #[arg(short = 'p', long = "publish", value_name = "[BIND:]HOST:GUEST")]
    publish: Vec<String>,
    /// Attach a volume: [NAME:]GUEST_PATH:SIZE (named => persistent under
    /// <data>/volumes and survives rm; anonymous => ephemeral). Repeatable.
    #[arg(long = "volume", value_name = "[NAME:]GUEST_PATH:SIZE")]
    volumes: Vec<String>,
    /// Egress policy YAML: a domain allow-list this sandbox may reach. Without
    /// it the sandbox is unrestricted (no firewall).
    #[arg(long, value_name = "FILE")]
    policy: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum DaemonCmd {
    /// Run the daemon in the foreground (debugging, service managers)
    Run,
    /// Show daemon health and supervised sandboxes (never starts a daemon)
    Status,
    /// Stop the daemon; sandboxes keep running, port relays pause
    Stop,
}

#[derive(Debug, Subcommand)]
enum PortCmd {
    /// Publish a port against a running sandbox
    Publish {
        /// Sandbox name
        name: String,
        /// [BIND:]HOST:GUEST
        rule: String,
        /// Also persist this forward to the sandbox config (survives restart)
        #[arg(long)]
        persist: bool,
    },
    /// Remove a published port by its [BIND:]HOST key
    Unpublish {
        /// Sandbox name
        name: String,
        /// [BIND:]HOST (GUEST is not needed)
        key: String,
    },
    /// List active published ports
    Ls {
        /// Sandbox name
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Create a sandbox for a workspace directory
    Create {
        #[command(flatten)]
        opts: SandboxOpts,
        /// Workspace directory to share with the sandbox
        #[arg(default_value = ".")]
        dir: PathBuf,
    },
    /// Create (if needed), start (if needed) and exec into a sandbox
    Run {
        #[command(flatten)]
        opts: SandboxOpts,
        /// Existing sandbox name, or a workspace directory
        #[arg(default_value = ".")]
        name_or_dir: String,
        /// Start the VMM WITHOUT host-side confinement (NOT recommended; only
        /// if confinement fails on your host)
        #[arg(long)]
        allow_unconfined: bool,
        /// Command to run (default: /bin/sh -l)
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Run a command in a running sandbox
    Exec {
        /// Sandbox name
        name: String,
        /// Attach stdin
        #[arg(short = 'i')]
        interactive: bool,
        /// Allocate a pty
        #[arg(short = 't')]
        tty: bool,
        /// Command to run
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Copy files between host and a running sandbox
    Cp {
        /// Source: HOST_PATH or NAME:GUEST_PATH
        src: String,
        /// Destination: HOST_PATH or NAME:GUEST_PATH
        dst: String,
    },
    /// List sandboxes
    Ls,
    /// Show detailed status for one sandbox (incl. host-side VMM confinement)
    Status {
        /// Sandbox name
        name: String,
    },
    /// Stop a running sandbox
    Stop {
        /// Sandbox name
        name: String,
    },
    /// Remove a sandbox
    Rm {
        /// Sandbox name
        name: String,
        /// Stop and remove even if running
        #[arg(long)]
        force: bool,
    },
    /// Show the egress audit log (every allowed/denied connection)
    Netlog {
        /// Sandbox name
        name: String,
        /// Aggregate into a per-endpoint summary instead of a line-by-line tail
        #[arg(long)]
        summary: bool,
        /// Keep printing new records as they arrive (ignored with --summary)
        #[arg(short, long)]
        follow: bool,
    },
    /// Manage published ports (host -> guest TCP)
    #[command(subcommand)]
    Port(PortCmd),
    /// Manage persistent volumes
    #[command(subcommand)]
    Volume(commands::volume::VolumeCmd),
    /// Manage a sandbox's egress policy
    #[command(subcommand)]
    Policy(commands::policy::PolicyCmd),
    /// Manage the izba daemon (auto-started by other commands)
    #[command(subcommand)]
    Daemon(DaemonCmd),
    /// Show detailed build info for the CLI and (if running) the daemon
    Version {
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Run this sandbox's VMM under a dedicated, ACL-scoped, network-dead local
    /// account (Windows). Pops a UAC prompt.
    Lockdown {
        /// Sandbox name
        name: String,
    },
    /// Release a sandbox's lock-down account + firewall rule (Windows). Pops a
    /// UAC prompt.
    Unlock {
        /// Sandbox name
        name: String,
    },
    /// Remove orphaned izba lock-down accounts/firewall rules with no live
    /// sandbox (Windows). Pops a UAC prompt.
    WindowsCleanup,
    /// Internal: print state-consistency report (used by the dogfooding harness).
    #[command(hide = true, name = "__reconcile")]
    Reconcile {
        #[arg(long)]
        json: bool,
    },
    /// (internal) launch a VMM confined; used by the lock-down launcher
    #[command(name = "__spawn-confined-vmm", hide = true)]
    SpawnConfinedVmm {
        /// Path where the spawned VMM's PidIdentity will be written
        #[arg(long)]
        pidfile: PathBuf,
        /// Path to the VMM log file (stdout/stderr)
        #[arg(long)]
        log: PathBuf,
        /// Path to a JSON file holding the VMM argv (a `["openvmm", …]` array).
        /// Passed by path, not inline, because CreateProcessWithLogonW caps the
        /// command line at 1024 chars and a real OpenVMM invocation is longer.
        #[arg(long)]
        spec: PathBuf,
    },
}

fn dispatch(cli: Cli, paths: &Paths) -> anyhow::Result<i32> {
    match cli.cmd {
        Cmd::Create { opts, dir } => commands::create::run(paths, &opts, &dir),
        Cmd::Run {
            opts,
            name_or_dir,
            allow_unconfined,
            cmd,
        } => commands::run::run(paths, &opts, &name_or_dir, allow_unconfined, cmd),
        Cmd::Exec {
            name,
            interactive,
            tty,
            cmd,
        } => commands::exec::run(paths, &name, interactive, tty, cmd),
        Cmd::Cp { src, dst } => commands::cp::run(paths, &src, &dst),
        Cmd::Ls => commands::ls::run(paths),
        Cmd::Status { name } => commands::status::run(paths, &name),
        Cmd::Stop { name } => commands::stop::run(paths, &name),
        Cmd::Rm { name, force } => commands::rm::run(paths, &name, force),
        Cmd::Netlog {
            name,
            summary,
            follow,
        } => commands::netlog::run(paths, &name, summary, follow),
        Cmd::Port(pc) => match pc {
            PortCmd::Publish {
                name,
                rule,
                persist,
            } => commands::port::publish(paths, &name, &rule, persist),
            PortCmd::Unpublish { name, key } => commands::port::unpublish(paths, &name, &key),
            PortCmd::Ls { name } => commands::port::ls(paths, &name),
        },
        Cmd::Volume(vc) => commands::volume::run(paths, &vc),
        Cmd::Policy(pc) => commands::policy::run(paths, &pc),
        Cmd::Version { json } => commands::version::run(paths, json),
        Cmd::Daemon(dc) => match dc {
            DaemonCmd::Run => commands::daemon::run_foreground(paths),
            DaemonCmd::Status => commands::daemon::status(paths),
            DaemonCmd::Stop => commands::daemon::stop(paths),
        },
        Cmd::Reconcile { json } => commands::reconcile::run(paths, json),
        Cmd::Lockdown { name } => commands::lockdown::run(paths, &name),
        Cmd::Unlock { name } => commands::lockdown::unlock(paths, &name),
        Cmd::WindowsCleanup => commands::lockdown::cleanup(paths),
        Cmd::SpawnConfinedVmm { pidfile, log, spec } => {
            use anyhow::Context;
            use izba_core::procmgr::{spawn_confined, ConfinementPolicy};
            use izba_core::vmm::CommandSpec;
            let argv: Vec<String> = izba_core::state::load_json(&spec)
                .with_context(|| format!("reading VMM spec {}", spec.display()))?
                .with_context(|| format!("VMM spec {} not found", spec.display()))?;
            let cmd = CommandSpec { argv };
            let (pid_identity, _mode) =
                spawn_confined(&cmd, &log, &ConfinementPolicy::vmm_default())?;
            izba_core::state::save_json(&pidfile, &pid_identity)?;
            Ok(0)
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let paths = Paths::from_env_or_default(std::env::var_os("IZBA_DATA_DIR").map(PathBuf::from));
    let code = match dispatch(cli, &paths) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("izba: error: {e:#}");
            1
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_create_defaults() {
        let cli = Cli::try_parse_from(["izba", "create"]).unwrap();
        let Cmd::Create { opts, dir } = cli.cmd else {
            panic!("expected create");
        };
        assert_eq!(opts.image, "ubuntu:24.04");
        assert_eq!(opts.cpus, 2);
        assert_eq!(opts.mem, 4096);
        assert_eq!(opts.rw_size_gb, 8);
        assert_eq!(opts.name, None);
        assert_eq!(dir, PathBuf::from("."));
    }

    #[test]
    fn parse_run_trailing_cmd() {
        let cli = Cli::try_parse_from(["izba", "run", ".", "--", "claude", "--yolo"]).unwrap();
        let Cmd::Run {
            name_or_dir,
            allow_unconfined,
            cmd,
            ..
        } = cli.cmd
        else {
            panic!("expected run");
        };
        assert_eq!(name_or_dir, ".");
        assert!(!allow_unconfined, "default must be confined");
        assert_eq!(cmd, vec!["claude".to_string(), "--yolo".to_string()]);
    }

    #[test]
    fn parse_run_allow_unconfined_flag() {
        let cli = Cli::try_parse_from(["izba", "run", "--allow-unconfined", "."]).unwrap();
        let Cmd::Run {
            allow_unconfined, ..
        } = cli.cmd
        else {
            panic!("expected run");
        };
        assert!(allow_unconfined);
        // Absent by default.
        let bare = Cli::try_parse_from(["izba", "run", "."]).unwrap();
        let Cmd::Run {
            allow_unconfined, ..
        } = bare.cmd
        else {
            panic!("expected run");
        };
        assert!(!allow_unconfined);
    }

    #[test]
    fn parse_exec_flags() {
        let cli = Cli::try_parse_from(["izba", "exec", "web", "-it", "--", "bash"]).unwrap();
        let Cmd::Exec {
            name,
            interactive,
            tty,
            cmd,
        } = cli.cmd
        else {
            panic!("expected exec");
        };
        assert_eq!(name, "web");
        assert!(interactive);
        assert!(tty);
        assert_eq!(cmd, vec!["bash".to_string()]);

        // cmd is mandatory
        assert!(Cli::try_parse_from(["izba", "exec", "web"]).is_err());
    }

    #[test]
    fn parse_create_policy_flag() {
        let cli =
            Cli::try_parse_from(["izba", "create", "--policy", "/etc/izba/web.yaml"]).unwrap();
        let Cmd::Create { opts, .. } = cli.cmd else {
            panic!("expected create");
        };
        assert_eq!(opts.policy, Some(PathBuf::from("/etc/izba/web.yaml")));
        // Absent by default (unrestricted sandbox).
        let bare = Cli::try_parse_from(["izba", "create"]).unwrap();
        let Cmd::Create { opts, .. } = bare.cmd else {
            panic!("expected create");
        };
        assert_eq!(opts.policy, None);
    }

    #[test]
    fn parse_netlog_flags() {
        let cli = Cli::try_parse_from(["izba", "netlog", "web", "--follow"]).unwrap();
        let Cmd::Netlog { name, follow, .. } = cli.cmd else {
            panic!("expected netlog");
        };
        assert_eq!(name, "web");
        assert!(follow);
        // name is required; -f is the short form.
        assert!(Cli::try_parse_from(["izba", "netlog"]).is_err());
        let short = Cli::try_parse_from(["izba", "netlog", "web", "-f"]).unwrap();
        assert!(matches!(short.cmd, Cmd::Netlog { follow: true, .. }));
    }

    #[test]
    fn parse_netlog_summary_flag() {
        let cli = Cli::try_parse_from(["izba", "netlog", "web", "--summary"]).unwrap();
        let Cmd::Netlog {
            summary, follow, ..
        } = cli.cmd
        else {
            panic!("expected netlog")
        };
        assert!(summary);
        assert!(!follow);
    }

    #[test]
    fn parse_spawn_confined_vmm() {
        let cli = Cli::try_parse_from([
            "izba",
            "__spawn-confined-vmm",
            "--pidfile",
            "/tmp/pid.json",
            "--log",
            "/tmp/vmm.log",
            "--spec",
            "/tmp/vmm-spec.json",
        ])
        .unwrap();
        let Cmd::SpawnConfinedVmm { pidfile, log, spec } = cli.cmd else {
            panic!("expected SpawnConfinedVmm");
        };
        assert_eq!(pidfile, PathBuf::from("/tmp/pid.json"));
        assert_eq!(log, PathBuf::from("/tmp/vmm.log"));
        assert_eq!(spec, PathBuf::from("/tmp/vmm-spec.json"));

        // --spec is required (the VMM argv is no longer inline).
        assert!(Cli::try_parse_from([
            "izba",
            "__spawn-confined-vmm",
            "--pidfile",
            "/tmp/pid.json",
            "--log",
            "/tmp/vmm.log",
        ])
        .is_err());
    }

    #[test]
    fn parse_cp_operands() {
        let cli = Cli::try_parse_from(["izba", "cp", "a.txt", "web:/etc/a"]).unwrap();
        let Cmd::Cp { src, dst } = cli.cmd else {
            panic!("expected cp");
        };
        assert_eq!(src, "a.txt");
        assert_eq!(dst, "web:/etc/a");
        // Both operands are required.
        assert!(Cli::try_parse_from(["izba", "cp", "only-one"]).is_err());
    }

    #[test]
    fn parse_create_publish_flags() {
        let cli = Cli::try_parse_from([
            "izba",
            "create",
            "-p",
            "8080:80",
            "-p",
            "0.0.0.0:9090:90",
            ".",
        ])
        .unwrap();
        let Cmd::Create { opts, .. } = cli.cmd else {
            panic!("expected create");
        };
        assert_eq!(
            opts.publish,
            vec!["8080:80".to_string(), "0.0.0.0:9090:90".to_string()]
        );
    }

    #[test]
    fn parse_port_publish() {
        let cli = Cli::try_parse_from(["izba", "port", "publish", "web", "8080:80"]).unwrap();
        let Cmd::Port(PortCmd::Publish {
            name,
            rule,
            persist,
        }) = cli.cmd
        else {
            panic!("expected port publish");
        };
        assert_eq!(name, "web");
        assert_eq!(rule, "8080:80");
        assert!(!persist, "persist must default to false");

        // --persist flag wires through.
        let with_persist =
            Cli::try_parse_from(["izba", "port", "publish", "--persist", "web", "8080:80"])
                .unwrap();
        let Cmd::Port(PortCmd::Publish { persist, .. }) = with_persist.cmd else {
            panic!("expected port publish");
        };
        assert!(persist);
    }

    #[test]
    fn parse_port_unpublish() {
        let cli =
            Cli::try_parse_from(["izba", "port", "unpublish", "web", "127.0.0.1:8080"]).unwrap();
        let Cmd::Port(PortCmd::Unpublish { name, key }) = cli.cmd else {
            panic!("expected port unpublish");
        };
        assert_eq!(name, "web");
        assert_eq!(key, "127.0.0.1:8080");
    }

    #[test]
    fn parse_port_ls() {
        let cli = Cli::try_parse_from(["izba", "port", "ls", "web"]).unwrap();
        let Cmd::Port(PortCmd::Ls { name }) = cli.cmd else {
            panic!("expected port ls");
        };
        assert_eq!(name, "web");
    }

    #[test]
    fn parse_daemon_subcommands() {
        for (args, expect) in [
            (vec!["izba", "daemon", "run"], DaemonCmd::Run),
            (vec!["izba", "daemon", "status"], DaemonCmd::Status),
            (vec!["izba", "daemon", "stop"], DaemonCmd::Stop),
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            let Cmd::Daemon(dc) = cli.cmd else {
                panic!("expected daemon subcommand");
            };
            assert_eq!(format!("{dc:?}"), format!("{expect:?}"));
        }
        // Bare `izba daemon` requires a subcommand.
        assert!(Cli::try_parse_from(["izba", "daemon"]).is_err());
    }

    #[test]
    fn parse_lockdown() {
        let cli = Cli::try_parse_from(["izba", "lockdown", "web"]).unwrap();
        let Cmd::Lockdown { name } = cli.cmd else {
            panic!("expected lockdown");
        };
        assert_eq!(name, "web");
        // name is required
        assert!(Cli::try_parse_from(["izba", "lockdown"]).is_err());
    }

    #[test]
    fn parse_unlock() {
        let cli = Cli::try_parse_from(["izba", "unlock", "web"]).unwrap();
        let Cmd::Unlock { name } = cli.cmd else {
            panic!("expected unlock");
        };
        assert_eq!(name, "web");
        // name is required
        assert!(Cli::try_parse_from(["izba", "unlock"]).is_err());
    }

    #[test]
    fn parse_windows_cleanup() {
        let cli = Cli::try_parse_from(["izba", "windows-cleanup"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::WindowsCleanup));
    }
}
