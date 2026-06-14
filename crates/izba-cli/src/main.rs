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
    version,
    about = "Run coding agents in microVM sandboxes"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
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
        /// Keep printing new records as they arrive
        #[arg(short, long)]
        follow: bool,
    },
    /// Manage published ports (host -> guest TCP)
    #[command(subcommand)]
    Port(PortCmd),
    /// Manage the izba daemon (auto-started by other commands)
    #[command(subcommand)]
    Daemon(DaemonCmd),
}

fn dispatch(cli: Cli, paths: &Paths) -> anyhow::Result<i32> {
    match cli.cmd {
        Cmd::Create { opts, dir } => commands::create::run(paths, &opts, &dir),
        Cmd::Run {
            opts,
            name_or_dir,
            cmd,
        } => commands::run::run(paths, &opts, &name_or_dir, cmd),
        Cmd::Exec {
            name,
            interactive,
            tty,
            cmd,
        } => commands::exec::run(paths, &name, interactive, tty, cmd),
        Cmd::Cp { src, dst } => commands::cp::run(paths, &src, &dst),
        Cmd::Ls => commands::ls::run(paths),
        Cmd::Stop { name } => commands::stop::run(paths, &name),
        Cmd::Rm { name, force } => commands::rm::run(paths, &name, force),
        Cmd::Netlog { name, follow } => commands::netlog::run(paths, &name, follow),
        Cmd::Port(pc) => match pc {
            PortCmd::Publish { name, rule } => commands::port::publish(paths, &name, &rule),
            PortCmd::Unpublish { name, key } => commands::port::unpublish(paths, &name, &key),
            PortCmd::Ls { name } => commands::port::ls(paths, &name),
        },
        Cmd::Daemon(dc) => match dc {
            DaemonCmd::Run => commands::daemon::run_foreground(paths),
            DaemonCmd::Status => commands::daemon::status(paths),
            DaemonCmd::Stop => commands::daemon::stop(paths),
        },
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
            name_or_dir, cmd, ..
        } = cli.cmd
        else {
            panic!("expected run");
        };
        assert_eq!(name_or_dir, ".");
        assert_eq!(cmd, vec!["claude".to_string(), "--yolo".to_string()]);
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
    fn parse_netlog_flags() {
        let cli = Cli::try_parse_from(["izba", "netlog", "web", "--follow"]).unwrap();
        let Cmd::Netlog { name, follow } = cli.cmd else {
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
        let Cmd::Port(PortCmd::Publish { name, rule }) = cli.cmd else {
            panic!("expected port publish");
        };
        assert_eq!(name, "web");
        assert_eq!(rule, "8080:80");
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
}
