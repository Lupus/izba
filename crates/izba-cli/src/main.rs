//! `izba` — daemonless microVM sandboxes. Arg parsing + dispatch only;
//! all behavior lives in `commands/`.

mod artifacts;
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
        Cmd::Ls => commands::ls::run(paths),
        Cmd::Stop { name } => commands::stop::run(paths, &name),
        Cmd::Rm { name, force } => commands::rm::run(paths, &name, force),
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
}
