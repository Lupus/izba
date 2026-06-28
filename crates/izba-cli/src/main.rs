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
#[derive(Debug, Clone, Args)]
struct SandboxOpts {
    /// Container image to boot
    #[arg(long, default_value_t = commands::DEFAULT_IMAGE.to_string())]
    image: String,
    /// Number of virtual CPUs
    #[arg(long, default_value_t = commands::DEFAULT_CPUS)]
    cpus: u32,
    /// Memory in MiB
    #[arg(long, default_value_t = commands::DEFAULT_MEM_MB)]
    mem: u32,
    /// Size of the writable scratch disk in GiB
    #[arg(long, default_value_t = commands::DEFAULT_RW_GB)]
    rw_size_gb: u64,
    /// Sandbox name (default: derived from the workspace directory name)
    #[arg(long)]
    name: Option<String>,
    /// Publish a host port to the guest: [BIND:]HOST:GUEST (repeatable)
    #[arg(short = 'p', long = "publish", value_name = "[BIND:]HOST:GUEST")]
    publish: Vec<String>,
    /// Attach a volume: [NAME:]GUEST_PATH:SIZE — SIZE needs a `g` or `m`
    /// suffix, e.g. `10g` or `512m`. Named => persistent under <data>/volumes
    /// (survives rm); anonymous => ephemeral. Repeatable.
    #[arg(long = "volume", value_name = "[NAME:]GUEST_PATH:SIZE")]
    volumes: Vec<String>,
    /// Egress policy YAML: turns the firewall ON (default-deny) and sets the
    /// allow-list this sandbox may reach (hosts/ports, plus optional `git:` and
    /// per-host `access:` rules; `enforce: false` makes it log-only). Without
    /// this flag the sandbox is unrestricted (firewall off); you can also turn
    /// it on later with `izba policy enforce NAME on`.
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
    ///
    /// By default the sandbox PERSISTS after the command exits (docker-parity:
    /// run = create + start + exec) — tear it down with `izba stop`/`izba rm`,
    /// or pass `--rm` to remove it automatically when the command exits.
    ///
    /// When NAME_OR_DIR is omitted it defaults to the current directory and the
    /// sandbox name is derived from that directory's basename (sanitized) — so
    /// running inside a `foo/` directory creates/starts a sandbox named `foo`.
    /// To start an existing/stopped sandbox without exec'ing, use `izba start`;
    /// to create + start in one step and leave it running, use `izba run -d`.
    Run {
        #[command(flatten)]
        opts: SandboxOpts,
        /// Existing sandbox name, or a workspace directory
        #[arg(default_value = ".")]
        name_or_dir: String,
        /// Remove the sandbox (and its ephemeral resources) once the command
        /// exits — for throwaway `izba run --rm -- <cmd>`. Only reaps a sandbox
        /// THIS run freshly created; attaching to a pre-existing sandbox leaves
        /// it untouched. Named/persistent volumes survive; the command's exit
        /// code is still propagated.
        #[arg(long = "rm")]
        rm: bool,
        /// Detached: create (if needed) + start the sandbox and return
        /// immediately, leaving it RUNNING — do NOT exec a shell/command into
        /// it. The docker-parity `run -d`. Reach the running sandbox afterward
        /// with `izba exec`, `izba ssh`, or published ports. Conflicts with
        /// `--rm` (nothing to reap) and with a trailing `-- CMD` (a detached
        /// start runs no command).
        #[arg(short = 'd', long = "detach", conflicts_with = "rm")]
        detach: bool,
        /// Start the VMM WITHOUT host-side confinement (NOT recommended; only
        /// if confinement fails on your host)
        #[arg(long)]
        allow_unconfined: bool,
        /// Build a Dockerfile (or directory) first, then run the resulting
        /// image. PATH may be a Dockerfile (context = its parent dir) or a
        /// directory (context = the directory itself). Mutually exclusive
        /// with --image.
        #[arg(long = "build", value_name = "PATH", conflicts_with = "image")]
        build: Option<PathBuf>,
        /// Extra host the build network may reach (registry/mirror; repeatable).
        /// Only meaningful with --build.
        #[arg(long = "build-allow", value_name = "HOST")]
        build_allow: Vec<String>,
        /// Command to run (default: /bin/sh -l)
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Build an OCI image from a Dockerfile in a throwaway builder VM
    Build {
        /// Path to the Dockerfile (default: <CONTEXT>/Dockerfile)
        #[arg(short = 'f', long = "file", value_name = "FILE")]
        file: Option<PathBuf>,
        /// Tag to apply to the built image
        #[arg(short = 't', long = "tag", value_name = "TAG")]
        tag: Option<String>,
        /// Extra host the build network may reach (registry/mirror; repeatable)
        #[arg(long = "build-allow", value_name = "HOST")]
        build_allow: Vec<String>,
        /// Number of virtual CPUs for the builder VM
        #[arg(long, default_value_t = 2)]
        cpus: u32,
        /// Memory in MiB for the builder VM
        #[arg(long, default_value_t = 4096)]
        mem: u32,
        /// Build context directory
        #[arg(default_value = ".")]
        context: PathBuf,
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
    /// Start a stopped sandbox's VM (symmetric with `stop`; does not exec)
    ///
    /// Boots an existing, stopped sandbox without attaching — then reach it with
    /// `izba exec`, `izba ssh`, or published ports. (`izba run NAME` also starts
    /// it but additionally execs a shell/command into it.) Already-running is a
    /// no-op success.
    Start {
        /// Sandbox name
        name: String,
        /// Start the VMM WITHOUT host-side confinement (NOT recommended; only
        /// if confinement fails on your host)
        #[arg(long)]
        allow_unconfined: bool,
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
    /// SSH into a running sandbox (uses the system ssh client).
    ///
    /// While a sandbox runs, izba writes a `Host izba-<name>` block into your
    /// `~/.ssh/config` (a single managed Include), so the whole OpenSSH
    /// ecosystem works against the `izba-<name>` alias with no setup — not just
    /// `ssh izba-<name>` but also file transfer: `scp FILE izba-<name>:PATH`
    /// (and back), `sftp izba-<name>` (a native sftp-server runs in the guest),
    /// `rsync … izba-<name>:…`, and VS Code Remote-SSH all ride the same path.
    ///
    /// `izba ssh <name>` is the config-independent fallback (it passes every
    /// knob inline) — but scp/sftp/rsync need the managed `izba-<name>` alias,
    /// which requires config management ON (the default; toggle in
    /// <data>/ssh/settings.json).
    Ssh {
        /// Sandbox name
        name: String,
        /// Command to run (and its arguments) inside the sandbox
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Internal: ssh ProxyCommand bridge (stdio <-> guest :22 over vsock).
    #[command(hide = true, name = "__ssh-proxy")]
    SshProxy {
        /// SSH host alias (izba-<name> or just <name>)
        host_alias: String,
    },
    /// Show drift between izba.yml and the managed sandbox truth
    Diff {
        /// Workspace directory containing izba.yml
        #[arg(default_value = ".")]
        dir: PathBuf,
        /// Sandbox name (default: from manifest metadata.name or the dir basename)
        #[arg(long)]
        name: Option<String>,
    },
    /// Write the managed sandbox truth back into izba.yml
    Export {
        /// Workspace directory to write izba.yml into
        #[arg(default_value = ".")]
        dir: PathBuf,
        /// Sandbox name (default: from existing izba.yml or the dir basename)
        #[arg(long)]
        name: Option<String>,
    },
    /// Apply izba.yml to the managed sandbox (requires a prior `izba diff`)
    Promote {
        /// Workspace directory containing izba.yml
        #[arg(default_value = ".")]
        dir: PathBuf,
        /// Sandbox name (default: from manifest metadata.name or the dir basename)
        #[arg(long)]
        name: Option<String>,
        /// Promote even if the manifest was never reviewed / changed since review
        #[arg(long)]
        force: bool,
        /// Stop+start the sandbox now to apply restart-class fields (cpus/mem/image)
        #[arg(long)]
        restart: bool,
        /// On an image change, reset the rw scratch overlay onto the new base
        /// (default true). `--reset-scratch=false` keeps it (expert-only, loud).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        reset_scratch: bool,
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
            rm,
            detach,
            allow_unconfined,
            build,
            build_allow,
            cmd,
        } => commands::run::run(
            paths,
            &opts,
            &name_or_dir,
            rm,
            detach,
            allow_unconfined,
            build,
            build_allow,
            cmd,
        ),
        Cmd::Build {
            file,
            tag,
            build_allow,
            cpus,
            mem,
            context,
        } => {
            let dockerfile = file.unwrap_or_else(|| context.join("Dockerfile"));
            commands::build::run(
                paths,
                &commands::build::BuildOpts {
                    dockerfile,
                    tag,
                    context,
                    build_allow,
                    cpus,
                    mem,
                },
            )
        }
        Cmd::Exec {
            name,
            interactive,
            tty,
            cmd,
        } => commands::exec::run(paths, &name, interactive, tty, cmd),
        Cmd::Cp { src, dst } => commands::cp::run(paths, &src, &dst),
        Cmd::Ls => commands::ls::run(paths),
        Cmd::Status { name } => commands::status::run(paths, &name),
        Cmd::Start {
            name,
            allow_unconfined,
        } => commands::start::run(paths, &name, allow_unconfined),
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
        Cmd::Diff { dir, name } => commands::diff::run(paths, &dir, name.as_deref()),
        Cmd::Export { dir, name } => commands::export::run(paths, &dir, name.as_deref()),
        Cmd::Promote {
            dir,
            name,
            force,
            restart,
            reset_scratch,
        } => commands::promote::run(paths, &dir, name.as_deref(), force, restart, reset_scratch),
        Cmd::Ssh { name, cmd } => commands::ssh::run(paths, &name, cmd),
        Cmd::SshProxy { host_alias } => commands::ssh_proxy::run(paths, &host_alias),
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
    fn parse_run_rm_flag() {
        let cli = Cli::try_parse_from(["izba", "run", "--rm", ".", "--", "uname", "-s"]).unwrap();
        let Cmd::Run { rm, cmd, .. } = cli.cmd else {
            panic!("expected run");
        };
        assert!(rm, "--rm must parse to true");
        assert_eq!(cmd, vec!["uname".to_string(), "-s".to_string()]);
        // Persist-after-run is the default: no --rm => false.
        let bare = Cli::try_parse_from(["izba", "run", "."]).unwrap();
        let Cmd::Run { rm, .. } = bare.cmd else {
            panic!("expected run");
        };
        assert!(!rm, "default must persist (rm = false)");
    }

    #[test]
    fn parse_run_detach_flag() {
        // Both spellings parse to detach = true.
        for argv in [["izba", "run", "-d", "."], ["izba", "run", "--detach", "."]] {
            let cli = Cli::try_parse_from(argv).unwrap();
            let Cmd::Run { detach, .. } = cli.cmd else {
                panic!("expected run");
            };
            assert!(detach, "{argv:?} must parse --detach to true");
        }
        // Foreground is the default: no flag => false.
        let bare = Cli::try_parse_from(["izba", "run", "."]).unwrap();
        let Cmd::Run { detach, .. } = bare.cmd else {
            panic!("expected run");
        };
        assert!(!detach, "default must be foreground (detach = false)");
    }

    #[test]
    fn parse_run_detach_conflicts_with_rm() {
        // `--rm` reaps on command exit; `--detach` runs no command — mutually
        // exclusive, rejected by clap before we ever reach the daemon.
        assert!(Cli::try_parse_from(["izba", "run", "--rm", "--detach", "."]).is_err());
        assert!(Cli::try_parse_from(["izba", "run", "-d", "--rm", "."]).is_err());
    }

    #[test]
    fn parse_run_detach_full_surface() {
        // `-d` composes with `--name`, an explicit NAME_OR_DIR, and rides
        // alongside `--allow-unconfined` — none of these flip detach off, and
        // detach does not imply `--rm`.
        let cli = Cli::try_parse_from([
            "izba",
            "run",
            "-d",
            "--name",
            "bg",
            "--allow-unconfined",
            "./proj",
        ])
        .unwrap();
        let Cmd::Run {
            opts,
            name_or_dir,
            rm,
            detach,
            allow_unconfined,
            cmd,
            ..
        } = cli.cmd
        else {
            panic!("expected run");
        };
        assert!(detach, "detached");
        assert!(!rm, "detach does not imply --rm");
        assert!(allow_unconfined, "rides alongside --allow-unconfined");
        assert_eq!(opts.name.as_deref(), Some("bg"));
        assert_eq!(name_or_dir, "./proj");
        assert!(cmd.is_empty(), "a detached run carries no trailing command");
    }

    #[test]
    fn parse_run_detach_long_form_with_directory() {
        // The `--detach` spelling against a bare directory (the issue's
        // `izba run -d myproj` bring-up path).
        let cli = Cli::try_parse_from(["izba", "run", "--detach", "myproj"]).unwrap();
        let Cmd::Run {
            name_or_dir,
            detach,
            ..
        } = cli.cmd
        else {
            panic!("expected run");
        };
        assert!(detach);
        assert_eq!(name_or_dir, "myproj");
    }

    #[test]
    fn parse_start() {
        let cli = Cli::try_parse_from(["izba", "start", "web"]).unwrap();
        let Cmd::Start {
            name,
            allow_unconfined,
        } = cli.cmd
        else {
            panic!("expected start");
        };
        assert_eq!(name, "web");
        assert!(!allow_unconfined, "default must be confined");
    }

    #[test]
    fn parse_start_allow_unconfined() {
        let cli = Cli::try_parse_from(["izba", "start", "--allow-unconfined", "web"]).unwrap();
        let Cmd::Start {
            allow_unconfined, ..
        } = cli.cmd
        else {
            panic!("expected start");
        };
        assert!(allow_unconfined);
    }

    #[test]
    fn parse_start_requires_a_name() {
        // `start` takes a mandatory NAME positional (unlike `run`, which
        // defaults to the cwd) — a bare `izba start` must be a parse error.
        assert!(Cli::try_parse_from(["izba", "start"]).is_err());
    }

    #[test]
    fn parse_run_rm_with_name() {
        // `--rm` composes with an explicit `--name`: the throwaway is the named
        // sandbox, not a cwd-derived one.
        let cli = Cli::try_parse_from(["izba", "run", "--rm", "--name", "throwaway", "."]).unwrap();
        let Cmd::Run { opts, rm, .. } = cli.cmd else {
            panic!("expected run");
        };
        assert!(rm);
        assert_eq!(opts.name.as_deref(), Some("throwaway"));
    }

    #[test]
    fn parse_run_persist_defaults_when_no_rm() {
        // The whole `run` surface at its defaults: a bare `run` persists
        // (rm = false), is confined, has no build, and reaches no trailing cmd.
        let cli = Cli::try_parse_from(["izba", "run"]).unwrap();
        let Cmd::Run {
            name_or_dir,
            rm,
            detach,
            allow_unconfined,
            build,
            build_allow,
            cmd,
            ..
        } = cli.cmd
        else {
            panic!("expected run");
        };
        assert_eq!(name_or_dir, ".");
        assert!(!rm, "persist-after-run is the default");
        assert!(!detach, "foreground exec is the default");
        assert!(!allow_unconfined);
        assert!(build.is_none());
        assert!(build_allow.is_empty());
        assert!(cmd.is_empty());
    }

    #[test]
    fn parse_run_rm_with_build() {
        // `--rm` composes with `--build`: build the image, run it, then tear the
        // throwaway sandbox down on exit.
        let cli =
            Cli::try_parse_from(["izba", "run", "--rm", "--build", "./Dockerfile", "."]).unwrap();
        let Cmd::Run { rm, build, .. } = cli.cmd else {
            panic!("expected run");
        };
        assert!(rm);
        assert_eq!(build.as_deref(), Some(std::path::Path::new("./Dockerfile")));
    }

    #[test]
    fn parse_run_rm_and_allow_unconfined() {
        // Both opt-ins can ride together on one throwaway run.
        let cli = Cli::try_parse_from(["izba", "run", "--rm", "--allow-unconfined", "."]).unwrap();
        let Cmd::Run {
            rm,
            allow_unconfined,
            ..
        } = cli.cmd
        else {
            panic!("expected run");
        };
        assert!(rm && allow_unconfined);
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
