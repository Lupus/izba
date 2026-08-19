# Run notes — your environment

You are a developer trying to use **izba** at a normal Linux shell. These are
facts about your environment a real user would already know — use them; they are
not part of what's being tested.

## Your shell & tools (on the host, where you run `izba`)

- Every command you issue runs via `bash -c` in your working directory. You have
  a real shell: pipes, redirects, quoting, `&&`, subshells. Your working
  directory persists between commands.
- `izba` is on your `PATH`. So are the usual tools: `bash`, `sh`, coreutils
  (`cat`, `echo`, `printf`, `grep`, `sed`, `head`, `find`…), `curl`, `git`,
  `python3`.
- **You can create and edit files.** To author a config file, use a heredoc or
  `printf`, e.g.:
  ```sh
  cat > policy.yaml <<'EOF'
  enforce: true
  allow:
    - example.com
  EOF
  ```
- Your shell's working directory is also shared into sandboxes you start, at
  `/workspace` (izba shares the cwd).
- **izba's data directory on this machine is the path in the `IZBA_DATA_DIR`
  environment variable** (it is set in your shell). Everything the docs describe
  as living under `~/.local/share/izba/` lives under that path here instead.
- You have **passwordless `sudo`** on this machine, so you can run a command as
  another local user (root) when you want to.
- The machine has working internet access, so a sandbox can reach public hosts
  when its firewall lets it.

## The guest (inside a sandbox)

- The default sandbox image is **`ubuntu:24.04`**. It has `bash`, `sh`,
  coreutils, `apt-get`, and `getent` — but **no `curl`, `wget`, `git`, `dig`, or
  `nc` preinstalled**. `alpine:3.20` is a much smaller image that boots faster
  when you only need a sandbox to exist.
- Run a guest command with `izba exec NAME -- <cmd>` or `izba run … -- <cmd>`.
  The part after `--` is the guest command. For a compound/piped guest command,
  wrap it: `izba exec NAME -- sh -c 'cmd1 && cmd2'` (a bare `&&` would otherwise
  be passed as an argument, not run by a shell).
- To test whether the guest can REACH a host/port **without installing
  anything**, use bash's built-in TCP:
  `izba exec NAME -- bash -c 'exec 3<>/dev/tcp/example.com/443 && echo OPEN'`
  (it fails, or hangs briefly, when the connection is not permitted). To test
  DNS resolution use `izba exec NAME -- getent hosts example.com`.
- Installing tools in the guest (`apt-get update && apt-get install -y curl`)
  needs network to the Ubuntu package mirrors — that works on an unrestricted
  sandbox; on a sandbox with its firewall on it works only if the mirror hosts
  are permitted. Prefer the no-install reachability checks above when the
  firewall is on.
- Guest commands are slow the first time (image pull + boot). That is normal;
  don't retry a command just because it took a while.

## This run's scope

You are exercising izba's **egress firewall and how it is configured**: the
per-sandbox egress policy (allow-list, enforce posture, ports, per-host
treatment, access verbs, git rules), the `izba netlog` audit log, the
`izba.yml` manifest review loop (`izba diff` / `izba promote` / `izba export`),
and who is allowed to control the izba daemon on this machine.

**Read `README.md` and `izba --help` / `izba <cmd> --help` to discover how.** If
something you'd expect to be possible isn't discoverable from those, that is a
finding — say so plainly and move on; don't guess at undocumented flags, and
don't invent behaviour you can't see.
