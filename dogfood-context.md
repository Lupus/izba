# Run notes — your environment

You are a developer trying to use **izba** at a normal Linux shell. These are
facts about your environment a real user would already know — use them; they are
not part of what's being tested.

## Your shell & tools (on the host, where you run `izba`)
- Every command you issue runs via `bash -c` in your working directory. You have
  a real shell: pipes, redirects, quoting, `&&`, subshells.
- `izba` is on your `PATH`. So are the usual tools: `bash`, `sh`, coreutils
  (`cat`, `echo`, `printf`, `grep`, `sed`, `head`…), `curl`, `git`, `python3`.
- **You can create and edit files.** To author a config file, use a heredoc or
  `printf`, e.g.:
  ```sh
  cat > policy.yaml <<'EOF'
  enforce: true
  allow:
    - example.com
  EOF
  ```
- Your shell's working directory is also shared into sandboxes you start at
  `/workspace` (izba shares the cwd).

## The guest (inside a sandbox)
- The default sandbox image is **`ubuntu:24.04`**. It has `bash`, `sh`,
  coreutils, `apt-get`, and `getent` — but **no `curl`, `wget`, `git`, `dig`, or
  `nc` preinstalled**.
- Run a guest command with `izba exec NAME -- <cmd>` or `izba run ... -- <cmd>`.
  The part after `--` is the guest command. For a compound/piped guest command,
  wrap it: `izba exec NAME -- sh -c 'cmd1 && cmd2'` (a bare `&&` would otherwise
  be passed as an argument, not run by a shell).
- To test whether the guest can REACH a host/port **without installing
  anything**, use bash's built-in TCP: `izba exec NAME -- bash -c 'exec 3<>/dev/tcp/example.com/443 && echo OPEN'` (it fails/﻿hangs briefly if blocked).
  To test DNS resolution use `izba exec NAME -- getent hosts example.com`.
- Installing tools in the guest (`apt-get update && apt-get install -y curl`)
  needs network to the Ubuntu package mirrors — that works on an unrestricted
  sandbox, but on an **enforcing** sandbox it will be blocked unless the mirror
  host is on the allow-list. Prefer the no-install reachability checks above when
  the firewall is on.

## This run's scope
You are exercising izba's **egress firewall**: the per-sandbox egress policy
(allow-list, enforce on/off, ports, git rules, HTTP access) and the `izba netlog`
audit log. Read the README and `izba --help` / `izba <cmd> --help` to discover
how. If something you'd expect to be possible isn't discoverable from those, that
is a finding — note it and move on; don't guess at undocumented flags.
