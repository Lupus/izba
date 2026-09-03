# 0001 — Does Windows AF_UNIX `connect()` require write access on the socket file?

Spike [#248](https://github.com/Lupus/izba/issues/248) · 2026-09-03 ·
script: [`hack/spike/afunix-connect-low-il-spike.ps1`](../../hack/spike/afunix-connect-low-il-spike.ps1)

## Question

On every default Windows start izba stamps the per-sandbox run dir
(`VmSpec::confined_write_surfaces`) with an inheritable **Low** mandatory-
integrity label (`procmgr::jail_windows::set_low_integrity_recursive`:
`SYSTEM_MANDATORY_LABEL_NO_WRITE_UP`, `OBJECT_INHERIT | CONTAINER_INHERIT`)
so the Low-IL VMM can write there. The egress listener `vsock.sock_1027` and
the USB broker `vsock.sock_1028` live in that dir and inherit the label.
Windows AF_UNIX has no `SO_PEERCRED`, so `peercred::enforcement_mode()` is
`Unavailable` and MIC's no-write-up rule is one of the last same-user
barriers on those planes — **if** `connect()` on an AF_UNIX socket file
requests write access. That is undocumented. The F-CRED-5 register entry
recorded it as explicitly untested.

So: can a same-user **Low-IL** process `connect()` to an existing AF_UNIX
socket file, comparing a file that carries izba's inheritable Low label
against one that does not?

## Approach

One self-contained PowerShell 5.1 script, run unelevated over WSL interop on
the real host (izba's default path is unelevated too). It compiles a small
P/Invoke helper once and then, for each of three conditions, has the
Medium-IL parent bind two AF_UNIX listeners named exactly like izba's
(`vsock.sock_1027`, `vsock.sock_1028`) plus a plain `probe.txt`, and runs the
same client script twice as a child process built **the way izba builds its
VMM token** — `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` →
`SetTokenInformation(TokenIntegrityLevel)` → `CreateProcessAsUserW` — once at
Low IL (`S-1-16-4096`) and once at Medium IL (`S-1-16-8192`, the control).
The label is applied with the same call sequence as
`jail_windows::apply_inheritable_integrity_label` (`InitializeAcl` +
`AddMandatoryAce(OI|CI, NO_WRITE_UP)` + `SetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)`).

| Condition | Meaning |
| --- | --- |
| `unlabelled` | dir carries no explicit label (implicit Medium) — the barrier under test |
| `label-before` | dir labelled Low **before** the sockets are bound (children inherit at creation) |
| `label-after` | sockets bound first, **then** the dir is labelled (`SetNamedSecurityInfoW` propagates over the existing subtree) |

Both orders that can occur in izbad are therefore covered. Per file the
client reports: the label it sees (SDDL), whether it can open the file for
`READ_CONTROL` / `FILE_WRITE_DATA` / `GENERIC_WRITE` (opening the reparse
point itself), and for the sockets whether `connect()` succeeds and completes
a `ping`/`pong` round trip with the parent's listener. The script computes the
verdict only when its controls pass: the Low client must be denied
`FILE_WRITE_DATA` on the unlabelled sockets (the MIC barrier is real), the
Medium client must round-trip everywhere, the Low client must round-trip on
the Low-labelled sockets, and the child ILs must read back as 4096 / 8192.

**Host tested:** Windows 11 24H2 (registry `ProductName` "Windows 10
Enterprise"), **build 26100.4349**, `Microsoft Windows NT 10.0.26100.0`,
Windows PowerShell 5.1.26100.4202, standard (non-elevated) user.

## Findings

**YES — Windows AF_UNIX `connect()` requires write access on the socket
file.** All controls passed; the verdict was reached on the first run.

| condition | client IL | file | label on file | open `FILE_WRITE_DATA` | `connect()` | WSA error | round trip |
| --- | --- | --- | --- | --- | --- | --- | --- |
| unlabelled | Low (4096) | `vsock.sock_1027` | (none) | 5 ACCESS_DENIED | −1 | **10013 WSAEACCES** | — |
| unlabelled | Low (4096) | `vsock.sock_1028` | (none) | 5 ACCESS_DENIED | −1 | **10013 WSAEACCES** | — |
| unlabelled | Medium (8192) | both sockets | (none) | 0 | 0 | 0 | pong |
| label-before | Low (4096) | both sockets | `S:AI(ML;ID;NW;;;LW)` | 0 | 0 | 0 | pong |
| label-before | Medium (8192) | both sockets | `S:AI(ML;ID;NW;;;LW)` | 0 | 0 | 0 | pong |
| label-after | Low (4096) | both sockets | `S:AI(ML;ID;NW;;;LW)` | 0 | 0 | 0 | pong |
| label-after | Medium (8192) | both sockets | `S:AI(ML;ID;NW;;;LW)` | 0 | 0 | 0 | pong |

(`probe.txt` behaved identically to the sockets on the open probes:
Low-IL write denied only in `unlabelled`. Full per-file lines are in the
script's transcript, `%LOCALAPPDATA%\izba-spike-afunix\transcript.txt`.)

Observations that matter beyond the yes/no:

- **Order does not matter.** A socket bound *after* the dir was labelled
  inherits `ML;ID;NW;;;LW`; a socket bound *before* is relabelled by
  `SetNamedSecurityInfoW`'s propagation. Either way the socket file ends up
  Low and the Low-IL client connects.
- **The label is load-bearing, not incidental.** On Windows the confined VMM
  runs at Low IL and is the process that dials `vsock.sock_1027` /
  `vsock.sock_1028` to bridge guest-initiated vsock (hybrid-vsock convention).
  Since `connect()` needs write access, the VMM's own dial would fail without
  the label — removing it is *not* a remediation; it would break egress and
  USB under confinement.
- **What the label therefore gives away.** With the socket files Low, MIC no
  longer distinguishes the sandbox's VMM from *any other same-user Low-IL
  process* — a browser renderer sandbox, any Low-IL app, and notably the
  Low-IL VMM of **every other izba sandbox**. Such a peer passes the profile
  DACL and MIC and can drive that sandbox's outbound proxy (its full
  allow-list and DNS) or its USB broker. A VMM escape at Low IL thus gains
  every sibling sandbox's egress plane rather than being contained to its own.
- **Same-user Medium-IL peers are unchanged.** They could always connect
  (profile DACL); the vault design already scopes them out of the socket
  layer by construction. The delta this spike sizes is precisely the Low-IL
  tier.
- **Dead ends:** none. The MSDN sample approach (duplicate + lower the
  caller's token, `CreateProcessAsUserW` without `SeAssignPrimaryTokenPrivilege`)
  worked unelevated, and Windows PowerShell ran at Low IL once `TEMP` pointed
  at a Low-labelled dir (`AppData\LocalLow`), matching the earlier
  `whp-local-account-spike.ps1` experience.

## Recommendation

Keep the Low label (the VMM needs it) and add a **Windows accept-time peer
gate** on both listeners that admits only the sandbox's own VMM process,
routed through the existing `peercred::authorize_stream` / `EgressAdmission`
seam so the accept-loop call-site tests cover it. Two candidate mechanisms,
to be chosen in the follow-up:

1. **Pinned peer PID.** `SIO_AF_UNIX_GETPEERPID` compared against the VMM pid
   izbad already tracks as `PidIdentity` (pid + creation time), with izbad
   holding an open process handle on the VMM for its lifetime so the pid
   cannot be recycled under the check. The PID-recycling objection F-09
   records against that ioctl is about an *unpinned* peer; it does not apply
   here.
2. **Explicit DACL under `izba lockdown`.** Grant write on the socket files
   only to the per-sandbox `izba-sb-<name>` account, so a sibling sandbox's
   VMM (a different account) is denied by the DACL even though MIC admits it.

Until that lands, the M5 credential-vault P2 prerequisite (F-CRED-5) stays
**Linux-only**, and the register now says why in concrete terms.

## Follow-on Work

- [#276](https://github.com/Lupus/izba/issues/276) — Windows: gate
  `vsock.sock_1027`/`1028` to the sandbox's own VMM — the run-dir Low label
  (which `connect()` needs) admits every same-user Low-IL process
  (`type:security`, `priority:P2`, `effort:M`).
