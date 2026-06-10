# Spike S1+ findings: OpenVMM on the Windows host

**Status:** in progress
**Spec:** [2026-06-10-openvmm-spike-s1-design.md](2026-06-10-openvmm-spike-s1-design.md)

## Environment

- Windows version: 10.0.26100 (Windows 11 24H2)
- OpenVMM binary provenance (CI run / commit, or source-build recipe):
- Windows-side installs performed: PowerShell 7.6.2 (installed via `winget install --id Microsoft.PowerShell` during Task 3)

**Interop notes (affects all later tasks):**
- WSL interop (`powershell.exe`) fails inside the default Claude Code sandbox (`UtilConnectUnix: socket failed 1`). All `powershell.exe` / `/mnt/c` commands require `dangerouslyDisableSandbox: true`.
- WHP (HypervisorPlatform): `Get-WindowsOptionalFeature` requires elevation; non-admin CIM probe returned `InstallState=2` (disabled). WHP must be enabled before OpenVMM can use WHP — requires elevation + reboot. **User action needed.**
- pwsh (PowerShell 7): was missing; installed 7.6.2 via winget during this task. Confirmed working.
- gh auth: authenticated as `Lupus` on github.com (token scopes: gist, read:org, repo). Ready for artifact download in Task 4.

## Rung verdicts

| # | Rung | Verdict | Notes |
| --- | --- | --- | --- |
| 0 | acquire openvmm.exe | | |
| 1 | smoke boot (their kernel) | | |
| 2 | direct-boot our vmlinux | | |
| 3 | virtio-fs share | | |
| 4 | vsock bridge | | |
| 5 | consomme networking | | |
| 6 | headless serial capture | | |
| 7 | integration preview (full izba guest) | | |
| S4 | mkfs.erofs on Windows | | |

## Working command lines

(exact invocations per rung as they pass — these become OpenVmmDriver fixtures)

## Kernel config deltas

(none yet)

## Go/no-go recommendation

(pending)
