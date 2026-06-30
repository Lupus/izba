# izba Desktop App — User Guide

The izba desktop app gives you a visual interface for managing your microVM
sandboxes. It talks to the izba daemon (`izbad`) in the background; the daemon
must be running for most operations to succeed (the app starts it automatically
if it is not already up).

## Main view — sandbox list

When you open the app you land on the sandbox list. Each row shows a sandbox
name and its current status (running, stopped, or unhealthy). The list refreshes
every few seconds so you see live state without reloading.

## Creating a sandbox

Click **Create sandbox** (top-right of the list). Enter a name and optionally
choose an OCI image. Confirm to launch the sandbox; it moves from "stopped" to
"running" once the microVM boots.

## Starting and stopping

Click the sandbox row to open its detail panel. Use the **Start** button to boot
a stopped sandbox and **Stop** to shut it down cleanly. The status badge updates
in the list as soon as the daemon confirms the transition.

## Opening a shell

With a sandbox running, click **Open shell** in its detail panel. A terminal
opens inside the microVM — this is equivalent to `izba exec -it <name> sh`.
Type `exit` to close the shell; the sandbox keeps running.

## SSH access

You can also reach a running sandbox over SSH:

```
ssh izba-<name>
```

The app manages the SSH config entry automatically; no manual setup required.

## Firewall / egress policy

Each sandbox enforces an egress policy. In the detail panel, click **Firewall**
to view or edit the active policy YAML. Rules control which hostnames and ports
outbound traffic is allowed to reach. Changes take effect immediately; the app
saves the policy file without restarting the sandbox.

## Removing a sandbox

From the detail panel (or by right-clicking the row), choose **Remove**. This
destroys the sandbox and frees its disk image. Named volumes you created
separately are not deleted and can be reattached to a new sandbox later.

## Daemon status

The bottom status bar shows whether the daemon is connected. A green indicator
means `izbad` is up and responding; amber means the app is reconnecting. If the
daemon is not installed, follow the CLI quickstart in README.md first.
