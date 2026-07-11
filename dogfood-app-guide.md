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
"running" once the microVM boots. If **Create** stays disabled, look just
below the button — it names exactly what's missing (for example, a name or a
workspace folder).

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

## Policy / egress firewall

Each sandbox enforces an egress policy. In the detail panel, click **Policy**
to view or edit the active policy YAML. Rules control which hostnames and ports
outbound traffic is allowed to reach. Changes take effect immediately; the app
saves the policy file without restarting the sandbox.

## Manifest (izba.yml)

If the sandbox's workspace has an `izba.yml`, the detail panel's **Manifest**
tab (right after **Policy**) shows how that file compares to the sandbox's
actual, running settings. A banner at the top gives you the state at a
glance:

- **In sync** — izba.yml and the live sandbox match; nothing to do.
- **izba.yml has changes not yet applied** — you (or someone) edited
  izba.yml; review the changes below, then **Promote**.
- **Live settings have drifted from izba.yml** — something changed the
  sandbox another way (for example, toggling the firewall on the
  **Policy** tab) without updating the file; **Export** to capture it.
- **Diverged** — both sides changed. Promoting applies izba.yml's version;
  Exporting overwrites izba.yml with the live version instead.

When there's a difference, a table below the banner lists each changed
field with its old and new value, plus a small tag showing when the change
takes effect: **live** (immediately), **restart** (on the sandbox's next
start), or **image** (next start, with a new image). A change that would
loosen the egress firewall is flagged with a red **⚠ weakens egress** marker.

- **Promote…** opens a confirmation dialog listing exactly what will
  change, then applies izba.yml's pending changes to the sandbox. If any
  change weakens the firewall, you must check "I understand this weakens the
  egress firewall" before you can confirm. If the sandbox is running and a
  change needs a restart, you can optionally check "Restart now to apply
  restart-class changes" to apply it right away instead of waiting for the
  next start. The button is disabled when there's nothing to promote.
- **Export to izba.yml** writes the sandbox's current live settings back
  into izba.yml, so a change made another way ends up captured in the file.
  It's disabled when there's no live-side drift to capture.
- **Refresh** re-reads both sides and updates the banner and table — use it
  after editing izba.yml by hand, or after making a change elsewhere in the
  app.

If the workspace has no izba.yml yet, the tab tells you so and points you at
`izba export <name>` (or the **Export** button here, once you've made some
changes) to create one from the sandbox's current settings.

## Removing a sandbox

From the detail panel (or by right-clicking the row), choose **Remove**. This
destroys the sandbox and frees its disk image. Named volumes you created
separately are not deleted and can be reattached to a new sandbox later.

## Daemon status

The bottom status bar shows whether the daemon is connected. A green indicator
means `izbad` is up and responding; amber means the app is reconnecting. If the
daemon is not installed, follow the CLI quickstart in README.md first.
