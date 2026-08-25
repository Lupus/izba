import { useEffect, useId, useRef, useState } from "react";
import { X } from "lucide-react";
import type { Access, AllowEntry, GitRule, PortSpec } from "../lib/types";
import { api } from "../lib/ipc";
import { WEB_DEFAULT_PORTS } from "../lib/ports";
import { AccessPicker } from "./AccessPicker";
import { Section } from "./Section";
import { EnforceToggle } from "./EnforceToggle";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { EditableList } from "@/components/ui/editable-list";

/** One port of a Row, with the inspectability declared FOR THAT PORT (#238).
 *  `protocol` is carried through unedited (F-1): the GUI has no authoring
 *  surface for it, but a value it read must survive a Save that did not touch
 *  it — and must survive against its OWN port, never spread to a sibling.
 *  `undefined` for a port that never declared one; that must round-trip as a
 *  bare number, not as some invented default. */
interface PortRow {
  port: number;
  protocol?: "http" | "tcp";
}

interface Row {
  host: string;
  ports: PortRow[];
  access: Access;
}

interface GitRow {
  /** The raw glob string ("host/owner/repo" or "host") */
  target: string;
  access: Access;
}

/** Extract the glob string from a GitRule. */
function gitRuleTarget(rule: GitRule): string {
  return "repo" in rule ? rule.repo : rule.host;
}

function toGitRow(rule: GitRule): GitRow {
  return { target: gitRuleTarget(rule), access: rule.access ?? "read" };
}

/** A wire `PortSpec` (bare number, or `{port, protocol}`) as a `PortRow`. */
function toPortRow(p: PortSpec): PortRow {
  return typeof p === "number" ? { port: p } : { port: p.port, protocol: p.protocol };
}

/** The inverse. A port with no declaration goes back as a BARE NUMBER, which
 *  is what the Rust `PortSpec` serializes to — so an untouched policy file is
 *  not rewritten into a shape its author never wrote. */
function toPortSpec(p: PortRow): PortSpec {
  return p.protocol ? { port: p.port, protocol: p.protocol } : p.port;
}

const webDefaultPortRows = (): PortRow[] => WEB_DEFAULT_PORTS.map((port) => ({ port }));

/** Normalize an `AllowEntry` (string = bare host → web default ports) to a Row. */
function toRow(e: AllowEntry): Row {
  return typeof e === "string"
    ? { host: e, ports: webDefaultPortRows(), access: "read-write" }
    : {
        host: e.host,
        ports: e.ports?.map(toPortRow) ?? webDefaultPortRows(),
        access: e.access ?? "read-write",
      };
}

/** How an operator gets past a Host rename lock — referenced by the Host
 *  lock's title, the Access-widening refusal, and the visible notice, so
 *  there is exactly one sentence to keep in sync (not several near-duplicate
 *  strings). Removing the pinned port is the escape valve for BOTH the Host
 *  lock and the Access-widening refusal (#239 1b) — once unpinned, this row
 *  is an ordinary row again. */
const PIN_ESCAPE_HINT =
  "remove the pinned port, or edit policy.yaml, or izba.yml followed by izba diff / izba promote";

/** How to actually make a dormant passthrough pin — NOT by widening Access
 *  in this editor. That transition is refused on a pinned row (#239 1b), and
 *  the picker gives no visible feedback when the click is silently ignored,
 *  so a dormant declaration's wording must never tell the operator to widen
 *  Access "here" without qualifying where "here" fails — that contradiction
 *  (Important B, final review) was the exact defect this constant closes. */
const WIDEN_ESCAPE_HINT =
  "widen access in policy.yaml, or in izba.yml followed by izba diff / izba promote";

/** How a declared port is announced — for the chip's accessible name/tooltip
 *  AND the row's visible passthrough notice (`passthroughNotice` below folds
 *  onto this single source; the final review caught the chip and the notice
 *  disagreeing about a dormant row's posture when they had separate copies
 *  of the `tcp` wording). `tcp` has THREE postures, and the enforce-off one
 *  is decided first — an access level cannot cancel a hatch that a stopped
 *  firewall never opened. With `enforce: false` `EgressPolicyConfig::compile`
 *  returns AllowAll and `router::passthrough_names` returns nothing, so every
 *  destination is reachable, no connection is terminated and there is nothing
 *  to splice: the declaration is inert. When enforcement IS on, the label is
 *  access-aware: an opaque splice carries no HTTP method, so `access: read`
 *  never authorizes one (`egress.rego`'s `host_access_ok("read")` requires
 *  GET/HEAD); `router::passthrough_names` drops the host and the connection
 *  stays terminated at L7 — a pinning client still sees izba's certificate.
 *  `izba policy show` (`crates/izba-cli/src/commands/policy.rs`) renders the
 *  same three branches in the same order (#239: both surfaces reveal posture
 *  and must not disagree), so neither GUI surface may claim the live
 *  substance for a row that doesn't have it. `http` and the undeclared case
 *  do not depend on access or enforcement — as on the CLI. */
function portDeclarationLabel(p: PortRow, access: Access, enforcing: boolean): string | null {
  switch (p.protocol) {
    case "tcp":
      if (!enforcing) {
        return `Port ${p.port}: TLS-pinning passthrough NOT in effect — enforcement is off, so every destination is reachable and no connection is terminated or spliced; this declaration is inert until enforcement is turned on`;
      }
      return access === "read-write"
        ? `Port ${p.port}: TLS-pinning passthrough — spliced opaquely, with no L7 rules, no request audit and no upstream certificate verification`
        : `Port ${p.port}: TLS-pinning passthrough NOT in effect — an opaque splice carries no HTTP method, so this row's "${access}" access never authorizes one; the connection stays terminated at L7 and a pinning client still sees izba's certificate. To pin, ${WIDEN_ESCAPE_HINT}`;
    case "http":
      return `Port ${p.port}: inspected at L7 (declared protocol: http)`;
    default:
      return null;
  }
}

/** Whether a port carries `protocol: "tcp"` — the boolean "is this a pinned
 *  port" predicate (#239), used wherever code only needs a yes/no answer:
 *  `pinnedPorts` below, and both `PortEditor` render sites that pick the
 *  `warning` Badge variant / `⚠ tcp` marker (a dormant declaration is still
 *  a declaration worth flagging — only the wording, via
 *  `portDeclarationLabel`, distinguishes live from not-in-effect).
 *  `portDeclarationLabel`'s own `switch (p.protocol)` is NOT a second
 *  derivation of this predicate: it needs the specific declared value
 *  (`tcp` vs `http` vs undeclared) to choose its wording, a three-way
 *  dispatch this boolean can't express, so it reads `p.protocol` directly
 *  rather than calling this. */
function isPinnedPort(p: PortRow): boolean {
  return p.protocol === "tcp";
}

/** Ports on this row that carry `protocol: "tcp"` (#239) — the derived list
 *  everything downstream (the Host lock, the Access-widening refusal, the
 *  visible notice) reads to decide whether a row is pinned, built from the
 *  single `isPinnedPort` predicate. A row carrying at least one locks its
 *  Host input and refuses widening its Access to `read-write`, because this
 *  component's Save path (`policySetFull`) skips the `izba diff`/
 *  `izba promote` weakening gate: renaming the host would relocate the hatch
 *  onto a host that never declared one, and widening Access would silently
 *  turn a dormant passthrough live — both unflagged. */
function pinnedPorts(r: Row): PortRow[] {
  return r.ports.filter(isPinnedPort);
}

/** Visible (not just aria-label) text for the notice rendered on a pinned
 *  row, built from the SAME `portDeclarationLabel` the chip uses. `pinned`
 *  is always non-empty when this is called (the caller only renders the
 *  notice for a locked row), and every element carries `protocol: "tcp"` by
 *  construction of `pinnedPorts`, so `portDeclarationLabel` only ever
 *  exercises its `tcp` branch here — its `http`/undeclared branches exist
 *  for the chip's use on an unfiltered port list, not for this call. For a
 *  `read-write` row the hatch is live and the Host lock is the only
 *  restriction; for anything narrower the hatch is dormant AND widening
 *  Access back to `read-write` is refused HERE (in this editor) while the
 *  row is pinned — silently turning a dormant passthrough live is exactly
 *  the "activate a hatch" move #239's 1b ruling closes. The route that
 *  actually pins (editing the file directly) is named in
 *  `portDeclarationLabel`'s own dormant wording, not repeated here, so this
 *  sentence only explains why the picker itself won't do it. */
function passthroughNotice(pinned: PortRow[], access: Access, enforcing: boolean): string {
  const declared = pinned.map((p) => portDeclarationLabel(p, access, enforcing)).join(". ");
  const remediation =
    access === "read-write"
      ? `The host is locked so this control cannot be silently relocated — ${PIN_ESCAPE_HINT}.`
      : `The host is locked, and widening Access to read-write here is refused while this row carries a pinned port (it would silently activate the passthrough) — ${PIN_ESCAPE_HINT}.`;
  return `${declared}. ${remediation}`;
}

/** Convert a target string and access into a GitRule. */
function toGitRule(target: string, access: Access): GitRule {
  return target.includes("/") ? { repo: target, access } : { host: target, access };
}

/** Mirror of the daemon's validate_host_pattern: '*' only as a leading
 *  '*.'/'**.' label, and — for wildcard patterns only — the remainder is
 *  restricted to hostname characters (regorus glob.match's `wax` engine
 *  treats `{}[]?<>` etc. as metacharacters, so e.g. `*.git{hub.com,evil.com}`
 *  would otherwise "validate" yet match far more than intended). Exact hosts
 *  (no `*` anywhere) are unaffected. The daemon re-validates on save — this
 *  is UX only. */
export function hostPatternError(host: string): string | null {
  const isWildcard = host.startsWith("**.") || host.startsWith("*.");
  const rest = host.startsWith("**.") ? host.slice(3) : host.startsWith("*.") ? host.slice(2) : host;
  if (rest === "" || rest.includes("*")) {
    return `Invalid host pattern "${host}": * is only allowed as a leading *. (one label) or **. (any depth) — e.g. *.example.com`;
  }
  if (isWildcard && !/^[a-zA-Z0-9._-]+$/.test(rest)) {
    return `Invalid host pattern "${host}": wildcard remainder "${rest}" may only contain letters, digits, '-', '.', and '_' — glob metacharacters like {}[]?<> would silently widen what the pattern matches`;
  }
  return null;
}

/** Per-host ports shown as removable chips plus a numeric "add port" field. */
function PortEditor({
  ports,
  access,
  enforcing,
  onAdd,
  onRemove,
}: {
  ports: PortRow[];
  // Needed only to make a `tcp` chip's label access-aware (#239 final
  // review) — the chip must not claim the live substance for a row whose
  // access has cancelled the hatch.
  access: Access;
  // Likewise for the posture the whole sandbox is in: a declared hatch on a
  // non-enforcing sandbox is inert, and the chip must say so in the same
  // words the row notice does (both read `portDeclarationLabel`).
  enforcing: boolean;
  onAdd: (port: number) => void;
  onRemove: (port: number) => void;
}) {
  const [draft, setDraft] = useState("");
  const [err, setErr] = useState<string | null>(null);
  function commit() {
    const t = draft.trim();
    if (!t) return; // empty field is a no-op, not an error (e.g. a stray Add click)
    if (!/^\d+$/.test(t)) {
      setErr("Enter a port between 1 and 65535.");
      return; // keep the draft so the user can fix it
    }
    const p = parseInt(t, 10);
    if (p < 1 || p > 65535) {
      setErr("Enter a port between 1 and 65535.");
      return;
    }
    if (ports.some((x) => x.port === p)) {
      setErr(`Port ${p} is already added.`);
      return;
    }
    onAdd(p);
    setDraft("");
    setErr(null);
  }
  return (
    <div className="flex flex-1 flex-col gap-1">
      <div className="flex flex-wrap items-center gap-1">
        {ports.map((p) => {
          const declaration = portDeclarationLabel(p, access, enforcing);
          return (
            <Badge
              key={p.port}
              variant={isPinnedPort(p) ? "warning" : "secondary"}
              className="gap-1"
            >
              {p.port}
              {/* #238: the declaration belongs to THIS port, so its marker does
                  too — a host-level annotation would misreport which port gave
                  a control up. Undeclared ports render exactly as before. */}
              {declaration && (
                <span aria-label={declaration} title={declaration}>
                  {isPinnedPort(p) ? "⚠ tcp" : "http"}
                </span>
              )}
              {/* Intentional in-chip remove button — distinct from row-level RemoveRowButton idiom */}
              <Button
                type="button"
                variant="ghost"
                size="icon"
                aria-label={`Remove port ${p.port}`}
                onClick={() => onRemove(p.port)}
                className="h-3.5 w-3.5 p-0 text-muted-foreground-2 hover:text-destructive"
              >
                <X className="h-3 w-3" />
              </Button>
            </Badge>
          );
        })}
        <Input
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value);
            if (err) setErr(null);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              commit();
            }
          }}
          placeholder="add port"
          aria-label="add port"
          inputMode="numeric"
          className="w-20 py-1 text-xs"
        />
        <Button
          type="button"
          variant="secondary"
          size="sm"
          onClick={commit}
        >
          Add
        </Button>
      </div>
      {err && <span className="text-xs text-destructive">{err}</span>}
    </div>
  );
}

interface LoadedSnapshot {
  hosts: Row[];
  git: GitRow[];
}

/** What this editor actually KNOWS about the sandbox's policy.
 *
 *  The three states are NOT interchangeable, and conflating the first with a
 *  loaded-and-empty policy is what made this tab able to disarm an egress
 *  jail with one click: while `policyShow` was in flight (and again when it
 *  REJECTED) the editor rendered "Firewall off" plus "No allowed hosts — add
 *  one to permit egress", and `save()` happily shipped that invented empty
 *  policy to `policySetFull`. That call REPLACES the sandbox's managed
 *  `policy.yaml` and — unlike the `izba.yml` route — skips the
 *  `izba diff`/`izba promote` weakening gate entirely, so nothing downstream
 *  flags it, warns, or asks. An unknown policy is not an empty one, and an
 *  errored load is not an empty one either. */
type LoadState = { kind: "loading" } | { kind: "ready" } | { kind: "error"; message: string };

/** Why a Save was refused, given what we know. Returned as text so the refusal
 *  is VISIBLE (a silently-ignored click teaches the operator nothing) and so
 *  `save()` has exactly one place that decides "may we write?". */
function saveRefusal(load: LoadState): string | null {
  if (load.kind === "ready") return null;
  const what =
    load.kind === "loading"
      ? "This sandbox's policy has not finished loading"
      : "This sandbox's policy could not be read";
  return `${what}, so saving is refused: writing now would replace its managed policy.yaml with whatever this half-built form contains — an empty allow-list and no git rules — on a path that skips the izba diff / izba promote weakening gate. Wait for the policy to load, or reopen this tab to retry.`;
}

export function PolicyEditor({ name }: { name: string }) {
  const [hosts, setHosts] = useState<Row[]>([]);
  const [gitRows, setGitRows] = useState<GitRow[]>([]);
  const [enforcing, setEnforcing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [load, setLoad] = useState<LoadState>({ kind: "loading" });
  const loadedRef = useRef<LoadedSnapshot>({ hosts: [], git: [] });
  // Namespaces the per-row passthrough-notice id so two concurrent
  // PolicyEditor instances can never collide an aria-describedby target.
  const instanceId = useId();

  // Derive dirty: current state differs from the last-saved/loaded snapshot.
  const dirty =
    JSON.stringify({ hosts, git: gitRows }) !==
    JSON.stringify({ hosts: loadedRef.current.hosts, git: loadedRef.current.git });

  useEffect(() => {
    let alive = true;
    // A different sandbox is a different policy: go back to "unknown" rather
    // than leaving the previous sandbox's rows on screen as if they were this
    // one's — and, with them, a Save that would write them here. Pinned by
    // "goes back to unknown when the sandbox changes...".
    setLoad({ kind: "loading" });
    setError(null);
    void (async () => {
      try {
        const p = await api.policyShow(name);
        if (alive) {
          // A refusal is a statement about a moment, and this is the moment it
          // stops being true: drop it as the load settles, so a "has not
          // finished loading" banner never sits above a Save that now works.
          // Leaving it up would assert a state the editor is not in — the same
          // sin, in miniature, as the posture claim this guard exists to stop.
          setError(null);
          const loadedHosts = p.allow.map(toRow);
          const loadedGit = p.git.map(toGitRow);
          setHosts(loadedHosts);
          setEnforcing(p.enforcing);
          setGitRows(loadedGit);
          loadedRef.current = { hosts: loadedHosts, git: loadedGit };
          setLoad({ kind: "ready" });
        }
      } catch (e) {
        if (alive) {
          // Same clearing on the failure edge: the load error is rendered by
          // the panel below, and a stale save-refusal alongside it would name
          // the wrong reason.
          setError(null);
          setLoad({ kind: "error", message: e instanceof Error ? e.message : String(e) });
        }
      }
    })();
    return () => {
      alive = false;
    };
  }, [name]);

  async function toggleEnforce() {
    // No load guard here on purpose: unlike Save, this control has no
    // rendered form before `load.kind === "ready"` (see the header below), so
    // there is no click to refuse — and an unreachable guard would be a
    // security rule with no test behind it. The invariant that keeps it
    // unreachable is asserted directly, in "offers no enforce toggle before
    // the policy has loaded".
    const next = !enforcing;
    setEnforcing(next);
    try {
      await api.policySetEnforce(name, next);
    } catch (e) {
      // revert on error
      setEnforcing(!next);
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  // Host row helpers
  function editHosts(f: (rs: Row[]) => Row[]) {
    setHosts(f);
    setSaved(false);
  }
  function setHost(i: number, host: string) {
    // A row carrying a pinned port keeps its Host inert — the lock is
    // behavioural, not merely a `readOnly` attribute a test can bypass with
    // `fireEvent.change` (#239).
    editHosts((rs) =>
      rs.map((r, j) => (j === i && pinnedPorts(r).length === 0 ? { ...r, host } : r)),
    );
  }
  function addPort(i: number, port: number) {
    editHosts((rs) =>
      rs.map((r, j) =>
        // The added port carries NO declaration (#238) — it is inspected by
        // default and cannot inherit a sibling port's `protocol: tcp`.
        j === i && !r.ports.some((p) => p.port === port)
          ? { ...r, ports: [...r.ports, { port }].sort((a, b) => a.port - b.port) }
          : r,
      ),
    );
  }
  function removePort(i: number, port: number) {
    editHosts((rs) =>
      rs.map((r, j) => (j === i ? { ...r, ports: r.ports.filter((p) => p.port !== port) } : r)),
    );
  }
  function addRow() {
    editHosts((rs) => [...rs, { host: "", ports: webDefaultPortRows(), access: "read-write" }]);
  }
  function removeRow(i: number) {
    editHosts((rs) => rs.filter((_, j) => j !== i));
  }
  function setHostAccess(i: number, access: Access) {
    // Widening a pinned row INTO read-write would silently ACTIVATE a
    // dormant passthrough (#239 1b, human-ruled) — the reducer is the
    // barrier, not just the picker's rendered state, so the refusal holds
    // even against a direct state-setting call. Narrowing (read-write ->
    // read, or any transition that is not INTO read-write) stays allowed on
    // a pinned row; only the widening direction is refused.
    editHosts((rs) =>
      rs.map((r, j) => {
        if (j !== i) return r;
        if (access === "read-write" && pinnedPorts(r).length > 0) return r;
        return { ...r, access };
      }),
    );
  }

  // Git row helpers
  function editGit(f: (rs: GitRow[]) => GitRow[]) {
    setGitRows(f);
    setSaved(false);
  }
  function addGitRow() {
    editGit((rs) => [...rs, { target: "", access: "read" }]);
  }
  function removeGitRow(i: number) {
    editGit((rs) => rs.filter((_, j) => j !== i));
  }
  function setGitTarget(i: number, target: string) {
    editGit((rs) => rs.map((r, j) => (j === i ? { ...r, target } : r)));
  }
  function setGitAccess(i: number, access: Access) {
    editGit((rs) => rs.map((r, j) => (j === i ? { ...r, access } : r)));
  }

  async function save() {
    setSaved(false);
    // THE guard: never write a policy we never read. It lives here, in the
    // state transition, and not merely in the Save control's rendered state —
    // the same reasoning that put #262's pinned-row Host lock and
    // Access-widening refusal in the reducer instead of in `readOnly`: a
    // scripted click, a stale render or a future markup edit must not be able
    // to route around it. The control is additionally marked `aria-disabled`
    // (belt), but that is presentation; this is the barrier.
    const refusal = saveRefusal(load);
    if (refusal) {
      setError(refusal);
      return;
    }
    setError(null);
    try {
      for (const r of hosts) {
        const h = r.host.trim();
        if (h === "") continue;
        const bad = hostPatternError(h);
        if (bad) {
          setError(bad);
          return;
        }
      }
      const allow: AllowEntry[] = hosts
        .filter((r) => r.host.trim() !== "")
        .map((r) => ({
          host: r.host.trim(),
          // A port that never declared anything goes back as a bare number
          // (F-1 / #238): the GUI must not invent a declaration, and on the
          // Rust side the bare form IS the canonical "no declaration" shape.
          // A port added here is a `PortRow` with no `protocol`, so it can
          // never leave carrying a sibling's declaration.
          ports: r.ports.map(toPortSpec),
          access: r.access,
        }));
      const git: GitRule[] = gitRows
        .filter((r) => r.target.trim() !== "")
        .map((r) => toGitRule(r.target.trim(), r.access));
      await api.policySetFull(name, allow, git);
      // Refresh the loaded snapshot and mark saved.
      loadedRef.current = { hosts, git: gitRows };
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="flex h-full flex-col">
      {/* Enforce toggle — always visible above the scroll area, but ONLY once
          the posture is known. `enforcing` initialises to `false`, so
          rendering the toggle early would announce "Firewall off" for a
          sandbox that may well be enforcing (the advertised-posture ≠
          enforced-posture class), and one click would then push that invented
          posture to the daemon. */}
      <div className="flex shrink-0 items-center gap-3 pb-3">
        {load.kind === "ready" ? (
          <EnforceToggle enforcing={enforcing} onToggle={() => void toggleEnforce()} />
        ) : (
          <span className="text-xs font-semibold text-muted-foreground">
            Firewall posture unknown
          </span>
        )}
      </div>
      {error && <div className="shrink-0 pb-3 text-sm text-destructive">{error}</div>}

      {/* Scrollable sections area — flexes to fill available height */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {load.kind === "ready" ? (
          <div className="flex flex-col gap-3 pb-3">
            <Section title="Hosts">
              <p className="mb-2 text-sm text-muted-foreground">
                Hosts this sandbox may reach — exact (api.example.com) or wildcard
                (*.example.com = one subdomain label, **.example.com = any depth; the
                apex needs its own entry). Add a port to a host, or remove one with its ✕.
              </p>
              <EditableList
                density="card"
                items={hosts}
                renderRow={(r, i) => {
                  const pinned = pinnedPorts(r);
                  const locked = pinned.length > 0;
                  // Namespaced by instanceId (useId) AND per-row by index, so
                  // aria-describedby resolves the right notice even with
                  // several locked rows in this instance, or two mounted
                  // instances of PolicyEditor.
                  const noticeId = `${instanceId}-passthrough-notice-${i}`;
                  return (
                    <>
                      <div className="flex w-full items-center gap-2">
                        <label className="w-12 shrink-0 text-xs font-semibold text-muted-foreground">Host</label>
                        <Input
                          value={r.host}
                          onChange={(e) => setHost(i, e.target.value)}
                          placeholder="api.example.com or *.example.com"
                          className="flex-1 font-mono text-sm"
                          readOnly={locked}
                          aria-describedby={locked ? noticeId : undefined}
                          title={
                            locked
                              ? `Locked: this row carries a TLS-pinning passthrough port — ${PIN_ESCAPE_HINT}.`
                              : undefined
                          }
                        />
                      </div>
                      {locked && (
                        <p
                          id={noticeId}
                          className="w-full rounded-md border border-destructive/30 bg-destructive/10 px-2 py-1.5 text-xs text-destructive"
                        >
                          {passthroughNotice(pinned, r.access, enforcing)}
                        </p>
                      )}
                      <div className="flex w-full items-center gap-2">
                        <label className="w-12 shrink-0 text-xs font-semibold text-muted-foreground">Ports</label>
                        <PortEditor
                          ports={r.ports}
                          access={r.access}
                          enforcing={enforcing}
                          onAdd={(p) => addPort(i, p)}
                          onRemove={(p) => removePort(i, p)}
                        />
                      </div>
                      <div className="flex w-full items-center gap-2">
                        <label className="w-12 shrink-0 text-xs font-semibold text-muted-foreground">Access</label>
                        <AccessPicker
                          value={r.access}
                          onChange={(v) => setHostAccess(i, v)}
                        />
                      </div>
                    </>
                  );
                }}
                onAdd={addRow}
                onRemove={(i) => removeRow(i)}
                addLabel="Add host"
                emptyHint="No allowed hosts — add one to permit egress."
                rowAriaLabel={(_,i) => `Remove host ${i + 1}`}
              />
            </Section>

            <Section title="Git repos">
              <p className="mb-2 text-sm text-muted-foreground">
                Git repositories this sandbox may clone or push to. Specify as{" "}
                <span className="font-mono">host/owner/repo</span> or <span className="font-mono">host</span>.
              </p>
              <EditableList
                density="card"
                items={gitRows}
                renderRow={(gr, i) => (
                  <div className="flex w-full items-center gap-2">
                    <Input
                      value={gr.target}
                      onChange={(e) => setGitTarget(i, e.target.value)}
                      placeholder="github.com/owner/repo"
                      className="flex-1 font-mono text-sm"
                    />
                    <AccessPicker
                      value={gr.access}
                      onChange={(v) => setGitAccess(i, v)}
                    />
                  </div>
                )}
                onAdd={addGitRow}
                onRemove={(i) => removeGitRow(i)}
                addLabel="Add repo"
                emptyHint="No git rules — add one to allow a repo."
                rowAriaLabel={(_,i) => `Remove repo ${i + 1}`}
              />
            </Section>
          </div>
        ) : (
          /* Distinct from a loaded-and-empty policy on purpose: this pane
             states what is NOT known instead of rendering "No allowed hosts",
             whose "add one to permit egress" invitation is exactly what made
             the destructive click attractive. */
          <p className="pb-3 text-sm text-muted-foreground">
            {load.kind === "loading"
              ? "Loading this sandbox's policy… its allowed hosts, git rules and enforcement posture are not known yet."
              : `Could not read this sandbox's policy: ${load.message}. Its allowed hosts, git rules and enforcement posture are unknown — an errored load is not an empty policy, so nothing shown here may be written back. Reopen this tab to retry.`}
          </p>
        )}
      </div>

      {/* Save footer — always visible, never scrolls away */}
      <div className="flex shrink-0 items-center gap-2 border-t border-border pt-3">
        {/* `aria-disabled`, deliberately NOT the native `disabled` attribute:
            the click must still reach `save()`, which is where the refusal
            actually lives and where it produces a VISIBLE reason. A natively
            disabled button would swallow the click silently and would make
            any test of the guard vacuous — the guard, not the markup, is what
            protects managed truth here. */}
        <Button
          type="button"
          aria-disabled={load.kind !== "ready"}
          className={load.kind !== "ready" ? "opacity-50" : undefined}
          title={saveRefusal(load) ?? undefined}
          onClick={() => void save()}
        >
          Save
        </Button>
        {dirty && <span className="self-center text-sm text-muted-foreground">● unsaved changes</span>}
        {saved && !dirty && <span className="self-center text-sm text-muted-foreground">saved · reloaded</span>}
      </div>
    </div>
  );
}
