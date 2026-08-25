import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach, type Mock } from "vitest";
import { PolicyEditor } from "../components/PolicyEditor";
import { api } from "../lib/ipc";

vi.mock("../lib/ipc", () => ({
  api: {
    policyShow: vi.fn(),
    policySet: vi.fn(),
    policySetFull: vi.fn(),
    policySetEnforce: vi.fn(),
    policyGitAllow: vi.fn(),
    policyGitBlock: vi.fn(),
  },
}));

beforeEach(() => {
  vi.clearAllMocks();
  (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
    enforcing: true,
    allow: ["api.x.com", { host: "db.internal", ports: [5432] }],
    git: [],
  });
  (api.policySetEnforce as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
  (api.policySetFull as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
});

describe("PolicyEditor layout", () => {
  it("root has h-full and flex-col, scroll region has overflow-y-auto and min-h-0", async () => {
    const { container } = render(<PolicyEditor name="web" />);
    // Wait for load
    await screen.findByDisplayValue("api.x.com");
    // Root div must be h-full flex-col (makes the component fill its parent column)
    const root = container.firstElementChild as HTMLElement;
    expect(root.className).toMatch(/\bh-full\b/);
    expect(root.className).toMatch(/\bflex-col\b/);
    // Scroll region: a direct child of root with overflow-y-auto and min-h-0
    const scrollRegion = Array.from(root.children).find(
      (el) =>
        el.className.includes("overflow-y-auto") &&
        el.className.includes("min-h-0"),
    );
    expect(scrollRegion).toBeDefined();
  });
});

describe("PolicyEditor", () => {
  it("renders entries and saves normalized rows via policySetFull", async () => {
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("api.x.com");
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        [
          { host: "api.x.com", ports: [80, 443], access: "read-write" },
          { host: "db.internal", ports: [5432], access: "read-write" },
        ],
        [],
      ),
    );
  });

  it("adds a port to a host via the add-port field", async () => {
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("db.internal");
    // Second row (db.internal) has the second "add port" input.
    const adders = screen.getAllByLabelText("add port");
    fireEvent.change(adders[1], { target: { value: "8443" } });
    fireEvent.keyDown(adders[1], { key: "Enter" });
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        [
          { host: "api.x.com", ports: [80, 443], access: "read-write" },
          { host: "db.internal", ports: [5432, 8443], access: "read-write" },
        ],
        [],
      ),
    );
  });

  it("adds a port via the Add button (not just Enter)", async () => {
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("db.internal");
    const adders = screen.getAllByLabelText("add port");
    fireEvent.change(adders[1], { target: { value: "8443" } });
    fireEvent.click(screen.getAllByRole("button", { name: /^add$/i })[1]);
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        [
          { host: "api.x.com", ports: [80, 443], access: "read-write" },
          { host: "db.internal", ports: [5432, 8443], access: "read-write" },
        ],
        [],
      ),
    );
  });

  it("shows an inline error and keeps the draft on non-numeric input", async () => {
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("api.x.com");
    const adder = screen.getAllByLabelText("add port")[0];
    fireEvent.change(adder, { target: { value: "sdfsdf" } });
    fireEvent.keyDown(adder, { key: "Enter" });
    expect(screen.getByText(/between 1 and 65535/i)).toBeInTheDocument();
    // The draft is preserved so the user can correct it — not silently cleared.
    expect((adder as HTMLInputElement).value).toBe("sdfsdf");
    // Nothing was added: saving yields the original ports.
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        [
          { host: "api.x.com", ports: [80, 443], access: "read-write" },
          { host: "db.internal", ports: [5432], access: "read-write" },
        ],
        [],
      ),
    );
  });

  it("does nothing (no error) when Add is clicked with an empty field", async () => {
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("api.x.com");
    fireEvent.click(screen.getAllByRole("button", { name: /^add$/i })[0]);
    expect(screen.queryByText(/between 1 and 65535/i)).not.toBeInTheDocument();
  });

  it("rejects a duplicate port already in the list", async () => {
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("api.x.com");
    const adder = screen.getAllByLabelText("add port")[0];
    fireEvent.change(adder, { target: { value: "443" } }); // api.x.com already has 443
    fireEvent.click(screen.getAllByRole("button", { name: /^add$/i })[0]);
    expect(screen.getByText(/already added/i)).toBeInTheDocument();
  });

  it("rejects an out-of-range port", async () => {
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("api.x.com");
    const adder = screen.getAllByLabelText("add port")[0];
    fireEvent.change(adder, { target: { value: "70000" } });
    fireEvent.click(screen.getAllByRole("button", { name: /^add$/i })[0]);
    expect(screen.getByText(/between 1 and 65535/i)).toBeInTheDocument();
  });

  it("removes a port chip", async () => {
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("api.x.com");
    fireEvent.click(screen.getByRole("button", { name: /remove port 80/i }));
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        [
          { host: "api.x.com", ports: [443], access: "read-write" },
          { host: "db.internal", ports: [5432], access: "read-write" },
        ],
        [],
      ),
    );
  });

  it("toggles enforce via the daemon", async () => {
    (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
      enforcing: true,
      allow: [],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    // Wait for the component to load the policy
    const toggle = await screen.findByRole("switch", { name: /enforce/i });
    expect(toggle).toBeChecked();
    fireEvent.click(toggle);
    await waitFor(() =>
      expect(api.policySetEnforce).toHaveBeenCalledWith("web", false),
    );
  });

  it("uses the shared WEB_DEFAULT_PORTS constant", async () => {
    const { WEB_DEFAULT_PORTS } = await import("../lib/ports");
    expect(WEB_DEFAULT_PORTS).toEqual([80, 443]);
  });

  it("renders existing git rules in a Git repos section", async () => {
    (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
      enforcing: true,
      allow: [],
      git: [{ repo: "github.com/o/a", access: "read" }],
    });
    render(<PolicyEditor name="web" />);
    // Section renders a button with title as accessible name (the heading-like element)
    expect(await screen.findByRole("button", { name: /git repos/i })).toBeInTheDocument();
    expect(screen.getByDisplayValue("github.com/o/a")).toBeInTheDocument();
  });

  // Staged save: adding a git row and saving uses policySetFull, not policyGitAllow
  it("one Save persists hosts and git together via policySetFull", async () => {
    (api.policyShow as Mock).mockResolvedValue({ enforcing: false, allow: [{host:"a.com",ports:[443]}], git: [] });
    const setFull = api.policySetFull as Mock;
    render(<PolicyEditor name="web" />);
    // add a git repo row, type a target, pick read-write
    fireEvent.click(await screen.findByRole("button", { name: /Add repo/ }));
    fireEvent.change(screen.getByPlaceholderText("github.com/owner/repo"), { target: { value: "github.com/o/a" } });
    fireEvent.click(screen.getByRole("button", { name: /Save/ }));
    await waitFor(() => expect(setFull).toHaveBeenCalledWith("web",
      [{ host: "a.com", ports: [443], access: "read-write" }],
      [{ repo: "github.com/o/a", access: "read" }]));
  });

  it("git target input is editable even when firewall is off", async () => {
    (api.policyShow as Mock).mockResolvedValue({ enforcing: false, allow: [], git: [] });
    render(<PolicyEditor name="web" />);
    fireEvent.click(await screen.findByRole("button", { name: /Add repo/ }));
    const input = screen.getByPlaceholderText("github.com/owner/repo") as HTMLInputElement;
    expect(input.disabled).toBe(false);
  });

  it("preserves per-host access=read on Save without editing the row", async () => {
    (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
      enforcing: true,
      allow: [{ host: "pypi.org", ports: [80, 443], access: "read" }],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pypi.org");
    // Click Save without touching the row at all.
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        expect.arrayContaining([
          expect.objectContaining({ host: "pypi.org", access: "read" }),
        ]),
        [],
      ),
    );
    // Make sure it was NOT called with access: "read-write" for pypi.org.
    const calls = (api.policySetFull as ReturnType<typeof vi.fn>).mock.calls;
    const allow: Array<{ host: string; access?: string }> = calls[0][1];
    const pypi = allow.find((e) => e.host === "pypi.org");
    expect(pypi?.access).toBe("read");
  });

  // --- #238: the declaration is per-PORT, so the GUI must carry it per port ---
  //
  // F-1 (below, restated) is why preservation is load-bearing: this path
  // writes policy.yaml through the daemon directly and never passes the
  // diff/promote weakening gate, so a Save that silently drops a declaration
  // performs an unflagged security weakening. Since #238 the declaration
  // rides on the port element rather than the entry, so "preserve" now means
  // preserve it against the right port.

  it("preserves a per-port protocol: http on Save without editing the row", async () => {
    (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
      enforcing: true,
      allow: [
        {
          host: "internal.example.com",
          ports: [{ port: 8000, protocol: "http" }],
          access: "read",
        },
      ],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("internal.example.com");
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        [
          {
            host: "internal.example.com",
            ports: [{ port: 8000, protocol: "http" }],
            access: "read",
          },
        ],
        [],
      ),
    );
  });

  it("preserves a per-port protocol: tcp against its own port, not the whole entry", async () => {
    // The port the operator pinned keeps its declaration; the port beside it
    // must come back as a BARE number. Emitting `{port: 80, protocol: "tcp"}`
    // here would be the widening this issue exists to make inexpressible,
    // performed by the GUI on a Save nobody asked to change posture.
    (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
      enforcing: true,
      allow: [{ host: "pinned.vendor.com", ports: [80, { port: 443, protocol: "tcp" }] }],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        [
          {
            host: "pinned.vendor.com",
            ports: [80, { port: 443, protocol: "tcp" }],
            access: "read-write",
          },
        ],
        [],
      ),
    );
  });

  it("adds a new port as a bare number, never inheriting a sibling's declaration", async () => {
    (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
      enforcing: true,
      allow: [{ host: "pinned.vendor.com", ports: [{ port: 443, protocol: "tcp" }] }],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    fireEvent.change(screen.getByLabelText("add port"), { target: { value: "8080" } });
    fireEvent.click(screen.getByRole("button", { name: /^add$/i }));
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(api.policySetFull).toHaveBeenCalled());
    const calls = (api.policySetFull as ReturnType<typeof vi.fn>).mock.calls;
    const allow: Array<{ ports: Array<number | { port: number }> }> = calls[0][1];
    expect(allow[0].ports).toEqual([{ port: 443, protocol: "tcp" }, 8080]);
  });

  it("does not emit a protocol key for a port that never had one", async () => {
    // A value the GUI never read must not be invented on Save — canonical
    // YAML for an entry with no declared protocol must not change.
    (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
      enforcing: true,
      allow: [{ host: "api.x.com", ports: [443] }],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("api.x.com");
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(api.policySetFull).toHaveBeenCalled());
    const calls = (api.policySetFull as ReturnType<typeof vi.fn>).mock.calls;
    const allow: Array<{ ports: unknown[] }> = calls[0][1];
    expect(allow[0].ports).toEqual([443]);
  });

  it("marks the pinned port, and only the pinned port, in the editor", async () => {
    // #239's display gap, narrowed to what #238 owns: a passthrough port must
    // not render identically to an ordinary one, and the marker belongs to
    // the PORT that carries the declaration.
    (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
      enforcing: true,
      allow: [{ host: "pinned.vendor.com", ports: [80, { port: 443, protocol: "tcp" }] }],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    expect(
      screen.getByLabelText(
        "Port 443: TLS-pinning passthrough — spliced opaquely, with no L7 rules, no request audit and no upstream certificate verification",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText(/^Port 80: /)).not.toBeInTheDocument();
  });

  it("marks the pinned port as NOT in effect when its row's access cancels it", async () => {
    // Final-review Important A: the chip's aria-label/title must agree with
    // the row's visible notice about whether the hatch is actually live —
    // a screen-reader user (or anyone hovering the chip) must not be told
    // the live substance for a row whose access never authorizes a splice.
    (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
      enforcing: true,
      allow: [
        { host: "pinned.vendor.com", ports: [{ port: 443, protocol: "tcp" }], access: "read" },
      ],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    expect(
      screen.getByLabelText(
        "Port 443: TLS-pinning passthrough NOT in effect — an opaque splice carries no HTTP method, " +
          'so this row\'s "read" access never authorizes one; the connection stays terminated at L7 ' +
          "and a pinning client still sees izba's certificate. To pin, widen access in policy.yaml, " +
          "or in izba.yml followed by izba diff / izba promote",
      ),
    ).toBeInTheDocument();
    // Must NOT claim the live substance.
    expect(
      screen.queryByLabelText(/no upstream certificate verification$/),
    ).not.toBeInTheDocument();
  });

  it("marks a port declared http as inspected", async () => {
    (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
      enforcing: true,
      allow: [{ host: "internal.example.com", ports: [{ port: 8000, protocol: "http" }] }],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("internal.example.com");
    expect(
      screen.getByLabelText("Port 8000: inspected at L7 (declared protocol: http)"),
    ).toBeInTheDocument();
  });

  it("loads a ports-less allow entry (backend None) without crashing", async () => {
    // Regression: a Scoped entry whose ports == web defaults comes back with no
    // `ports` field. toRow must default to the web ports, not undefined.
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [{ host: "pypi.org", access: "read" }],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    expect(await screen.findByDisplayValue("pypi.org")).toBeInTheDocument();
    // Saving sends the web-default ports for the ports-less entry.
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        [{ host: "pypi.org", ports: [80, 443], access: "read" }],
        [],
      ),
    );
  });

  it("accepts a wildcard host pattern and saves it", async () => {
    (api.policyShow as Mock).mockResolvedValue({ enforcing: true, allow: [], git: [] });
    render(<PolicyEditor name="web" />);
    fireEvent.click(await screen.findByRole("button", { name: /Add host/i }));
    fireEvent.change(screen.getByPlaceholderText(/example\.com/i), {
      target: { value: "*.example.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        [{ host: "*.example.com", ports: [80, 443], access: "read-write" }],
        [],
      ),
    );
  });

  it("Add host seeds the web default ports 80 and 443", async () => {
    (api.policyShow as Mock).mockResolvedValue({ enforcing: true, allow: [], git: [] });
    render(<PolicyEditor name="web" />);
    fireEvent.click(await screen.findByRole("button", { name: /Add host/i }));
    const chips = screen.getAllByText(/^(80|443)$/);
    expect(chips.map((c) => c.textContent)).toEqual(
      expect.arrayContaining(["80", "443"]),
    );
  });

  it("rejects a malformed wildcard pattern before saving", async () => {
    (api.policyShow as Mock).mockResolvedValue({ enforcing: true, allow: [], git: [] });
    render(<PolicyEditor name="web" />);
    fireEvent.click(await screen.findByRole("button", { name: /Add host/i }));
    fireEvent.change(screen.getByPlaceholderText(/example\.com/i), {
      target: { value: "foo.*.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(screen.getByText(/foo\.\*\.com/)).toBeInTheDocument());
    expect(api.policySetFull).not.toHaveBeenCalled();
  });

  it("rejects a wildcard pattern containing glob metacharacters before saving", async () => {
    // *.git{hub.com,evil.com} looks like a well-formed leading-'*.' wildcard
    // but `{}` is a wax glob alternation metacharacter — regorus glob.match
    // would treat it as matching either "githu.com" branch, silently
    // widening egress far beyond what the pattern's author intended.
    (api.policyShow as Mock).mockResolvedValue({ enforcing: true, allow: [], git: [] });
    render(<PolicyEditor name="web" />);
    fireEvent.click(await screen.findByRole("button", { name: /Add host/i }));
    fireEvent.change(screen.getByPlaceholderText(/example\.com/i), {
      target: { value: "*.git{hub.com,evil.com}" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(screen.getByText(/git\{hub\.com,evil\.com\}/)).toBeInTheDocument(),
    );
    expect(api.policySetFull).not.toHaveBeenCalled();
  });

  // --- #239: a `protocol: tcp` port is a TLS-pinning passthrough — spliced
  // opaquely, no L7 rules, no request audit, no upstream certificate
  // verification. The GUI must surface that fact visibly (not just in an
  // aria-label) and must never let a Save relocate the hatch onto a host
  // that never declared one, since this Save path skips the diff/promote
  // weakening gate.

  it("renders a visible passthrough notice on a row carrying a pinned port", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [{ host: "pinned.vendor.com", ports: [80, { port: 443, protocol: "tcp" }] }],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    // Visible text, not merely an aria-label/title — naming the pinned port
    // and carrying the full substance of what the passthrough gives up.
    // Each clause is asserted individually so the notice cannot silently
    // lose one and still pass (a wildcard `.*` regex would let that slide).
    const notice = screen.getByText(/Port 443:/i);
    expect(notice.textContent).toMatch(/Port 443:/);
    expect(notice.textContent).toMatch(/spliced opaquely/);
    expect(notice.textContent).toMatch(/no L7 rules/);
    expect(notice.textContent).toMatch(/no request audit/);
    expect(notice.textContent).toMatch(/no upstream certificate verification/);
  });

  it("renders no passthrough notice for a port declared http", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [{ host: "internal.example.com", ports: [{ port: 8000, protocol: "http" }] }],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("internal.example.com");
    expect(screen.queryByText(/TLS-pinning passthrough/i)).not.toBeInTheDocument();
    expect(screen.queryByText("⚠ tcp")).not.toBeInTheDocument();
  });

  it("renders no passthrough notice for an undeclared port", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [{ host: "plain.example.com", ports: [443] }],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("plain.example.com");
    expect(screen.queryByText(/TLS-pinning passthrough/i)).not.toBeInTheDocument();
    expect(screen.queryByText("⚠ tcp")).not.toBeInTheDocument();
  });

  it("locks the Host field of a row carrying a pinned port", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [
        { host: "pinned.vendor.com", ports: [80, { port: 443, protocol: "tcp" }] },
        "ordinary.example.com",
      ],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    const pinnedInput = (await screen.findByDisplayValue(
      "pinned.vendor.com",
    )) as HTMLInputElement;
    const ordinaryInput = screen.getByDisplayValue("ordinary.example.com") as HTMLInputElement;
    expect(pinnedInput.readOnly).toBe(true);
    expect(ordinaryInput.readOnly).toBe(false);
  });

  it("unlocks the Host field once the pinned port is removed", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [{ host: "pinned.vendor.com", ports: [80, { port: 443, protocol: "tcp" }] }],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    expect(screen.getByText(/TLS-pinning passthrough/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /remove port 443/i }));
    const input = screen.getByDisplayValue("pinned.vendor.com") as HTMLInputElement;
    expect(input.readOnly).toBe(false);
    expect(screen.queryByText(/TLS-pinning passthrough/i)).not.toBeInTheDocument();
  });

  it("keeps a pinned row's host inert against a direct DOM change event", async () => {
    // The lock must be behavioural, not merely the `readOnly` HTML attribute:
    // `fireEvent.change` (and scripted automation generally) can dispatch a
    // change event on a readOnly input directly, bypassing what a real
    // browser's keyboard-editing restriction would block. `setHost` itself
    // must refuse to apply the edit for a row that still carries a pinned
    // port.
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [{ host: "pinned.vendor.com", ports: [80, { port: 443, protocol: "tcp" }] }],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    const input = (await screen.findByDisplayValue("pinned.vendor.com")) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "attacker.example.com" } });
    expect(input.value).toBe("pinned.vendor.com");
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        [expect.objectContaining({ host: "pinned.vendor.com" })],
        [],
      ),
    );
  });

  it("preserves protocol: tcp when an unrelated field on the row is edited and saved", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [
        {
          host: "pinned.vendor.com",
          ports: [80, { port: 443, protocol: "tcp" }],
          access: "read-write",
        },
      ],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    // Change Access on the pinned row — an edit unrelated to the port
    // declaration or the host.
    fireEvent.click(screen.getByRole("radio", { name: "read" }));
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        [
          {
            host: "pinned.vendor.com",
            ports: [80, { port: 443, protocol: "tcp" }],
            access: "read",
          },
        ],
        [],
      ),
    );
  });

  // --- Final-review round: the notice must not misreport posture for a
  // pinned row whose `access` cancels the hatch (1a), and widening Access
  // on a pinned row must be refused the same way renaming its Host is (1b).
  // An opaque splice carries no HTTP method, so `access: read` never
  // authorizes one (egress.rego's host_access_ok("read") requires GET/HEAD);
  // router::passthrough_names drops the host and the connection stays
  // terminated at L7. The CLI (crates/izba-cli/src/commands/policy.rs)
  // already renders this NOT-in-effect case distinctly — the GUI must not
  // disagree.

  it("renders the NOT-in-effect notice for a pinned row whose access cancels the hatch", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [
        { host: "pinned.vendor.com", ports: [{ port: 443, protocol: "tcp" }], access: "read" },
      ],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    const notice = screen.getByText(/Port 443:/i);
    // Distinguishing clauses asserted individually — a `.*`-spanning regex
    // would let any one of these silently vanish and still pass.
    expect(notice.textContent).toMatch(/NOT in effect/);
    expect(notice.textContent).toMatch(/opaque splice carries no HTTP method/);
    expect(notice.textContent).toMatch(/stays terminated at L7/);
    expect(notice.textContent).toMatch(/pinning client still sees izba's certificate/);
    // The route to actually pin is qualified — NOT a bare instruction to use
    // the (silently refused) picker; see Important B, final review.
    expect(notice.textContent).toMatch(/To pin, widen access in policy\.yaml/);
    expect(notice.textContent).not.toMatch(/[Ww]iden to read-write to pin\b/);
    // Must NOT claim the live substance — that would misreport this row.
    expect(notice.textContent).not.toMatch(/no upstream certificate verification/);
    // …nor the inert substance: this sandbox IS enforcing, so the hatch is
    // cancelled by access, not by a stopped firewall (three-way split).
    expect(notice.textContent).not.toMatch(/enforcement is off/i);
  });

  it("keeps the live notice for a pinned row with read-write access", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [
        {
          host: "pinned.vendor.com",
          ports: [{ port: 443, protocol: "tcp" }],
          access: "read-write",
        },
      ],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    const notice = screen.getByText(/Port 443:/i);
    expect(notice.textContent).toMatch(/spliced opaquely/);
    expect(notice.textContent).toMatch(/no L7 rules/);
    expect(notice.textContent).toMatch(/no request audit/);
    expect(notice.textContent).toMatch(/no upstream certificate verification/);
    // Must NOT claim the dormant substance.
    expect(notice.textContent).not.toMatch(/NOT in effect/);
    expect(notice.textContent).not.toMatch(/enforcement is off/i);
  });

  // --- Dogfooding, passthrough run (#239 parity): with enforcement OFF the
  // compiled policy is AllowAll (`EgressPolicyConfig::compile`) and
  // `router::passthrough_names` returns nothing, so no connection is
  // terminated and there is nothing to splice. `izba policy show` renders
  // that inert case distinctly; this tab is the other revealing surface and
  // must not disagree about the same policy. Display only.

  it("renders the inert notice for a pinned row when the sandbox is not enforcing", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: false,
      allow: [
        {
          host: "pinned.vendor.com",
          ports: [{ port: 443, protocol: "tcp" }],
          access: "read-write",
        },
      ],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    const notice = screen.getByText(/Port 443:/i);
    expect(notice.textContent).toMatch(/NOT in effect/);
    expect(notice.textContent).toMatch(/enforcement is off/i);
    expect(notice.textContent).toMatch(/every destination is reachable/);
    expect(notice.textContent).toMatch(/no connection is terminated or spliced/);
    expect(notice.textContent).toMatch(/inert/);
    // An access level that would carry the LIVE hatch under enforcement must
    // not print it here — that claim is the finding.
    expect(notice.textContent).not.toMatch(/spliced opaquely/);
    expect(notice.textContent).not.toMatch(/no upstream certificate verification/);
    // A declaration is still worth flagging even when inert.
    expect(screen.getByText("\u26A0 tcp")).toBeInTheDocument();
  });

  it("prefers the inert wording over the access-cancelled wording when enforcement is off", async () => {
    // Three postures, one label: the enforce-off case is decided FIRST, the
    // same order `izba policy show` uses — an access level cannot cancel a
    // hatch that a stopped firewall never opened.
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: false,
      allow: [
        { host: "pinned.vendor.com", ports: [{ port: 443, protocol: "tcp" }], access: "read" },
      ],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    const notice = screen.getByText(/Port 443:/i);
    expect(notice.textContent).toMatch(/enforcement is off/i);
    expect(notice.textContent).not.toMatch(/opaque splice carries no HTTP method/);
  });

  it("joins the notice for two pinned ports on the same row, naming both", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [
        {
          host: "pinned.vendor.com",
          ports: [
            { port: 443, protocol: "tcp" },
            { port: 8443, protocol: "tcp" },
          ],
        },
      ],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    const notice = screen.getByText(/Port 443:/i);
    expect(notice.textContent).toMatch(/Port 443:/);
    expect(notice.textContent).toMatch(/Port 8443:/);
  });

  it("states the remediation for the lock in the visible notice", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [{ host: "pinned.vendor.com", ports: [{ port: 443, protocol: "tcp" }] }],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    const notice = screen.getByText(/Port 443:/i);
    expect(notice.textContent).toMatch(/remove the pinned port/i);
    expect(notice.textContent).toMatch(/izba diff/);
    expect(notice.textContent).toMatch(/izba promote/);
  });

  it("states the Access-widening refusal in a dormant row's remediation, without telling the operator to use the refused picker", async () => {
    // Final-review Important B: the old dormant wording said "Widen to
    // read-write to pin" — the exact click the 1b guard silently refuses.
    // The corrected copy must explain the refusal AND name a route that
    // actually works (editing the file directly), never the picker.
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [
        { host: "pinned.vendor.com", ports: [{ port: 443, protocol: "tcp" }], access: "read" },
      ],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    const notice = screen.getByText(/Port 443:/i);
    expect(notice.textContent).toMatch(/widening Access to read-write here is refused/i);
    expect(notice.textContent).toMatch(/silently activate the passthrough/i);
    expect(notice.textContent).toMatch(/remove the pinned port/i);
    expect(notice.textContent).toMatch(/widen access in policy\.yaml/i);
    // The contradictory instruction from the pre-fix wording must be gone.
    expect(notice.textContent).not.toMatch(/[Ww]iden to read-write to pin\b/);
  });

  it("refuses widening Access from read to read-write on a dormant pinned row", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [
        {
          host: "pinned.vendor.com",
          ports: [80, { port: 443, protocol: "tcp" }],
          access: "read",
        },
      ],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    const readWriteRadio = screen.getByRole("radio", { name: "read-write" });
    fireEvent.click(readWriteRadio);
    // Rendered control state must not move: the click is refused, so "read"
    // stays the checked option.
    expect(screen.getByRole("radio", { name: "read" })).toHaveAttribute("aria-checked", "true");
    expect(readWriteRadio).toHaveAttribute("aria-checked", "false");
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        [
          {
            host: "pinned.vendor.com",
            ports: [80, { port: 443, protocol: "tcp" }],
            access: "read",
          },
        ],
        [],
      ),
    );
  });

  it("still allows narrowing Access from read-write to read on a live pinned row", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [
        {
          host: "pinned.vendor.com",
          ports: [80, { port: 443, protocol: "tcp" }],
          access: "read-write",
        },
      ],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("pinned.vendor.com");
    fireEvent.click(screen.getByRole("radio", { name: "read" }));
    expect(screen.getByRole("radio", { name: "read" })).toHaveAttribute("aria-checked", "true");
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        [
          {
            host: "pinned.vendor.com",
            ports: [80, { port: 443, protocol: "tcp" }],
            access: "read",
          },
        ],
        [],
      ),
    );
  });

  it("still allows widening Access to read-write on an ordinary unpinned row", async () => {
    (api.policyShow as Mock).mockResolvedValue({
      enforcing: true,
      allow: [{ host: "plain.example.com", ports: [443], access: "read" }],
      git: [],
    });
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("plain.example.com");
    fireEvent.click(screen.getByRole("radio", { name: "read-write" }));
    expect(screen.getByRole("radio", { name: "read-write" })).toHaveAttribute(
      "aria-checked",
      "true",
    );
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySetFull).toHaveBeenCalledWith(
        "web",
        [{ host: "plain.example.com", ports: [443], access: "read-write" }],
        [],
      ),
    );
  });
});
