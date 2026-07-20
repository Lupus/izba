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
});
