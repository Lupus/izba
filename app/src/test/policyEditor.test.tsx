import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { PolicyEditor } from "../components/PolicyEditor";
import { api } from "../lib/ipc";

vi.mock("../lib/ipc", () => ({
  api: {
    policyShow: vi.fn(),
    policySet: vi.fn(),
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
});

describe("PolicyEditor", () => {
  it("renders entries and saves normalized rows", async () => {
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("api.x.com");
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.policySet).toHaveBeenCalledWith("web", [
        { host: "api.x.com", ports: [80, 443] },
        { host: "db.internal", ports: [5432] },
      ]),
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
      expect(api.policySet).toHaveBeenCalledWith("web", [
        { host: "api.x.com", ports: [80, 443] },
        { host: "db.internal", ports: [5432, 8443] },
      ]),
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
      expect(api.policySet).toHaveBeenCalledWith("web", [
        { host: "api.x.com", ports: [80, 443] },
        { host: "db.internal", ports: [5432, 8443] },
      ]),
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
      expect(api.policySet).toHaveBeenCalledWith("web", [
        { host: "api.x.com", ports: [80, 443] },
        { host: "db.internal", ports: [5432] },
      ]),
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
      expect(api.policySet).toHaveBeenCalledWith("web", [
        { host: "api.x.com", ports: [443] },
        { host: "db.internal", ports: [5432] },
      ]),
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
    const toggle = await screen.findByRole("checkbox", { name: /enforce/i });
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
    expect(await screen.findByRole("heading", { name: /git repos/i })).toBeInTheDocument();
    expect(screen.getByText("github.com/o/a")).toBeInTheDocument();
  });

  it("calls policyGitAllow when adding a git rule and saving", async () => {
    (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
      enforcing: true,
      allow: [],
      git: [],
    });
    (api.policyGitAllow as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    render(<PolicyEditor name="web" />);
    await screen.findByRole("heading", { name: /git repos/i });
    // Find and fill the "add repo" input
    const input = screen.getByPlaceholderText(/github\.com\/owner\/repo/i);
    fireEvent.change(input, { target: { value: "github.com/o/b" } });
    fireEvent.keyDown(input, { key: "Enter" });
    // The row should appear; now save it
    await screen.findByText("github.com/o/b");
    fireEvent.click(screen.getByRole("button", { name: /^save git$/i }));
    await waitFor(() =>
      expect(api.policyGitAllow).toHaveBeenCalledWith("web", "github.com/o/b", false),
    );
  });

  it("calls policyGitBlock when removing a git rule", async () => {
    (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
      enforcing: true,
      allow: [],
      git: [{ repo: "github.com/o/a", access: "read" }],
    });
    (api.policyGitBlock as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    render(<PolicyEditor name="web" />);
    await screen.findByText("github.com/o/a");
    fireEvent.click(screen.getByRole("button", { name: /remove github\.com\/o\/a/i }));
    await waitFor(() =>
      expect(api.policyGitBlock).toHaveBeenCalledWith("web", "github.com/o/a"),
    );
  });

  it("calls policyGitAllow with write=true when access is changed to read-write", async () => {
    (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
      enforcing: true,
      allow: [],
      git: [{ repo: "github.com/o/a", access: "read" }],
    });
    (api.policyGitAllow as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    render(<PolicyEditor name="web" />);
    await screen.findByText("github.com/o/a");
    // Click "read-write" in the AccessPicker for that row
    fireEvent.click(screen.getByRole("button", { name: /read-write/i }));
    fireEvent.click(screen.getByRole("button", { name: /^save git$/i }));
    await waitFor(() =>
      expect(api.policyGitAllow).toHaveBeenCalledWith("web", "github.com/o/a", true),
    );
  });
});
