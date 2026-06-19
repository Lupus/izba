import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const { create, onCreateProgress, volumeList } = vi.hoisted(() => ({
  create: vi.fn(),
  onCreateProgress: vi.fn(),
  volumeList: vi.fn(),
}));
vi.mock("../lib/ipc", () => ({ api: { create, volumeList }, onCreateProgress }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn().mockResolvedValue("/picked/ws") }));

import { NewSandbox } from "../components/NewSandbox";

describe("NewSandbox", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    create.mockResolvedValue("web");
    onCreateProgress.mockResolvedValue(() => {});
    volumeList.mockResolvedValue([]);
  });

  it("submits create with form values", async () => {
    const onClose = vi.fn();
    render(<NewSandbox onClose={onClose} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(
        expect.objectContaining({ name: "web", workspace: "/ws", image: "ubuntu:24.04" }),
      ),
    );
  });

  it("assembles a host:guest port from an added row", async () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    fireEvent.change(screen.getByLabelText(/port 1 host/i), { target: { value: "8080" } });
    fireEvent.change(screen.getByLabelText(/port 1 guest/i), { target: { value: "80" } });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(expect.objectContaining({ ports: ["8080:80"] })),
    );
  });

  it("includes the bind prefix when given, and drops removed rows", async () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    fireEvent.change(screen.getByLabelText(/port 1 bind/i), { target: { value: "127.0.0.1" } });
    fireEvent.change(screen.getByLabelText(/port 1 host/i), { target: { value: "5432" } });
    fireEvent.change(screen.getByLabelText(/port 1 guest/i), { target: { value: "5432" } });
    fireEvent.click(screen.getByRole("button", { name: /remove port 2/i }));
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(
        expect.objectContaining({ ports: ["127.0.0.1:5432:5432"] }),
      ),
    );
  });

  it("labels the port columns and explains the bind field", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    expect(screen.getByText(/host port/i)).toBeInTheDocument();
    expect(screen.getByText(/guest port/i)).toBeInTheDocument();
    expect(screen.getByText(/defaults to 127\.0\.0\.1/i)).toBeInTheDocument();
  });

  it("disables Create and explains when a port is not a valid number", async () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    fireEvent.change(screen.getByLabelText(/port 1 host/i), { target: { value: "sdfsdf" } });
    fireEvent.change(screen.getByLabelText(/port 1 guest/i), { target: { value: "80" } });
    expect(screen.getByText(/65535/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /create/i })).toBeDisabled();
  });

  it("disables Create when the bind address is not a valid IPv4", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    fireEvent.change(screen.getByLabelText(/port 1 bind/i), { target: { value: "sdsdasdas" } });
    fireEvent.change(screen.getByLabelText(/port 1 host/i), { target: { value: "8080" } });
    fireEvent.change(screen.getByLabelText(/port 1 guest/i), { target: { value: "80" } });
    expect(screen.getByText(/IPv4/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /create/i })).toBeDisabled();
  });

  it("an empty port row does not block Create", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    expect(screen.getByRole("button", { name: /create/i })).not.toBeDisabled();
  });

  it("disables Create when name is empty", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    expect(screen.getByRole("button", { name: /create/i })).toBeDisabled();
  });

  it("surfaces a create error", async () => {
    create.mockRejectedValueOnce(new Error("invalid sandbox name 'X'"));
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "x" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() => expect(screen.getByText(/invalid sandbox name/i)).toBeInTheDocument());
  });

  // ── Volume section (E2) ─────────────────────────────────────────────────

  it("submits a named volume row as name:path:size", async () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    // Switch to new persistent type
    fireEvent.click(screen.getByRole("button", { name: /new persistent/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 name/i), { target: { value: "cache" } });
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(
        expect.objectContaining({ volumes: ["cache:/data:1g"] }),
      ),
    );
  });

  it("disables Create when volume path lacks leading slash", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("button", { name: /new persistent/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 name/i), { target: { value: "cache" } });
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });
    expect(screen.getByRole("button", { name: /create/i })).toBeDisabled();
  });

  it("disables Create when volume size is invalid", () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("button", { name: /new persistent/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 name/i), { target: { value: "cache" } });
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/data" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1x" } });
    expect(screen.getByRole("button", { name: /create/i })).toBeDisabled();
  });

  it("emits ephemeral spec (no name prefix) for empty-name volume row", async () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    // Ephemeral is the default type
    fireEvent.click(screen.getByRole("button", { name: /ephemeral/i }));
    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/scratch" } });
    fireEvent.change(screen.getByLabelText(/volume 1 size/i), { target: { value: "1g" } });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(
        expect.objectContaining({ volumes: ["/scratch:1g"] }),
      ),
    );
  });

  it("existing persistent: emits name:path:sizeMiB m spec on Create", async () => {
    volumeList.mockResolvedValue([
      { name: "archive", size_bytes: 1073741824, actual_bytes: 0, referenced_by: [] },
    ]);
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));

    // Switch to existing persistent type
    fireEvent.click(screen.getByRole("button", { name: /existing/i }));

    await waitFor(() => expect(volumeList).toHaveBeenCalled());
    const select = screen.getByRole("combobox", { name: /existing volume/i });
    fireEvent.change(select, { target: { value: "archive" } });

    fireEvent.change(screen.getByLabelText(/volume 1 path/i), { target: { value: "/arch" } });

    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(
        expect.objectContaining({ volumes: ["archive:/arch:1024m"] }),
      ),
    );
  });

  it("ignores fully-blank volume rows on submit", async () => {
    render(<NewSandbox onClose={() => {}} onCreated={() => {}} />);
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText(/workspace/i), { target: { value: "/ws" } });
    fireEvent.click(screen.getByRole("button", { name: /add volume/i }));
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(expect.objectContaining({ volumes: [] })),
    );
  });
});
