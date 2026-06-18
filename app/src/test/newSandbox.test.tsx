import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const { create, onCreateProgress } = vi.hoisted(() => ({
  create: vi.fn(),
  onCreateProgress: vi.fn(),
}));
vi.mock("../lib/ipc", () => ({ api: { create }, onCreateProgress }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn().mockResolvedValue("/picked/ws") }));

import { NewSandbox } from "../components/NewSandbox";

describe("NewSandbox", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    create.mockResolvedValue("web");
    onCreateProgress.mockResolvedValue(() => {});
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
});
