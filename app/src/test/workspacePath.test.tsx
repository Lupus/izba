import { render, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach, type Mock } from "vitest";
import { WorkspacePath } from "../components/WorkspacePath";
import { api } from "../lib/ipc";

vi.mock("../lib/ipc", () => ({
  api: {
    inspect: vi.fn(),
  },
}));

function detail(workspace: string) {
  return {
    name: "web",
    image: "ubuntu:24.04",
    status: "running",
    workspace,
    ports: [],
    volumes: [],
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("WorkspacePath", () => {
  it("renders the labeled workspace path once inspect resolves", async () => {
    (api.inspect as Mock).mockResolvedValue(detail("/home/u/proj"));
    render(<WorkspacePath name="web" />);

    expect(await screen.findByText("/home/u/proj")).toBeInTheDocument();
    expect(screen.getByText(/workspace/i)).toBeInTheDocument();
    expect(api.inspect).toHaveBeenCalledWith("web");
  });

  it("renders nothing when inspect fails (best-effort, never an error banner)", async () => {
    (api.inspect as Mock).mockRejectedValue(new Error("daemon restarting"));
    const { container } = render(<WorkspacePath name="web" />);

    await waitFor(() => expect(api.inspect).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing for an empty recorded workspace", async () => {
    (api.inspect as Mock).mockResolvedValue(detail(""));
    const { container } = render(<WorkspacePath name="web" />);

    await waitFor(() => expect(api.inspect).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });
});
