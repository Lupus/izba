import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { PolicyEditor } from "../components/PolicyEditor";
import { api } from "../lib/ipc";

vi.mock("../lib/ipc", () => ({
  api: { policyShow: vi.fn(), policySet: vi.fn() },
}));

beforeEach(() => {
  vi.clearAllMocks();
  (api.policyShow as ReturnType<typeof vi.fn>).mockResolvedValue({
    enforcing: true,
    allow: ["api.x.com", { host: "db.internal", ports: [5432] }],
  });
});

describe("PolicyEditor", () => {
  it("renders entries and saves normalized rows", async () => {
    render(<PolicyEditor name="web" />);
    await screen.findByDisplayValue("api.x.com");
    fireEvent.click(screen.getByRole("button", { name: /save/i }));
    await waitFor(() =>
      expect(api.policySet).toHaveBeenCalledWith("web", [
        { host: "api.x.com", ports: [80, 443] },
        { host: "db.internal", ports: [5432] },
      ]),
    );
  });
});
