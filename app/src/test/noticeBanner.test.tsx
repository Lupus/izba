import { fireEvent, render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { NoticeBanner } from "../components/NoticeBanner";

describe("NoticeBanner", () => {
  it("renders nothing without a notice", () => {
    render(<NoticeBanner notice={null} onDismiss={() => {}} />);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows the notice and Dismiss clears it", () => {
    const onDismiss = vi.fn();
    render(<NoticeBanner notice="run 'izba windows-cleanup'" onDismiss={onDismiss} />);
    expect(screen.getByRole("alert")).toHaveTextContent("izba windows-cleanup");
    fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(onDismiss).toHaveBeenCalled();
  });
});
