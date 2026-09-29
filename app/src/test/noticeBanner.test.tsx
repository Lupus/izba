import { fireEvent, render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { NoticeBanner, appendNotice } from "../components/NoticeBanner";

describe("NoticeBanner", () => {
  it("renders nothing without notices", () => {
    render(<NoticeBanner notices={[]} onDismiss={() => {}} />);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows the notice and Dismiss reports its index", () => {
    const onDismiss = vi.fn();
    render(<NoticeBanner notices={["run 'izba windows-cleanup'"]} onDismiss={onDismiss} />);
    expect(screen.getByRole("alert")).toHaveTextContent("izba windows-cleanup");
    fireEvent.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(onDismiss).toHaveBeenCalledWith(0);
  });

  it("renders every notice with its own Dismiss", () => {
    const onDismiss = vi.fn();
    render(<NoticeBanner notices={["first", "second"]} onDismiss={onDismiss} />);
    expect(screen.getAllByRole("alert")).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "Dismiss notice 2" }));
    expect(onDismiss).toHaveBeenCalledWith(1);
  });

  it("caps the stack's height and scrolls so notices never crowd out the app", () => {
    render(<NoticeBanner notices={["a", "b", "c", "d", "e"]} onDismiss={() => {}} />);
    const stack = screen.getByTestId("notice-stack");
    expect(stack).toHaveClass("max-h-40", "overflow-y-auto", "shrink-0");
  });
});

describe("appendNotice", () => {
  it("appends, keeping earlier guidance", () => {
    expect(appendNotice(["a"], "b")).toEqual(["a", "b"]);
  });
  it("skips an identical notice", () => {
    const list = ["a"];
    expect(appendNotice(list, "a")).toBe(list);
  });
});
