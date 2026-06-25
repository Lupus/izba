import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { Dialog, DialogContent, DialogTitle, DialogClose } from "@/components/ui/dialog";

describe("Dialog", () => {
  it("renders content with an accessible dialog role and title when open", () => {
    render(
      <Dialog open onOpenChange={() => {}}>
        <DialogContent><DialogTitle>Remove web?</DialogTitle></DialogContent>
      </Dialog>,
    );
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("Remove web?")).toBeInTheDocument();
  });
  it("requests close via DialogClose", () => {
    const onOpenChange = vi.fn();
    render(
      <Dialog open onOpenChange={onOpenChange}>
        <DialogContent>
          <DialogTitle>t</DialogTitle>
          <DialogClose>Cancel</DialogClose>
        </DialogContent>
      </Dialog>,
    );
    fireEvent.click(screen.getByText("Cancel"));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });
});
