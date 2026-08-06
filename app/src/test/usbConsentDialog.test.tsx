import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { UsbConsentDialog } from "../components/UsbConsentDialog";

const props = {
  device: "0403:6001",
  description: "FT232 USB UART",
  sandbox: "web",
};

describe("UsbConsentDialog", () => {
  it("states every consequence the CLI banner states", () => {
    render(<UsbConsentDialog {...props} onConfirm={() => {}} onCancel={() => {}} />);
    const body = (document.body.textContent ?? "").toLowerCase();
    for (const clause of ["reflash", "not visible", "unavailable to the host", "cannot verify"]) {
      expect(body).toContain(clause);
    }
  });

  it("keeps the grant button disabled until the device id is typed back", () => {
    const onConfirm = vi.fn();
    render(<UsbConsentDialog {...props} onConfirm={onConfirm} onCancel={() => {}} />);
    const grant = screen.getByRole("button", { name: /^grant$/i });
    expect(grant).toBeDisabled();

    const input = screen.getByLabelText(/type the device id/i);
    fireEvent.change(input, { target: { value: "0403:6002" } });
    expect(grant).toBeDisabled();

    // Case and stray spaces are not the point — the device is.
    fireEvent.change(input, { target: { value: " 0403:6001 " } });
    expect(grant).toBeEnabled();
    fireEvent.click(grant);
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it("cancels without granting", () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    render(<UsbConsentDialog {...props} onConfirm={onConfirm} onCancel={onCancel} />);
    fireEvent.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalled();
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("names the device without empty parentheses when it has no description", () => {
    render(
      <UsbConsentDialog {...props} description="" onConfirm={() => {}} onCancel={() => {}} />,
    );
    expect(document.body.textContent).not.toContain("()");
  });
});
