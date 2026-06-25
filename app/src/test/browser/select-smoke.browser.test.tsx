/**
 * Smoke test: Radix Select open + pick in real Chromium.
 *
 * This is the capability gate for Task 29.  jsdom cannot reliably test Radix
 * Select because it depends on pointer-capture, scrollIntoView, ResizeObserver,
 * and pointer-events:none body suppression — none of which jsdom implements
 * faithfully.  Running in Vitest Browser Mode (Playwright / Chromium) exercises
 * the real DOM, so the dropdown opens and option clicks register correctly.
 */
import { useState } from "react";
import { render } from "vitest-browser-react";
import { expect, test } from "vitest";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

// Minimal wrapper that surfaces the selected value in the DOM so locators can
// assert the update without querying Radix internals.
function TestSelect() {
  const [value, setValue] = useState("");
  return (
    <div>
      <Select value={value} onValueChange={setValue}>
        <SelectTrigger aria-label="colour">
          <SelectValue placeholder="Pick a colour" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="red">Red</SelectItem>
          <SelectItem value="green">Green</SelectItem>
          <SelectItem value="blue">Blue</SelectItem>
        </SelectContent>
      </Select>
      {/* Surface the current value so assertions can find it without Radix internals */}
      <output data-testid="selected-value">{value}</output>
    </div>
  );
}

test("Select: opens dropdown and picks an option in real Chromium", async () => {
  const screen = await render(<TestSelect />);

  // Trigger should start with placeholder text
  await expect.element(screen.getByRole("combobox")).toBeVisible();

  // Open the dropdown by clicking the trigger
  await screen.getByRole("combobox").click();

  // The Select portal appends to document.body — the option should become
  // visible in the page after opening (Radix uses [data-state=open]).
  const greenOption = screen.getByRole("option", { name: "Green" });
  await expect.element(greenOption).toBeVisible();

  // Click the option — Radix calls onValueChange("green")
  await greenOption.click();

  // The wrapper surfaces the value in an <output> element
  await expect
    .element(screen.getByTestId("selected-value"))
    .toHaveTextContent("green");
});
