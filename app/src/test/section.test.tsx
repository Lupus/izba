import { render, screen, fireEvent } from "@testing-library/react";
import { Section } from "../components/Section";

it("toggles children visibility", () => {
  render(<Section title="Hosts"><p>body</p></Section>);
  expect(screen.getByText("body")).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: /Hosts/ }));
  expect(screen.queryByText("body")).toBeNull();
});
