import { RuleTester } from "eslint";
import parser from "@typescript-eslint/parser";
import { describe, it } from "vitest";
import rule from "../../../eslint-rules/no-raw-control.js";

const ruleTester = new RuleTester({
  languageOptions: { parser, parserOptions: { ecmaFeatures: { jsx: true } } },
});

describe("no-raw-control", () => {
  it("passes RuleTester cases", () => {
    ruleTester.run("no-raw-control", rule, {
      valid: [
        { code: "const x = <Button>ok</Button>;" },
        { code: "const x = <div className='a' />;" },
      ],
      invalid: [
        { code: "const x = <button>no</button>;", errors: [{ messageId: "rawControl" }] },
        { code: "const x = <input />;", errors: [{ messageId: "rawControl" }] },
        { code: "const x = <select />;", errors: [{ messageId: "rawControl" }] },
        { code: "const x = <textarea />;", errors: [{ messageId: "rawControl" }] },
      ],
    });
  });
});
