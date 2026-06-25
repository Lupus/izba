const BANNED = new Set(["button", "input", "select"]);

/** @type {import("eslint").Rule.RuleModule} */
export default {
  meta: {
    type: "problem",
    docs: { description: "Disallow raw interactive elements; use @/components/ui/* primitives." },
    messages: {
      rawControl:
        "Use the shared @/components/ui primitive instead of a raw <{{name}}>. (escape hatch: // eslint-disable-next-line izba/no-raw-control -- <reason>)",
    },
    schema: [],
  },
  create(context) {
    return {
      JSXOpeningElement(node) {
        const el = node.name;
        if (el.type === "JSXIdentifier" && BANNED.has(el.name)) {
          context.report({ node, messageId: "rawControl", data: { name: el.name } });
        }
      },
    };
  },
};
