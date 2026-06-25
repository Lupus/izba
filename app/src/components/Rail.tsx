import type { SandboxView } from "../lib/types";
import { Button } from "@/components/ui/button";
import { StatusDot } from "./StatusDot";

type View = "sandboxes" | "storage";

interface Props {
  sandboxes: SandboxView[];
  selected: string | null;
  onSelect: (name: string) => void;
  onNew: () => void;
  view: View;
  onView: (v: View) => void;
}

export function Rail({ sandboxes, selected, onSelect, onNew, view, onView }: Props) {
  return (
    <nav className="flex h-full w-56 shrink-0 flex-col gap-1 overflow-y-auto border-r border-border bg-sidebar p-3">
      <Button
        type="button"
        onClick={onNew}
        aria-label="New sandbox"
        className="mb-2 w-full"
      >
        ＋ New sandbox
      </Button>
      <Button
        type="button"
        variant="ghost"
        onClick={() => onView("storage")}
        aria-pressed={view === "storage"}
        className={`flex w-full items-center gap-2 text-left justify-start ${
          view === "storage" ? "bg-accent font-semibold" : ""
        }`}
      >
        Storage
      </Button>
      <div className="px-2 pt-1 pb-1 text-xs uppercase tracking-wide text-muted-foreground-2 font-bold">
        Sandboxes · {sandboxes.length}
      </div>
      {sandboxes.map((s) => (
        <Button
          key={s.name}
          variant="ghost"
          onClick={() => {
            onSelect(s.name);
            onView("sandboxes");
          }}
          aria-pressed={view === "sandboxes" && selected === s.name}
          className={`flex w-full items-center gap-2 text-left justify-start ${
            view === "sandboxes" && selected === s.name ? "bg-accent font-semibold" : ""
          }`}
        >
          <StatusDot state={s.state} />
          <span className="leading-tight">
            {s.name}
            <small className="block text-muted-foreground-2 font-normal text-xs">{s.image}</small>
          </span>
        </Button>
      ))}
    </nav>
  );
}
