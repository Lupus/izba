import type { SandboxView } from "../lib/types";
import { Button } from "@/components/ui/button";
import { StatusDot } from "./StatusDot";

type View = "sandboxes" | "storage" | "usb";

interface Props {
  sandboxes: SandboxView[];
  selected: string | null;
  onSelect: (name: string) => void;
  onNew: () => void;
  /** Open the Save-archive dialog (`izba save`). */
  onSave: () => void;
  /** Open the Load-archive dialog (`izba load`). */
  onLoad: () => void;
  view: View;
  onView: (v: View) => void;
}

export function Rail({
  sandboxes,
  selected,
  onSelect,
  onNew,
  onSave,
  onLoad,
  view,
  onView,
}: Readonly<Props>) {
  return (
    <nav className="flex h-full w-56 shrink-0 flex-col gap-1 overflow-y-auto border-r border-border bg-sidebar p-3">
      <Button
        type="button"
        onClick={onNew}
        aria-label="New sandbox"
        className="mb-1 w-full"
      >
        ＋ New sandbox
      </Button>
      <div className="mb-2 flex gap-1">
        <Button
          type="button"
          variant="secondary"
          size="sm"
          onClick={onSave}
          disabled={sandboxes.length === 0}
          aria-label="Save archive"
          title="Save sandboxes to an archive you can move to another machine"
          className="flex-1"
        >
          Save…
        </Button>
        <Button
          type="button"
          variant="secondary"
          size="sm"
          onClick={onLoad}
          aria-label="Load archive"
          title="Load sandboxes from an archive"
          className="flex-1"
        >
          Load…
        </Button>
      </div>
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
      <Button
        type="button"
        variant="ghost"
        onClick={() => onView("usb")}
        aria-pressed={view === "usb"}
        className={`flex w-full items-center gap-2 text-left justify-start ${
          view === "usb" ? "bg-accent font-semibold" : ""
        }`}
      >
        Devices
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
          <span className="min-w-0 leading-tight">
            <span className="block truncate" title={s.name}>
              {s.name}
            </span>
            <small
              className="block truncate text-muted-foreground-2 font-normal text-xs"
              title={s.image}
            >
              {s.image}
            </small>
          </span>
        </Button>
      ))}
    </nav>
  );
}
