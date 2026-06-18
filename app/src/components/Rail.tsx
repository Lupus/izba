import type { SandboxView } from "../lib/types";
import { StatusDot } from "./StatusDot";

interface Props {
  sandboxes: SandboxView[];
  selected: string | null;
  onSelect: (name: string) => void;
  onNew: () => void;
}

export function Rail({ sandboxes, selected, onSelect, onNew }: Props) {
  return (
    <nav className="flex h-full w-56 shrink-0 flex-col gap-1 overflow-y-auto border-r border-line bg-rail p-3">
      <button
        type="button"
        onClick={onNew}
        aria-label="New sandbox"
        className="mb-2 rounded-lg bg-accent text-white font-semibold py-2 shadow-sm hover:bg-accent/90"
      >
        ＋ New sandbox
      </button>
      <div className="px-2 pt-1 pb-1 text-[11px] uppercase tracking-wide text-ink-3 font-bold">
        Sandboxes · {sandboxes.length}
      </div>
      {sandboxes.map((s) => (
        <button
          key={s.name}
          onClick={() => onSelect(s.name)}
          aria-pressed={selected === s.name}
          className={`flex items-center gap-2 rounded-lg px-2.5 py-2 text-left hover:bg-hover ${
            selected === s.name ? "bg-accent-weak text-accent font-semibold" : ""
          }`}
        >
          <StatusDot state={s.state} />
          <span className="leading-tight">
            {s.name}
            <small className="block text-ink-3 font-normal text-[11.5px]">{s.image}</small>
          </span>
        </button>
      ))}
    </nav>
  );
}
