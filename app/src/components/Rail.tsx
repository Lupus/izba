import type { SandboxView } from "../lib/types";
import { StatusDot } from "./StatusDot";

interface Props {
  sandboxes: SandboxView[];
  selected: string | null;
  onSelect: (name: string) => void;
}

export function Rail({ sandboxes, selected, onSelect }: Props) {
  return (
    <nav className="w-56 shrink-0 border-r border-line bg-rail p-3 flex flex-col gap-1">
      <button className="mb-2 rounded-lg bg-accent text-white font-semibold py-2 shadow-sm">
        ＋ New sandbox
      </button>
      <div className="px-2 pt-1 pb-1 text-[11px] uppercase tracking-wide text-ink-3 font-bold">
        Sandboxes · {sandboxes.length}
      </div>
      {sandboxes.map((s) => (
        <button
          key={s.name}
          onClick={() => onSelect(s.name)}
          className={`flex items-center gap-2 rounded-lg px-2.5 py-2 text-left hover:bg-[#eef1f5] ${
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
