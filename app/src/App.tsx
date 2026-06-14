import { useState } from "react";
import { usePolling } from "./lib/store";
import { TopBar } from "./components/TopBar";
import { Rail } from "./components/Rail";
import { Detail } from "./components/Detail";

export default function App() {
  const { sandboxes, daemon, error } = usePolling(2000);
  const [selected, setSelected] = useState<string | null>(null);
  const current = sandboxes.find((s) => s.name === selected) ?? null;

  return (
    <div className="h-full flex flex-col">
      <TopBar daemon={daemon} error={error} />
      <div className="flex flex-1 min-h-0">
        <Rail sandboxes={sandboxes} selected={selected} onSelect={setSelected} />
        <Detail sandbox={current} />
      </div>
    </div>
  );
}
