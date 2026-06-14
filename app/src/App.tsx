import { useState } from "react";
import { usePolling } from "./lib/store";
import { TopBar } from "./components/TopBar";
import { Rail } from "./components/Rail";
import { Detail } from "./components/Detail";
import { About } from "./components/About";

export default function App() {
  // `refresh` is also available from usePolling for a future manual-refresh control.
  const { sandboxes, daemon, error } = usePolling(2000);
  const [selected, setSelected] = useState<string | null>(null);
  const [showAbout, setShowAbout] = useState(false);
  const current = sandboxes.find((s) => s.name === selected) ?? null;

  return (
    <div className="h-full flex flex-col">
      <TopBar daemon={daemon} error={error} onAbout={() => setShowAbout(true)} />
      <div className="flex flex-1 min-h-0">
        <Rail sandboxes={sandboxes} selected={selected} onSelect={setSelected} />
        <Detail sandbox={current} />
      </div>
      {showAbout && <About onClose={() => setShowAbout(false)} />}
    </div>
  );
}
