import { useState } from "react";
import { usePolling } from "./lib/store";
import { TopBar } from "./components/TopBar";
import { Rail } from "./components/Rail";
import { Detail } from "./components/Detail";
import { About } from "./components/About";
import { NewSandbox } from "./components/NewSandbox";

export default function App() {
  const { sandboxes, daemon, phase, refresh } = usePolling(2000);
  const [selected, setSelected] = useState<string | null>(null);
  const [showAbout, setShowAbout] = useState(false);
  const [creating, setCreating] = useState(false);
  const current = sandboxes.find((s) => s.name === selected) ?? null;

  return (
    <div className="h-full flex flex-col">
      <TopBar phase={phase} daemon={daemon} onAbout={() => setShowAbout(true)} />
      <div className="flex flex-1 min-h-0">
        <Rail
          sandboxes={sandboxes}
          selected={selected}
          onSelect={setSelected}
          onNew={() => setCreating(true)}
        />
        <Detail sandbox={current} onChanged={refresh} />
      </div>
      {showAbout && <About onClose={() => setShowAbout(false)} />}
      {creating && (
        <NewSandbox
          onClose={() => setCreating(false)}
          onCreated={(name) => {
            setCreating(false);
            setSelected(name);
            refresh();
          }}
        />
      )}
    </div>
  );
}
