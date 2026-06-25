/** A labelled on/off switch for firewall enforcement. The knob position shows
 *  the current state (no "what does this checkbox mean" ambiguity); clicking
 *  flips it. Shared by the Netlog header and the Policy editor so the control
 *  reads the same in both places. */
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";

export function EnforceToggle({
  enforcing,
  disabled = false,
  onToggle,
}: Readonly<{ enforcing: boolean; disabled?: boolean; onToggle: () => void }>) {
  return (
    <div className="inline-flex items-center gap-2">
      <Switch
        id="enforce-toggle"
        checked={enforcing}
        disabled={disabled}
        aria-label="Enforce firewall"
        onCheckedChange={() => onToggle()}
      />
      <Label
        htmlFor="enforce-toggle"
        className="cursor-pointer text-xs font-semibold"
      >
        {enforcing ? "Firewall on" : "Firewall off"}
      </Label>
    </div>
  );
}
