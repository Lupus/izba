/** A labelled on/off switch for firewall enforcement. The knob position shows
 *  the current state (no "what does this checkbox mean" ambiguity); clicking
 *  flips it. Shared by the Netlog header and the Policy editor so the control
 *  reads the same in both places. */
export function EnforceToggle({
  enforcing,
  disabled = false,
  onToggle,
}: Readonly<{ enforcing: boolean; disabled?: boolean; onToggle: () => void }>) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={enforcing}
      aria-label="Enforce firewall"
      disabled={disabled}
      onClick={onToggle}
      className="inline-flex items-center gap-2 text-xs font-semibold disabled:opacity-50"
    >
      <span
        className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors ${
          enforcing ? "bg-accent" : "bg-line"
        }`}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
            enforcing ? "translate-x-[1.125rem]" : "translate-x-0.5"
          }`}
        />
      </span>
      <span>{enforcing ? "Firewall on" : "Firewall off"}</span>
    </button>
  );
}
