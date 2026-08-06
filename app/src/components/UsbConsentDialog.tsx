import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface Props {
  device: string;
  description: string;
  sandbox: string;
  onConfirm: () => void;
  onCancel: () => void;
}

/** The consequences of a grant, kept in step with the CLI's `consent_banner`
 *  (crates/izba-cli/src/commands/usb.rs). Two surfaces, one set of facts — a
 *  GUI gate weaker than the CLI's would just be the way to get a device
 *  granted without reading any of this. */
const CLAUSES = [
  "The agent in that sandbox gets raw, transfer-level access to this device. It can reflash it, change its firmware, or permanently damage it.",
  "USB traffic is not visible to the egress firewall: Netlog will not show what crosses this link, and no allow-list applies to it.",
  "While attached, the device is unavailable to the host and to every other sandbox.",
  "izba cannot verify that this is the physical object in front of you — the USB/IP protocol carries no serial number, and a device asserts its own id.",
];

export function UsbConsentDialog({ device, description, sandbox, onConfirm, onCancel }: Props) {
  const [typed, setTyped] = useState("");
  // Same leniency as the CLI's confirm_matches: the human is retyping an id
  // they read off a listing, so case and stray spaces are not the point.
  const matches = typed.trim().toLowerCase() === device.toLowerCase();
  const what = description ? `${device} (${description})` : device;

  return (
    <Dialog
      open
      onOpenChange={(o) => {
        if (!o) onCancel();
      }}
    >
      <DialogContent aria-label={`Grant ${device} to ${sandbox}`}>
        <DialogHeader>
          <DialogTitle>
            Grant {what} to “{sandbox}”?
          </DialogTitle>
          <DialogDescription>
            This is a standing grant: it survives replug and restart until you revoke it.
          </DialogDescription>
        </DialogHeader>
        <ul className="flex list-disc flex-col gap-2 pl-5 text-sm text-muted-foreground">
          {CLAUSES.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
        <div className="mt-2 grid gap-1">
          <label htmlFor="usb-consent-confirm" className="text-sm font-medium">
            Type the device id to confirm
          </label>
          <Input
            id="usb-consent-confirm"
            aria-label="Type the device id to confirm"
            value={typed}
            placeholder={device}
            onChange={(e) => setTyped(e.target.value)}
          />
        </div>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="ghost">Cancel</Button>
          </DialogClose>
          <Button variant="destructive" disabled={!matches} onClick={onConfirm}>
            Grant
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
