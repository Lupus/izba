interface Props {
  title: string;
  message: string;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({ title, message, confirmLabel, danger, onConfirm, onCancel }: Props) {
  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-black/30"
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      <div className="w-[26rem] max-w-[90vw] rounded-xl bg-surface p-5 shadow-xl">
        <h2 className="text-lg font-semibold">{title}</h2>
        <p className="mt-2 text-ink-2 text-sm">{message}</p>
        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-lg px-3 py-1.5 text-ink-2 hover:bg-hover"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className={`rounded-lg px-3 py-1.5 font-semibold text-white shadow-sm ${
              danger ? "bg-warn" : "bg-accent"
            }`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
