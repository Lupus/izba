/** A small CSS spinner (spinning ring). `currentColor` so it inherits text color. */
export function Spinner({ className = "" }: { className?: string }) {
  return (
    <span
      role="status"
      aria-label="loading"
      className={
        "inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent " +
        className
      }
    />
  );
}
