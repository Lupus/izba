import type { ReactNode } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** The shared frame for every Overview card: a small-caps-ish title with an
 *  optional muted caption ("· 3.7 GiB on host", "· guest-reported"). Keeping
 *  it in one place is what makes the four cards read as one dashboard. */
export function OverviewCard({
  title,
  caption,
  children,
}: Readonly<{ title: string; caption?: ReactNode; children: ReactNode }>) {
  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">
          {title}
          {caption != null && (
            <span className="ml-1 font-normal text-muted-foreground-2">· {caption}</span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="text-sm">{children}</CardContent>
    </Card>
  );
}

/** One label/value line. The value is right-aligned against a muted label so
 *  the cards line up without a table. */
export function Row({ label, children }: Readonly<{ label: string; children: ReactNode }>) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-0.5">
      <span className="shrink-0 text-muted-foreground-2">{label}</span>
      <span className="min-w-0 text-right">{children}</span>
    </div>
  );
}

/** A quiet body for the degraded states ("not running", "guest not
 *  responding", "…" while the first poll is in flight). Never dressed up as
 *  data — an absent tier must read as absent. */
export function Quiet({ children }: Readonly<{ children: ReactNode }>) {
  return <div className="py-1 text-muted-foreground-2">{children}</div>;
}
