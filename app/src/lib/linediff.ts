/** Line-level diff for the Manifest tab's From/To values.
 *
 * Delta values from the backend are small multi-line strings (egress policy
 * YAML, one port/volume rule per line), so a classic LCS over lines is cheap
 * and gives exactly the granularity the UI needs: unchanged lines render
 * plain, removed lines highlight on the From side, added lines on the To
 * side. Hand-rolled (~40 lines) instead of pulling in a diff dependency —
 * values are a few KB at most, so the O(n·m) table is irrelevant.
 */

/** One aligned row of a side-by-side diff. `from`/`to` are `null` when the
 *  row has no line on that side (a pure insertion/deletion). `changed` is
 *  false only for lines common to both sides. */
export interface DiffRow {
  from: string | null;
  to: string | null;
  changed: boolean;
}

function splitLines(s: string): string[] {
  // A trailing newline (serde_yaml always emits one) is not an extra empty line.
  const trimmed = s.endsWith("\n") ? s.slice(0, -1) : s;
  return trimmed === "" ? [] : trimmed.split("\n");
}

/** Longest-common-subsequence table over `a` × `b` (classic DP). */
function lcsTable(a: string[], b: string[]): number[][] {
  const t: number[][] = Array.from({ length: a.length + 1 }, () =>
    new Array<number>(b.length + 1).fill(0),
  );
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      t[i][j] = a[i] === b[j] ? t[i + 1][j + 1] + 1 : Math.max(t[i + 1][j], t[i][j + 1]);
    }
  }
  return t;
}

/** Side-by-side line diff of `from` → `to`. Adjacent removal/addition runs are
 *  paired up row-wise so a changed line renders as one row with both sides
 *  highlighted rather than a deletion row followed by an insertion row. */
export function diffLines(from: string, to: string): DiffRow[] {
  const a = splitLines(from);
  const b = splitLines(to);
  const t = lcsTable(a, b);

  const rows: DiffRow[] = [];
  let dels: string[] = [];
  let adds: string[] = [];
  const flush = () => {
    const n = Math.max(dels.length, adds.length);
    for (let k = 0; k < n; k++) {
      rows.push({ from: dels[k] ?? null, to: adds[k] ?? null, changed: true });
    }
    dels = [];
    adds = [];
  };

  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      flush();
      rows.push({ from: a[i], to: b[j], changed: false });
      i++;
      j++;
    } else if (t[i + 1][j] >= t[i][j + 1]) {
      dels.push(a[i++]);
    } else {
      adds.push(b[j++]);
    }
  }
  while (i < a.length) dels.push(a[i++]);
  while (j < b.length) adds.push(b[j++]);
  flush();
  return rows;
}
