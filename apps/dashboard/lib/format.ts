// Pure helpers shared by dashboard pages (unit-tested).

export function shortID(id: string): string {
  return id.slice(0, 8);
}

export function statusColor(status: string): string {
  switch (status) {
    case "complete":
      return "#1a7f37";
    case "failed":
      return "#cf222e";
    case "cancelled":
      return "#57606a";
    case "needs_approval":
      return "#9a6700";
    default:
      return "#0969da";
  }
}

export function formatMs(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  const m = Math.floor(ms / 60_000);
  return `${m}m ${Math.round((ms % 60_000) / 1000)}s`;
}

export function formatCost(cents: number): string {
  if (cents === 0) return "$0";
  if (cents < 1) return `${(cents * 100).toFixed(2)}¢`;
  return `$${cents.toFixed(2)}`;
}

export function pct(f: number): string {
  return `${Math.round(f * 100)}%`;
}
