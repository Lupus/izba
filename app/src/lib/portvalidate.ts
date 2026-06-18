/** Port number is a positive integer in [1, 65535]. */
export const isValidPort = (v: string): boolean =>
  /^\d+$/.test(v.trim()) && +v >= 1 && +v <= 65535;

/** Bind address must be a valid IPv4 quad or empty (daemon defaults to 127.0.0.1). */
export const isValidBind = (v: string): boolean => {
  const t = v.trim();
  if (!t) return true; // empty is allowed; the daemon fills in 127.0.0.1
  const octets = t.split(".");
  return octets.length === 4 && octets.every((o) => /^\d+$/.test(o) && +o >= 0 && +o <= 255);
};
