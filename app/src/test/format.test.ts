import { describe, expect, it } from "vitest";
import { formatBytes, formatUptime, meterTone } from "../lib/format";

describe("formatBytes", () => {
  it("renders binary units with one decimal", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2.0 KiB");
    expect(formatBytes(1288490189)).toBe("1.2 GiB");
    expect(formatBytes(429916160)).toBe("410.0 MiB");
  });
});

describe("formatUptime", () => {
  it("picks the two most significant units", () => {
    expect(formatUptime(45_000)).toBe("45s");
    expect(formatUptime(8_040_000)).toBe("2h 14m");
    expect(formatUptime(277_200_000)).toBe("3d 5h");
  });
});

describe("meterTone", () => {
  it("applies the 80/95 thresholds", () => {
    expect(meterTone(0)).toBe("ok");
    expect(meterTone(0.79)).toBe("ok");
    expect(meterTone(0.8)).toBe("warn");
    expect(meterTone(0.94)).toBe("warn");
    expect(meterTone(0.95)).toBe("crit");
    expect(meterTone(2)).toBe("crit");
  });
});
