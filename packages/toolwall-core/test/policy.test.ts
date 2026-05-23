import { describe, expect, it } from "vitest";
import {
  fileReadPolicy,
  mcpPolicy,
  PolicySchema,
  policy,
  webFetchPolicy,
} from "../src/index.js";

describe("Policy schema", () => {
  it("fills defaults for empty input", () => {
    const p = policy();
    expect(p.urlAllowlist).toEqual([]);
    expect(p.responseIpiThreshold).toBe(0.6);
    expect(p.callsPerMin).toBe(30);
  });

  it("rejects unknown fields (strict)", () => {
    expect(() =>
      PolicySchema.parse({ unknownField: true } as unknown as object),
    ).toThrow();
  });

  it("rejects out-of-range threshold", () => {
    expect(() => policy({ responseIpiThreshold: 1.5 })).toThrow();
    expect(() => policy({ responseIpiThreshold: -0.1 })).toThrow();
  });

  it("webFetchPolicy denies all egress by default", () => {
    const p = webFetchPolicy();
    expect(p.egressDenylist).toEqual(["*"]);
    expect(p.redact).toContain("API_KEY");
  });

  it("mcpPolicy includes private-IP redaction", () => {
    const p = mcpPolicy();
    expect(p.redact).toContain("URL_PRIVATE_IP");
  });

  it("fileReadPolicy carries pathScope", () => {
    const p = fileReadPolicy("/workspace");
    expect(p.pathScope).toBe("/workspace");
  });
});
