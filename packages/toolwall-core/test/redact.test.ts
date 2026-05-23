import { describe, expect, it } from "vitest";
import { redact } from "../src/redact.js";

describe("redact()", () => {
  it("redacts email addresses", () => {
    const out = redact("contact me at alice@example.com please", ["EMAIL"]);
    expect(out).toContain("[REDACTED:EMAIL]");
    expect(out).not.toContain("alice@example.com");
  });

  it("redacts API keys with known prefixes", () => {
    const out = redact(
      "OPENAI_API_KEY=sk-proj-abcdefghij1234567890ABC keep going",
      ["API_KEY"],
    );
    expect(out).toContain("[REDACTED:API_KEY]");
    expect(out).not.toMatch(/sk-proj-/);
  });

  it("redacts E.164 phone numbers", () => {
    const out = redact("call me at +447911123456 thanks", ["PHONE_E164"]);
    expect(out).toContain("[REDACTED:PHONE]");
  });

  it("redacts bearer tokens", () => {
    const out = redact(
      "Authorization: Bearer abcdefghij1234567890",
      ["BEARER_TOKEN"],
    );
    expect(out).toContain("[REDACTED:BEARER]");
  });

  it("redacts URLs with private IPs", () => {
    const out = redact(
      "Fetch http://192.168.1.5:8080/admin/secrets now",
      ["URL_PRIVATE_IP"],
    );
    expect(out).toContain("[REDACTED:PRIVATE_URL]");
    expect(out).not.toContain("192.168.1.5");
  });

  it("is a no-op when no kinds requested", () => {
    const input = "alice@example.com and +447911123456";
    expect(redact(input, [])).toBe(input);
  });

  it("applies multiple kinds in order", () => {
    const out = redact(
      "email alice@example.com phone +447911123456",
      ["EMAIL", "PHONE_E164"],
    );
    expect(out).toContain("[REDACTED:EMAIL]");
    expect(out).toContain("[REDACTED:PHONE]");
  });
});
