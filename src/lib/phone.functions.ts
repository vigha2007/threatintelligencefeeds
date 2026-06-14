import { createServerFn } from "@tanstack/react-start";

export interface AbstractPhoneResult {
  valid: boolean;
  number: string;            // E.164 / international
  local_format: string;
  country: string;
  countryCode: string;       // dial prefix incl '+'
  countryIso: string;
  carrier: string;
  lineType: string;          // mobile / landline / voip / toll_free / unknown
  location: string;
}

export const validatePhoneAbstract = createServerFn({ method: "POST" })
  .inputValidator((d: { phone: string }) => {
    if (!d || typeof d.phone !== "string" || !d.phone.trim()) {
      throw new Error("phone required");
    }
    return { phone: d.phone.trim().slice(0, 32) };
  })
  .handler(async ({ data }): Promise<AbstractPhoneResult> => {
    const key = process.env.ABSTRACT_PHONE_API_KEY;
    if (!key) throw new Error("ABSTRACT_PHONE_API_KEY is not configured");
    const url = `https://phonevalidation.abstractapi.com/v1/?api_key=${encodeURIComponent(key)}&phone=${encodeURIComponent(data.phone)}`;
    const res = await fetch(url);
    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      throw new Error(`Abstract phone validation failed (${res.status}) ${txt.slice(0, 200)}`);
    }
    const j = (await res.json()) as Record<string, unknown>;
    const country = (j.country ?? {}) as Record<string, unknown>;
    const format = (j.format ?? {}) as Record<string, unknown>;
    return {
      valid: Boolean(j.valid),
      number: String(format.international ?? j.phone ?? data.phone),
      local_format: String(format.local ?? ""),
      country: String(country.name ?? "Unknown"),
      countryCode: String(country.prefix ?? ""),
      countryIso: String(country.code ?? ""),
      carrier: String(j.carrier ?? "") || "Unknown",
      lineType: String(j.type ?? "unknown"),
      location: String(j.location ?? ""),
    };
  });
