import { createServerFn } from "@tanstack/react-start";
import { parsePhoneNumberWithError, ParseError } from "libphonenumber-js/max";

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
  reason?: string;
}

export const validatePhoneAbstract = createServerFn({ method: "POST" })
  .validator((d: { phone: string }) => {
    if (!d || typeof d.phone !== "string" || !d.phone.trim()) {
      throw new Error("Please enter a valid phone number to analyze.");
    }
    return { phone: d.phone.trim().slice(0, 32) };
  })
  .handler(async ({ data }): Promise<AbstractPhoneResult> => {
    let phoneNumber;
    try {
      phoneNumber = parsePhoneNumberWithError(data.phone);
    } catch (error) {
      if (error instanceof ParseError) {
        return {
          valid: false,
          number: data.phone,
          local_format: data.phone,
          country: "Unknown",
          countryCode: "",
          countryIso: "",
          carrier: "Unknown",
          lineType: "unknown",
          location: "Unknown",
          reason: "Number does not match the numbering plan for the specified country."
        };
      }
      throw error;
    }

    if (!phoneNumber.isValid()) {
      return {
        valid: false,
        number: phoneNumber.number || data.phone,
        local_format: phoneNumber.formatNational() || data.phone,
        country: "Unknown",
        countryCode: phoneNumber.countryCallingCode ? `+${phoneNumber.countryCallingCode}` : "",
        countryIso: phoneNumber.country || "",
        carrier: "Unknown",
        lineType: phoneNumber.getType()?.toLowerCase() || "unknown",
        location: "Unknown",
        reason: "Number does not match the numbering plan for the specified country."
      };
    }

    const key = process.env.ABSTRACT_PHONE_API_KEY;
    let carrier = "Unknown";
    let location = "Unknown";
    let type = phoneNumber.getType()?.toLowerCase() || "unknown";

    if (key && key !== "your_api_key_here") {
      const url = `https://phonevalidation.abstractapi.com/v1/?api_key=${encodeURIComponent(key)}&phone=${encodeURIComponent(phoneNumber.number)}`;
      try {
        const res = await fetch(url);
        if (res.ok) {
          const j = (await res.json()) as Record<string, unknown>;
          if (!j.error) {
            if (j.carrier && String(j.carrier).trim() !== "") carrier = String(j.carrier);
            if (j.location && String(j.location).trim() !== "") location = String(j.location);
            if (j.type && String(j.type).trim() !== "") type = String(j.type).toLowerCase();
          }
        }
      } catch (e) {
        // Fallback to Unknown if API fails
      }
    }

    let countryName = "Unknown";
    if (phoneNumber.country) {
      try {
        const displayNames = new Intl.DisplayNames(["en"], { type: "region" });
        countryName = displayNames.of(phoneNumber.country) || "Unknown";
      } catch {
        countryName = phoneNumber.country;
      }
    }

    return {
      valid: true,
      number: phoneNumber.number,
      local_format: phoneNumber.formatNational(),
      country: countryName,
      countryCode: `+${phoneNumber.countryCallingCode}`,
      countryIso: phoneNumber.country || "",
      carrier,
      lineType: type,
      location,
    };
  });