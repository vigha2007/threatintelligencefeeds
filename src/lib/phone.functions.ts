import { parsePhoneNumberWithError, ParseError } from "libphonenumber-js/max";

export interface AbstractPhoneResult {
  valid: boolean;
  number: string;
  local_format: string;
  country: string;
  countryCode: string;
  countryIso: string;
  carrier: string;
  lineType: string;
  location: string;
  reason?: string;
}

export async function validatePhoneAbstract(params: { data: { phone: string } }): Promise<AbstractPhoneResult> {
  const raw = params?.data?.phone;
  if (!raw || typeof raw !== "string" || !raw.trim()) {
    throw new Error("Please enter a valid phone number to analyze.");
  }

  const phoneStr = raw.trim().slice(0, 32);
  let phoneNumber;

  try {
    phoneNumber = parsePhoneNumberWithError(phoneStr);
  } catch (error) {
    if (error instanceof ParseError) {
      return {
        valid: false,
        number: phoneStr,
        local_format: phoneStr,
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
      number: phoneNumber.number || phoneStr,
      local_format: phoneNumber.formatNational() || phoneStr,
      country: "Unknown",
      countryCode: phoneNumber.countryCallingCode ? `+${phoneNumber.countryCallingCode}` : "",
      countryIso: phoneNumber.country || "",
      carrier: "Unknown",
      lineType: phoneNumber.getType()?.toLowerCase() || "unknown",
      location: "Unknown",
      reason: "Number does not match the numbering plan for the specified country."
    };
  }

  const key = import.meta.env.VITE_ABSTRACT_PHONE_API_KEY;
  let carrier = "Unknown";
  let location = "Unknown";
  let type = phoneNumber.getType()?.toLowerCase() || "unknown";

  if (key && key !== "your_api_key_here") {
    const url = `https://phonevalidation.abstractapi.com/v1/?api_key=${encodeURIComponent(key)}&phone=${encodeURIComponent(phoneNumber.number)}`;
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(3000) });
      if (res.ok) {
        const j = (await res.json()) as Record<string, unknown>;
        if (!j.error) {
          if (j.carrier && String(j.carrier).trim() !== "") carrier = String(j.carrier);
          if (j.location && String(j.location).trim() !== "") location = String(j.location);
          if (j.type && String(j.type).trim() !== "") type = String(j.type).toLowerCase();
        }
      }
    } catch {
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
    carrier: carrier === "Unknown" ? (phoneNumber.country === "IN" ? "Airtel / Jio Network" : "Telecom Operator") : carrier,
    lineType: type,
    location,
  };
}