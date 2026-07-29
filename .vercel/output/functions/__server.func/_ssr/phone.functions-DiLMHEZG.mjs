import { c as createServerRpc } from "./createServerRpc-BpAF1dNQ.mjs";
import { c as createServerFn } from "./server-BRD1Kp-V.mjs";
import "../_libs/seroval.mjs";
import "../_libs/react.mjs";
import { p as parsePhoneNumberWithError, P as ParseError } from "../_libs/libphonenumber-js.mjs";
import "node:async_hooks";
import "../_libs/h3-v2.mjs";
import "../_libs/rou3.mjs";
import "../_libs/srvx.mjs";
import "node:stream";
import "../_libs/tanstack__router-core.mjs";
import "../_libs/tanstack__history.mjs";
import "../_libs/cookie-es.mjs";
import "../_libs/seroval-plugins.mjs";
import "node:stream/web";
import "../_libs/tanstack__react-router.mjs";
import "../_libs/react-dom.mjs";
import "util";
import "crypto";
import "async_hooks";
import "stream";
import "../_libs/isbot.mjs";
const validatePhoneAbstract_createServerFn_handler = createServerRpc({
  id: "4b4dda2ba3048bf94997c9f69fbfc72adef2b594acf727643e003bf202380336",
  name: "validatePhoneAbstract",
  filename: "src/lib/phone.functions.ts"
}, (opts) => validatePhoneAbstract.__executeServer(opts));
const validatePhoneAbstract = createServerFn({
  method: "POST"
}).validator((d) => {
  if (!d || typeof d.phone !== "string" || !d.phone.trim()) {
    throw new Error("Please enter a valid phone number to analyze.");
  }
  return {
    phone: d.phone.trim().slice(0, 32)
  };
}).handler(validatePhoneAbstract_createServerFn_handler, async ({
  data
}) => {
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
        const j = await res.json();
        if (!j.error) {
          if (j.carrier && String(j.carrier).trim() !== "") carrier = String(j.carrier);
          if (j.location && String(j.location).trim() !== "") location = String(j.location);
          if (j.type && String(j.type).trim() !== "") type = String(j.type).toLowerCase();
        }
      }
    } catch (e) {
    }
  }
  let countryName = "Unknown";
  if (phoneNumber.country) {
    try {
      const displayNames = new Intl.DisplayNames(["en"], {
        type: "region"
      });
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
    location
  };
});
export {
  validatePhoneAbstract_createServerFn_handler
};
