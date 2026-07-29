import { c as createServerRpc } from "./createServerRpc-BpAF1dNQ.mjs";
import { c as createServerFn } from "./server-BRD1Kp-V.mjs";
import "../_libs/seroval.mjs";
import "../_libs/react.mjs";
import { o as objectType, s as stringType, b as booleanType, e as enumType } from "../_libs/zod.mjs";
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
const JAVA_BASE = process.env.JAVA_BASE_URL || "http://localhost:8081";
async function logSearchActivity(module, input, dbMatch, aiUsed, result) {
  if (typeof window !== "undefined") return;
  const fs = await import("fs");
  const path = await import("path");
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  const logDir = path.join(process.cwd(), "logs");
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, {
      recursive: true
    });
  }
  const logPath = path.join(logDir, "search_activity.log");
  const logLine = `[${timestamp}] [Module: ${module}] [Input: "${input.replace(/\n/g, "\\n")}"] [DB Match: ${dbMatch ? "Yes" : "No"}] [AI Used: ${aiUsed ? "Yes" : "No"}] [Final Result: ${result}]
`;
  console.log(`📊 SEARCH LOG: ${logLine.trim()}`);
  try {
    fs.appendFileSync(logPath, logLine, "utf8");
  } catch (err) {
    console.error("Failed to write to search activity log file:", err);
  }
}
const logSearch_createServerFn_handler = createServerRpc({
  id: "56ffed848676ff2dca76e77ee858f7a4f052bf171b442714f869c9340b76cb3d",
  name: "logSearch",
  filename: "src/lib/db-lookup.functions.ts"
}, (opts) => logSearch.__executeServer(opts));
const logSearch = createServerFn({
  method: "POST"
}).validator((d) => objectType({
  module: enumType(["Phone", "SMS"]),
  input: stringType(),
  dbMatch: booleanType(),
  aiUsed: booleanType(),
  result: stringType()
}).parse(d)).handler(logSearch_createServerFn_handler, async ({
  data
}) => {
  await logSearchActivity(data.module, data.input, data.dbMatch, data.aiUsed, data.result);
  return {
    ok: true
  };
});
const lookupPhoneInDb_createServerFn_handler = createServerRpc({
  id: "f0f5abecd357a34916b9e286e3f5612cec1dac051a6a2256e115c5722f71bec6",
  name: "lookupPhoneInDb",
  filename: "src/lib/db-lookup.functions.ts"
}, (opts) => lookupPhoneInDb.__executeServer(opts));
const lookupPhoneInDb = createServerFn({
  method: "GET"
}).validator((d) => objectType({
  phone: stringType().min(1).max(64)
}).parse(d)).handler(lookupPhoneInDb_createServerFn_handler, async ({
  data
}) => {
  try {
    const url = `${JAVA_BASE}/api/v1/search/phone?q=${encodeURIComponent(data.phone)}`;
    const res = await fetch(url, {
      signal: AbortSignal.timeout(5e3)
    });
    if (!res.ok) return {
      found: false
    };
    const json = await res.json();
    if (!json.found) return {
      found: false
    };
    const row = json.row ?? {};
    return {
      found: true,
      source: json.source ?? "exact",
      matchScore: Number(json.matchScore ?? 1),
      id: Number(row.id ?? 0),
      phone_number: String(row.phone_number ?? data.phone),
      country: row.country != null ? String(row.country) : null,
      severity: row.severity ?? "low",
      pattern: row.pattern != null ? String(row.pattern) : null,
      reported_at: row.reported_at != null ? String(row.reported_at) : null,
      detected_at: row.detected_at != null ? String(row.detected_at) : null
    };
  } catch {
    return {
      found: false
    };
  }
});
const lookupSmsInDb_createServerFn_handler = createServerRpc({
  id: "f8550fda4adfe7b6ead313b5fa35cd1452ec544bc0489e84ee144caed83a41cf",
  name: "lookupSmsInDb",
  filename: "src/lib/db-lookup.functions.ts"
}, (opts) => lookupSmsInDb.__executeServer(opts));
const lookupSmsInDb = createServerFn({
  method: "GET"
}).validator((d) => objectType({
  text: stringType().min(1).max(4e3)
}).parse(d)).handler(lookupSmsInDb_createServerFn_handler, async ({
  data
}) => {
  try {
    const url = `${JAVA_BASE}/api/v1/search/sms?q=${encodeURIComponent(data.text)}`;
    const res = await fetch(url, {
      signal: AbortSignal.timeout(5e3)
    });
    if (!res.ok) return {
      found: false
    };
    const json = await res.json();
    if (!json.found) return {
      found: false
    };
    const row = json.row ?? {};
    return {
      found: true,
      source: json.source ?? "exact",
      matchScore: Number(json.matchScore ?? 1),
      id: Number(row.id ?? 0),
      channel: String(row.channel ?? "sms"),
      sender: row.sender != null ? String(row.sender) : null,
      content: String(row.content ?? ""),
      severity: row.severity ?? "low",
      detected_at: row.detected_at != null ? String(row.detected_at) : null
    };
  } catch {
    return {
      found: false
    };
  }
});
export {
  logSearch_createServerFn_handler,
  lookupPhoneInDb_createServerFn_handler,
  lookupSmsInDb_createServerFn_handler
};
