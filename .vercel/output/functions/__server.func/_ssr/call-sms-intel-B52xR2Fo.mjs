import { r as reactExports, j as jsxRuntimeExports } from "../_libs/react.mjs";
import { u as useQueryClient, a as useQuery, b as useMutation } from "../_libs/tanstack__react-query.mjs";
import { u as useServerFn, i as createEntity, l as listEntity, I as Input, B as Button, T as Textarea, a as Table, b as TableHeader, d as TableRow, e as TableHead, f as TableBody, h as TableCell, c as createSsrRpc } from "./router-D42rnSKO.mjs";
import { t as toast } from "../_libs/sonner.mjs";
import { P as ParticlesBackground } from "./particles-background-BTkR0O5l.mjs";
import { b as buildPhoneAnalysis, s as statusToSeverity, a as analyzeSms } from "./intel-analyzers-CxuAEFHl.mjs";
import { c as createServerFn } from "./server-BRD1Kp-V.mjs";
import "../_libs/seroval.mjs";
import { R as Radar, P as Phone, g as LoaderCircle, Q as ShieldCheck, G as Globe, U as Hash, V as Signal, W as ShieldQuestionMark, T as TriangleAlert, Y as Gauge, d as MessageSquare, Z as ShieldAlert, k as Clock, b as Link2, v as Activity, D as Database, _ as Cpu } from "../_libs/lucide-react.mjs";
import { m as motion, A as AnimatePresence } from "../_libs/framer-motion.mjs";
import { o as objectType, s as stringType, b as booleanType, e as enumType } from "../_libs/zod.mjs";
import "../_libs/tanstack__query-core.mjs";
import "../_libs/tanstack__react-router.mjs";
import "../_libs/tanstack__router-core.mjs";
import "../_libs/tanstack__history.mjs";
import "../_libs/cookie-es.mjs";
import "../_libs/seroval-plugins.mjs";
import "node:stream/web";
import "node:stream";
import "../_libs/react-dom.mjs";
import "util";
import "crypto";
import "async_hooks";
import "stream";
import "../_libs/isbot.mjs";
import "../_libs/radix-ui__react-slot.mjs";
import "../_libs/radix-ui__react-compose-refs.mjs";
import "../_libs/class-variance-authority.mjs";
import "../_libs/clsx.mjs";
import "../_libs/tailwind-merge.mjs";
import "../_libs/radix-ui__react-label.mjs";
import "../_libs/radix-ui__react-primitive.mjs";
import "../_libs/radix-ui__react-select.mjs";
import "../_libs/radix-ui__number.mjs";
import "../_libs/radix-ui__primitive.mjs";
import "../_libs/radix-ui__react-collection.mjs";
import "../_libs/radix-ui__react-context.mjs";
import "../_libs/radix-ui__react-direction.mjs";
import "../_libs/@radix-ui/react-dismissable-layer+[...].mjs";
import "../_libs/@radix-ui/react-use-callback-ref+[...].mjs";
import "../_libs/@radix-ui/react-use-escape-keydown+[...].mjs";
import "../_libs/radix-ui__react-focus-guards.mjs";
import "../_libs/radix-ui__react-focus-scope.mjs";
import "../_libs/radix-ui__react-id.mjs";
import "../_libs/@radix-ui/react-use-layout-effect+[...].mjs";
import "../_libs/radix-ui__react-popper.mjs";
import "../_libs/floating-ui__react-dom.mjs";
import "../_libs/floating-ui__dom.mjs";
import "../_libs/floating-ui__core.mjs";
import "../_libs/floating-ui__utils.mjs";
import "../_libs/radix-ui__react-arrow.mjs";
import "../_libs/radix-ui__react-use-size.mjs";
import "../_libs/radix-ui__react-portal.mjs";
import "../_libs/radix-ui__react-presence.mjs";
import "../_libs/@radix-ui/react-use-controllable-state+[...].mjs";
import "../_libs/radix-ui__react-use-previous.mjs";
import "../_libs/@radix-ui/react-visually-hidden+[...].mjs";
import "../_libs/aria-hidden.mjs";
import "../_libs/react-remove-scroll.mjs";
import "tslib";
import "../_libs/react-remove-scroll-bar.mjs";
import "../_libs/react-style-singleton.mjs";
import "../_libs/get-nonce.mjs";
import "../_libs/use-sidecar.mjs";
import "../_libs/use-callback-ref.mjs";
import "../_libs/radix-ui__react-dialog.mjs";
import "./threat-entities-SRQqKOBI.mjs";
import "node:async_hooks";
import "../_libs/h3-v2.mjs";
import "../_libs/rou3.mjs";
import "../_libs/srvx.mjs";
import "../_libs/motion-dom.mjs";
import "../_libs/motion-utils.mjs";
import "../_libs/fuse.js.mjs";
const validatePhoneAbstract = createServerFn({
  method: "POST"
}).validator((d) => {
  if (!d || typeof d.phone !== "string" || !d.phone.trim()) {
    throw new Error("Please enter a valid phone number to analyze.");
  }
  return {
    phone: d.phone.trim().slice(0, 32)
  };
}).handler(createSsrRpc("4b4dda2ba3048bf94997c9f69fbfc72adef2b594acf727643e003bf202380336"));
const logSearch = createServerFn({
  method: "POST"
}).validator((d) => objectType({
  module: enumType(["Phone", "SMS"]),
  input: stringType(),
  dbMatch: booleanType(),
  aiUsed: booleanType(),
  result: stringType()
}).parse(d)).handler(createSsrRpc("56ffed848676ff2dca76e77ee858f7a4f052bf171b442714f869c9340b76cb3d"));
const lookupPhoneInDb = createServerFn({
  method: "GET"
}).validator((d) => objectType({
  phone: stringType().min(1).max(64)
}).parse(d)).handler(createSsrRpc("f0f5abecd357a34916b9e286e3f5612cec1dac051a6a2256e115c5722f71bec6"));
const lookupSmsInDb = createServerFn({
  method: "GET"
}).validator((d) => objectType({
  text: stringType().min(1).max(4e3)
}).parse(d)).handler(createSsrRpc("f8550fda4adfe7b6ead313b5fa35cd1452ec544bc0489e84ee144caed83a41cf"));
const statusStyles = {
  scam: {
    color: "#E05A52",
    bg: "rgba(224,90,82,0.06)",
    border: "rgba(224,90,82,0.2)",
    label: "Scam / Threat Detected",
    icon: ShieldAlert
  },
  suspicious: {
    color: "#E8A23C",
    bg: "rgba(232,162,60,0.06)",
    border: "rgba(232,162,60,0.2)",
    label: "Suspicious Activity",
    icon: ShieldQuestionMark
  },
  legitimate: {
    color: "#34A853",
    bg: "rgba(52,168,83,0.06)",
    border: "rgba(52,168,83,0.2)",
    label: "No Active Threats",
    icon: ShieldCheck
  }
};
function severityToTrustDb(sev) {
  return sev === "critical" ? 8 : sev === "high" ? 25 : sev === "medium" ? 52 : 85;
}
function severityToStatusDb(sev) {
  return sev === "critical" || sev === "high" ? "scam" : sev === "medium" ? "suspicious" : "legitimate";
}
function severityToThreatLevelDb(sev) {
  return sev === "critical" ? "Critical" : sev === "high" ? "High" : sev === "medium" ? "Medium" : "Low";
}
function parsePattern(pattern) {
  const parts = (pattern ?? "").split(" · ");
  return {
    category: parts[0] || "Unknown",
    numberType: parts[1] || "Unknown",
    carrier: parts[2] || "Unknown",
    trustScore: parseInt(parts[3]?.replace(/[^0-9]/g, "") ?? "", 10) || -1
  };
}
function dbPhoneToAnalysis(hit) {
  const {
    category,
    numberType,
    carrier,
    trustScore: patternTrust
  } = parsePattern(hit.pattern);
  const trust = patternTrust >= 0 ? patternTrust : severityToTrustDb(hit.severity);
  const status = severityToStatusDb(hit.severity);
  const checkedAt = hit.reported_at ?? hit.detected_at ?? (/* @__PURE__ */ new Date()).toISOString();
  return {
    phoneNumber: hit.phone_number,
    normalized: hit.phone_number,
    nationalNumber: hit.phone_number,
    valid: true,
    trustScore: trust,
    status,
    threatCategory: category,
    reports: 0,
    country: hit.country ?? "Unknown",
    countryCode: "",
    carrier,
    numberType,
    confidence: 100,
    checkedAt,
    explanation: `This phone number was found in the threat database with severity “${hit.severity}”. The information displayed is taken directly from the database record and has not been modified.`,
    reasons: [`Database record ID: ${hit.id}.`, `Stored severity: ${hit.severity}.`, hit.pattern ? `Pattern: ${hit.pattern}.` : "No additional pattern data."],
    reputation: status === "scam" ? "Known Threat" : status === "suspicious" ? "Suspicious" : "Verified Safe",
    riskLevel: severityToThreatLevelDb(hit.severity),
    validStatus: "Database Record",
    source: "Database Match"
  };
}
function dbSmsToAnalysis(hit) {
  const status = severityToStatusDb(hit.severity);
  const checkedAt = hit.detected_at ?? (/* @__PURE__ */ new Date()).toISOString();
  let category = "Unknown";
  const lower = hit.content.toLowerCase();
  if (/lottery|prize|winner|won|jackpot|lucky/.test(lower)) category = "Lottery Scam";
  else if (/bank|account|kyc|suspended|blocked/.test(lower)) category = "Banking Fraud";
  else if (/invest|return|profit|crypto|double/.test(lower)) category = "Fraud";
  else if (/otp|verification code|passcode/.test(lower)) category = "OTP Scam";
  else if (/phish|verify your|click the link/.test(lower)) category = "Phishing";
  else if (status === "scam") category = "Fraud";
  else if (status === "suspicious") category = "Spam";
  else category = "Legitimate";
  return {
    trustScore: severityToTrustDb(hit.severity),
    status,
    threatLevel: severityToThreatLevelDb(hit.severity),
    category,
    reasons: [`Database record ID: ${hit.id}.`, `Stored severity: ${hit.severity}.`, `Channel: ${hit.channel}${hit.sender ? ` | Sender: ${hit.sender}` : ""}.`, "This result is taken directly from the database and has not been modified."],
    urls: [],
    confidence: 100,
    checkedAt,
    explanation: `This SMS was found in the threat database (ID: ${hit.id}) with severity “${hit.severity}”. The result is taken directly from the database record.`,
    source: "Database Match"
  };
}
function IntelPage() {
  const qc = useQueryClient();
  const create = useServerFn(createEntity);
  const list = useServerFn(listEntity);
  const validatePhone = useServerFn(validatePhoneAbstract);
  const dbPhoneLookup = useServerFn(lookupPhoneInDb);
  const dbSmsLookup = useServerFn(lookupSmsInDb);
  const logSearchCall = useServerFn(logSearch);
  const [phone, setPhone] = reactExports.useState("");
  const [sms, setSms] = reactExports.useState("");
  const [phoneResult, setPhoneResult] = reactExports.useState(null);
  const [smsResult, setSmsResult] = reactExports.useState(null);
  const [localLog, setLocalLog] = reactExports.useState([]);
  const recentCalls = useQuery({
    queryKey: ["entity", "spam_calls"],
    queryFn: () => list({
      data: {
        entity: "spam_calls"
      }
    }),
    staleTime: 1e4
  });
  const recentMessages = useQuery({
    queryKey: ["entity", "scam_messages"],
    queryFn: () => list({
      data: {
        entity: "scam_messages"
      }
    }),
    staleTime: 1e4
  });
  const phoneMutation = useMutation({
    mutationFn: async (value) => {
      const dbHit = await dbPhoneLookup({
        data: {
          phone: value
        }
      });
      if (dbHit.found) {
        const res = dbPhoneToAnalysis(dbHit);
        try {
          await logSearchCall({
            data: {
              module: "Phone",
              input: value,
              dbMatch: true,
              aiUsed: false,
              result: res.threatCategory
            }
          });
        } catch {
        }
        return res;
      }
      const api = await validatePhone({
        data: {
          phone: value
        }
      });
      const result = buildPhoneAnalysis(value, api);
      try {
        await logSearchCall({
          data: {
            module: "Phone",
            input: value,
            dbMatch: false,
            aiUsed: true,
            result: result.threatCategory
          }
        });
      } catch {
      }
      try {
        await create({
          data: {
            entity: "spam_calls",
            values: {
              phone_number: result.normalized || value,
              country: result.country,
              severity: statusToSeverity(result.status, result.trustScore),
              pattern: `${result.threatCategory} · ${result.numberType} · ${result.carrier} · trust ${result.trustScore}%`.slice(0, 500)
            }
          }
        });
      } catch {
      }
      return result;
    },
    onSuccess: (r) => {
      setPhoneResult(r);
      const item = {
        id: crypto.randomUUID(),
        ts: r.checkedAt,
        analysisType: "Phone Number Analysis",
        threatCategory: r.threatCategory,
        target: r.phoneNumber,
        trustScore: r.trustScore,
        status: r.status,
        country: r.country,
        carrier: r.carrier,
        confidence: r.confidence,
        sourceType: r.source === "Database Match" ? "DB" : "AI"
      };
      setLocalLog((l) => [item, ...l].slice(0, 50));
      const t = r.status === "scam" ? "error" : r.status === "suspicious" ? "warning" : "success";
      toast[t](`${r.phoneNumber} — ${r.threatCategory} (trust ${r.trustScore}%) · ${r.source}`);
      qc.invalidateQueries({
        queryKey: ["entity", "spam_calls"]
      });
      qc.invalidateQueries({
        queryKey: ["dashboard-metrics"]
      });
    },
    onError: (e) => toast.error(e.message)
  });
  const smsMutation = useMutation({
    mutationFn: async (text) => {
      const dbHit = await dbSmsLookup({
        data: {
          text
        }
      });
      if (dbHit.found) {
        const res = dbSmsToAnalysis(dbHit);
        try {
          await logSearchCall({
            data: {
              module: "SMS",
              input: text,
              dbMatch: true,
              aiUsed: false,
              result: res.category
            }
          });
        } catch {
        }
        return res;
      }
      const api = await analyzeSms(text);
      try {
        await logSearchCall({
          data: {
            module: "SMS",
            input: text,
            dbMatch: false,
            aiUsed: true,
            result: api.category
          }
        });
      } catch {
      }
      try {
        await create({
          data: {
            entity: "scam_messages",
            values: {
              channel: "sms",
              content: text,
              severity: statusToSeverity(api.status, api.trustScore)
            }
          }
        });
      } catch {
      }
      return api;
    },
    onSuccess: (r) => {
      setSmsResult(r);
      const item = {
        id: crypto.randomUUID(),
        ts: r.checkedAt,
        analysisType: "SMS Analysis",
        threatCategory: r.category,
        target: sms.length > 50 ? `${sms.slice(0, 50)}…` : sms,
        trustScore: r.trustScore,
        status: r.status,
        country: "N/A",
        carrier: "N/A",
        confidence: r.confidence,
        sourceType: r.source === "Database Match" ? "DB" : "AI"
      };
      setLocalLog((l) => [item, ...l].slice(0, 50));
      const t = r.status === "scam" ? "error" : r.status === "suspicious" ? "warning" : "success";
      toast[t](`SMS analyzed — category: ${r.category} (trust ${r.trustScore}%) · ${r.source}`);
      qc.invalidateQueries({
        queryKey: ["entity", "scam_messages"]
      });
      qc.invalidateQueries({
        queryKey: ["dashboard-metrics"]
      });
    },
    onError: (e) => toast.error(e.message)
  });
  const callsList = recentCalls.data?.rows ?? [];
  const msgsList = recentMessages.data?.rows ?? [];
  const log = [...localLog];
  callsList.forEach((c) => {
    const {
      category,
      carrier,
      trustScore: patternTrust
    } = parsePattern(c.pattern);
    const trust = patternTrust >= 0 ? patternTrust : severityToTrustDb(c.severity);
    const status = severityToStatusDb(c.severity);
    if (!log.some((l) => l.id === c.id || l.target === c.phone_number)) {
      log.push({
        id: c.id,
        ts: c.reported_at ?? c.created_at ?? (/* @__PURE__ */ new Date()).toISOString(),
        analysisType: "Phone Number Analysis",
        threatCategory: category,
        target: c.phone_number,
        trustScore: trust,
        status,
        country: c.country ?? "Unknown",
        carrier,
        confidence: 100,
        sourceType: "DB"
      });
    }
  });
  msgsList.forEach((m) => {
    const status = severityToStatusDb(m.severity);
    if (!log.some((l) => l.id === m.id || l.target.startsWith(m.content.slice(0, 30)))) {
      log.push({
        id: m.id,
        ts: m.detected_at ?? m.created_at ?? (/* @__PURE__ */ new Date()).toISOString(),
        analysisType: "SMS Analysis",
        threatCategory: "Scam Message",
        target: m.content,
        trustScore: severityToTrustDb(m.severity),
        status,
        country: "N/A",
        carrier: "N/A",
        confidence: 100,
        sourceType: "DB"
      });
    }
  });
  log.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative min-h-screen pb-12", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "absolute inset-0 -z-10", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ParticlesBackground, {}) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("section", { className: "mx-auto max-w-7xl px-4 pt-8 sm:px-6 lg:px-8", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-3xl bg-white border border-[#E4DEC6]/80 p-8 shadow-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex h-12 w-12 items-center justify-center rounded-xl bg-[#C48A5A]/15 ring-1 ring-[#C48A5A]/40", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Radar, { className: "h-6 w-6 text-[#C48A5A]" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-2xl font-extrabold text-gray-800 font-poppins", children: "Phone & SMS Intelligence" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-gray-500 font-manrope mt-0.5", children: "Real-time validation against the numbering plan and scanning with explainable scam logic." })
      ] })
    ] }) }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mx-auto mt-8 grid max-w-7xl grid-cols-1 gap-6 px-4 sm:px-6 lg:grid-cols-2 lg:px-8", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(motion.div, { initial: {
        opacity: 0,
        y: 12
      }, animate: {
        opacity: 1,
        y: 0
      }, className: "rounded-3xl bg-white border border-[#E4DEC6]/60 p-6 shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4 flex items-center gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex h-10 w-10 items-center justify-center rounded-xl bg-[#C48A5A]/10 border border-[#C48A5A]/25", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Phone, { className: "h-5 w-5 text-[#C48A5A]" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-md font-bold text-gray-800 font-poppins", children: "Phone Number Intelligence" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[11px] font-medium text-gray-500 font-manrope", children: "Validate & reputation-check any phone number — country code optional." })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { onSubmit: (e) => {
          e.preventDefault();
          if (!phone.trim()) return toast.error("Enter a phone number");
          phoneMutation.mutate(phone.trim());
        }, className: "flex gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Input, { placeholder: "e.g. 9876543210 or +91 80 6527 3679", value: phone, onChange: (e) => setPhone(e.target.value), maxLength: 32, className: "bg-[#FAF8F5] border-[#E4DEC6] text-gray-800 rounded-xl" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Button, { type: "submit", disabled: phoneMutation.isPending, className: "bg-[#C48A5A] text-white hover:bg-[#C48A5A]/90 rounded-xl", children: phoneMutation.isPending ? /* @__PURE__ */ jsxRuntimeExports.jsx(LoaderCircle, { className: "h-4 w-4 animate-spin" }) : "Analyze Number" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(AnimatePresence, { mode: "wait", children: [
          phoneMutation.isPending && /* @__PURE__ */ jsxRuntimeExports.jsx(ScanLoader, { label: "Querying numbering plan & intelligence feeds…" }, "pl"),
          phoneResult && !phoneMutation.isPending && /* @__PURE__ */ jsxRuntimeExports.jsxs(motion.div, { initial: {
            opacity: 0,
            y: 8
          }, animate: {
            opacity: 1,
            y: 0
          }, className: "mt-5 space-y-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(TrustBanner, { score: phoneResult.trustScore, status: phoneResult.status, category: phoneResult.threatCategory, source: phoneResult.source }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-2 gap-3 text-sm", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(InfoCell, { icon: Phone, label: "Phone Number", value: phoneResult.normalized || phoneResult.phoneNumber }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(InfoCell, { icon: ShieldCheck, label: "Valid Status", value: phoneResult.validStatus }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(InfoCell, { icon: Globe, label: "Country", value: phoneResult.countryCode ? `${phoneResult.country} (${phoneResult.countryCode})` : phoneResult.country }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(InfoCell, { icon: Hash, label: "National Number", value: phoneResult.nationalNumber || "Unknown" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(InfoCell, { icon: Signal, label: "Carrier", value: phoneResult.carrier }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(InfoCell, { icon: Phone, label: "Number Type", value: phoneResult.numberType }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(InfoCell, { icon: ShieldQuestionMark, label: "Reputation", value: phoneResult.reputation }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(InfoCell, { icon: TriangleAlert, label: "Risk Level", value: phoneResult.riskLevel }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(InfoCell, { icon: TriangleAlert, label: "Spam Reports", value: phoneResult.reports.toLocaleString() }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(InfoCell, { icon: Gauge, label: "Confidence", value: `${phoneResult.confidence}%` })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Explanation, { text: phoneResult.explanation }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(ReasonList, { reasons: phoneResult.reasons })
          ] }, "pr")
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(motion.div, { initial: {
        opacity: 0,
        y: 12
      }, animate: {
        opacity: 1,
        y: 0,
        transition: {
          delay: 0.05
        }
      }, className: "rounded-3xl bg-white border border-[#E4DEC6]/60 p-6 shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4 flex items-center gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex h-10 w-10 items-center justify-center rounded-xl bg-[#4F7EF7]/10 border border-[#4F7EF7]/25", children: /* @__PURE__ */ jsxRuntimeExports.jsx(MessageSquare, { className: "h-5 w-5 text-[#4F7EF7]" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-md font-bold text-gray-800 font-poppins", children: "SMS Scam Detection" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[11px] font-medium text-gray-500 font-manrope", children: "Detects lottery, OTP, banking, phishing & investment scams — typo-tolerant." })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { onSubmit: (e) => {
          e.preventDefault();
          if (!sms.trim()) return toast.error("Paste SMS content");
          smsMutation.mutate(sms.trim());
        }, className: "space-y-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Textarea, { placeholder: "e.g. Congratulations! You won a lottry prize of $500000. Click here to claim.", value: sms, onChange: (e) => setSms(e.target.value), maxLength: 4e3, rows: 4, className: "resize-none bg-[#FAF8F5] border-[#E4DEC6] text-gray-800 rounded-xl" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Button, { type: "submit", disabled: smsMutation.isPending, className: "w-full bg-[#4F7EF7] text-white hover:bg-[#4F7EF7]/90 rounded-xl", children: smsMutation.isPending ? /* @__PURE__ */ jsxRuntimeExports.jsx(LoaderCircle, { className: "h-4 w-4 animate-spin" }) : "Analyze SMS" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(AnimatePresence, { mode: "wait", children: [
          smsMutation.isPending && /* @__PURE__ */ jsxRuntimeExports.jsx(ScanLoader, { label: "Scanning content & extracting indicators…" }, "sl"),
          smsResult && !smsMutation.isPending && /* @__PURE__ */ jsxRuntimeExports.jsxs(motion.div, { initial: {
            opacity: 0,
            y: 8
          }, animate: {
            opacity: 1,
            y: 0
          }, className: "mt-5 space-y-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(TrustBanner, { score: smsResult.trustScore, status: smsResult.status, category: smsResult.category, source: smsResult.source }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-2 gap-3 text-sm", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(InfoCell, { icon: TriangleAlert, label: "Threat Level", value: smsResult.threatLevel }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(InfoCell, { icon: ShieldAlert, label: "Threat Category", value: smsResult.category }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(InfoCell, { icon: Gauge, label: "Confidence", value: `${Math.round(smsResult.confidence)}%` }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(InfoCell, { icon: Clock, label: "Last Checked", value: new Date(smsResult.checkedAt).toLocaleTimeString() })
            ] }),
            smsResult.urls.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mb-2 text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope", children: "Extracted URLs" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-1", children: smsResult.urls.map((u, i) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 rounded-xl border border-[#E05A52]/20 bg-[#E05A52]/[0.04] px-3 py-1.5 text-xs text-[#E05A52]", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(Link2, { className: "h-3 w-3 shrink-0" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate", children: u })
              ] }, i)) })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Explanation, { text: smsResult.explanation }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(ReasonList, { reasons: smsResult.reasons })
          ] }, "sr")
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("section", { className: "mx-auto mt-10 max-w-7xl px-4 pb-16 sm:px-6 lg:px-8", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(motion.div, { initial: {
      opacity: 0,
      y: 12
    }, whileInView: {
      opacity: 1,
      y: 0
    }, viewport: {
      once: true
    }, className: "rounded-3xl bg-white border border-[#E4DEC6]/60 p-6 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4 flex items-center justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Activity, { className: "h-5 w-5 text-[#34A853]" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-md font-bold text-gray-800 font-poppins", children: "Threat Intelligence Log" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-gray-400 font-medium font-manrope font-semibold", children: [
          "Live · ",
          log.length,
          " events"
        ] })
      ] }),
      log.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-[#E4DEC6] bg-[#FAF8F5] p-8 text-center text-xs font-semibold text-gray-500 font-manrope", children: "No events yet. Run an analysis above to populate the log." }) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "overflow-x-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(Table, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(TableHeader, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(TableRow, { className: "border-b border-[#E4DEC6]/60", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(TableHead, { className: "text-xs font-bold text-gray-400 font-manrope uppercase", children: "Timestamp" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(TableHead, { className: "text-xs font-bold text-gray-400 font-manrope uppercase", children: "Analysis Type" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(TableHead, { className: "text-xs font-bold text-gray-400 font-manrope uppercase", children: "Threat Category" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(TableHead, { className: "text-xs font-bold text-gray-400 font-manrope uppercase", children: "Phone / SMS" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(TableHead, { className: "text-xs font-bold text-gray-400 font-manrope uppercase", children: "Trust" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(TableHead, { className: "text-xs font-bold text-gray-400 font-manrope uppercase", children: "Status" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(TableHead, { className: "text-xs font-bold text-gray-400 font-manrope uppercase", children: "Country" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(TableHead, { className: "text-xs font-bold text-gray-400 font-manrope uppercase", children: "Carrier" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(TableHead, { className: "text-xs font-bold text-gray-400 font-manrope uppercase", children: "Confidence" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(TableHead, { className: "text-xs font-bold text-gray-400 font-manrope uppercase", children: "Source" })
        ] }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(TableBody, { children: log.map((row) => {
          const s = statusStyles[row.status];
          return /* @__PURE__ */ jsxRuntimeExports.jsxs(TableRow, { className: "border-b border-[#E4DEC6]/40 hover:bg-[#FAF8F5]/30", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(TableCell, { className: "whitespace-nowrap text-xs text-gray-500 font-manrope", children: new Date(row.ts).toLocaleString() }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(TableCell, { className: "text-xs text-gray-700 font-medium font-poppins", children: row.analysisType }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(TableCell, { className: "text-xs text-gray-800 font-semibold font-manrope", children: row.threatCategory }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(TableCell, { className: "max-w-[260px] truncate text-xs font-semibold text-gray-700 font-manrope", children: row.target }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(TableCell, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-mono text-xs font-bold", style: {
              color: s.color
            }, children: [
              row.trustScore,
              "%"
            ] }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(TableCell, { children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rounded-full px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-wider", style: {
              background: s.bg,
              color: s.color,
              border: `1px solid ${s.border}`
            }, children: s.label }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(TableCell, { className: "text-xs text-gray-600 font-medium font-manrope", children: row.country }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(TableCell, { className: "text-xs text-gray-600 font-medium font-manrope", children: row.carrier }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs(TableCell, { className: "text-xs text-gray-600 font-medium font-manrope", children: [
              row.confidence,
              "%"
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(TableCell, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider", style: row.sourceType === "DB" ? {
              background: "rgba(52,168,83,0.06)",
              color: "#34A853",
              border: "1px solid rgba(52,168,83,0.15)"
            } : {
              background: "rgba(79,126,247,0.06)",
              color: "#4F7EF7",
              border: "1px solid rgba(79,126,247,0.15)"
            }, children: [
              row.sourceType === "DB" ? /* @__PURE__ */ jsxRuntimeExports.jsx(Database, { className: "h-2.5 w-2.5" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Cpu, { className: "h-2.5 w-2.5" }),
              row.sourceType === "DB" ? "DB" : "AI"
            ] }) })
          ] }, row.id);
        }) })
      ] }) })
    ] }) })
  ] });
}
function TrustBanner({
  score,
  status,
  category,
  source
}) {
  const s = statusStyles[status];
  const Icon = s.icon;
  const displayLabel = category === "Invalid Number" ? "Unverifiable" : s.label;
  const isDb = source === "Database Match";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative overflow-hidden rounded-2xl p-4.5", style: {
    background: s.bg,
    border: `1px solid ${s.border}`
  }, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-6 w-6", style: {
          color: s.color
        } }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope", children: [
            "Status · ",
            category
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-md font-extrabold font-poppins", style: {
            color: s.color
          }, children: displayLabel })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-right", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope", children: "Trust Score" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-2xl font-extrabold tabular-nums font-poppins", style: {
          color: s.color
        }, children: [
          score,
          "%"
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3.5 h-2 overflow-hidden rounded-full bg-gray-200", children: /* @__PURE__ */ jsxRuntimeExports.jsx(motion.div, { initial: {
      width: 0
    }, animate: {
      width: `${score}%`
    }, transition: {
      duration: 0.8,
      ease: "easeOut"
    }, className: "h-full rounded-full", style: {
      background: s.color
    } }) }),
    source && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2.5 flex justify-end", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider font-poppins", style: isDb ? {
      background: "rgba(52,168,83,0.06)",
      color: "#34A853",
      border: "1px solid rgba(52,168,83,0.15)"
    } : {
      background: "rgba(79,126,247,0.06)",
      color: "#4F7EF7",
      border: "1px solid rgba(79,126,247,0.15)"
    }, children: [
      isDb ? /* @__PURE__ */ jsxRuntimeExports.jsx(Database, { className: "h-2.5 w-2.5" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Cpu, { className: "h-2.5 w-2.5" }),
      source
    ] }) })
  ] });
}
function InfoCell({
  icon: Icon,
  label,
  value
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-[#E4DEC6]/40 bg-[#FAF8F5] p-3.5 shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-3.5 w-3.5" }),
      " ",
      label
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1.5 truncate text-xs font-bold text-gray-700 font-poppins", children: value })
  ] });
}
function Explanation({
  text
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-[#C48A5A]/20 bg-[#C48A5A]/[0.04] p-4 text-xs leading-relaxed text-gray-600 font-manrope shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-bold text-[#C48A5A] font-poppins", children: "Analyst summary: " }),
    text
  ] });
}
function ReasonList({
  reasons
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-[#E4DEC6]/40 bg-[#FAF8F5] p-4 shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mb-2 text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope", children: "Evidence & indicators" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-1.5", children: reasons.map((r, i) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex items-start gap-2.5 text-xs text-gray-600 font-manrope leading-relaxed", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[#C48A5A]" }),
      " ",
      r
    ] }, i)) })
  ] });
}
function ScanLoader({
  label
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(motion.div, { initial: {
    opacity: 0
  }, animate: {
    opacity: 1
  }, exit: {
    opacity: 0
  }, className: "mt-5 rounded-2xl border border-[#C48A5A]/20 bg-[#C48A5A]/[0.03] p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3 text-xs font-bold text-[#C48A5A] font-poppins", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(LoaderCircle, { className: "h-4 w-4 animate-spin" }),
      " ",
      label
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3.5 h-1 overflow-hidden rounded-full bg-gray-200", children: /* @__PURE__ */ jsxRuntimeExports.jsx(motion.div, { animate: {
      x: ["-100%", "100%"]
    }, transition: {
      duration: 1.2,
      repeat: Infinity,
      ease: "easeInOut"
    }, className: "h-full w-1/3 rounded-full bg-gradient-to-r from-transparent via-[#C48A5A] to-transparent" }) })
  ] });
}
export {
  IntelPage as component
};
