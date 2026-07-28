import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { motion, AnimatePresence } from "framer-motion";
import {
  Phone, MessageSquare, Loader2, ShieldAlert, ShieldCheck, ShieldQuestion,
  Globe, Signal, Clock, Link2, AlertTriangle, Activity, Radar, Hash, Gauge,
  Database, Cpu,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ParticlesBackground } from "@/components/particles-background";
import {
  analyzeSms, buildPhoneAnalysis, statusToSeverity,
  type PhoneAnalysis, type SmsAnalysis, type TrustStatus,
} from "@/lib/intel-analyzers";
import { validatePhoneAbstract } from "@/lib/phone.functions";
import { createEntity, listEntity } from "@/lib/entities.functions";
import { lookupPhoneInDb, lookupSmsInDb, logSearch } from "@/lib/db-lookup.functions";


export const Route = createFileRoute("/call-sms-intel")({
  head: () => ({
    meta: [
      { title: "Phone & SMS Intelligence — Scam Detector AI" },
      { name: "description", content: "Phone Number Intelligence and SMS scam detection with explainable trust scores, validation, and realistic telecom data." },
    ],
  }),
  component: IntelPage,
});

const statusStyles: Record<TrustStatus, { color: string; bg: string; border: string; label: string; icon: typeof ShieldAlert }> = {
  scam: { color: "#E05A52", bg: "rgba(224,90,82,0.06)", border: "rgba(224,90,82,0.2)", label: "Scam / Threat Detected", icon: ShieldAlert },
  suspicious: { color: "#E8A23C", bg: "rgba(232,162,60,0.06)", border: "rgba(232,162,60,0.2)", label: "Suspicious Activity", icon: ShieldQuestion },
  legitimate: { color: "#34A853", bg: "rgba(52,168,83,0.06)", border: "rgba(52,168,83,0.2)", label: "No Active Threats", icon: ShieldCheck },
};

interface LogItem {
  id: string;
  ts: string;
  analysisType: "Phone Number Analysis" | "SMS Analysis";
  threatCategory: string;
  target: string;
  trustScore: number;
  status: TrustStatus;
  country: string;
  carrier: string;
  confidence: number;
  sourceType: "DB" | "AI";
}


// ---------------------------------------------------------------------------
// DB row → PhoneAnalysis / SmsAnalysis mappers
// The database is the source of truth. We read values EXACTLY as stored.
// ---------------------------------------------------------------------------
import type { DbPhoneRecord, DbSmsRecord } from "@/lib/db-lookup.functions";

function severityToTrustDb(sev: string): number {
  return sev === "critical" ? 8 : sev === "high" ? 25 : sev === "medium" ? 52 : 85;
}
function severityToStatusDb(sev: string): TrustStatus {
  return sev === "critical" || sev === "high" ? "scam" : sev === "medium" ? "suspicious" : "legitimate";
}
function severityToThreatLevelDb(sev: string): "Low" | "Medium" | "High" | "Critical" {
  return sev === "critical" ? "Critical" : sev === "high" ? "High" : sev === "medium" ? "Medium" : "Low";
}

function parsePattern(pattern: string | null) {
  // Pattern stored as "Category · Type · Carrier · trust X%"
  const parts = (pattern ?? "").split(" · ");
  return {
    category:   (parts[0] || "Unknown") as import("@/lib/intel-analyzers").ThreatCategory,
    numberType: (parts[1] || "Unknown") as import("@/lib/intel-analyzers").NumberType,
    carrier:    parts[2] || "Unknown",
    trustScore: parseInt(parts[3]?.replace(/[^0-9]/g, "") ?? "", 10) || -1,
  };
}

function dbPhoneToAnalysis(hit: DbPhoneRecord): import("@/lib/intel-analyzers").PhoneAnalysis {
  const { category, numberType, carrier, trustScore: patternTrust } = parsePattern(hit.pattern);
  const trust = patternTrust >= 0 ? patternTrust : severityToTrustDb(hit.severity);
  const status = severityToStatusDb(hit.severity);
  const checkedAt = hit.reported_at ?? hit.detected_at ?? new Date().toISOString();
  return {
    phoneNumber:    hit.phone_number,
    normalized:     hit.phone_number,
    nationalNumber: hit.phone_number,
    valid:          true,
    trustScore:     trust,
    status,
    threatCategory: category,
    reports:        0,
    country:        hit.country ?? "Unknown",
    countryCode:    "",
    carrier,
    numberType,
    confidence:     100,
    checkedAt,
    explanation:    `This phone number was found in the threat database with severity “${hit.severity}”. The information displayed is taken directly from the database record and has not been modified.`,
    reasons:        [
      `Database record ID: ${hit.id}.`,
      `Stored severity: ${hit.severity}.`,
      hit.pattern ? `Pattern: ${hit.pattern}.` : "No additional pattern data.",
    ],
    reputation:     status === "scam" ? "Known Threat" : status === "suspicious" ? "Suspicious" : "Verified Safe",
    riskLevel:      severityToThreatLevelDb(hit.severity),
    validStatus:    "Database Record",
    source:         "Database Match",
  };
}

function dbSmsToAnalysis(hit: DbSmsRecord): import("@/lib/intel-analyzers").SmsAnalysis {
  const status = severityToStatusDb(hit.severity);
  const checkedAt = hit.detected_at ?? new Date().toISOString();
  // Derive category from severity + content keywords
  let category: import("@/lib/intel-analyzers").SmsCategory = "Unknown";
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
    trustScore:  severityToTrustDb(hit.severity),
    status,
    threatLevel: severityToThreatLevelDb(hit.severity),
    category,
    reasons: [
      `Database record ID: ${hit.id}.`,
      `Stored severity: ${hit.severity}.`,
      `Channel: ${hit.channel}${hit.sender ? ` | Sender: ${hit.sender}` : ""}.`,
      "This result is taken directly from the database and has not been modified.",
    ],
    urls:        [],
    confidence:  100,
    checkedAt,
    explanation: `This SMS was found in the threat database (ID: ${hit.id}) with severity “${hit.severity}”. The result is taken directly from the database record.`,
    source:      "Database Match",
  };
}

function IntelPage() {
  const qc = useQueryClient();
  const create = useServerFn(createEntity);
  const list = useServerFn(listEntity);
  const validatePhone = useServerFn(validatePhoneAbstract);
  const dbPhoneLookup = useServerFn(lookupPhoneInDb);
  const dbSmsLookup   = useServerFn(lookupSmsInDb);
  const logSearchCall = useServerFn(logSearch);


  const [phone, setPhone] = useState("");
  const [sms, setSms] = useState("");
  const [phoneResult, setPhoneResult] = useState<PhoneAnalysis | null>(null);
  const [smsResult, setSmsResult] = useState<SmsAnalysis | null>(null);
  const [localLog, setLocalLog] = useState<LogItem[]>([]);

  const recentCalls = useQuery({
    queryKey: ["entity", "spam_calls"],
    queryFn: () => list({ data: { entity: "spam_calls" } }),
    staleTime: 10_000,
  });
  const recentMessages = useQuery({
    queryKey: ["entity", "scam_messages"],
    queryFn: () => list({ data: { entity: "scam_messages" } }),
    staleTime: 10_000,
  });

  const phoneMutation = useMutation({
    mutationFn: async (value: string) => {
      // ── STEP 1: Check database first ────────────────────────────────────
      const dbHit = await dbPhoneLookup({ data: { phone: value } });
      if (dbHit.found) {
        const res = dbPhoneToAnalysis(dbHit);
        try {
          await logSearchCall({
            data: {
              module: "Phone",
              input: value,
              dbMatch: true,
              aiUsed: false,
              result: res.threatCategory,
            },
          });
        } catch { /* best-effort */ }
        return res;
      }

      // ── STEP 2: No DB match — run existing AI analysis ──────────────────
      const api = await validatePhone({ data: { phone: value } });
      const result = buildPhoneAnalysis(value, api);
      try {
        await logSearchCall({
          data: {
            module: "Phone",
            input: value,
            dbMatch: false,
            aiUsed: true,
            result: result.threatCategory,
          },
        });
      } catch { /* best-effort */ }
      try {
        await create({
          data: {
            entity: "spam_calls",
            values: {
              phone_number: result.normalized || value,
              country: result.country,
              severity: statusToSeverity(result.status, result.trustScore),
              pattern: `${result.threatCategory} · ${result.numberType} · ${result.carrier} · trust ${result.trustScore}%`.slice(0, 500),
            },
          },
        });
      } catch { /* best-effort */ }
      return result;
    },
    onSuccess: (r) => {
      setPhoneResult(r);
      const item: LogItem = {
        id: crypto.randomUUID(), ts: r.checkedAt,
        analysisType: "Phone Number Analysis", threatCategory: r.threatCategory,
        target: r.phoneNumber, trustScore: r.trustScore, status: r.status,
        country: r.country, carrier: r.carrier, confidence: r.confidence,
        sourceType: r.source === "Database Match" ? "DB" : "AI",
      };
      setLocalLog((l) => [item, ...l].slice(0, 50));
      const t = r.status === "scam" ? "error" : r.status === "suspicious" ? "warning" : "success";
      toast[t](`${r.phoneNumber} — ${r.threatCategory} (trust ${r.trustScore}%) · ${r.source}`);
      qc.invalidateQueries({ queryKey: ["entity", "spam_calls"] });
      qc.invalidateQueries({ queryKey: ["dashboard-metrics"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });


  const smsMutation = useMutation({
    mutationFn: async (text: string) => {
      // ── STEP 1: Check database first ────────────────────────────────────
      const dbHit = await dbSmsLookup({ data: { text } });
      if (dbHit.found) {
        const res = dbSmsToAnalysis(dbHit);
        try {
          await logSearchCall({
            data: {
              module: "SMS",
              input: text,
              dbMatch: true,
              aiUsed: false,
              result: res.category,
            },
          });
        } catch { /* best-effort */ }
        return res;
      }

      // ── STEP 2: No DB match — run existing AI analysis ──────────────────
      const api = await analyzeSms(text);
      try {
        await logSearchCall({
          data: {
            module: "SMS",
            input: text,
            dbMatch: false,
            aiUsed: true,
            result: api.category,
          },
        });
      } catch { /* best-effort */ }
      try {
        await create({
          data: {
            entity: "scam_messages",
            values: {
              channel: "sms",
              content: text,
              severity: statusToSeverity(api.status, api.trustScore),
            },
          },
        });
      } catch { /* best-effort */ }
      return api;
    },
    onSuccess: (r) => {
      setSmsResult(r);
      const item: LogItem = {
        id: crypto.randomUUID(), ts: r.checkedAt,
        analysisType: "SMS Analysis", threatCategory: r.category,
        target: sms.length > 50 ? `${sms.slice(0, 50)}…` : sms,
        trustScore: r.trustScore, status: r.status,
        country: "N/A", carrier: "N/A", confidence: r.confidence,
        sourceType: r.source === "Database Match" ? "DB" : "AI",
      };
      setLocalLog((l) => [item, ...l].slice(0, 50));
      const t = r.status === "scam" ? "error" : r.status === "suspicious" ? "warning" : "success";
      toast[t](`SMS analyzed — category: ${r.category} (trust ${r.trustScore}%) · ${r.source}`);
      qc.invalidateQueries({ queryKey: ["entity", "scam_messages"] });
      qc.invalidateQueries({ queryKey: ["dashboard-metrics"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const callsList = recentCalls.data?.rows ?? [];
  const msgsList  = recentMessages.data?.rows ?? [];

  // Build client-side history timeline by merging state events with DB records
  const log: LogItem[] = [...localLog];

  callsList.forEach((c) => {
    const { category, carrier, trustScore: patternTrust } = parsePattern(c.pattern);
    const trust = patternTrust >= 0 ? patternTrust : severityToTrustDb(c.severity);
    const status = severityToStatusDb(c.severity);
    if (!log.some((l) => l.id === c.id || l.target === c.phone_number)) {
      log.push({
        id:             c.id,
        ts:             c.reported_at ?? c.created_at ?? new Date().toISOString(),
        analysisType:   "Phone Number Analysis",
        threatCategory: category,
        target:         c.phone_number,
        trustScore:     trust,
        status,
        country:        c.country ?? "Unknown",
        carrier,
        confidence:     100,
        sourceType:     "DB",
      });
    }
  });

  msgsList.forEach((m) => {
    const status = severityToStatusDb(m.severity);
    if (!log.some((l) => l.id === m.id || l.target.startsWith(m.content.slice(0, 30)))) {
      log.push({
        id:             m.id,
        ts:             m.detected_at ?? m.created_at ?? new Date().toISOString(),
        analysisType:   "SMS Analysis",
        threatCategory: "Scam Message",
        target:         m.content,
        trustScore:     severityToTrustDb(m.severity),
        status,
        country:        "N/A",
        carrier:        "N/A",
        confidence:     100,
        sourceType:     "DB",
      });
    }
  });

  // Sort log by timestamp descending
  log.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());

  return (
    <div className="relative min-h-screen pb-12">
      <div className="absolute inset-0 -z-10"><ParticlesBackground /></div>

      {/* Header Banner */}
      <section className="mx-auto max-w-7xl px-4 pt-8 sm:px-6 lg:px-8">
        <div className="rounded-3xl bg-white border border-[#E4DEC6]/80 p-8 shadow-sm">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-[#C48A5A]/15 ring-1 ring-[#C48A5A]/40">
              <Radar className="h-6 w-6 text-[#C48A5A]" />
            </div>
            <div>
              <h1 className="text-2xl font-extrabold text-gray-800 font-poppins">Phone &amp; SMS Intelligence</h1>
              <p className="text-sm font-medium text-gray-500 font-manrope mt-0.5">
                Real-time validation against the numbering plan and scanning with explainable scam logic.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto mt-8 grid max-w-7xl grid-cols-1 gap-6 px-4 sm:px-6 lg:grid-cols-2 lg:px-8">
        {/* PHONE ANALYZER */}
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="rounded-3xl bg-white border border-[#E4DEC6]/60 p-6 shadow-sm">
          <div className="mb-4 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#C48A5A]/10 border border-[#C48A5A]/25">
              <Phone className="h-5 w-5 text-[#C48A5A]" />
            </div>
            <div>
              <h2 className="text-md font-bold text-gray-800 font-poppins">Phone Number Intelligence</h2>
              <p className="text-[11px] font-medium text-gray-500 font-manrope">Validate &amp; reputation-check any phone number — country code optional.</p>
            </div>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!phone.trim()) return toast.error("Enter a phone number");
              phoneMutation.mutate(phone.trim());
            }}
            className="flex gap-2"
          >
            <Input
              placeholder="e.g. 9876543210 or +91 80 6527 3679"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              maxLength={32}
              className="bg-[#FAF8F5] border-[#E4DEC6] text-gray-800 rounded-xl"
            />
            <Button type="submit" disabled={phoneMutation.isPending} className="bg-[#C48A5A] text-white hover:bg-[#C48A5A]/90 rounded-xl">
              {phoneMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Analyze Number"}
            </Button>
          </form>

          <AnimatePresence mode="wait">
            {phoneMutation.isPending && <ScanLoader key="pl" label="Querying numbering plan &amp; intelligence feeds…" />}
            {phoneResult && !phoneMutation.isPending && (
              <motion.div key="pr" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-5 space-y-4">
                <TrustBanner score={phoneResult.trustScore} status={phoneResult.status} category={phoneResult.threatCategory} source={phoneResult.source} />
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <InfoCell icon={Phone} label="Phone Number" value={phoneResult.normalized || phoneResult.phoneNumber} />
                  <InfoCell icon={ShieldCheck} label="Valid Status" value={phoneResult.validStatus} />
                  <InfoCell icon={Globe} label="Country" value={phoneResult.countryCode ? `${phoneResult.country} (${phoneResult.countryCode})` : phoneResult.country} />
                  <InfoCell icon={Hash} label="National Number" value={phoneResult.nationalNumber || "Unknown"} />
                  <InfoCell icon={Signal} label="Carrier" value={phoneResult.carrier} />
                  <InfoCell icon={Phone} label="Number Type" value={phoneResult.numberType} />
                  <InfoCell icon={ShieldQuestion} label="Reputation" value={phoneResult.reputation} />
                  <InfoCell icon={AlertTriangle} label="Risk Level" value={phoneResult.riskLevel} />
                  <InfoCell icon={AlertTriangle} label="Spam Reports" value={phoneResult.reports.toLocaleString()} />
                  <InfoCell icon={Gauge} label="Confidence" value={`${phoneResult.confidence}%`} />
                </div>
                <Explanation text={phoneResult.explanation} />
                <ReasonList reasons={phoneResult.reasons} />
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {/* SMS ANALYZER */}
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0, transition: { delay: 0.05 } }} className="rounded-3xl bg-white border border-[#E4DEC6]/60 p-6 shadow-sm">
          <div className="mb-4 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#4F7EF7]/10 border border-[#4F7EF7]/25">
              <MessageSquare className="h-5 w-5 text-[#4F7EF7]" />
            </div>
            <div>
              <h2 className="text-md font-bold text-gray-800 font-poppins">SMS Scam Detection</h2>
              <p className="text-[11px] font-medium text-gray-500 font-manrope">Detects lottery, OTP, banking, phishing &amp; investment scams — typo-tolerant.</p>
            </div>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!sms.trim()) return toast.error("Paste SMS content");
              smsMutation.mutate(sms.trim());
            }}
            className="space-y-2"
          >
            <Textarea
              placeholder="e.g. Congratulations! You won a lottry prize of $500000. Click here to claim."
              value={sms}
              onChange={(e) => setSms(e.target.value)}
              maxLength={4000}
              rows={4}
              className="resize-none bg-[#FAF8F5] border-[#E4DEC6] text-gray-800 rounded-xl"
            />
            <Button type="submit" disabled={smsMutation.isPending} className="w-full bg-[#4F7EF7] text-white hover:bg-[#4F7EF7]/90 rounded-xl">
              {smsMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Analyze SMS"}
            </Button>
          </form>

          <AnimatePresence mode="wait">
            {smsMutation.isPending && <ScanLoader key="sl" label="Scanning content &amp; extracting indicators…" />}
            {smsResult && !smsMutation.isPending && (
              <motion.div key="sr" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-5 space-y-4">
                <TrustBanner score={smsResult.trustScore} status={smsResult.status} category={smsResult.category} source={smsResult.source} />
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <InfoCell icon={AlertTriangle} label="Threat Level" value={smsResult.threatLevel} />
                  <InfoCell icon={ShieldAlert} label="Threat Category" value={smsResult.category} />
                  <InfoCell icon={Gauge} label="Confidence" value={`${Math.round(smsResult.confidence)}%`} />
                  <InfoCell icon={Clock} label="Last Checked" value={new Date(smsResult.checkedAt).toLocaleTimeString()} />
                </div>
                {smsResult.urls.length > 0 && (
                  <div>
                    <div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">Extracted URLs</div>
                    <div className="space-y-1">
                      {smsResult.urls.map((u, i) => (
                        <div key={i} className="flex items-center gap-2 rounded-xl border border-[#E05A52]/20 bg-[#E05A52]/[0.04] px-3 py-1.5 text-xs text-[#E05A52]">
                          <Link2 className="h-3 w-3 shrink-0" />
                          <span className="truncate">{u}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                <Explanation text={smsResult.explanation} />
                <ReasonList reasons={smsResult.reasons} />
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      </section>

      {/* THREAT INTELLIGENCE LOG */}
      <section className="mx-auto mt-10 max-w-7xl px-4 pb-16 sm:px-6 lg:px-8">
        <motion.div initial={{ opacity: 0, y: 12 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="rounded-3xl bg-white border border-[#E4DEC6]/60 p-6 shadow-sm">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-[#34A853]" />
              <h2 className="text-md font-bold text-gray-800 font-poppins">Threat Intelligence Log</h2>
            </div>
            <span className="text-xs text-gray-400 font-medium font-manrope font-semibold">Live · {log.length} events</span>
          </div>
          {log.length === 0 ? (
            <div className="rounded-xl border border-[#E4DEC6] bg-[#FAF8F5] p-8 text-center text-xs font-semibold text-gray-500 font-manrope">
              No events yet. Run an analysis above to populate the log.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-b border-[#E4DEC6]/60">
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Timestamp</TableHead>
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Analysis Type</TableHead>
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Threat Category</TableHead>
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Phone / SMS</TableHead>
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Trust</TableHead>
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Status</TableHead>
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Country</TableHead>
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Carrier</TableHead>
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Confidence</TableHead>
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Source</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {log.map((row) => {
                    const s = statusStyles[row.status];
                    return (
                      <TableRow key={row.id} className="border-b border-[#E4DEC6]/40 hover:bg-[#FAF8F5]/30">
                        <TableCell className="whitespace-nowrap text-xs text-gray-500 font-manrope">{new Date(row.ts).toLocaleString()}</TableCell>
                        <TableCell className="text-xs text-gray-700 font-medium font-poppins">{row.analysisType}</TableCell>
                        <TableCell className="text-xs text-gray-800 font-semibold font-manrope">{row.threatCategory}</TableCell>
                        <TableCell className="max-w-[260px] truncate text-xs font-semibold text-gray-700 font-manrope">{row.target}</TableCell>
                        <TableCell>
                          <span className="font-mono text-xs font-bold" style={{ color: s.color }}>{row.trustScore}%</span>
                        </TableCell>
                        <TableCell>
                          <span className="rounded-full px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-wider" style={{ background: s.bg, color: s.color, border: `1px solid ${s.border}` }}>
                            {s.label}
                          </span>
                        </TableCell>
                        <TableCell className="text-xs text-gray-600 font-medium font-manrope">{row.country}</TableCell>
                        <TableCell className="text-xs text-gray-600 font-medium font-manrope">{row.carrier}</TableCell>
                        <TableCell className="text-xs text-gray-600 font-medium font-manrope">{row.confidence}%</TableCell>
                        <TableCell>
                          <span
                            className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider"
                            style={row.sourceType === "DB"
                              ? { background: "rgba(52,168,83,0.06)", color: "#34A853", border: "1px solid rgba(52,168,83,0.15)" }
                              : { background: "rgba(79,126,247,0.06)", color: "#4F7EF7", border: "1px solid rgba(79,126,247,0.15)" }
                            }
                          >
                            {row.sourceType === "DB" ? <Database className="h-2.5 w-2.5" /> : <Cpu className="h-2.5 w-2.5" />}
                            {row.sourceType === "DB" ? "DB" : "AI"}
                          </span>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </motion.div>
      </section>
    </div>
  );
}

function TrustBanner({ score, status, category, source }: { score: number; status: TrustStatus; category: string; source?: "Database Match" | "AI Analysis" }) {
  const s = statusStyles[status];
  const Icon = s.icon;
  const displayLabel = category === "Invalid Number" ? "Unverifiable" : s.label;
  const isDb = source === "Database Match";
  return (
    <div className="relative overflow-hidden rounded-2xl p-4.5" style={{ background: s.bg, border: `1px solid ${s.border}` }}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Icon className="h-6 w-6" style={{ color: s.color }} />
          <div>
            <div className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">Status · {category}</div>
            <div className="text-md font-extrabold font-poppins" style={{ color: s.color }}>{displayLabel}</div>
          </div>
        </div>
        <div className="text-right">
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">Trust Score</div>
          <div className="text-2xl font-extrabold tabular-nums font-poppins" style={{ color: s.color }}>{score}%</div>
        </div>
      </div>
      <div className="mt-3.5 h-2 overflow-hidden rounded-full bg-gray-200">
        <motion.div initial={{ width: 0 }} animate={{ width: `${score}%` }} transition={{ duration: 0.8, ease: "easeOut" }} className="h-full rounded-full" style={{ background: s.color }} />
      </div>
      {source && (
        <div className="mt-2.5 flex justify-end">
          <span
            className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider font-poppins"
            style={isDb
              ? { background: "rgba(52,168,83,0.06)", color: "#34A853", border: "1px solid rgba(52,168,83,0.15)" }
              : { background: "rgba(79,126,247,0.06)", color: "#4F7EF7", border: "1px solid rgba(79,126,247,0.15)" }
            }
          >
            {isDb ? <Database className="h-2.5 w-2.5" /> : <Cpu className="h-2.5 w-2.5" />}
            {source}
          </span>
        </div>
      )}
    </div>
  );
}


function InfoCell({ icon: Icon, label, value }: { icon: typeof Phone; label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#E4DEC6]/40 bg-[#FAF8F5] p-3.5 shadow-sm">
      <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">
        <Icon className="h-3.5 w-3.5" /> {label}
      </div>
      <div className="mt-1.5 truncate text-xs font-bold text-gray-700 font-poppins">{value}</div>
    </div>
  );
}

function Explanation({ text }: { text: string }) {
  return (
    <div className="rounded-2xl border border-[#C48A5A]/20 bg-[#C48A5A]/[0.04] p-4 text-xs leading-relaxed text-gray-600 font-manrope shadow-sm">
      <span className="font-bold text-[#C48A5A] font-poppins">Analyst summary: </span>{text}
    </div>
  );
}

function ReasonList({ reasons }: { reasons: string[] }) {
  return (
    <div className="rounded-2xl border border-[#E4DEC6]/40 bg-[#FAF8F5] p-4 shadow-sm">
      <div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">Evidence &amp; indicators</div>
      <ul className="space-y-1.5">
        {reasons.map((r, i) => (
          <li key={i} className="flex items-start gap-2.5 text-xs text-gray-600 font-manrope leading-relaxed">
            <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[#C48A5A]" /> {r}
          </li>
        ))}
      </ul>
    </div>
  );
}

function ScanLoader({ label }: { label: string }) {
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="mt-5 rounded-2xl border border-[#C48A5A]/20 bg-[#C48A5A]/[0.03] p-4">
      <div className="flex items-center gap-3 text-xs font-bold text-[#C48A5A] font-poppins">
        <Loader2 className="h-4 w-4 animate-spin" /> {label}
      </div>
      <div className="mt-3.5 h-1 overflow-hidden rounded-full bg-gray-200">
        <motion.div animate={{ x: ["-100%", "100%"] }} transition={{ duration: 1.2, repeat: Infinity, ease: "easeInOut" }} className="h-full w-1/3 rounded-full bg-gradient-to-r from-transparent via-[#C48A5A] to-transparent" />
      </div>
    </motion.div>
  );
}

function severityToTrust(sev: string): number {
  return sev === "critical" ? 8 : sev === "high" ? 25 : sev === "medium" ? 52 : 85;
}
function severityToStatus(sev: string): TrustStatus {
  return sev === "critical" || sev === "high" ? "scam" : sev === "medium" ? "suspicious" : "legitimate";
}
