import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  Phone, MessageSquare, Loader2, ShieldAlert, ShieldCheck, ShieldQuestion,
  Globe, Signal, Link2, AlertTriangle, Activity, Radar, Hash, Gauge,
  Database, Cpu, CheckCircle2, Search, Mail, AlertCircle, Server,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ParticlesBackground } from "@/components/particles-background";
import {
  buildPhoneAnalysis, predictCallApi, detectThreatApi,
  type PhoneAnalysis, type TrustStatus, type CallDetectionResponse,
  type GenericThreatDetectionResponse, type SmsAnalysis,
} from "@/lib/intel-analyzers";
import { validatePhoneAbstract } from "@/lib/phone.functions";
import { createEntity, listEntity, toSafeString } from "@/lib/entities.functions";
import { lookupPhoneInDb, logSearch } from "@/lib/db-lookup.functions";
import { formatConfidence, formatPercent, parseNumeric, normalizeConfidence } from "@/lib/formatters";


interface DbSmsRecord {
  id?: string;
  severity?: string;
  detected_at?: string;
  content?: string;
  channel?: string;
  sender?: string;
}

export const Route = createFileRoute("/call-sms-intel")({
  head: () => ({
    meta: [
      { title: "Threat Intelligence — VigiLock" },
      { name: "description", content: "Investigate potential threats using VigiLock. Analyze calls, SMS, URLs, IPs, and emails across all 5 CTI domains." },
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
  analysisType: string;
  threatCategory: string;
  target: string;
  trustScore: number;
  status: TrustStatus;
  country: string;
  carrier: string;
  confidence: number;
  sourceType: "DB" | "AI";
}

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
  const parts = (pattern ?? "").split(" · ");
  return {
    category: (parts[0] || "Unknown") as import("@/lib/intel-analyzers").ThreatCategory,
    numberType: (parts[1] || "Unknown") as import("@/lib/intel-analyzers").NumberType,
    carrier: parts[2] || "Unknown",
    trustScore: parseInt(parts[3]?.replace(/[^0-9]/g, "") ?? "", 10) || -1,
  };
}

function dbSmsToAnalysis(hit: DbSmsRecord): import("@/lib/intel-analyzers").SmsAnalysis {
  const status = severityToStatusDb(hit.severity ?? "");
  const checkedAt = hit.detected_at ?? new Date().toISOString();
  let category: import("@/lib/intel-analyzers").SmsCategory = "Unknown";
  const lower = (hit.content ?? "").toLowerCase();
  if (/lottery|prize|winner|won|jackpot|lucky/.test(lower)) category = "Lottery Scam";
  else if (/bank|account|kyc|suspended|blocked/.test(lower)) category = "Banking Fraud";
  else if (/invest|return|profit|crypto|double/.test(lower)) category = "Fraud";
  else if (/otp|verification code|passcode/.test(lower)) category = "OTP Scam";
  else if (/phish|verify your|click the link/.test(lower)) category = "Phishing";
  else if (status === "scam") category = "Fraud";
  else if (status === "suspicious") category = "Spam";
  else category = "Legitimate";

  return {
    trustScore: severityToTrustDb(hit.severity ?? ""),
    status,
    threatLevel: severityToThreatLevelDb(hit.severity ?? ""),
    category,
    reasons: [
      `Database record ID: ${hit.id ?? "Unknown"}.`,
      `Stored severity: ${hit.severity ?? "Unknown"}.`,
      `Channel: ${hit.channel ?? "N/A"}${hit.sender ? ` | Sender: ${hit.sender}` : ""}.`,
      "This result is taken directly from the database and has not been modified.",
    ],
    urls: [],
    confidence: 100,
    checkedAt,
    explanation: `This SMS was found in the threat database (ID: ${hit.id}) with severity “${hit.severity}”. The result is taken directly from the database record.`,
    source: "Database Match",
  };
}

function IntelPage() {
  const qc = useQueryClient();
  const create = createEntity;
  const list = listEntity;
  const validatePhone = validatePhoneAbstract;
  const dbPhoneLookup = lookupPhoneInDb;
  const logSearchCall = logSearch;

  // Active Tab: "phone" | "sms" | "email" | "url" | "ip"
  const [activeTab, setActiveTab] = useState<"phone" | "sms" | "email" | "url" | "ip">("phone");

  // Inputs
  const [phone, setPhone] = useState("");
  const [sms, setSms] = useState("");
  const [email, setEmail] = useState("");
  const [url, setUrl] = useState("");
  const [ip, setIp] = useState("");

  // Results
  const [phoneResult, setPhoneResult] = useState<PhoneAnalysis | null>(null);
  const [callDetectionResult, setCallDetectionResult] = useState<CallDetectionResponse | null>(null);
  const [smsResult, setSmsResult] = useState<GenericThreatDetectionResponse | null>(null);
  const [emailResult, setEmailResult] = useState<GenericThreatDetectionResponse | null>(null);
  const [urlResult, setUrlResult] = useState<GenericThreatDetectionResponse | null>(null);
  const [ipResult, setIpResult] = useState<GenericThreatDetectionResponse | null>(null);

  const [localLog, setLocalLog] = useState<LogItem[]>([]);

  const recentCalls = useQuery({
    queryKey: ["entity", "suspicious_calls"],
    queryFn: () => list({ data: { entity: "suspicious_calls" } }),
    staleTime: 10_000,
  });
  const recentMessages = useQuery({
    queryKey: ["entity", "scam_messages"],
    queryFn: () => list({ data: { entity: "scam_messages" } }),
    staleTime: 10_000,
  });
  const recentUrls = useQuery({
    queryKey: ["entity", "phishing_urls"],
    queryFn: () => list({ data: { entity: "phishing_urls" } }),
    staleTime: 10_000,
  });
  const recentEmails = useQuery({
    queryKey: ["entity", "email_scams"],
    queryFn: () => list({ data: { entity: "email_scams" } }),
    staleTime: 10_000,
  });
  const recentIps = useQuery({
    queryKey: ["entity", "malicious_ips"],
    queryFn: () => list({ data: { entity: "malicious_ips" } }),
    staleTime: 10_000,
  });

  // 1. Phone Reputation Mutation (calling Java /api/v1/detect/call)
  const phoneMutation = useMutation({
    mutationFn: async (value: string) => {
      const apiInfo = await validatePhone({ data: { phone: value } });
      const phoneAnalysis = buildPhoneAnalysis(value, apiInfo);
      const callDetectRes = await predictCallApi(value, apiInfo);

      const dbHit = await dbPhoneLookup({ data: { phone: value } });
      if (dbHit.found) {
        callDetectRes.source = "Database Match & ML Engine";
      }

      try {
        await logSearchCall({
          data: {
            module: "Phone",
            input: value,
            dbMatch: dbHit.found,
            aiUsed: true,
            result: callDetectRes.prediction,
          },
        });
      } catch { /* best-effort */ }

      return { phoneAnalysis, callDetectRes };
    },
    onSuccess: ({ phoneAnalysis, callDetectRes }) => {
      setPhoneResult(phoneAnalysis);
      setCallDetectionResult(callDetectRes);

      const statusVal = (callDetectRes.status || callDetectRes.rawPrediction || callDetectRes.category || "").toUpperCase();
      const isThreat = statusVal === "SCAM" || statusVal === "FRAUD";
      const isSusp   = statusVal === "SUSPICIOUS" || statusVal === "SPAM" || statusVal.includes("REPETITIVE");
      const isInv    = statusVal === "INVALID_NUMBER" || statusVal === "INVALID";

      const status: TrustStatus = isThreat ? "scam" : isSusp ? "suspicious" : "legitimate";
      const callConf = parseNumeric(callDetectRes.confidence);
      const item: LogItem = {
        id: crypto.randomUUID(),
        ts: callDetectRes.timestamp,
        analysisType: "Phone Number Analysis",
        threatCategory: callDetectRes.category || (isThreat ? "Scam / Fraud Call" : isSusp ? "Suspicious Pattern" : "Unreported Number"),
        target: callDetectRes.phone,
        trustScore: callConf != null ? (isThreat ? Math.round(100 - callConf) : Math.round(callConf)) : 50,
        status,
        country: callDetectRes.country,
        carrier: phoneAnalysis.carrier,
        confidence: callConf ?? 0,
        sourceType: callDetectRes.source.includes("Database") ? "DB" : "AI",
      };
      setLocalLog((l) => [item, ...l].slice(0, 50));

      if (isThreat) {
        toast.error(`🚨 THREAT DETECTED: ${callDetectRes.phone} ${callConf != null ? `(${formatPercent(callConf, 0)} confidence)` : "(Confidence: Unverified)"}`);
      } else if (isSusp) {
        toast.warning(`⚠️ SUSPICIOUS CALLER: ${callDetectRes.phone} (${callDetectRes.category || "Suspicious Structure"})`);
      } else if (isInv) {
        toast.error(`❌ INVALID NUMBER: ${callDetectRes.phone}`);
      } else {
        toast.info(`ℹ️ NUMBER ANALYZED: ${callDetectRes.phone} (${callDetectRes.category || "Unreported"})`);
      }

      qc.invalidateQueries({ queryKey: ["entity", "spam_calls"] });
      qc.invalidateQueries({ queryKey: ["entity", "suspicious_calls"] });
      qc.invalidateQueries({ queryKey: ["dashboard-metrics"] });
    },
    onError: (err: Error) => {
      setCallDetectionResult(null);
      const msg = err?.message || "Detection service error.";
      toast.error(msg.includes("backend") ? "Unable to analyze this input. Please check that the Java backend is running on port 8081." : msg);
    },
  });

  // 2. SMS Mutation — same pipeline as Email/URL/IP: React → Java /api/v1/detect/sms → FastAPI scam_messages model
  const smsMutation = useMutation({
    mutationFn: async (text: string) => {
      return await detectThreatApi("sms", text);
    },
    onSuccess: (res) => {
      setSmsResult(res);
      const raw = (res.classification || res.status || res.prediction || "").toUpperCase();
      const isMal = raw === "MALICIOUS" || raw === "SCAM" || raw === "PHISHING" || raw === "CRITICAL" || raw === "FRAUD";
      const isSusp = raw === "SUSPICIOUS" || raw === "SPAM";
      const isInv = raw === "INVALID" || raw === "INVALID_INPUT" || raw === "MALFORMED" || raw.includes("INVALID");
      const isUnv = raw === "UNVERIFIED" || raw === "UNKNOWN";
      const logStatus: TrustStatus = isMal ? "scam" : isSusp ? "suspicious" : "legitimate";

      const confPct = normalizeConfidence(res.ml_confidence, res.confidence) ?? 0;

      const item: LogItem = {
        id: crypto.randomUUID(),
        ts: new Date().toISOString(),
        analysisType: "SMS Analysis",
        threatCategory: res.category || (isMal ? "Scam Message" : isSusp ? "Suspicious Message" : "Legitimate Message"),
        target: sms.length > 50 ? `${sms.slice(0, 50)}…` : sms,
        trustScore: isMal ? Math.max(0, 100 - confPct) : confPct,
        status: logStatus,
        country: "N/A",
        carrier: "N/A",
        confidence: confPct,
        sourceType: res.databaseMatch ? "DB" : "AI",
      };
      setLocalLog((l) => [item, ...l].slice(0, 50));

      const catLabel = res.category?.replace(/_/g, " ") || (isMal ? "SCAM" : isSusp ? "SUSPICIOUS" : "SAFE");
      if (isMal) {
        toast.error(`🚨 SCAM MESSAGE DETECTED (${catLabel}) · Confidence: ${confPct > 0 ? `${confPct}%` : "Unverified"}`);
      } else if (isSusp) {
        toast.warning(`⚠️ SUSPICIOUS MESSAGE (${catLabel}) · Confidence: ${confPct > 0 ? `${confPct}%` : "Unverified"}`);
      } else if (isUnv) {
        toast.info(`⚪ UNVERIFIED MESSAGE (${catLabel})`);
      } else if (isInv) {
        toast.error(`⚪ INVALID MESSAGE INPUT`);
      } else {
        toast.success(`🟢 SAFE MESSAGE: Legitimate content · Confidence: ${confPct > 0 ? `${confPct}%` : "N/A"}`);
      }

      qc.invalidateQueries({ queryKey: ["entity", "scam_messages"] });
      qc.invalidateQueries({ queryKey: ["dashboard-metrics"] });
    },
    onError: (e: Error) => {
      toast.error(e?.message || "Unable to analyze SMS. Ensure the Java backend is running on port 8081.");
    },
  });

  // 3. Email Mutation (calling Java /api/v1/detect/email)
  const emailMutation = useMutation({
    mutationFn: async (text: string) => {
      return await detectThreatApi("email", text);
    },
    onSuccess: (res) => {
      setEmailResult(res);
      const raw = (res.classification || res.status || res.prediction || "").toUpperCase();
      const isMal = raw === "MALICIOUS" || raw === "SCAM" || raw === "PHISHING" || raw === "CRITICAL" || raw === "FRAUD";
      const isSusp = raw === "SUSPICIOUS" || raw === "SPAM";
      const isInv = raw === "INVALID" || raw === "INVALID_INPUT" || raw === "MALFORMED" || raw.includes("INVALID");
      const isUnv = raw === "UNVERIFIED" || raw === "UNKNOWN";
      const status: TrustStatus = isMal ? "scam" : isSusp ? "suspicious" : "legitimate";

      const confNum = normalizeConfidence(res.ml_confidence, res.confidence) ?? 0;

      const dbMatched = !!(res.sources as any)?.database?.matched;
      const item: LogItem = {
        id: crypto.randomUUID(),
        ts: (res as any).timestamp || new Date().toISOString(),
        analysisType: "Email Scam Analysis",
        threatCategory: res.category || res.attack_type || (isMal ? "Phishing Email" : isSusp ? "Suspicious Email" : "Legitimate Email"),
        target: email.length > 50 ? `${email.slice(0, 50)}…` : email,
        trustScore: isMal ? 10 : isSusp ? 50 : 90,
        status,
        country: "Global",
        carrier: "N/A",
        confidence: confNum,
        sourceType: dbMatched ? "DB" : "AI",
      };
      setLocalLog((l) => [item, ...l].slice(0, 50));

      if (isMal) {
        toast.error(`🚨 PHISHING/SCAM EMAIL DETECTED (${res.category || "Malicious"})`);
      } else if (isSusp) {
        toast.warning(`⚠️ SUSPICIOUS EMAIL (${res.category || "Suspicious"})`);
      } else if (isUnv) {
        toast.info(`⚪ UNVERIFIED EMAIL: ${res.category || "Unverified"}`);
      } else if (isInv) {
        toast.error(`⚪ INVALID EMAIL INPUT`);
      } else {
        toast.success(`🟢 LEGITIMATE EMAIL: Low-risk content`);
      }

      qc.invalidateQueries({ queryKey: ["entity", "email_scams"] });
      qc.invalidateQueries({ queryKey: ["dashboard-metrics"] });
    },
    onError: (e: Error) => toast.error(e?.message || "Unable to analyze this email. Please try again."),
  });

  // 4. URL Mutation (calling Java /api/v1/detect/url)
  const urlMutation = useMutation({
    mutationFn: async (text: string) => {
      return await detectThreatApi("url", text);
    },
    onSuccess: (res) => {
      setUrlResult(res);
      const raw = (res.classification || res.status || res.prediction || "").toUpperCase();
      const isMal = raw === "MALICIOUS" || raw === "SCAM" || raw === "PHISHING" || raw === "CRITICAL" || raw === "FRAUD";
      const isSusp = raw === "SUSPICIOUS" || raw === "SPAM";
      const isInv = raw === "INVALID" || raw === "INVALID_INPUT" || raw === "MALFORMED" || raw.includes("INVALID");
      const isUnv = raw === "UNVERIFIED" || raw === "UNKNOWN";
      const status: TrustStatus = isMal ? "scam" : isSusp ? "suspicious" : "legitimate";

      const confNum = normalizeConfidence(res.ml_confidence, res.confidence) ?? 0;

      const dbMatched = !!(res.sources as any)?.database?.matched;
      const item: LogItem = {
        id: crypto.randomUUID(),
        ts: (res as any).timestamp || new Date().toISOString(),
        analysisType: "Phishing URL Analysis",
        threatCategory: res.category || res.attack_type || (isMal ? "Phishing URL" : isSusp ? "Suspicious URL" : "Legitimate URL"),
        target: url,
        trustScore: isMal ? 10 : isSusp ? 50 : 90,
        status,
        country: "Global",
        carrier: "N/A",
        confidence: confNum,
        sourceType: dbMatched ? "DB" : "AI",
      };
      setLocalLog((l) => [item, ...l].slice(0, 50));

      if (isMal) toast.error(`🚨 PHISHING URL DETECTED: ${url}`);
      else if (isSusp) toast.warning(`⚠️ SUSPICIOUS URL: ${url}`);
      else if (isUnv) toast.info(`⚪ UNVERIFIED URL: ${url}`);
      else if (isInv) toast.error(`⚪ INVALID URL INPUT`);
      else toast.success(`🟢 SAFE URL: ${url}`);

      qc.invalidateQueries({ queryKey: ["entity", "phishing_urls"] });
      qc.invalidateQueries({ queryKey: ["dashboard-metrics"] });
    },
    onError: (e: Error) => toast.error(e?.message || "Unable to analyze this URL. Please try again."),
  });

  // 5. IP Mutation (calling Java /api/v1/detect/ip)
  const ipMutation = useMutation({
    mutationFn: async (text: string) => {
      return await detectThreatApi("ip", text);
    },
    onSuccess: (res) => {
      setIpResult(res);
      const cat = (res.category || "").toUpperCase();
      const isPriv = cat.includes("PRIVATE") || cat.includes("LOOPBACK");
      const raw = (res.classification || res.status || res.prediction || "").toUpperCase();
      const isMal = !isPriv && (raw === "MALICIOUS" || raw === "SCAM" || raw === "PHISHING" || raw === "CRITICAL" || raw === "FRAUD");
      const isSusp = !isPriv && (raw === "SUSPICIOUS" || raw === "SPAM");
      const isInv = raw === "INVALID" || raw === "INVALID_INPUT" || raw === "MALFORMED" || raw.includes("INVALID");
      const isUnv = !isPriv && (raw === "UNVERIFIED" || raw === "UNKNOWN");
      const status: TrustStatus = isMal ? "scam" : isSusp ? "suspicious" : "legitimate";

      const confNum = !isPriv ? (normalizeConfidence(res.ml_confidence, res.confidence) ?? 0) : 0;

      const dbMatched = !!(res.sources as any)?.database?.matched;
      const item: LogItem = {
        id: crypto.randomUUID(),
        ts: (res as any).timestamp || new Date().toISOString(),
        analysisType: isPriv ? "Private IP Analysis" : "Malicious IP Analysis",
        threatCategory: res.category || res.attack_type || (isPriv ? "Private Network" : isMal ? "Malicious IP" : isSusp ? "Suspicious IP" : "Legitimate IP"),
        target: ip,
        trustScore: isPriv ? 100 : isMal ? 10 : isSusp ? 50 : 90,
        status,
        country: isPriv ? "Internal Network" : "Global",
        carrier: "N/A",
        confidence: confNum,
        sourceType: dbMatched ? "DB" : "AI",
      };
      setLocalLog((l) => [item, ...l].slice(0, 50));

      if (isPriv) toast.info(`ℹ️ PRIVATE IP ANALYZED: SAFE (${res.category || "Private Network"})`);
      else if (isMal) toast.error(`🚨 MALICIOUS IP DETECTED: ${ip}`);
      else if (isSusp) toast.warning(`⚠️ SUSPICIOUS IP: ${ip}`);
      else if (isUnv) toast.info(`⚪ UNVERIFIED IP: ${ip}`);
      else if (isInv) toast.error(`⚪ INVALID IP INPUT`);
      else toast.success(`🟢 SAFE IP: ${ip}`);

      qc.invalidateQueries({ queryKey: ["entity", "malicious_ips"] });
      qc.invalidateQueries({ queryKey: ["dashboard-metrics"] });
    },
    onError: (e: Error) => toast.error(e?.message || "Unable to analyze this IP address. Please try again."),
  });

  const callsList = recentCalls.data?.rows ?? [];
  const msgsList = recentMessages.data?.rows ?? [];
  const urlsList = recentUrls.data?.rows ?? [];
  const emailsList = recentEmails.data?.rows ?? [];
  const ipsList = recentIps.data?.rows ?? [];
  const log: LogItem[] = [...localLog];

  const seenTargets = new Set<string>();
  log.forEach((l) => { if (l.target) seenTargets.add(l.target.toLowerCase().trim()); });

  callsList.forEach((c) => {
    const rawPattern = toSafeString(c.pattern);
    const rawSeverity = toSafeString(c.severity);
    const rawPhone = toSafeString(c.phone_number);
    const rawId = `call_${toSafeString(c.id)}`;
    const ts = toSafeString(c.detected_at || c.created_at) || new Date().toISOString();
    const country = toSafeString(c.country) || "Unknown";
    const { category, carrier, trustScore: patternTrust } = parsePattern(rawPattern);
    const trust = patternTrust >= 0 ? patternTrust : severityToTrustDb(rawSeverity);
    const status = severityToStatusDb(rawSeverity);
    const key = rawPhone.toLowerCase().trim();

    if (rawPhone && !seenTargets.has(key)) {
      seenTargets.add(key);
      log.push({
        id: rawId, ts, analysisType: "Phone Number Analysis",
        threatCategory: category || "Suspicious Call", target: rawPhone, trustScore: trust,
        status, country, carrier, confidence: 100, sourceType: "DB",
      });
    }
  });

  msgsList.forEach((m) => {
    const rawSeverity = toSafeString(m.severity);
    const rawContent = toSafeString(m.content);
    const rawId = `sms_${toSafeString(m.id)}`;
    const ts = toSafeString(m.detected_at || m.created_at) || new Date().toISOString();
    const status = severityToStatusDb(rawSeverity);
    const key = rawContent.toLowerCase().trim();

    if (rawContent && !seenTargets.has(key)) {
      seenTargets.add(key);
      log.push({
        id: rawId, ts, analysisType: "SMS Analysis",
        threatCategory: "Scam Message", target: rawContent.length > 50 ? `${rawContent.slice(0, 50)}…` : rawContent,
        trustScore: severityToTrustDb(rawSeverity), status,
        country: "N/A", carrier: "N/A", confidence: 100, sourceType: "DB",
      });
    }
  });

  urlsList.forEach((u) => {
    const rawSeverity = toSafeString(u.severity);
    const rawUrl = toSafeString(u.url);
    const rawId = `url_${toSafeString(u.id)}`;
    const ts = toSafeString(u.detected_at || u.created_at) || new Date().toISOString();
    const status = severityToStatusDb(rawSeverity);
    const key = rawUrl.toLowerCase().trim();

    if (rawUrl && !seenTargets.has(key)) {
      seenTargets.add(key);
      log.push({
        id: rawId, ts, analysisType: "Phishing URL Analysis",
        threatCategory: "Phishing URL", target: rawUrl.length > 50 ? `${rawUrl.slice(0, 50)}…` : rawUrl,
        trustScore: severityToTrustDb(rawSeverity), status,
        country: "Global", carrier: "N/A", confidence: 100, sourceType: "DB",
      });
    }
  });

  emailsList.forEach((e) => {
    const rawSeverity = toSafeString(e.severity);
    const rawSender = toSafeString(e.sender || e.subject);
    const rawCategory = toSafeString(e.category) || "Email Scam";
    const rawId = `email_${toSafeString(e.id)}`;
    const ts = toSafeString(e.detected_at || e.created_at) || new Date().toISOString();
    const status = severityToStatusDb(rawSeverity);
    const key = rawSender.toLowerCase().trim();

    if (rawSender && !seenTargets.has(key)) {
      seenTargets.add(key);
      log.push({
        id: rawId, ts, analysisType: "Email Scam Analysis",
        threatCategory: rawCategory, target: rawSender.length > 50 ? `${rawSender.slice(0, 50)}…` : rawSender,
        trustScore: severityToTrustDb(rawSeverity), status,
        country: "Global", carrier: "N/A", confidence: 100, sourceType: "DB",
      });
    }
  });

  ipsList.forEach((i) => {
    const rawSeverity = toSafeString(i.severity);
    const rawIp = toSafeString(i.ip_address);
    const rawThreatType = toSafeString(i.threat_type) || "Malicious IP";
    const rawCountry = toSafeString(i.country) || "Global";
    const rawId = `ip_${toSafeString(i.id)}`;
    const ts = toSafeString(i.detected_at || i.created_at) || new Date().toISOString();
    const status = severityToStatusDb(rawSeverity);
    const key = rawIp.toLowerCase().trim();

    if (rawIp && !seenTargets.has(key)) {
      seenTargets.add(key);
      log.push({
        id: rawId, ts, analysisType: "Malicious IP Analysis",
        threatCategory: rawThreatType, target: rawIp,
        trustScore: severityToTrustDb(rawSeverity), status,
        country: rawCountry, carrier: "N/A", confidence: 100, sourceType: "DB",
      });
    }
  });

  log.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());

  return (
    <div className="relative min-h-screen pb-12">
      <div className="absolute inset-0 -z-10"><ParticlesBackground /></div>

      {/* Header Banner & All 5 Active Navigation Tabs */}
      <section className="mx-auto max-w-7xl px-4 pt-8 sm:px-6 lg:px-8">
        <div className="rounded-3xl bg-white border border-[#E4DEC6]/80 p-6 sm:p-8 shadow-sm">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
            <div className="flex items-center gap-4">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-[#C48A5A]/15 ring-1 ring-[#C48A5A]/40 shrink-0">
                <Radar className="h-7 w-7 text-[#C48A5A]" />
              </div>
              <div>
                <h1 className="text-2xl font-extrabold text-gray-900 font-poppins">Threat Intelligence</h1>
                <p className="text-xs font-semibold text-gray-500 font-manrope mt-1">
                  Investigate potential threats using VigiLock. Select a threat type to analyze suspicious activity.
                </p>
              </div>
            </div>

            {/* 5-Domain Active Tab Navigation */}
            <div className="flex flex-wrap items-center gap-2 rounded-2xl bg-[#FAF8F5] p-2 border border-[#E4DEC6]/70">
              {/* 1. Call */}
              <button
                type="button"
                onClick={() => setActiveTab("phone")}
                className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-bold font-poppins transition-all ${
                  activeTab === "phone"
                    ? "bg-[#C48A5A] text-white shadow-md"
                    : "text-gray-600 hover:bg-white hover:text-gray-900"
                }`}
              >
                <Phone className="h-4 w-4" />
                <span>📞 Call</span>
              </button>

              {/* 2. SMS */}
              <button
                type="button"
                onClick={() => setActiveTab("sms")}
                className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-bold font-poppins transition-all ${
                  activeTab === "sms"
                    ? "bg-[#4F7EF7] text-white shadow-md"
                    : "text-gray-600 hover:bg-white hover:text-gray-900"
                }`}
              >
                <MessageSquare className="h-4 w-4" />
                <span>📱 SMS</span>
              </button>

              {/* 3. URL */}
              <button
                type="button"
                onClick={() => setActiveTab("url")}
                className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-bold font-poppins transition-all ${
                  activeTab === "url"
                    ? "bg-[#8B5CF6] text-white shadow-md"
                    : "text-gray-600 hover:bg-white hover:text-gray-900"
                }`}
              >
                <Link2 className="h-4 w-4" />
                <span>🔗 URL</span>
              </button>

              {/* 4. IP */}
              <button
                type="button"
                onClick={() => setActiveTab("ip")}
                className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-bold font-poppins transition-all ${
                  activeTab === "ip"
                    ? "bg-[#059669] text-white shadow-md"
                    : "text-gray-600 hover:bg-white hover:text-gray-900"
                }`}
              >
                <Globe className="h-4 w-4" />
                <span>🌐 IP</span>
              </button>

              {/* 5. Email */}
              <button
                type="button"
                onClick={() => setActiveTab("email")}
                className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-bold font-poppins transition-all ${
                  activeTab === "email"
                    ? "bg-[#E05A52] text-white shadow-md"
                    : "text-gray-600 hover:bg-white hover:text-gray-900"
                }`}
              >
                <Mail className="h-4 w-4" />
                <span>✉ Email</span>
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* Main Analyzer Container — Only ONE analyzer active at a time */}
      <section className="mx-auto mt-8 max-w-7xl px-4 sm:px-6 lg:px-8">
        <AnimatePresence mode="wait">
          {/* ========================================================================= */}
          {/*  1. PHONE ANALYZER                                                         */}
          {/* ========================================================================= */}
          {activeTab === "phone" && (
            <motion.div
              key="phone-tab"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.15 }}
              className="rounded-3xl bg-white border border-[#E4DEC6]/80 p-6 sm:p-8 shadow-sm"
            >
              <div className="mb-6 flex items-center gap-3">
                <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-[#C48A5A]/10 border border-[#C48A5A]/25">
                  <Phone className="h-5 w-5 text-[#C48A5A]" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-900 font-poppins">CALL INTELLIGENCE</h2>
                  <p className="text-xs font-medium text-gray-500 font-manrope">
                    Search any phone number for threat reputation and telecom anomalies.
                  </p>
                </div>
              </div>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!phone.trim()) return toast.error("Please enter a phone number");
                  phoneMutation.mutate(phone.trim());
                }}
                className="space-y-4"
              >
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-gray-500 font-manrope mb-2">
                    Search Phone Number
                  </label>
                  <div className="flex gap-2">
                    <Input
                      placeholder="+91 9876543210"
                      value={phone}
                      onChange={(e) => setPhone(e.target.value)}
                      maxLength={32}
                      className="bg-[#FAF8F5] border-[#E4DEC6] text-gray-900 rounded-xl font-poppins text-sm py-2.5"
                    />
                    <Button
                      type="submit"
                      disabled={phoneMutation.isPending}
                      className="bg-[#C48A5A] text-white hover:bg-[#C48A5A]/90 rounded-xl px-6 font-poppins font-bold shrink-0"
                    >
                      {phoneMutation.isPending ? (
                        <>
                          <Loader2 className="h-4 w-4 animate-spin mr-2" />
                          Analyzing...
                        </>
                      ) : (
                        <>
                          <Search className="h-4 w-4 mr-2" />
                          Search Threat
                        </>
                      )}
                    </Button>
                    {(phone || callDetectionResult || phoneResult) && !phoneMutation.isPending && (
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => { setPhone(""); setCallDetectionResult(null); setPhoneResult(null); }}
                        className="rounded-xl border-[#E4DEC6] text-gray-600 font-poppins font-semibold shrink-0 px-4"
                      >
                        Clear
                      </Button>
                    )}
                  </div>
                </div>
              </form>

              {/* Error State */}
              {phoneMutation.isError && (
                <div className="mt-5 rounded-2xl border border-red-200 bg-red-50/50 p-4 flex items-center gap-3 text-xs text-red-700 font-semibold font-manrope">
                  <AlertCircle className="h-4 w-4 text-red-500 shrink-0" />
                  <span>Unable to analyze this input. Please try again.</span>
                </div>
              )}

              {/* Scanner Loader */}
              <AnimatePresence mode="wait">
                {phoneMutation.isPending && <ScanLoader key="pl" label="Analyzing phone number against threat database & telecom engine..." />}
                {callDetectionResult && !phoneMutation.isPending && (
                  <motion.div key="cres" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-6 space-y-4">
                    <CallResultCard result={callDetectionResult} />
                  </motion.div>
                )}
                {phoneResult && !callDetectionResult && !phoneMutation.isPending && (
                  <motion.div key="pr" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-6 space-y-4">
                    <TrustBanner score={phoneResult.trustScore} status={phoneResult.status} category={phoneResult.threatCategory} source={phoneResult.source} />
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-sm">
                      <InfoCell icon={Phone} label="Phone Number" value={phoneResult.normalized || phoneResult.phoneNumber} />
                      <InfoCell icon={ShieldCheck} label="Valid Status" value={phoneResult.validStatus} />
                      <InfoCell icon={Globe} label="Country" value={phoneResult.countryCode ? `${phoneResult.country} (${phoneResult.countryCode})` : phoneResult.country} />
                      <InfoCell icon={Hash} label="National Number" value={phoneResult.nationalNumber || "Unknown"} />
                      <InfoCell icon={Signal} label="Carrier" value={phoneResult.carrier} />
                      <InfoCell icon={Phone} label="Number Type" value={phoneResult.numberType} />
                      <InfoCell icon={ShieldQuestion} label="Reputation" value={phoneResult.reputation} />
                      <InfoCell icon={AlertTriangle} label="Risk Level" value={phoneResult.riskLevel} />
                      <InfoCell icon={Gauge} label="Confidence" value={formatConfidence(phoneResult.confidence, undefined, 0, "Unverified")} />
                    </div>
                    <Explanation text={phoneResult.explanation} />
                    <ReasonList reasons={phoneResult.reasons} />
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          )}

          {/* ========================================================================= */}
          {/*  2. SMS ANALYZER                                                           */}
          {/* ========================================================================= */}
          {activeTab === "sms" && (
            <motion.div
              key="sms-tab"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.15 }}
              className="rounded-3xl bg-white border border-[#E4DEC6]/80 p-6 sm:p-8 shadow-sm"
            >
              <div className="mb-6 flex items-center gap-3">
                <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-[#4F7EF7]/10 border border-[#4F7EF7]/25">
                  <MessageSquare className="h-5 w-5 text-[#4F7EF7]" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-900 font-poppins">SMS INTELLIGENCE</h2>
                  <p className="text-xs font-medium text-gray-500 font-manrope">
                    Search SMS messages for scams, phishing, OTP abuse, banking fraud and other threats.
                  </p>
                </div>
              </div>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!sms.trim()) return toast.error("Please paste SMS message content");
                  smsMutation.mutate(sms.trim());
                }}
                className="space-y-4"
              >
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-gray-500 font-manrope mb-2">
                    Search Message
                  </label>
                  <Textarea
                    placeholder="e.g. Congratulations! You won a lottery prize of $500,000. Click here to claim your prize now."
                    value={sms}
                    onChange={(e) => setSms(e.target.value)}
                    maxLength={4000}
                    rows={5}
                    className="resize-none bg-[#FAF8F5] border-[#E4DEC6] text-gray-900 rounded-xl font-manrope text-sm p-3.5"
                  />
                </div>
                <div className="flex gap-2">
                  <Button
                    type="submit"
                    disabled={smsMutation.isPending}
                    className="flex-1 bg-[#4F7EF7] text-white hover:bg-[#4F7EF7]/90 rounded-xl font-poppins font-bold py-2.5"
                  >
                    {smsMutation.isPending ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin mr-2" />
                        Analyzing...
                      </>
                    ) : (
                      <><Search className="h-4 w-4 mr-2" />Search Threat</>
                    )}
                  </Button>
                  {(sms || smsResult) && !smsMutation.isPending && (
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => { setSms(""); setSmsResult(null); }}
                      className="rounded-xl border-[#E4DEC6] text-gray-600 font-poppins font-semibold px-4"
                    >
                      Clear
                    </Button>
                  )}
                </div>
              </form>

              {/* Error State */}
              {smsMutation.isError && (
                <div className="mt-5 rounded-2xl border border-red-200 bg-red-50/50 p-4 flex items-center gap-3 text-xs text-red-700 font-semibold font-manrope">
                  <AlertCircle className="h-4 w-4 text-red-500 shrink-0" />
                  <span>Unable to analyze this input. Please try again.</span>
                </div>
              )}

              {/* Scanner Loader */}
              <AnimatePresence mode="wait">
                {smsMutation.isPending && <ScanLoader key="sl" label="Querying scam_messages XGBClassifier model via FastAPI..." />}
                {smsResult && !smsMutation.isPending && (
                  <motion.div key="sr" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-6 space-y-4">
                    <CommonThreatResultCard type="sms" input={sms} result={smsResult} />
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          )}

          {/* ========================================================================= */}
          {/*  3. EMAIL ANALYZER                                                         */}
          {/* ========================================================================= */}
          {activeTab === "email" && (
            <motion.div
              key="email-tab"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.15 }}
              className="rounded-3xl bg-white border border-[#E4DEC6]/80 p-6 sm:p-8 shadow-sm"
            >
              <div className="mb-6 flex items-center gap-3">
                <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-[#E05A52]/10 border border-[#E05A52]/25">
                  <Mail className="h-5 w-5 text-[#E05A52]" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-900 font-poppins">EMAIL INTELLIGENCE</h2>
                  <p className="text-xs font-medium text-gray-500 font-manrope">
                    Search emails for phishing, credential theft, KYC fraud, malicious links and other email-based threats.
                  </p>
                </div>
              </div>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!email.trim()) return toast.error("Please enter or paste email content");
                  emailMutation.mutate(email.trim());
                }}
                className="space-y-4"
              >
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-gray-500 font-manrope mb-2">
                    Search Email / Email Content
                  </label>
                  <Textarea
                    placeholder="From: security-alert@verify-account-kyc.xyz&#10;Subject: Urgent KYC Verification Required&#10;&#10;Your account will be suspended unless you verify your KYC information immediately. Click the link below to verify your account."
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    maxLength={10000}
                    rows={6}
                    className="resize-none bg-[#FAF8F5] border-[#E4DEC6] text-gray-900 rounded-xl font-manrope text-sm p-3.5"
                  />
                </div>
                <div className="flex gap-2">
                  <Button
                    type="submit"
                    disabled={emailMutation.isPending}
                    className="flex-1 bg-[#E05A52] text-white hover:bg-[#E05A52]/90 rounded-xl font-poppins font-bold py-2.5"
                  >
                    {emailMutation.isPending ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin mr-2" />
                        Analyzing...
                      </>
                    ) : (
                      <><Search className="h-4 w-4 mr-2" />Search Threat</>
                    )}
                  </Button>
                  {(email || emailResult) && !emailMutation.isPending && (
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => { setEmail(""); setEmailResult(null); }}
                      className="rounded-xl border-[#E4DEC6] text-gray-600 font-poppins font-semibold px-4"
                    >
                      Clear
                    </Button>
                  )}
                </div>
              </form>

              {/* Error State */}
              {emailMutation.isError && (
                <div className="mt-5 rounded-2xl border border-red-200 bg-red-50/50 p-4 flex items-center gap-3 text-xs text-red-700 font-semibold font-manrope">
                  <AlertCircle className="h-4 w-4 text-red-500 shrink-0" />
                  <span>Unable to analyze this input. Please try again.</span>
                </div>
              )}

              {/* Scanner Loader */}
              <AnimatePresence mode="wait">
                {emailMutation.isPending && <ScanLoader key="el" label="Analyzing email headers, domain reputation & CatBoost ML model..." />}
                {emailResult && !emailMutation.isPending && (
                  <motion.div key="er" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-6 space-y-4">
                    <CommonThreatResultCard type="email" input={email} result={emailResult} />
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          )}

          {/* ========================================================================= */}
          {/*  4. URL ANALYZER                                                           */}
          {/* ========================================================================= */}
          {activeTab === "url" && (
            <motion.div
              key="url-tab"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.15 }}
              className="rounded-3xl bg-white border border-[#E4DEC6]/80 p-6 sm:p-8 shadow-sm"
            >
              <div className="mb-6 flex items-center gap-3">
                <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-[#8B5CF6]/10 border border-[#8B5CF6]/25">
                  <Link2 className="h-5 w-5 text-[#8B5CF6]" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-900 font-poppins">URL INTELLIGENCE</h2>
                  <p className="text-xs font-medium text-gray-500 font-manrope">
                    Analyze URLs for phishing and malicious web activity.
                  </p>
                </div>
              </div>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!url.trim()) return toast.error("Please enter a URL");
                  urlMutation.mutate(url.trim());
                }}
                className="space-y-4"
              >
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-gray-500 font-manrope mb-2">
                    Search URL
                  </label>
                  <div className="flex gap-2">
                    <Input
                      placeholder="e.g. http://paypal-security-verification.com/login.php?cmd=webscr&ssl=1"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      maxLength={2048}
                      className="bg-[#FAF8F5] border-[#E4DEC6] text-gray-900 rounded-xl font-mono text-sm py-2.5"
                    />
                    <Button
                      type="submit"
                      disabled={urlMutation.isPending}
                      className="bg-[#8B5CF6] text-white hover:bg-[#8B5CF6]/90 rounded-xl px-6 font-poppins font-bold shrink-0"
                    >
                      {urlMutation.isPending ? (
                        <>
                          <Loader2 className="h-4 w-4 animate-spin mr-2" />
                          Analyzing...
                        </>
                      ) : (
                        <>
                          <Search className="h-4 w-4 mr-2" />
                          Search Threat
                        </>
                      )}
                    </Button>
                    {(url || urlResult) && !urlMutation.isPending && (
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => { setUrl(""); setUrlResult(null); }}
                        className="rounded-xl border-[#E4DEC6] text-gray-600 font-poppins font-semibold shrink-0 px-4"
                      >
                        Clear
                      </Button>
                    )}
                  </div>
                </div>
              </form>

              {/* Error State */}
              {urlMutation.isError && (
                <div className="mt-5 rounded-2xl border border-red-200 bg-red-50/50 p-4 flex items-center gap-3 text-xs text-red-700 font-semibold font-manrope">
                  <AlertCircle className="h-4 w-4 text-red-500 shrink-0" />
                  <span>Unable to analyze this input. Please try again.</span>
                </div>
              )}

              {/* Scanner Loader */}
              <AnimatePresence mode="wait">
                {urlMutation.isPending && <ScanLoader key="ul" label="Evaluating domain reputation, lexical features & XGBoost ML model..." />}
                {urlResult && !urlMutation.isPending && (
                  <motion.div key="ur" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-6 space-y-4">
                    <CommonThreatResultCard type="url" input={url} result={urlResult} />
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          )}

          {/* ========================================================================= */}
          {/*  5. IP ANALYZER                                                            */}
          {/* ========================================================================= */}
          {activeTab === "ip" && (
            <motion.div
              key="ip-tab"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.15 }}
              className="rounded-3xl bg-white border border-[#E4DEC6]/80 p-6 sm:p-8 shadow-sm"
            >
              <div className="mb-6 flex items-center gap-3">
                <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-[#059669]/10 border border-[#059669]/25">
                  <Globe className="h-5 w-5 text-[#059669]" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-900 font-poppins">IP INTELLIGENCE</h2>
                  <p className="text-xs font-medium text-gray-500 font-manrope">
                    Analyze IP addresses for malicious activity and threat reputation.
                  </p>
                </div>
              </div>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!ip.trim()) return toast.error("Please enter an IP address");
                  ipMutation.mutate(ip.trim());
                }}
                className="space-y-4"
              >
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-gray-500 font-manrope mb-2">
                    Search IP Address
                  </label>
                  <div className="flex gap-2">
                    <Input
                      placeholder="e.g. 185.220.101.45"
                      value={ip}
                      onChange={(e) => setIp(e.target.value)}
                      maxLength={64}
                      className="bg-[#FAF8F5] border-[#E4DEC6] text-gray-900 rounded-xl font-mono text-sm py-2.5"
                    />
                    <Button
                      type="submit"
                      disabled={ipMutation.isPending}
                      className="bg-[#059669] text-white hover:bg-[#059669]/90 rounded-xl px-6 font-poppins font-bold shrink-0"
                    >
                      {ipMutation.isPending ? (
                        <>
                          <Loader2 className="h-4 w-4 animate-spin mr-2" />
                          Analyzing...
                        </>
                      ) : (
                        <>
                          <Search className="h-4 w-4 mr-2" />
                          Search Threat
                        </>
                      )}
                    </Button>
                    {(ip || ipResult) && !ipMutation.isPending && (
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => { setIp(""); setIpResult(null); }}
                        className="rounded-xl border-[#E4DEC6] text-gray-600 font-poppins font-semibold shrink-0 px-4"
                      >
                        Clear
                      </Button>
                    )}
                  </div>
                </div>
              </form>

              {/* Error State */}
              {ipMutation.isError && (
                <div className="mt-5 rounded-2xl border border-red-200 bg-red-50/50 p-4 flex items-center gap-3 text-xs text-red-700 font-semibold font-manrope">
                  <AlertCircle className="h-4 w-4 text-red-500 shrink-0" />
                  <span>Unable to analyze this input. Please try again.</span>
                </div>
              )}

              {/* Scanner Loader */}
              <AnimatePresence mode="wait">
                {ipMutation.isPending && <ScanLoader key="ipl" label="Checking IP threat database, Tor exit nodes & XGBoost ML model..." />}
                {ipResult && !ipMutation.isPending && (
                  <motion.div key="ipr" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-6 space-y-4">
                    <CommonThreatResultCard type="ip" input={ip} result={ipResult} />
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          )}
        </AnimatePresence>
      </section>

      {/* THREAT INTELLIGENCE LOG */}
      <section className="mx-auto mt-10 max-w-7xl px-4 pb-16 sm:px-6 lg:px-8">
        <motion.div initial={{ opacity: 0, y: 12 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="rounded-3xl bg-white border border-[#E4DEC6]/60 p-6 shadow-sm">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-[#34A853]" />
              <h2 className="text-md font-bold text-gray-800 font-poppins">Threat Intelligence Log</h2>
            </div>
            <span className="text-xs text-gray-400 font-semibold font-manrope">Live · {log.length} events</span>
          </div>
          {log.length === 0 ? (
            <div className="rounded-xl border border-[#E4DEC6] bg-[#FAF8F5] p-8 text-center text-xs font-semibold text-gray-500 font-manrope">
              No events yet. Run an analysis above to populate the live log.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-b border-[#E4DEC6]/60">
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Timestamp</TableHead>
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Analysis Type</TableHead>
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Threat Category</TableHead>
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Target Input</TableHead>
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
                        <TableCell className="text-xs text-gray-600 font-medium font-manrope">{formatPercent(row.confidence, 0, "—")}</TableCell>
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

function CallResultCard({ result }: { result: CallDetectionResponse }) {
  const statusStr = (result.status || result.rawPrediction || result.classification || "").toUpperCase();
  const catStr    = (result.category || "").toUpperCase();

  const isScam       = statusStr === "SCAM" || statusStr === "FRAUD" || statusStr === "MALICIOUS" || catStr.includes("SCAM") || catStr.includes("FRAUD");
  const isSuspicious = statusStr === "SUSPICIOUS" || catStr.includes("SUSPICIOUS") || catStr.includes("REPETITIVE");
  const isInvalid    = statusStr === "INVALID_NUMBER" || statusStr === "INVALID" || catStr.includes("INVALID");
  const isUnverified = statusStr === "UNVERIFIED" || statusStr === "UNKNOWN" || catStr.includes("UNVERIFIED");

  let classification = "LEGITIMATE";
  let statusBg = "bg-[#34A853]/5 border-[#34A853]/20";
  let statusColor = "#34A853";
  let titleText = "🟢 LEGITIMATE";
  let defaultSeverity = "LOW";
  let defaultRecommendation = "No significant threat indicators were detected. Continue normal use while remaining cautious of unexpected requests.";

  if (isScam) {
    classification = "MALICIOUS";
    statusBg = "bg-[#E05A52]/5 border-[#E05A52]/20";
    statusColor = "#E05A52";
    titleText = "🚨 MALICIOUS";
    defaultSeverity = "HIGH";
    defaultRecommendation = "Do not click, reply, download files, or provide sensitive information. Block or report the source where appropriate.";
  } else if (isSuspicious) {
    classification = "SUSPICIOUS";
    statusBg = "bg-[#E8A23C]/5 border-[#E8A23C]/20";
    statusColor = "#E8A23C";
    titleText = "🟠 SUSPICIOUS";
    defaultSeverity = "MEDIUM";
    defaultRecommendation = "Exercise caution. Verify the sender or source through an official channel before taking action.";
  } else if (isInvalid) {
    classification = "INVALID";
    statusBg = "bg-[#6B7280]/5 border-[#6B7280]/20";
    statusColor = "#6B7280";
    titleText = "⚪ INVALID";
    defaultSeverity = "NONE";
    defaultRecommendation = "Please provide a valid input.";
  } else if (isUnverified) {
    classification = "UNVERIFIED";
    statusBg = "bg-[#6B7280]/5 border-[#6B7280]/20";
    statusColor = "#6B7280";
    titleText = "⚪ UNVERIFIED";
    defaultSeverity = "UNKNOWN";
    defaultRecommendation = "Insufficient threat intelligence to verify this input. Verify independently before taking action.";
  }

  const dbInfo   = result.sources?.database;
  const mlInfo   = result.sources?.ml;
  const tcInfo   = result.sources?.truecaller;
  const ipqsInfo = result.sources?.external || result.sources?.ipqs;

  const confVal = normalizeConfidence(result.confidence);
  const confText = confVal !== null ? `${confVal}%` : "N/A";
  const severity = (result.riskLevel || result.threatLevel || defaultSeverity).toUpperCase();
  const recommendation = result.recommendation || defaultRecommendation;

  const handleAskSentinel = () => {
    try {
      sessionStorage.setItem(
        "vigilock_threat_context",
        JSON.stringify({
          type: "Call",
          input: result.phone || "Unknown Phone",
          classification,
          confidence: confText,
          severity,
          evidence: result.evidence || (result.reason ? [result.reason] : []),
          summary: recommendation,
        })
      );
    } catch { /* ignore storage error */ }
    window.location.href = "/chatbot?context=threat_result";
  };

  return (
    <div className={`rounded-2xl p-6 border shadow-sm transition-all ${statusBg} text-gray-900`}>
      <div className="flex items-center justify-between mb-4 pb-3 border-b border-gray-200/50">
        <div className="flex items-center gap-2">
          <Phone className="h-5 w-5 text-gray-700" />
          <h3 className="font-poppins font-bold text-gray-800 text-sm tracking-wide uppercase">Caller Intelligence</h3>
        </div>
        <span
          className="rounded-full px-3 py-1 text-xs font-extrabold uppercase tracking-wider font-poppins"
          style={{
            background: isScam ? "rgba(224,90,82,0.1)" : isSuspicious ? "rgba(232,162,60,0.1)" : isInvalid || isUnverified ? "rgba(107,114,128,0.1)" : "rgba(52,168,83,0.1)",
            color: statusColor,
            border: `1px solid ${statusColor}40`,
          }}
        >
          {titleText}
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 gap-y-4 gap-x-2 text-xs font-manrope mb-5">
        <div>
          <div className="font-bold text-gray-400 text-[10px] uppercase">Phone</div>
          <div className="font-bold text-gray-800 text-xs font-poppins">{result.phone}</div>
        </div>
        <div>
          <div className="font-bold text-gray-400 text-[10px] uppercase">Caller</div>
          <div className="font-bold text-gray-800 text-xs">{result.callerIdentity || "Unidentified Number"}</div>
        </div>
        <div>
          <div className="font-bold text-gray-400 text-[10px] uppercase">Category</div>
          <div className="font-bold text-gray-800 text-xs">{result.category || "Unknown Caller"}</div>
        </div>
        <div>
          <div className="font-bold text-gray-400 text-[10px] uppercase">Carrier</div>
          <div className="font-semibold text-gray-700 text-xs">{result.carrier || "Unknown"}</div>
        </div>
        <div>
          <div className="font-bold text-gray-400 text-[10px] uppercase">Line Type</div>
          <div className="font-semibold text-gray-700 text-xs">{result.lineType || "Unknown"}</div>
        </div>
        <div>
          <div className="font-bold text-gray-400 text-[10px] uppercase">Country</div>
          <div className="font-semibold text-gray-700 text-xs">{result.country || "Unknown"}</div>
        </div>
      </div>

      <div className="border-t border-gray-200/50 pt-4 mb-4 grid grid-cols-2 gap-4">
        <div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-500 font-manrope mb-1">Verdict</div>
          <div className="text-lg font-extrabold font-poppins flex items-center gap-2 leading-tight" style={{ color: statusColor }}>
            {titleText}
          </div>
        </div>
        <div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-500 font-manrope mb-1">Risk Level</div>
          <div className="text-sm font-extrabold tabular-nums font-poppins uppercase" style={{ color: statusColor }}>
            {severity}
          </div>
          <div className="text-[11px] font-semibold text-gray-500 mt-0.5">
            Confidence: {confText}
          </div>
        </div>
      </div>

      <div className="border-t border-gray-200/50 pt-4 mb-4">
        <span className="font-bold text-gray-900 block text-[10px] uppercase mb-3">Detection Sources</span>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 text-xs font-manrope">
          <div className="flex items-start gap-2">
            <Database className="h-4 w-4 shrink-0 text-gray-400 mt-0.5" />
            <div>
              <div className="text-[10px] font-bold text-gray-500 uppercase">Threat Database</div>
              <div className="font-bold text-gray-800 text-[11px]">{dbInfo?.matched ? `✓ MATCHED` : "NO MATCH"}</div>
            </div>
          </div>
          <div className="flex items-start gap-2">
            <Phone className="h-4 w-4 shrink-0 text-gray-400 mt-0.5" />
            <div>
              <div className="text-[10px] font-bold text-gray-500 uppercase">Truecaller</div>
              <div className="font-bold text-gray-800 text-[11px]">{tcInfo?.available ? `✓ CHECKED` : "NOT CONFIGURED"}</div>
            </div>
          </div>
          <div className="flex items-start gap-2">
            <Radar className="h-4 w-4 shrink-0 text-gray-400 mt-0.5" />
            <div>
              <div className="text-[10px] font-bold text-gray-500 uppercase">IPQualityScore</div>
              <div className="font-bold text-gray-800 text-[11px]">{ipqsInfo?.available ? `✓ CHECKED` : "NOT CONFIGURED"}</div>
            </div>
          </div>
          {mlInfo?.available && (
            <div className="flex items-start gap-2">
              <Cpu className="h-4 w-4 shrink-0 text-gray-400 mt-0.5" />
              <div>
                <div className="text-[10px] font-bold text-gray-500 uppercase">ML Model</div>
                <div className="font-bold text-gray-800 text-[11px]">✓ ANALYZED</div>
              </div>
            </div>
          )}
        </div>
      </div>

      {recommendation && (
        <div className="mb-4 border-t border-gray-200/50 pt-3">
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-500 font-manrope mb-1">Recommended Action</div>
          <p className="text-xs font-semibold leading-relaxed text-gray-800 font-manrope bg-white/50 p-3 rounded-xl border border-gray-200/50">
            {recommendation}
          </p>
        </div>
      )}

      {result.evidence && result.evidence.length > 0 && (
        <div className="border-t border-gray-200/50 pt-4 mb-4">
          <span className="font-bold text-gray-900 block text-[10px] uppercase mb-2">Evidence</span>
          <ul className="space-y-1">
            {result.evidence.map((ev, i) => (
              <li key={i} className="flex items-start gap-2 text-gray-700 text-xs font-manrope">
                <CheckCircle2 className="h-3.5 w-3.5 text-gray-400 shrink-0 mt-0.5" />
                {ev}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Cyber Sentinel AI Action */}
      <div className="border-t border-gray-200/50 pt-3 flex justify-end">
        <button
          onClick={handleAskSentinel}
          className="inline-flex items-center gap-2 rounded-xl bg-[#2E323A] text-white px-3.5 py-2 text-xs font-bold hover:bg-[#C48A5A] transition-colors shadow-sm"
        >
          <MessageSquare className="h-3.5 w-3.5 text-[#C48A5A]" />
          Ask Cyber Sentinel AI about this result
        </button>
      </div>
    </div>
  );
}

function SmsResultCard({ result }: { result: SmsAnalysis }) {
  const isThreat = result.status === "scam" || result.status === "suspicious";
  const isMalicious = result.status === "scam";
  const isSuspicious = result.status === "suspicious";
  const isLegitimate = result.status === "legitimate";

  let classification = "LEGITIMATE";
  let statusColor = "#34A853";
  let statusBg = "bg-[#34A853]/5 border-[#34A853]/20";
  let titleText = "🟢 LEGITIMATE";
  let defaultRecommendation = "No significant threat indicators were detected. Continue normal use while remaining cautious of unexpected requests.";

  if (isMalicious) {
    classification = "MALICIOUS";
    statusColor = "#E05A52";
    statusBg = "bg-[#E05A52]/5 border-[#E05A52]/20";
    titleText = "🚨 MALICIOUS";
    defaultRecommendation = "Do not click, reply, download files, or provide sensitive information. Block or report the source where appropriate.";
  } else if (isSuspicious) {
    classification = "SUSPICIOUS";
    statusColor = "#E8A23C";
    statusBg = "bg-[#E8A23C]/5 border-[#E8A23C]/20";
    titleText = "🟠 SUSPICIOUS";
    defaultRecommendation = "Exercise caution. Verify the sender or source through an official channel before taking action.";
  }

  const confVal = normalizeConfidence(result.confidence);
  const confText = confVal !== null ? `${confVal}%` : "N/A";

  const handleAskSentinel = () => {
    try {
      sessionStorage.setItem(
        "vigilock_threat_context",
        JSON.stringify({
          type: "SMS",
          input: result.urls?.[0] || result.explanation || "SMS Message",
          classification,
          confidence: confText,
          severity: isMalicious ? "HIGH" : isSuspicious ? "MEDIUM" : "LOW",
          evidence: result.reasons || [],
          summary: result.explanation || defaultRecommendation,
        })
      );
    } catch { /* ignore */ }
    window.location.href = "/chatbot?context=threat_result";
  };

  return (
    <div className={`rounded-2xl p-6 border shadow-sm transition-all ${statusBg} text-gray-900`}>
      <div className="flex items-center justify-between mb-4 pb-3 border-b border-gray-200/50">
        <div className="flex items-center gap-2">
          <MessageSquare className="h-5 w-5 text-gray-700" />
          <h3 className="font-poppins font-bold text-gray-800 text-sm tracking-wide uppercase">SMS Analysis</h3>
        </div>
        <span
          className="rounded-full px-3 py-1 text-xs font-extrabold uppercase tracking-wider font-poppins"
          style={{
            background: isMalicious ? "rgba(224,90,82,0.1)" : isSuspicious ? "rgba(232,162,60,0.1)" : "rgba(52,168,83,0.1)",
            color: statusColor,
            border: `1px solid ${statusColor}40`,
          }}
        >
          {titleText}
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-5">
        <div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">Trust Score</div>
          <div className="text-xl font-extrabold tabular-nums font-poppins" style={{ color: statusColor }}>
            {result.trustScore}%
          </div>
        </div>
        <div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">Threat Level</div>
          <div className="text-sm font-extrabold font-poppins uppercase mt-0.5" style={{ color: statusColor }}>
            {result.threatLevel}
          </div>
        </div>
        <div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">Threat Category</div>
          <div className="text-xs font-bold text-gray-800 font-poppins mt-0.5">{result.category}</div>
        </div>
        <div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">Confidence</div>
          <div className="text-xs font-bold text-gray-800 font-poppins mt-0.5">{confText}</div>
        </div>
      </div>

      {result.urls && result.urls.length > 0 && (
        <div className="mb-4 border-t border-gray-200/50 pt-3">
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope mb-2">Extracted Malicious URLs</div>
          <div className="space-y-1.5">
            {result.urls.map((u: string, i: number) => (
              <div key={i} className="flex items-center gap-2 rounded-xl border border-[#E05A52]/20 bg-[#E05A52]/[0.04] px-3 py-1.5 text-xs text-[#E05A52]">
                <Link2 className="h-3.5 w-3.5 shrink-0" />
                <span className="truncate font-mono">{u}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {result.explanation && (
        <div className="mb-4 border-t border-gray-200/50 pt-3">
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-500 font-manrope mb-1">Analyst Summary</div>
          <p className="text-xs leading-relaxed text-gray-700 font-manrope">{result.explanation}</p>
        </div>
      )}

      {result.reasons && result.reasons.length > 0 && (
        <div className="border-t border-gray-200/50 pt-3 mb-4">
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-500 font-manrope mb-2">Evidence &amp; Indicators</div>
          <ul className="space-y-1.5">
            {result.reasons.map((r: string, i: number) => (
              <li key={i} className="flex items-start gap-2 text-xs text-gray-700 font-manrope leading-relaxed">
                <CheckCircle2 className="h-3.5 w-3.5 text-gray-400 shrink-0 mt-0.5" />
                {r}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Cyber Sentinel AI Action */}
      <div className="border-t border-gray-200/50 pt-3 flex justify-end">
        <button
          onClick={handleAskSentinel}
          className="inline-flex items-center gap-2 rounded-xl bg-[#2E323A] text-white px-3.5 py-2 text-xs font-bold hover:bg-[#C48A5A] transition-colors shadow-sm"
        >
          <MessageSquare className="h-3.5 w-3.5 text-[#C48A5A]" />
          Ask Cyber Sentinel AI about this result
        </button>
      </div>
    </div>
  );
}

function CommonThreatResultCard({
  type,
  input,
  result,
}: {
  type: "email" | "url" | "ip" | "sms";
  input: string;
  result: GenericThreatDetectionResponse;
}) {
  const rawPred = (result.classification || result.status || result.prediction || "").toUpperCase();
  const isMalicious  = rawPred === "MALICIOUS" || rawPred === "SCAM" || rawPred === "PHISHING" || rawPred === "CRITICAL" || rawPred === "FRAUD";
  const isSuspicious = rawPred === "SUSPICIOUS" || rawPred === "SPAM";
  const isInvalid    = rawPred === "INVALID" || rawPred === "INVALID_INPUT" || rawPred === "MALFORMED" || rawPred.includes("INVALID");
  const isUnverified = rawPred === "UNVERIFIED" || rawPred === "UNKNOWN";
  const isLegitimate = !isMalicious && !isSuspicious && !isInvalid && !isUnverified;

  let classification = "LEGITIMATE";
  let statusBg    = "bg-[#34A853]/5 border-[#34A853]/20";
  let statusColor = "#34A853";
  let titleText   = "🟢 LEGITIMATE";
  let defaultSeverity = "LOW";
  let defaultRecommendation = "No significant threat indicators were detected. Continue normal use while remaining cautious of unexpected requests.";

  if (isMalicious) {
    classification = "MALICIOUS";
    statusBg    = "bg-[#E05A52]/5 border-[#E05A52]/20";
    statusColor = "#E05A52";
    titleText   = "🚨 MALICIOUS";
    defaultSeverity = "HIGH";
    defaultRecommendation = "Do not click, reply, download files, or provide sensitive information. Block or report the source where appropriate.";
  } else if (isSuspicious) {
    classification = "SUSPICIOUS";
    statusBg    = "bg-[#E8A23C]/5 border-[#E8A23C]/20";
    statusColor = "#E8A23C";
    titleText   = "🟠 SUSPICIOUS";
    defaultSeverity = "MEDIUM";
    defaultRecommendation = "Exercise caution. Verify the sender or source through an official channel before taking action.";
  } else if (isInvalid) {
    classification = "INVALID";
    statusBg    = "bg-[#6B7280]/5 border-[#6B7280]/20";
    statusColor = "#6B7280";
    titleText   = "⚪ INVALID";
    defaultSeverity = "NONE";
    defaultRecommendation = "Please provide a valid input.";
  } else if (isUnverified) {
    classification = "UNVERIFIED";
    statusBg    = "bg-[#6B7280]/5 border-[#6B7280]/20";
    statusColor = "#6B7280";
    titleText   = "⚪ UNVERIFIED";
    defaultSeverity = "UNKNOWN";
    defaultRecommendation = "Insufficient threat intelligence to verify this input. Verify independently before taking action.";
  }

  const modelClass = result.model_class || (result.sources as any)?.ml?.model_class || (type === "email" ? "CatBoostClassifier" : "XGBClassifier");
  const datasetName = result.dataset || (result.sources as any)?.ml?.dataset || (type === "url" ? "phishing_urls" : type === "email" ? "email_scams" : type === "sms" ? "scam_messages" : "malicious_ips");
  const attackType = (isLegitimate || isUnverified || isInvalid)
    ? "None Detected"
    : (result.attack_type && result.attack_type !== "None Detected"
        ? result.attack_type
        : (result.sources as any)?.ml?.attack_type || (
            isMalicious
              ? (type === "email" ? "Phishing Email" : type === "url" ? "Phishing URL" : type === "sms" ? "Scam Message" : "Malicious IP")
              : (type === "email" ? "Suspicious Email" : type === "url" ? "Suspicious URL" : type === "sms" ? "Suspicious Message" : "Suspicious IP")
          )
      );

  const recommendedAction = result.recommended_action || (result.sources as any)?.ml?.recommended_action || defaultRecommendation;

  // Real confidence percentage display (or N/A)
  const confVal = normalizeConfidence(result.ml_confidence, result.confidence);
  const confText = confVal !== null ? `${confVal}%` : "N/A";

  let severity = (result.severity || result.threat_level || result.riskLevel || defaultSeverity).toUpperCase();
  if (isMalicious && (severity === "NONE" || severity === "LOW" || severity === "UNKNOWN")) {
    severity = "HIGH";
  } else if (isLegitimate && (severity === "HIGH" || severity === "CRITICAL" || severity === "MEDIUM")) {
    severity = "LOW";
  } else if (isSuspicious && (severity === "NONE" || severity === "LOW")) {
    severity = "MEDIUM";
  }

  const dbMatchedFlag = result.databaseMatch ?? !!(result.sources as any)?.database?.matched;
  const dbMatchCount = (result.sources as any)?.database?.matchedCount ?? 0;
  const mlAvailable = !!(result.sources as any)?.ml?.available;
  const sourceLabel = dbMatchedFlag && mlAvailable ? "Database + ML Model" : dbMatchedFlag ? "Database Match" : mlAvailable ? "ML Model" : "Unavailable";

  const handleAskSentinel = () => {
    try {
      sessionStorage.setItem(
        "vigilock_threat_context",
        JSON.stringify({
          type: type.toUpperCase(),
          input,
          classification,
          confidence: confText,
          severity,
          evidence: result.evidence || [],
          summary: recommendedAction,
        })
      );
    } catch { /* ignore */ }
    window.location.href = "/chatbot?context=threat_result";
  };

  return (
    <div className={`rounded-2xl p-6 border shadow-sm transition-all ${statusBg} text-gray-900`}>
      <div className="flex items-center justify-between mb-4 pb-3 border-b border-gray-200/50">
        <div className="flex items-center gap-2">
          {type === "url" ? <Link2 className="h-5 w-5 text-gray-700" /> : type === "email" ? <Mail className="h-5 w-5 text-gray-700" /> : type === "sms" ? <MessageSquare className="h-5 w-5 text-gray-700" /> : <Globe className="h-5 w-5 text-gray-700" />}
          <h3 className="font-poppins font-bold text-gray-800 text-sm tracking-wide uppercase">
            {type === "url" ? "URL Intelligence" : type === "email" ? "Email Intelligence" : type === "sms" ? "SMS Intelligence" : "IP Intelligence"} Result
          </h3>
        </div>
        <span
          className="rounded-full px-3 py-1 text-xs font-extrabold uppercase tracking-wider font-poppins"
          style={{
            background: isMalicious ? "rgba(224,90,82,0.1)" : isSuspicious ? "rgba(232,162,60,0.1)" : isInvalid || isUnverified ? "rgba(107,114,128,0.1)" : "rgba(52,168,83,0.1)",
            color: statusColor,
            border: `1px solid ${statusColor}40`,
          }}
        >
          {titleText}
        </span>
      </div>

      <div className="mb-4 rounded-xl border border-gray-200/60 bg-white/60 p-3">
        <div className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">Target Input</div>
        <div className="text-xs font-mono font-bold text-gray-800 break-all mt-0.5 max-h-24 overflow-y-auto">{input}</div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-5">
        <div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">Verdict</div>
          <div className="text-xs font-extrabold font-poppins mt-0.5" style={{ color: statusColor }}>{titleText}</div>
        </div>
        <div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">Threat Level</div>
          <div className="text-xs font-extrabold font-poppins uppercase mt-0.5" style={{ color: statusColor }}>
            {severity}
          </div>
        </div>
        <div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">Attack Type</div>
          <div className="text-xs font-bold text-gray-800 font-poppins mt-0.5">{attackType}</div>
        </div>
        <div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">Model Confidence</div>
          <div className="text-xs font-bold font-poppins mt-0.5" style={{ color: confText === "N/A" ? "#9CA3AF" : statusColor }}>{confText}</div>
        </div>
      </div>

      {/* Detection Sources */}
      <div className="border-t border-gray-200/50 pt-4 mb-4">
        <span className="font-bold text-gray-900 block text-[10px] uppercase mb-3">Detection Sources</span>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-manrope">
          {/* Database */}
          <div className="flex items-center gap-2 rounded-xl border border-gray-200/50 bg-white/40 p-2.5">
            <Database className="h-4 w-4 shrink-0" style={{ color: dbMatchedFlag ? "#34A853" : "#9CA3AF" }} />
            <div>
              <div className="text-[10px] font-bold text-gray-400 uppercase">Threat Database</div>
              <div className="font-bold text-xs" style={{ color: dbMatchedFlag ? "#34A853" : "#6B7280" }}>
                {dbMatchedFlag ? `✓ MATCHED (${dbMatchCount} record${dbMatchCount !== 1 ? "s" : ""})` : "NO MATCH"}
              </div>
            </div>
          </div>
          {/* ML Model */}
          <div className="flex items-center gap-2 rounded-xl border border-gray-200/50 bg-white/40 p-2.5">
            <Cpu className="h-4 w-4 shrink-0" style={{ color: mlAvailable ? "#4F7EF7" : "#9CA3AF" }} />
            <div>
              <div className="text-[10px] font-bold text-gray-400 uppercase">ML Model</div>
              <div className="font-bold text-xs" style={{ color: mlAvailable ? "#4F7EF7" : "#6B7280" }}>
                {mlAvailable ? `✓ ${modelClass}` : "UNAVAILABLE"}
              </div>
            </div>
          </div>
          {/* Dataset */}
          <div className="flex items-center gap-2 rounded-xl border border-gray-200/50 bg-white/40 p-2.5">
            <Server className="h-4 w-4 shrink-0 text-gray-400" />
            <div>
              <div className="text-[10px] font-bold text-gray-400 uppercase">Training Dataset</div>
              <div className="font-mono font-bold text-gray-800 text-xs">{datasetName}</div>
            </div>
          </div>
        </div>
        {/* Source label */}
        <div className="mt-2 flex justify-end">
          <span className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider font-poppins"
            style={dbMatchedFlag
              ? { background: "rgba(52,168,83,0.06)", color: "#34A853", border: "1px solid rgba(52,168,83,0.15)" }
              : { background: "rgba(79,126,247,0.06)", color: "#4F7EF7", border: "1px solid rgba(79,126,247,0.15)" }
            }
          >
            {dbMatchedFlag ? <Database className="h-2.5 w-2.5" /> : <Cpu className="h-2.5 w-2.5" />}
            {sourceLabel}
          </span>
        </div>
      </div>

      {recommendedAction && (
        <div className="mb-4 border-t border-gray-200/50 pt-3">
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-500 font-manrope mb-1">Recommended Action</div>
          <p className="text-xs font-semibold leading-relaxed text-gray-800 font-manrope bg-white/50 p-3 rounded-xl border border-gray-200/50">
            {recommendedAction}
          </p>
        </div>
      )}

      {result.evidence && result.evidence.length > 0 && (
        <div className="border-t border-gray-200/50 pt-3 mb-4">
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-500 font-manrope mb-2">Evidence &amp; Indicators</div>
          <ul className="space-y-1.5">
            {result.evidence.map((ev, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-gray-700 font-manrope leading-relaxed">
                <CheckCircle2 className="h-3.5 w-3.5 text-gray-400 shrink-0 mt-0.5" />
                {ev}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Cyber Sentinel AI Action */}
      <div className="border-t border-gray-200/50 pt-3 flex justify-end">
        <button
          onClick={handleAskSentinel}
          className="inline-flex items-center gap-2 rounded-xl bg-[#2E323A] text-white px-3.5 py-2 text-xs font-bold hover:bg-[#C48A5A] transition-colors shadow-sm"
        >
          <MessageSquare className="h-3.5 w-3.5 text-[#C48A5A]" />
          Ask Cyber Sentinel AI about this result
        </button>
      </div>
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
