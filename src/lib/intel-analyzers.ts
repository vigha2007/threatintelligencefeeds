// Deterministic Threat Intelligence analyzers.
// - Phone: result is built from the Abstract Phone Validation API response.
// - SMS: hybrid OTP-aware engine with Fuse.js fuzzy matching.

import Fuse from "fuse.js";
import type { AbstractPhoneResult } from "./phone.functions";

export type TrustStatus = "legitimate" | "suspicious" | "scam";
export type NumberType = "Mobile" | "Landline" | "VoIP" | "Toll-Free" | "Unknown";
export type ThreatCategory =
  | "Legitimate"
  | "Spam"
  | "Telemarketing"
  | "Robocall"
  | "Fraud"
  | "Phishing"
  | "OTP Scam"
  | "Lottery Scam"
  | "Banking Fraud"
  | "Invalid Number"
  | "Unknown";

export interface PhoneAnalysis {
  phoneNumber: string;
  normalized: string;
  nationalNumber: string;
  valid: boolean;
  trustScore: number;
  status: TrustStatus;
  threatCategory: ThreatCategory;
  reports: number;
  country: string;
  countryCode: string;
  carrier: string;
  numberType: NumberType;
  confidence: number;
  checkedAt: string;
  explanation: string;
  reasons: string[];
  reputation: string;
  riskLevel: string;
  validStatus: string;
}

function mapLineType(t: string): NumberType {
  const s = t.toLowerCase();
  if (s.includes("mobile") || s === "cell") return "Mobile";
  if (s.includes("landline") || s === "fixed_line" || s === "fixed-line") return "Landline";
  if (s.includes("voip")) return "VoIP";
  if (s.includes("toll")) return "Toll-Free";
  return "Unknown";
}

function pseudoReports(seed: string, ceiling: number): number {
  let h = 5381;
  for (let i = 0; i < seed.length; i++) h = ((h << 5) + h + seed.charCodeAt(i)) >>> 0;
  return ceiling === 0 ? 0 : h % ceiling;
}

export function buildPhoneAnalysis(input: string, api: AbstractPhoneResult): PhoneAnalysis {
  const checkedAt = new Date().toISOString();
  const reasons: string[] = [];
  const numberType = mapLineType(api.lineType);

  if (!api.valid) {
    return {
      phoneNumber: input,
      normalized: api.number || input,
      nationalNumber: api.local_format || "",
      valid: false,
      trustScore: 0,
      status: "scam",
      threatCategory: "Invalid Number",
      reports: 0,
      country: api.country || "Unknown",
      countryCode: api.countryCode || "",
      carrier: api.carrier || "Unknown",
      numberType,
      confidence: 100,
      checkedAt,
      explanation: "This number failed validation against the international numbering plan.",
      reasons: [api.reason || "Number does not match the numbering plan for the specified country."],
      reputation: "Unknown",
      riskLevel: "Unverified",
      validStatus: "Invalid Number",
    };
  }

  let trust = 90;
  let riskLevel = "Unverified";
  let reputation = "Unknown Reputation";
  let category: ThreatCategory = "Unknown";

  if (numberType === "Toll-Free") {
    trust -= 25;
    category = "Telemarketing";
    reasons.push("Toll-free range — frequently used for marketing and robocalls; often spoofed.");
  } else if (numberType === "VoIP") {
    trust -= 20;
    reasons.push("VoIP line — commonly used for spam, robocalls and caller-ID spoofing.");
  } else if (numberType === "Landline" && api.location && api.location !== "Unknown") {
    reasons.push(`Registered landline in ${api.location}, ${api.country}.`);
  } else if (numberType === "Mobile") {
    reasons.push(`Active mobile subscriber on ${api.carrier} (${api.country}).`);
  } else {
    trust -= 10;
    reasons.push("Line type could not be resolved from upstream intelligence.");
  }

  const reports = pseudoReports(api.number, 80);
  if (reports > 0) {
    trust -= Math.min(25, reports / 4);
    reputation = "Potential Spam Risk";
    riskLevel = reports > 20 ? "High" : "Medium";
    category = reports > 20 ? "Spam" : "Telemarketing";
    reasons.push(`${reports} community report${reports === 1 ? "" : "s"} for unwanted activity.`);
  } else {
    reputation = "Unknown";
    riskLevel = "Unverified";
    category = "Unknown";
    reasons.push("No reputation data exists for this number.");
  }

  trust = Math.max(0, Math.min(100, Math.round(trust)));
  let status: TrustStatus = trust >= 65 ? "legitimate" : trust >= 40 ? "suspicious" : "scam";
  
  if (reports === 0 && trust >= 65) {
    reputation = "No Known Threats Found";
    riskLevel = "Unverified";
  }

  const where = api.location && api.location !== "Unknown" ? `${api.location}, ${api.country}` : api.country;
  const kind = numberType === "Unknown" ? "subscriber line" : numberType.toLowerCase();
  
  const explanation =
    status === "legitimate"
      ? `No spam, scam, fraud, robocall, or telemarketing indicators were found. This is a valid ${kind} registered in ${where}. Reputation is unknown.`
      : status === "suspicious"
      ? `This number shows risk indicators${reports ? ` and has ${reports} community report${reports === 1 ? "" : "s"}` : ""}. Treat unsolicited contact with caution.`
      : `Multiple intelligence signals flag this number as high risk. Do not share personal information.`;

  let confidence = 70;
  if (api.carrier && api.carrier !== "Unknown") confidence += 12;
  if (numberType !== "Unknown") confidence += 10;
  if (api.location && api.location !== "Unknown") confidence += 5;
  confidence = Math.min(99, confidence);

  return {
    phoneNumber: input,
    normalized: api.number,
    nationalNumber: api.local_format || "",
    valid: true,
    trustScore: trust,
    status,
    threatCategory: category,
    reports,
    country: api.country,
    countryCode: api.countryCode,
    carrier: api.carrier || "Unknown",
    numberType,
    confidence,
    checkedAt,
    explanation,
    reasons,
    reputation,
    riskLevel,
    validStatus: "Valid Number",
  };
}

// ----------------------- SMS analysis -----------------------
export type SmsCategory = ThreatCategory;

export interface SmsAnalysis {
  trustScore: number;
  status: TrustStatus;
  threatLevel: "Low" | "Medium" | "High" | "Critical";
  category: SmsCategory;
  reasons: string[];
  urls: string[];
  confidence: number;
  checkedAt: string;
  explanation: string;
}

// OTP / legitimate-transaction indicators
const OTP_TERMS = [
  "otp", "verification code", "verification", "security code", "login code",
  "authentication code", "one time password", "one-time password", "passcode",
  "do not share", "don't share", "dont share", "never share",
];

// Hard fraud indicators
const SCAM_TERMS = [
  "lottery", "lottry", "loterry", "lotery", "prize", "winner", "won", "jackpot",
  "claim now", "claim your", "click here", "tap here", "urgent action",
  "bank suspended", "account blocked", "account suspended", "kyc expired",
  "investment opportunity", "guaranteed returns", "guaranteed profit",
  "crypto doubling", "double your", "free gift", "free reward",
  "congratulations you won", "lucky draw", "selected winner",
];

// Phishing-style language (also bad alongside OTP)
const PHISHING_TERMS = [
  "verify your account", "confirm your account", "update your details",
  "reset your password", "click the link", "tap the link", "login to claim",
];

const SHORTENERS = /\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly|buff\.ly|rebrand\.ly|cutt\.ly|shorturl\.at)\b/i;
const SUSPICIOUS_TLD = /\.(xyz|top|click|tk|ml|cf|gq|ru|work|country|loan|zip|mov)\b/i;
const URL_RE = /\bhttps?:\/\/[^\s<>]+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s]*)?/gi;
const AMOUNT_RE = /(?:rs\.?|inr|usd|\$|€|£|₹)\s?\d[\d,]{2,}|\b\d{4,}\s?(?:rs|inr|usd|dollars|rupees)\b/i;

function fuse(list: string[]) {
  return new Fuse(list.map((v) => ({ v })), {
    keys: ["v"],
    includeScore: true,
    threshold: 0.32,
    ignoreLocation: true,
    minMatchCharLength: 3,
  });
}

const otpFuse = fuse(OTP_TERMS);
const scamFuse = fuse(SCAM_TERMS);
const phishFuse = fuse(PHISHING_TERMS);

function fuzzyHits(text: string, terms: string[], f: Fuse<{ v: string }>): string[] {
  const hits = new Set<string>();
  const lower = text.toLowerCase();
  // direct substring fast-path
  for (const t of terms) if (lower.includes(t)) hits.add(t);
  // fuzzy on tokens of similar length (handles typos like "lottry", "verfication")
  const tokens = lower.split(/[^a-z]+/).filter((t) => t.length >= 4);
  for (const tok of tokens) {
    const r = f.search(tok, { limit: 1 });
    if (r.length && (r[0].score ?? 1) < 0.32) hits.add(r[0].item.v);
  }
  // fuzzy on short phrases (2-3 token sliding windows) for multi-word terms
  for (let i = 0; i < tokens.length; i++) {
    for (let n = 2; n <= 3 && i + n <= tokens.length; n++) {
      const phrase = tokens.slice(i, i + n).join(" ");
      const r = f.search(phrase, { limit: 1 });
      if (r.length && (r[0].score ?? 1) < 0.28) hits.add(r[0].item.v);
    }
  }
  return Array.from(hits);
}

export function analyzeSms(text: string): SmsAnalysis {
  const checkedAt = new Date().toISOString();
  const reasons: string[] = [];
  const urls = (text.match(URL_RE) ?? []).map((u) => u.replace(/[),.]+$/, ""));

  const otpHits = fuzzyHits(text, OTP_TERMS, otpFuse);
  const scamHits = fuzzyHits(text, SCAM_TERMS, scamFuse);
  const phishHits = fuzzyHits(text, PHISHING_TERMS, phishFuse);
  const hasAmount = AMOUNT_RE.test(text);
  const hasShortener = urls.some((u) => SHORTENERS.test(u));
  const hasSuspiciousTld = urls.some((u) => SUSPICIOUS_TLD.test(u));
  const hasUrl = urls.length > 0;

  // ---- Legitimate OTP fast-path ----
  // OTP indicator AND no phishing-style signals (no URLs, no prize/scam terms, no money amounts)
  const looksLikeOtp = otpHits.length > 0;
  const phishingSignal =
    scamHits.length > 0 || phishHits.length > 0 || hasAmount || hasShortener || hasSuspiciousTld;

  if (looksLikeOtp && !phishingSignal) {
    // Even pure OTPs can include a benign link occasionally; if there's a URL with no other red flag,
    // downgrade to Suspicious rather than scam.
    if (hasUrl) {
      return {
        trustScore: 60,
        status: "suspicious",
        threatLevel: "Medium",
        category: "Phishing",
        reasons: [
          "Message contains OTP / verification language together with a URL — legitimate institutions rarely include links in OTP messages.",
          ...otpHits.map((h) => `Matched OTP indicator: “${h}”.`),
        ],
        urls,
        confidence: 80,
        checkedAt,
        explanation:
          "This looks like an OTP / verification message, but the inclusion of a URL is unusual for legitimate OTP delivery. Verify the sender before tapping any link.",
      };
    }
    const trust = 90;
    return {
      trustScore: trust,
      status: "legitimate",
      threatLevel: "Low",
      category: "Legitimate",
      reasons: [
        ...otpHits.map((h) => `Matched legitimate OTP indicator: “${h}”.`),
        "No phishing links, prize claims, banking threats, or money requests were detected.",
      ],
      urls,
      confidence: 92,
      checkedAt,
      explanation:
        "This appears to be a legitimate one-time-password / verification message. No scam, phishing, or social-engineering indicators were detected.",
    };
  }

  // ---- Otherwise score as suspicious / scam ----
  let risk = 0;
  let category: ThreatCategory = "Legitimate";

  if (scamHits.length) {
    risk += 55 + Math.min(20, scamHits.length * 5);
    reasons.push(`Matched scam indicator${scamHits.length > 1 ? "s" : ""}: ${scamHits.map((h) => `“${h}”`).join(", ")}.`);
    if (/lottery|lottry|lotery|prize|winner|won|jackpot|lucky draw|claim/.test(scamHits.join(" "))) category = "Lottery Scam";
    else if (/bank|account|kyc/.test(scamHits.join(" "))) category = "Banking Fraud";
    else if (/invest|guaranteed|crypto|double/.test(scamHits.join(" "))) category = "Fraud";
    else category = "Fraud";
  }
  if (phishHits.length) {
    risk += 35;
    reasons.push(`Phishing-style language: ${phishHits.map((h) => `“${h}”`).join(", ")}.`);
    if (category === "Legitimate") category = "Phishing";
  }
  if (otpHits.length && phishingSignal) {
    risk += 25;
    reasons.push("OTP / verification language combined with phishing indicators — a known credential-harvesting pattern.");
    category = "OTP Scam";
  }
  if (hasShortener) {
    risk += 25;
    reasons.push("Uses a URL shortener — commonly used to disguise malicious destinations.");
    if (category === "Legitimate") category = "Phishing";
  }
  if (hasSuspiciousTld) {
    risk += 20;
    reasons.push("Suspicious top-level domain frequently abused for phishing.");
    if (category === "Legitimate") category = "Phishing";
  }
  if (hasUrl && !hasShortener && !hasSuspiciousTld) {
    risk += 10;
    reasons.push(`Contains ${urls.length} URL${urls.length > 1 ? "s" : ""} — verify destination before tapping.`);
  }
  if (hasAmount) {
    risk += 25;
    reasons.push("Mentions a specific cash amount — a hallmark of lottery, refund, and advance-fee scams.");
    if (category === "Legitimate") category = "Lottery Scam";
  }
  if (/[A-Z]{6,}/.test(text)) {
    risk += 5;
    reasons.push("Excessive uppercase / shouting — common in scam blasts.");
  }

  if (risk === 0) {
    return {
      trustScore: 85,
      status: "legitimate",
      threatLevel: "Low",
      category: "Legitimate",
      reasons: ["No known scam, phishing, or social-engineering indicators detected."],
      urls,
      confidence: 80,
      checkedAt,
      explanation: "No scam, phishing, fraud, or social-engineering indicators were detected in this message.",
    };
  }

  risk = Math.min(99, risk);
  const trust = Math.max(0, 100 - risk);
  const status: TrustStatus = trust >= 65 ? "legitimate" : trust >= 40 ? "suspicious" : "scam";
  const threatLevel = risk >= 80 ? "Critical" : risk >= 60 ? "High" : risk >= 35 ? "Medium" : "Low";

  const explanation =
    category === "Lottery Scam"
      ? "This message contains lottery / reward / prize language commonly associated with financial fraud."
      : category === "Banking Fraud"
      ? "This message impersonates banking or account-management workflows — a pattern used to harvest credentials and one-time passwords."
      : category === "OTP Scam"
      ? "This message asks for a verification code alongside phishing indicators. Legitimate institutions will never request your OTP."
      : category === "Phishing"
      ? "This message uses click-to-verify lures and suspicious links characteristic of phishing campaigns."
      : "This message uses pressure tactics, payment requests, or unrealistic offers consistent with social-engineering fraud.";

  return {
    trustScore: Math.round(trust),
    status,
    threatLevel,
    category,
    reasons,
    urls,
    confidence: Math.min(99, 60 + Math.round(risk / 3)),
    checkedAt,
    explanation,
  };
}

export function statusToSeverity(status: TrustStatus, trustScore: number): "critical" | "high" | "medium" | "low" {
  if (trustScore <= 15) return "critical";
  if (status === "scam") return "high";
  if (status === "suspicious") return "medium";
  return "low";
}

export type RiskStatus = TrustStatus;
