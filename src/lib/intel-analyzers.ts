// Heuristic analyzers for phone numbers and SMS content.
// Pure functions — deterministic-ish realistic outputs without external APIs.

export type RiskStatus = "safe" | "suspicious" | "scam";
export type NumberType = "Mobile" | "Landline" | "VoIP" | "Unknown";

export interface PhoneAnalysis {
  phoneNumber: string;
  normalized: string;
  riskScore: number;
  status: RiskStatus;
  reports: number;
  country: string;
  carrier: string;
  numberType: NumberType;
  checkedAt: string;
  reasons: string[];
}

const COUNTRY_CODES: Record<string, string> = {
  "1": "United States",
  "44": "United Kingdom",
  "91": "India",
  "234": "Nigeria",
  "61": "Australia",
  "49": "Germany",
  "33": "France",
  "81": "Japan",
  "86": "China",
  "55": "Brazil",
  "27": "South Africa",
  "971": "United Arab Emirates",
};

const CARRIERS = ["Verizon", "AT&T", "T-Mobile", "Vodafone", "Airtel", "Jio", "Orange", "MTN", "Telstra", "Bharti", "Twilio (VoIP)", "Bandwidth (VoIP)"];

function hashStr(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return Math.abs(h);
}

export function analyzePhone(input: string): PhoneAnalysis {
  const normalized = input.replace(/[^\d+]/g, "");
  const digits = normalized.replace(/\D/g, "");
  const reasons: string[] = [];

  // Country detection
  let country = "Unknown";
  for (const cc of Object.keys(COUNTRY_CODES).sort((a, b) => b.length - a.length)) {
    if (digits.startsWith(cc)) {
      country = COUNTRY_CODES[cc];
      break;
    }
  }

  const h = hashStr(digits || input);
  const typePool: NumberType[] = ["Mobile", "Mobile", "Mobile", "Landline", "VoIP"];
  const numberType = digits.length < 7 ? "Unknown" : typePool[h % typePool.length];
  const carrier = numberType === "VoIP"
    ? (h % 2 === 0 ? "Twilio (VoIP)" : "Bandwidth (VoIP)")
    : CARRIERS[h % (CARRIERS.length - 2)];

  let score = h % 40; // 0–39 baseline

  if (numberType === "VoIP") { score += 25; reasons.push("VoIP numbers are commonly used in robocall scams"); }
  if (digits.length < 7) { score += 30; reasons.push("Unusually short number length"); }
  if (digits.length > 0 && /(\d)\1{4,}/.test(digits)) { score += 25; reasons.push("Contains long repeating digit sequences"); }
  if (digits.startsWith("234")) { score += 20; reasons.push("Originates from a region with high advance-fee fraud activity"); }
  if (/^(\+?1?)?(800|888|877|866|855|844|833)/.test(normalized)) { score += 10; reasons.push("Toll-free number — frequently spoofed in robocalls"); }
  if (digits.length === 0) { score = 95; reasons.push("Empty / invalid input"); }

  score = Math.min(99, score);
  const status: RiskStatus = score >= 70 ? "scam" : score >= 40 ? "suspicious" : "safe";
  const reports = status === "scam" ? 50 + (h % 950) : status === "suspicious" ? 5 + (h % 80) : (h % 5);

  if (reasons.length === 0) reasons.push("No strong scam indicators detected in caller metadata");

  return {
    phoneNumber: input,
    normalized,
    riskScore: score,
    status,
    reports,
    country,
    carrier,
    numberType,
    checkedAt: new Date().toISOString(),
    reasons,
  };
}

export type SmsCategory =
  | "Phishing"
  | "Fake OTP"
  | "Bank Fraud"
  | "Lottery Scam"
  | "Fake Job Offer"
  | "Malicious Link"
  | "Urgent Payment"
  | "Clean";

export interface SmsAnalysis {
  riskScore: number;
  status: RiskStatus;
  threatLevel: "Low" | "Medium" | "High" | "Critical";
  category: SmsCategory;
  reasons: string[];
  urls: string[];
  checkedAt: string;
}

const PATTERNS: Array<{ re: RegExp; cat: SmsCategory; weight: number; reason: string }> = [
  { re: /\b(otp|one[\s-]?time\s?password|verification\s?code)\b/i, cat: "Fake OTP", weight: 30, reason: "Mentions OTP / verification code" },
  { re: /\b(bank|account\s*(blocked|suspended|frozen)|kyc|debit\s?card|credit\s?card)\b/i, cat: "Bank Fraud", weight: 35, reason: "References bank account / KYC actions" },
  { re: /\b(lottery|jackpot|won|winner|prize|congratulations)\b/i, cat: "Lottery Scam", weight: 35, reason: "Lottery / prize language" },
  { re: /\b(job\s?offer|work\s?from\s?home|earn\s?\$?\d+|hiring|part[\s-]?time)\b/i, cat: "Fake Job Offer", weight: 25, reason: "Suspicious employment offer" },
  { re: /\b(urgent|immediately|within\s?\d+\s?(hour|min)|act\s?now|final\s?notice)\b/i, cat: "Urgent Payment", weight: 25, reason: "Pressure / urgency tactics" },
  { re: /\b(click|tap|visit|verify|login|sign[\s-]?in|update)\b.*\bhere\b/i, cat: "Phishing", weight: 25, reason: "Click-here phishing pattern" },
  { re: /\b(pay|transfer|send)\s?(rs\.?|usd|\$|€|£|inr)\s?\d/i, cat: "Urgent Payment", weight: 30, reason: "Direct payment request" },
];

const SHORTENERS = /\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly|buff\.ly|rebrand\.ly|cutt\.ly)\b/i;
const URL_RE = /\bhttps?:\/\/[^\s<>]+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s]*)?/gi;

export function analyzeSms(text: string): SmsAnalysis {
  const reasons: string[] = [];
  const urls = (text.match(URL_RE) ?? []).map((u) => u.replace(/[),.]+$/, ""));
  let score = 0;
  let category: SmsCategory = "Clean";
  let topWeight = 0;

  for (const p of PATTERNS) {
    if (p.re.test(text)) {
      score += p.weight;
      reasons.push(p.reason);
      if (p.weight > topWeight) { topWeight = p.weight; category = p.cat; }
    }
  }

  if (urls.length > 0) { score += 10; reasons.push(`Contains ${urls.length} URL${urls.length > 1 ? "s" : ""}`); }
  if (urls.some((u) => SHORTENERS.test(u))) { score += 25; reasons.push("Uses a URL shortener — common in malicious links"); category = category === "Clean" ? "Malicious Link" : category; }
  if (urls.some((u) => /\d{2,}[a-z]{2,}\.|\.(xyz|top|click|tk|ml|cf)\b/i.test(u))) { score += 20; reasons.push("Suspicious TLD / domain pattern"); }
  if (/[A-Z]{6,}/.test(text)) { score += 5; reasons.push("Excessive uppercase / shouting"); }
  if (text.length < 8) { score += 5; reasons.push("Very short message"); }

  score = Math.min(99, score);
  if (score === 0) {
    reasons.push("No known scam indicators detected");
    category = "Clean";
  }

  const status: RiskStatus = score >= 70 ? "scam" : score >= 40 ? "suspicious" : "safe";
  const threatLevel = score >= 80 ? "Critical" : score >= 60 ? "High" : score >= 35 ? "Medium" : "Low";

  return {
    riskScore: score,
    status,
    threatLevel,
    category,
    reasons,
    urls,
    checkedAt: new Date().toISOString(),
  };
}

export function statusToSeverity(status: RiskStatus, score: number): "critical" | "high" | "medium" | "low" {
  if (score >= 85) return "critical";
  if (status === "scam") return "high";
  if (status === "suspicious") return "medium";
  return "low";
}
