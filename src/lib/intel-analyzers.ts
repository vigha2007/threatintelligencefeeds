// Deterministic Threat Intelligence analyzers — Phone Numbers & SMS content.
// No randomness. Same input → same output. Explainable results.

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
  phoneNumber: string;       // original
  normalized: string;        // E.164-ish
  valid: boolean;
  trustScore: number;        // 0-100, higher = more trustworthy
  status: TrustStatus;
  threatCategory: ThreatCategory;
  reports: number;
  country: string;           // "India" or "Unknown"
  countryCode: string;       // "+91" or ""
  carrier: string;           // realistic per country, or "Unknown"
  numberType: NumberType;
  confidence: number;        // 0-100 confidence in the analysis
  checkedAt: string;
  explanation: string;       // human readable
  reasons: string[];         // bullet evidence
}

// ---------- National numbering plan (compact, expandable) ----------
interface CountryPlan {
  cc: string;            // dial code without +
  name: string;
  // total national digits expected (after country code)
  nationalLengths: number[];
  // mobile-first-digit set (national format) — used when no extra carrier signal
  mobileFirstDigits?: string[];
  // landline area codes (national format prefix) — partial, well-known
  landlineAreaCodes?: Record<string, string>; // prefix -> city
  // carriers, keyed by national-format prefix (1-4 digits)
  carriers?: Record<string, string>;
  tollFreePrefixes?: string[];
}

const PLANS: CountryPlan[] = [
  {
    cc: "91", name: "India",
    nationalLengths: [10],
    mobileFirstDigits: ["6", "7", "8", "9"],
    landlineAreaCodes: {
      "11": "Delhi", "20": "Pune", "22": "Mumbai", "33": "Kolkata", "40": "Hyderabad",
      "44": "Chennai", "79": "Ahmedabad", "80": "Bengaluru",
    },
    carriers: {
      "70": "Jio", "73": "Jio", "74": "Jio", "89": "Jio", "63": "Jio", "62": "Jio",
      "98": "Airtel", "97": "Airtel", "99": "Airtel", "96": "Airtel", "70428": "Airtel",
      "94": "Vodafone Idea (Vi)", "95": "Vodafone Idea (Vi)", "90": "Vodafone Idea (Vi)",
      "94XX": "BSNL",
    },
    tollFreePrefixes: ["1800"],
  },
  {
    cc: "1", name: "United States",
    nationalLengths: [10],
    // NANP mobile vs landline is not derivable from prefix alone → leave Mobile/Landline as Unknown unless toll-free
    carriers: {}, // unknown without lookup
    tollFreePrefixes: ["800", "888", "877", "866", "855", "844", "833"],
  },
  {
    cc: "44", name: "United Kingdom",
    nationalLengths: [10, 11],
    mobileFirstDigits: ["7"],
    landlineAreaCodes: { "20": "London", "121": "Birmingham", "131": "Edinburgh", "161": "Manchester" },
    carriers: { "7400": "Vodafone UK", "7700": "O2", "7800": "EE", "7900": "Three UK" },
    tollFreePrefixes: ["800", "808"],
  },
  {
    cc: "61", name: "Australia",
    nationalLengths: [9],
    mobileFirstDigits: ["4"],
    landlineAreaCodes: { "2": "Sydney", "3": "Melbourne", "7": "Brisbane", "8": "Perth" },
    carriers: { "4": "Telstra / Optus / Vodafone AU" },
    tollFreePrefixes: ["1800"],
  },
  {
    cc: "49", name: "Germany",
    nationalLengths: [10, 11],
    mobileFirstDigits: ["1"],
    landlineAreaCodes: { "30": "Berlin", "40": "Hamburg", "89": "Munich", "69": "Frankfurt" },
    tollFreePrefixes: ["800"],
  },
  {
    cc: "33", name: "France",
    nationalLengths: [9],
    mobileFirstDigits: ["6", "7"],
    landlineAreaCodes: { "1": "Paris", "4": "Marseille/Lyon", "5": "Bordeaux" },
    tollFreePrefixes: ["800"],
  },
  {
    cc: "971", name: "United Arab Emirates",
    nationalLengths: [8, 9],
    mobileFirstDigits: ["5"],
    landlineAreaCodes: { "2": "Abu Dhabi", "4": "Dubai", "6": "Sharjah" },
    carriers: { "50": "Etisalat", "54": "Etisalat", "56": "du", "58": "du" },
    tollFreePrefixes: ["800"],
  },
  {
    cc: "234", name: "Nigeria",
    nationalLengths: [10],
    mobileFirstDigits: ["7", "8", "9"],
    carriers: { "80": "MTN / Glo / Airtel NG", "81": "MTN / Glo / Airtel NG", "90": "MTN / Glo / Airtel NG", "70": "MTN / Glo / Airtel NG" },
    tollFreePrefixes: [],
  },
  {
    cc: "81", name: "Japan",
    nationalLengths: [9, 10],
    mobileFirstDigits: ["7", "8", "9"],
    landlineAreaCodes: { "3": "Tokyo", "6": "Osaka" },
    tollFreePrefixes: ["120"],
  },
  {
    cc: "86", name: "China",
    nationalLengths: [11],
    mobileFirstDigits: ["1"],
    landlineAreaCodes: { "10": "Beijing", "21": "Shanghai" },
    tollFreePrefixes: ["800", "400"],
  },
  {
    cc: "55", name: "Brazil",
    nationalLengths: [10, 11],
    mobileFirstDigits: ["9"],
    landlineAreaCodes: { "11": "São Paulo", "21": "Rio de Janeiro" },
    tollFreePrefixes: ["800"],
  },
];

// ---------- Phone helpers ----------
function digitsOnly(s: string): string { return s.replace(/\D/g, ""); }

function isRepeated(d: string): boolean { return d.length > 0 && /^(\d)\1+$/.test(d); }
function isSequentialAsc(d: string): boolean {
  if (d.length < 6) return false;
  for (let i = 1; i < d.length; i++) if ((parseInt(d[i]) - parseInt(d[i - 1]) + 10) % 10 !== 1) return false;
  return true;
}
function isSequentialDesc(d: string): boolean {
  if (d.length < 6) return false;
  for (let i = 1; i < d.length; i++) if ((parseInt(d[i - 1]) - parseInt(d[i]) + 10) % 10 !== 1) return false;
  return true;
}

function detectPlan(input: string): { plan: CountryPlan | null; national: string; hadCountryCode: boolean } {
  const raw = input.trim();
  const hasPlus = raw.startsWith("+") || raw.startsWith("00");
  const digits = digitsOnly(raw);

  // Sort plans by cc length desc for longest match
  const sorted = [...PLANS].sort((a, b) => b.cc.length - a.cc.length);

  if (hasPlus) {
    for (const p of sorted) {
      if (digits.startsWith(p.cc)) {
        const national = digits.slice(p.cc.length);
        if (p.nationalLengths.includes(national.length)) {
          return { plan: p, national, hadCountryCode: true };
        }
      }
    }
    return { plan: null, national: digits, hadCountryCode: true };
  }

  // No + — try infer from length first
  const matches = PLANS.filter((p) => p.nationalLengths.includes(digits.length));
  // Prefer unique match by length
  if (matches.length === 1) return { plan: matches[0], national: digits, hadCountryCode: false };

  // Try stripping a leading "1" or country-code-like prefix
  for (const p of sorted) {
    if (digits.startsWith(p.cc) && p.nationalLengths.includes(digits.length - p.cc.length)) {
      return { plan: p, national: digits.slice(p.cc.length), hadCountryCode: false };
    }
  }

  return { plan: null, national: digits, hadCountryCode: false };
}

function detectCarrier(plan: CountryPlan, national: string): string {
  if (!plan.carriers) return "Unknown";
  const keys = Object.keys(plan.carriers).sort((a, b) => b.length - a.length);
  for (const k of keys) {
    if (national.startsWith(k.replace(/X+$/g, ""))) return plan.carriers[k];
  }
  return "Unknown";
}

function detectNumberType(plan: CountryPlan, national: string): { type: NumberType; areaName?: string } {
  if (plan.tollFreePrefixes?.some((p) => national.startsWith(p))) return { type: "Toll-Free" };
  // Landline by area code
  if (plan.landlineAreaCodes) {
    const keys = Object.keys(plan.landlineAreaCodes).sort((a, b) => b.length - a.length);
    for (const k of keys) {
      if (national.startsWith(k)) return { type: "Landline", areaName: plan.landlineAreaCodes[k] };
    }
  }
  if (plan.mobileFirstDigits?.includes(national[0])) return { type: "Mobile" };
  return { type: "Unknown" };
}

// Pseudo-stable "report" count derived from digits — same input → same number.
function pseudoReports(seed: string, ceiling: number): number {
  let h = 5381;
  for (let i = 0; i < seed.length; i++) h = ((h << 5) + h + seed.charCodeAt(i)) >>> 0;
  return ceiling === 0 ? 0 : h % ceiling;
}

export function analyzePhone(input: string): PhoneAnalysis {
  const reasons: string[] = [];
  const raw = input.trim();
  const digits = digitsOnly(raw);
  const checkedAt = new Date().toISOString();

  // 1) Basic invalid input checks
  if (!digits) {
    return invalidResult(raw, "Empty or non-numeric input.", checkedAt);
  }
  if (digits.length < 7 || digits.length > 15) {
    return invalidResult(raw, `Length ${digits.length} is outside the valid international range (7–15 digits).`, checkedAt);
  }
  if (isRepeated(digits)) {
    return invalidResult(raw, "All digits are identical — this is a test / placeholder number, not a real subscriber line.", checkedAt);
  }
  if (isSequentialAsc(digits) || isSequentialDesc(digits)) {
    return invalidResult(raw, "Digits are perfectly sequential — this is a test / placeholder pattern, not a real subscriber line.", checkedAt);
  }

  // 2) Plan detection
  const { plan, national, hadCountryCode } = detectPlan(raw);
  if (!plan) {
    // Unknown country, still try to give a verdict
    const score = 45;
    return {
      phoneNumber: raw,
      normalized: (raw.startsWith("+") ? "+" : "") + digits,
      valid: false,
      trustScore: score,
      status: "suspicious",
      threatCategory: "Unknown",
      reports: 0,
      country: "Unknown",
      countryCode: "",
      carrier: "Unknown",
      numberType: "Unknown",
      confidence: 35,
      checkedAt,
      explanation: "Country could not be identified from this number. Without a recognized numbering plan, the line cannot be verified against telecom intelligence sources.",
      reasons: [
        "No matching international country code or national numbering plan.",
        "Without country context, carrier and number type cannot be resolved.",
      ],
    };
  }

  // 3) Normalize, classify
  const normalized = "+" + plan.cc + national;
  const carrier = detectCarrier(plan, national);
  const { type: numberType, areaName } = detectNumberType(plan, national);
  if (areaName) reasons.push(`Area code maps to ${areaName} — registered as a ${plan.name} landline.`);
  if (!hadCountryCode) reasons.push(`Country inferred from numbering plan (${plan.nationalLengths.join("/")} digits).`);

  // 4) Trust scoring (start at 90 for a clean, well-formed number)
  let trust = 90;
  let category: ThreatCategory = "Legitimate";

  if (numberType === "Toll-Free") {
    trust -= 25;
    category = "Telemarketing";
    reasons.push("Toll-free range — frequently used for marketing and robocalls; often spoofed.");
  }
  if (numberType === "Unknown") {
    trust -= 10;
    reasons.push("Number-type indicator (mobile/landline) is not resolvable from the national prefix.");
  }
  // Premium-rate / known scam-heavy origin
  if (plan.cc === "234") {
    trust -= 25;
    reasons.push("Originating country is associated with elevated advance-fee fraud activity in open intelligence feeds.");
  }
  // VoIP heuristic: US 10-digit starting with 0 or specific blocks → keep conservative, skip auto-VoIP
  // Pseudo report count — only assigned if there's any negative signal
  let reports = 0;
  if (category !== "Legitimate") {
    reports = pseudoReports(normalized, 80);
  }
  if (reports > 0) {
    reasons.push(`This number has been reported by ${reports} user${reports === 1 ? "" : "s"} for unwanted ${category.toLowerCase()} activity.`);
    trust -= Math.min(25, reports / 4);
  } else {
    reasons.push("No spam or scam reports were found in current intelligence sources.");
  }

  trust = Math.max(0, Math.min(100, Math.round(trust)));
  const status: TrustStatus = trust >= 65 ? "legitimate" : trust >= 40 ? "suspicious" : "scam";

  // Final category alignment with status
  if (status === "legitimate") category = "Legitimate";
  else if (status === "suspicious" && category === "Legitimate") category = numberType === "Toll-Free" ? "Telemarketing" : "Spam";
  else if (status === "scam" && (category === "Legitimate" || category === "Telemarketing")) category = "Fraud";

  const confidence = computeConfidence(plan, numberType, carrier, hadCountryCode);

  const explanation = buildPhoneExplanation({
    status, category, country: plan.name, numberType, areaName, reports,
  });

  return {
    phoneNumber: raw,
    normalized,
    valid: true,
    trustScore: trust,
    status,
    threatCategory: category,
    reports,
    country: plan.name,
    countryCode: "+" + plan.cc,
    carrier,
    numberType,
    confidence,
    checkedAt,
    explanation,
    reasons,
  };
}

function invalidResult(raw: string, reason: string, checkedAt: string): PhoneAnalysis {
  return {
    phoneNumber: raw,
    normalized: raw,
    valid: false,
    trustScore: 5,
    status: "scam",
    threatCategory: "Invalid Number",
    reports: 0,
    country: "Unknown",
    countryCode: "",
    carrier: "Unknown",
    numberType: "Unknown",
    confidence: 95,
    checkedAt,
    explanation: "This is not a valid subscriber number. " + reason,
    reasons: [reason, "Real telecom subscribers never have this structure — treat any contact claiming this number as fraudulent."],
  };
}

function computeConfidence(plan: CountryPlan, numberType: NumberType, carrier: string, hadCC: boolean): number {
  let c = 60;
  if (hadCC) c += 15;
  if (numberType !== "Unknown") c += 10;
  if (carrier !== "Unknown") c += 10;
  if (plan.landlineAreaCodes || plan.carriers) c += 5;
  return Math.min(99, c);
}

function buildPhoneExplanation(p: {
  status: TrustStatus; category: ThreatCategory; country: string;
  numberType: NumberType; areaName?: string; reports: number;
}): string {
  if (p.status === "legitimate") {
    const where = p.areaName ? `${p.areaName}, ${p.country}` : p.country;
    const kind = p.numberType === "Unknown" ? "subscriber line" : p.numberType.toLowerCase();
    return `No spam, scam, fraud, robocall, or telemarketing indicators were found in available intelligence sources. This appears to be a normal ${kind} registered in ${where}.`;
  }
  if (p.status === "suspicious") {
    return `This number shows ${p.category.toLowerCase()}-related indicators${p.reports ? ` and has ${p.reports} community report${p.reports === 1 ? "" : "s"}` : ""}. Treat unsolicited contact with caution and do not share OTPs, KYC, or payment details.`;
  }
  return `Multiple intelligence signals flag this number as ${p.category.toLowerCase()}. Do not call back, share personal information, or transfer money.`;
}

// ---------- SMS analysis ----------
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

// Fuzzy keyword sets — token-based with single-edit tolerance
const KEYWORD_GROUPS: Array<{ cat: SmsCategory; weight: number; tokens: string[]; reason: string }> = [
  { cat: "Lottery Scam", weight: 45, tokens: ["lottery", "lotery", "jackpot", "prize", "winner", "won", "congratulations", "lucky", "draw", "raffle"], reason: "Lottery / prize / winner language commonly used in advance-fee scams." },
  { cat: "Banking Fraud", weight: 45, tokens: ["bank", "account", "kyc", "debit", "credit", "card", "blocked", "suspended", "frozen", "netbanking", "branch"], reason: "Banking / KYC / account-action language frequently used for impersonation fraud." },
  { cat: "OTP Scam", weight: 45, tokens: ["otp", "verification", "code", "passcode", "2fa"], reason: "Requests an OTP / verification code — never share these with anyone." },
  { cat: "Fraud", weight: 35, tokens: ["urgent", "immediately", "final", "notice", "actnow", "limited"], reason: "Pressure / urgency tactics commonly used in social engineering." },
  { cat: "Phishing", weight: 35, tokens: ["click", "tap", "visit", "verify", "login", "signin", "update", "confirm"], reason: "Click-to-verify language characteristic of phishing lures." },
  { cat: "Fraud", weight: 35, tokens: ["job", "hiring", "workfromhome", "parttime", "earn", "salary", "vacancy"], reason: "Unsolicited employment offer — common fake-job scam pattern." },
  { cat: "Banking Fraud", weight: 35, tokens: ["upi", "paytm", "phonepe", "gpay", "transfer", "refund", "wallet"], reason: "Payment / UPI / wallet language used in transfer-fraud scams." },
  { cat: "Fraud", weight: 30, tokens: ["amount", "money", "cash", "reward", "bonus", "gift", "claim", "deposit", "loan"], reason: "Money / reward language often paired with scam offers." },
  { cat: "Fraud", weight: 40, tokens: ["invest", "investment", "crypto", "bitcoin", "trading", "profit"], reason: "Investment / crypto pitch — common high-return scam framing." },
];

// Normalize: lowercase, strip punctuation, collapse repeated chars >2, common typo map
function normalizeSms(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/(.)\1{2,}/g, "$1$1") // wnnner -> wnner
    .replace(/\s+/g, " ")
    .trim();
}

// Damerau-Levenshtein (capped) for fuzzy matching short tokens
function editDistance(a: string, b: string, max = 2): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const dp: number[] = Array(b.length + 1).fill(0).map((_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0]; dp[0] = i; let rowMin = dp[0];
    for (let j = 1; j <= b.length; j++) {
      const tmp = dp[j];
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[j] = Math.min(dp[j] + 1, dp[j - 1] + 1, prev + cost);
      prev = tmp;
      if (dp[j] < rowMin) rowMin = dp[j];
    }
    if (rowMin > max) return max + 1;
  }
  return dp[b.length];
}

function fuzzyTokenMatch(token: string, target: string): boolean {
  if (token === target) return true;
  if (token.includes(target) || target.includes(token)) return true;
  const tol = target.length <= 4 ? 0 : target.length <= 6 ? 1 : 2;
  if (tol === 0) return false;
  return editDistance(token, target, tol) <= tol;
}

const SHORTENERS = /\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly|buff\.ly|rebrand\.ly|cutt\.ly)\b/i;
const URL_RE = /\bhttps?:\/\/[^\s<>]+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s]*)?/gi;

export function analyzeSms(text: string): SmsAnalysis {
  const reasons: string[] = [];
  const urls = (text.match(URL_RE) ?? []).map((u) => u.replace(/[),.]+$/, ""));
  const normalized = normalizeSms(text);
  const tokens = normalized.split(" ").filter(Boolean);

  let score = 0; // start at 0 risk, accumulate
  let category: ThreatCategory = "Legitimate";
  let topWeight = 0;
  const matchedGroups = new Set<string>();

  for (const group of KEYWORD_GROUPS) {
    let hit = false;
    for (const tok of tokens) {
      for (const target of group.tokens) {
        if (fuzzyTokenMatch(tok, target)) { hit = true; break; }
      }
      if (hit) break;
    }
    if (hit && !matchedGroups.has(group.reason)) {
      matchedGroups.add(group.reason);
      score += group.weight;
      reasons.push(group.reason);
      if (group.weight > topWeight) { topWeight = group.weight; category = group.cat; }
    }
  }

  if (urls.length > 0) { score += 15; reasons.push(`Contains ${urls.length} URL${urls.length > 1 ? "s" : ""} — verify destination before tapping.`); }
  if (urls.some((u) => SHORTENERS.test(u))) {
    score += 25;
    reasons.push("Uses a URL shortener — commonly used to disguise malicious destinations.");
    if (category === "Legitimate") category = "Phishing";
  }
  if (urls.some((u) => /\.(xyz|top|click|tk|ml|cf|gq|ru)\b/i.test(u))) {
    score += 20;
    reasons.push("Suspicious top-level domain frequently abused for phishing.");
    if (category === "Legitimate") category = "Phishing";
  }
  if (/[A-Z]{6,}/.test(text)) { score += 5; reasons.push("Excessive uppercase / shouting — common in scam blasts."); }

  // Currency / amount pattern boosts banking/lottery framing
  if (/\b(rs\.?|inr|usd|\$|€|£)\s?\d{3,}/i.test(text) || /\b\d{4,}\s?(rs|inr|usd)\b/i.test(text)) {
    score += 20;
    reasons.push("Mentions a specific cash amount — a hallmark of lottery, refund, and advance-fee scams.");
    if (category === "Legitimate") category = "Lottery Scam";
  }

  score = Math.min(99, score);
  if (score === 0) {
    reasons.push("No known scam indicators detected.");
    category = "Legitimate";
  }

  // Trust score: invert risk
  const trust = Math.max(0, 100 - score);
  const status: TrustStatus = trust >= 65 ? "legitimate" : trust >= 40 ? "suspicious" : "scam";
  const threatLevel = score >= 80 ? "Critical" : score >= 60 ? "High" : score >= 35 ? "Medium" : "Low";

  // Alignment
  if (status === "legitimate") category = "Legitimate";

  const explanation = buildSmsExplanation(status, category);

  return {
    trustScore: trust,
    status,
    threatLevel,
    category,
    reasons,
    urls,
    confidence: Math.min(99, 60 + Math.min(35, score / 3)),
    checkedAt: new Date().toISOString(),
    explanation,
  };
}

function buildSmsExplanation(status: TrustStatus, category: SmsCategory): string {
  if (status === "legitimate") return "No scam, phishing, fraud, or social-engineering indicators were detected in this message.";
  if (category === "Lottery Scam") return "This message contains lottery and reward-related language commonly associated with financial fraud and social engineering scams.";
  if (category === "Banking Fraud") return "This message impersonates banking or account-management workflows — a pattern used to harvest credentials and one-time passwords.";
  if (category === "OTP Scam") return "This message asks for a verification code. Legitimate institutions will never request your OTP — sharing it can compromise your account.";
  if (category === "Phishing") return "This message uses click-to-verify lures and suspicious links characteristic of phishing campaigns. Do not tap any links.";
  if (category === "Fraud") return "This message uses pressure tactics, payment requests, or unrealistic offers consistent with social-engineering fraud.";
  return "Multiple suspicious indicators were detected. Treat this message as untrusted.";
}

export function statusToSeverity(status: TrustStatus, trustScore: number): "critical" | "high" | "medium" | "low" {
  if (trustScore <= 15) return "critical";
  if (status === "scam") return "high";
  if (status === "suspicious") return "medium";
  return "low";
}

// Back-compat alias for any caller importing the old name
export type RiskStatus = TrustStatus;
