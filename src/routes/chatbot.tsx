import { createFileRoute, Link } from "@tanstack/react-router";
import { motion, AnimatePresence } from "framer-motion";
import { useState, useRef, useEffect } from "react";
import {
  Shield,
  Plus,
  Search,
  Download,
  Settings,
  Pin,
  Trash2,
  Phone,
  Globe,
  Mail,
  AlertTriangle,
  HelpCircle,
  ShieldAlert,
  MessageSquare,
  Clock,
  Send,
  Mic,
  MicOff,
  Image as ImageIcon,
  ArrowLeft,
  Loader2,
  CheckCircle,
  AlertCircle,
  X,
  FileText,
  FileJson,
  Languages,
  Info,
} from "lucide-react";
import { analyzeSms, predictCallApi, JAVA_BASE } from "../lib/intel-analyzers";
import { normalizeConfidence } from "../lib/formatters";

export const Route = createFileRoute("/chatbot")({
  head: () => ({
    meta: [
      { title: "Cyber Sentinel AI — Intelligent Cybersecurity Assistant" },
      { name: "description", content: "AI-powered cybersecurity assistant for interactive questions, incident guidance, and threat intelligence explanation." },
    ],
  }),
  component: ChatbotPage,
});

/* ─── Types ─────────────────────────────────────────────── */
interface ChatSession {
  id: string;
  title: string;
  preview: string;
  timestamp: string;
  pinned: boolean;
  createdAt: number;
  language?: SupportedLanguage;
}

interface ThreatAnalysisData {
  score: number | null;
  status: "legitimate" | "suspicious" | "scam" | "invalid" | "unknown";
  category: string;
  reasons: string[];
  summary: string;
  source?: string;
}

interface ChatMessage {
  id: string;
  sender: "user" | "ai";
  text: string;
  timestamp: string;
  image?: string;
  analysis?: ThreatAnalysisData;
  source?: "GEMINI" | "LOCAL_FALLBACK" | "DETECTOR";
}

interface ThreatContextData {
  type: string;
  input: string;
  classification: string;
  confidence: string;
  severity: string;
  evidence: string[];
  summary: string;
}

type Language = "en" | "ta";
type VoiceLang = "en-IN" | "ta-IN";

/* ─── LocalStorage Keys ──────────────────────────────────── */
const SESSIONS_STORAGE_KEY = "vigilock_sentinel_sessions";
const MESSAGES_STORAGE_KEY = "vigilock_sentinel_messages";
const SETTINGS_STORAGE_KEY = "vigilock_sentinel_settings";

/* ─── SVG Background Watermark ───────────────────────────── */
function CyberWatermark() {
  return (
    <svg
      className="absolute inset-0 w-full h-full pointer-events-none select-none"
      viewBox="0 0 800 600"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <path d="M400 120 L460 150 L460 220 Q460 270 400 300 Q340 270 340 220 L340 150 Z" fill="#C48A5A" opacity="0.05" />
      <path d="M400 138 L448 163 L448 218 Q448 260 400 286 Q352 260 352 218 L352 163 Z" stroke="#C48A5A" strokeWidth="1.5" opacity="0.07" fill="none" />
      <rect x="387" y="210" width="26" height="20" rx="3" fill="#C48A5A" opacity="0.06" />
      <circle cx="160" cy="180" r="6" fill="#4F7EF7" opacity="0.05" />
      <circle cx="200" cy="280" r="4" fill="#4F7EF7" opacity="0.04" />
      <circle cx="640" cy="160" r="6" fill="#4F7EF7" opacity="0.05" />
      <circle cx="670" cy="280" r="4" fill="#34A853" opacity="0.04" />
      <line x1="160" y1="180" x2="340" y2="180" stroke="#4F7EF7" strokeWidth="0.8" opacity="0.04" strokeDasharray="4 4" />
      <line x1="460" y1="180" x2="640" y2="180" stroke="#4F7EF7" strokeWidth="0.8" opacity="0.04" strokeDasharray="4 4" />
      <circle cx="400" cy="460" r="70" stroke="#4F7EF7" strokeWidth="1" opacity="0.03" fill="none" />
    </svg>
  );
}

/* ─── AI Avatar ──────────────────────────────────────────── */
function AIAvatar({ size = 32 }: { size?: number }) {
  return (
    <div
      className="flex shrink-0 items-center justify-center rounded-full"
      style={{
        width: size,
        height: size,
        background: "linear-gradient(135deg, #C48A5A 0%, #E8A23C 50%, #4F7EF7 100%)",
        boxShadow: "0 2px 8px rgba(196,138,90,0.25)",
      }}
    >
      <Shield style={{ width: size * 0.45, height: size * 0.45, color: "white" }} />
    </div>
  );
}

/* ─── Language Helpers ───────────────────────────────────── */
function isTamilScript(text: string): boolean {
  return /[\u0B80-\u0BFF]/.test(text);
}

function isTanglishQuery(text: string): boolean {
  const l = text.toLowerCase();
  return /\b(na enna|epdi|panrathu|pannunga|eppadi|solunga|irukku|enna|aagum|varum|theriyuma|kudukalama|solla mudiyuma)\b/.test(l);
}

/* ─── Gemini-backed Cybersecurity AI Knowledge Engine ───────── */
import { getCybersecurityAnswer, ChatHistoryMessage, ThreatContext, SupportedLanguage, resolveTargetLanguage } from "../lib/chatbot-knowledge";

/* ─── Incident Guidance Handler ───────────────────────────── */
function getIncidentGuidance(text: string, isTamil: boolean): string | null {
  const l = text.toLowerCase().trim();

  // 1. Clicked suspicious link
  if (
    /clicked.*(link|url|website)|opened.*(link|site)|i clicked|suspicious link|தவறான இணைப்பு|இணைப்பை கிளிக்/i.test(l) &&
    !/what is|how to|explain|difference/i.test(l)
  ) {
    if (isTamil) {
      return (
        `🛡️ **சந்தேகத்திற்கிடமான இணைப்பைக் கிளிக் செய்ததற்கான உடனடி வழிகாட்டுதல்:**\n\n` +
        `பயப்பட வேண்டாம். பின்வரும் தற்காப்பு நடவடிக்கைகளை உடனடியாக எடுக்கவும்:\n\n` +
        `1. **உலாவியின் பக்கத்தை உடனே மூடவும்** — அந்த தளத்திலிருந்து உடனடியாக வெளியேறவும்.\n` +
        `2. **எந்த தகவலையும் உள்ளிட வேண்டாம்** — கடவுச்சொல், OTP அல்லது தனிப்பட்ட விவரங்களை சமர்ப்பிக்காதீர்கள்.\n` +
        `3. **பதிவிறக்கம் செய்யப்பட்ட கோப்புகளை நீக்கவும்** — ஏதேனும் கோப்பு தானாகப் பதிவிறக்கப்பட்டால், அதைத் திறக்காமல் நீக்கவும்.\n` +
        `4. **Browser Cache & Cookies அழிக்கவும்** — உங்கள் உலாவியின் சமீபத்திய தற்காலிக நினைவகத்தை அழிக்கவும்.\n` +
        `5. **வைரஸ் ஸ்கேன் இயக்கவும்** — உங்கள் சாதனத்தில் முழுமையான Antivirus ஸ்கேன் இயக்கவும்.\n` +
        `6. **கணக்கு நடவடிக்கைகளைக் கண்காணிக்கவும்** — உங்கள் வங்கி மற்றும் மின்னஞ்சல் கணக்குகளை உன்னிப்பாகக் கவனிக்கவும்.\n\n` +
        `💡 *குறிப்பு: நீங்கள் அந்த இணைப்பை பகுப்பாய்வு செய்ய விரும்பினால், அந்த URL-ஐ மட்டும் இங்கே அனுப்பவும்.*`
      );
    }
    return (
      `🛡️ **Immediate Incident Guidance: Suspicious Link Clicked**\n\n` +
      `Don't panic. Follow these immediate containment steps:\n\n` +
      `1. **Close the website/tab immediately** — Disconnect from the destination page.\n` +
      `2. **Do not enter any information** — Never submit passwords, PINs, OTPs, or personal data on the opened page.\n` +
      `3. **Delete any downloaded files** — If a file downloaded automatically, do NOT open or run it. Delete it from Downloads.\n` +
      `4. **Clear browser cache & cookies** — Clear cookies and cached site data in your browser settings.\n` +
      `5. **Run a full security scan** — Run a trusted antivirus or antimalware scan on your device.\n` +
      `6. **Monitor your accounts** — Keep an eye on your banking and primary email for unauthorized login notifications.\n\n` +
      `💡 *If you would like me to check the reputation of the link itself, you can paste the URL with the prompt "Analyze this URL: <link>".*`
    );
  }

  // 2. Entered password on suspicious site
  if (
    /entered.*password|typed.*password|gave.*password|shared.*password|கடவுச்சொல்.*(உள்ளிட்டேன்|கொடுத்துவிட்டேன்)/i.test(l) &&
    !/how do i create|what is a strong password|password policy/i.test(l)
  ) {
    if (isTamil) {
      return (
        `🚨 **அவசர வழிகாட்டுதல்: கடவுச்சொல் சமர்ப்பிக்கப்பட்டது**\n\n` +
        `1. **கடவுச்சொல்லை உடனடியாக மாற்றவும்** — பாதிக்கப்பட்ட சேவையின் அதிகாரப்பூர்வ இணையதளத்திற்கு நேரடியாகச் சென்று புதிய வலுவான கடவுச்சொல்லை அமைக்கவும்.\n` +
        `2. **பிற கணக்குகளிலும் மாற்றவும்** — இதே கடவுச்சொல்லை வேறு ஏதேனும் இணையதளங்களில் பயன்படுத்தியிருந்தால் அங்கேயும் மாற்றவும்.\n` +
        `3. **அனைத்து அமர்வுகளிலிருந்தும் வெளியேறவும் (Sign out of all sessions)** — கணக்கு அமைப்புகளில் சென்று மற்ற எல்லா சாதனங்களிலிருந்தும் வெளியேறவும்.\n` +
        `4. **2FA / MFA செயல்படுத்தவும்** — Authenticator App (Google Authenticator / Authy) வழியான 2-படி சரிபார்ப்பை ஆன் செய்யவும்.\n` +
        `5. **மீட்பு விவரங்களைச் சரிபார்க்கவும்** — கணக்கின் மீட்பு மின்னஞ்சல் மற்றும் தொலைபேசி எண் மாற்றப்படாமல் உள்ளதா என சரிபார்க்கவும்.`
      );
    }
    return (
      `🚨 **Urgent Action Required: Compromised Password**\n\n` +
      `Take these immediate containment actions:\n\n` +
      `1. **Change your password immediately** — Go directly to the official service website (type the URL manually) and reset your password.\n` +
      `2. **Update any reused passwords** — If you reused this password across other accounts, change those immediately.\n` +
      `3. **Terminate all active sessions** — Use the "Sign out of all devices" or "Revoke sessions" security feature in your account settings.\n` +
      `4. **Enable Two-Factor Authentication (2FA)** — Activate an authenticator app (Google Authenticator, Microsoft Authenticator, Authy).\n` +
      `5. **Review recovery methods** — Confirm that recovery email addresses and phone numbers have not been altered by an attacker.`
    );
  }

  // 3. Shared OTP
  if (
    /shared.*otp|gave.*otp|told.*otp|sent.*otp|otp.*(பகிர்ந்து|கொடுத்துவிட்டேன்)/i.test(l) &&
    !/what is otp|how does otp work/i.test(l)
  ) {
    if (isTamil) {
      return (
        `🚨 **அதிதீவிர எச்சரிக்கை: OTP பகிரப்பட்டது**\n\n` +
        `1. **வங்கி/சேவையை உடனே அழைக்கவும்** — சம்பந்தப்பட்ட வங்கி அல்லது நிறுவனத்தின் அதிகாரப்பூர்வ வாடிக்கையாளர் உதவி மையத்தை உடனடியாகத் தொடர்பு கொள்ளவும்.\n` +
        `2. **கணக்கு/அட்டையை தற்காலிகமாக முடக்கவும்** — வங்கி மொபைல் செயலியில் Debit/Credit Card மற்றும் UPI பரிவர்த்தனைகளை தற்காலிகமாக Block செய்யவும்.\n` +
        `3. **பரிவர்த்தனைகளைச் சரிபார்க்கவும்** — வங்கி அறிக்கையில் ஏதேனும் அங்கீகரிக்கப்படாத பரிவர்த்தனைகள் நடந்துள்ளனவா என சரிபார்க்கவும்.\n` +
        `4. **1930 எண்ணை அழைக்கவும்** — நிதி சார்ந்த சைபர் மோசடி உதவி எண்ணான **1930**-ஐ அழைக்கவும் அல்லது **cybercrime.gov.in** தளத்தில் புகார் அளிக்கவும்.\n\n` +
        `⚠️ *நினைவில் கொள்ளுங்கள்: எந்தவொரு வங்கியும் அல்லது அதிகாரப்பூர்வ அதிகாரியும் ஒருபோதும் OTP கேட்க மாட்டார்கள்.*`
      );
    }
    return (
      `🚨 **Critical Alert: OTP Compromised**\n\n` +
      `Act immediately to protect your funds and accounts:\n\n` +
      `1. **Contact your bank/service provider right now** — Call the official customer helpline printed on the back of your card.\n` +
      `2. **Freeze card & net-banking transactions** — Use your mobile banking app to temporarily block debit/credit cards and UPI transfers.\n` +
      `3. **Audit transaction history** — Check your account balance and mini-statement for unauthorized debit transactions.\n` +
      `4. **File an immediate report** — In India, dial **1930** immediately for financial cyber fraud or report at **cybercrime.gov.in**.\n` +
      `5. **Golden Rule**: Legitimate organizations and banks will NEVER ask you to read out or share an OTP.`
    );
  }

  // 4. Gave bank details / UPI PIN exposed
  if (
    /gave.*(bank details|card details|cvv|upi pin)|entered.*(cvv|card number|upi pin)|bank details exposed/i.test(l) &&
    !/how to protect|how to secure|explain/i.test(l)
  ) {
    if (isTamil) {
      return (
        `🚨 **அவசர வழிகாட்டுதல்: வங்கி விவரங்கள் வெளிப்பட்டது**\n\n` +
        `1. **அட்டையை உடனே முடக்கவும்** — மொபைல் பேங்கிங் ஆப் மூலம் உங்கள் Debit/Credit கார்டை உடனே Block செய்யவும்.\n` +
        `2. **UPI PIN-ஐ உடனே மாற்றவும்** — UPI செயலிகளில் (Google Pay, PhonePe, Paytm) புதிய PIN அமைக்கவும்.\n` +
        `3. **Net Banking கடவுச்சொல்லை மாற்றவும்** — Login Password மற்றும் Transaction Password இரண்டையும் மாற்றவும்.\n` +
        `4. **1930-ல் புகார் அளிக்கவும்** — உடனடியாக 1930 என்ற எண்ணில் சைபர் குற்றப்பிரிவைத் தொடர்பு கொள்ளவும்.`
      );
    }
    return (
      `🚨 **Emergency Guidance: Financial Details Exposed**\n\n` +
      `1. **Block affected cards immediately** — Block your card instantly via your mobile banking app or customer hotline.\n` +
      `2. **Change your UPI PIN & Netbanking passwords** — Reset your credentials from the official banking app.\n` +
      `3. **Request a temporary debit freeze** — Ask your bank's fraud monitoring team to stop outgoing transaction authorization.\n` +
      `4. **Report to Cybercrime authorities** — Dial **1930** (Financial Cyber Fraud Helpline) or report at **cybercrime.gov.in**.\n` +
      `5. **Preserve evidence** — Save screenshots of the interaction, numbers, and transaction IDs for the police report.`
    );
  }

  // 5. Downloaded suspicious file / Malware infection
  if (
    /downloaded.*(file|apk|app|malware|exe)|installed.*(apk|app|software)|phone.*has malware|laptop.*infected|account.*(was )?hacked/i.test(l) &&
    !/what is malware|how does malware work|types of malware/i.test(l)
  ) {
    if (isTamil) {
      return (
        `🛡️ **பாதுகாப்பு வழிகாட்டுதல்: சந்தேகத்திற்கிடமான கோப்பு பதிவிறக்கம் / கணினி பாதிப்பு**\n\n` +
        `1. **கோப்பை இயக்கவோ திறக்கவோ வேண்டாம்** — பதிவிறக்கம் செய்யப்பட்ட கோப்பைத் திறக்காதீர்கள்.\n` +
        `2. **இணைய இணைப்பை துண்டிக்கவும்** — Wi-Fi மற்றும் மொபைல் டேட்டாவை தற்காலிகமாக அணைக்கவும்.\n` +
        `3. **கோப்பை நிரந்தரமாக நீக்கவும்** — Downloads கோப்புறையிலிருந்து கோப்பை முழுமையாக நீக்கவும்.\n` +
        `4. **சமீபத்திய செயலிகளைச் சரிபார்க்கவும்** — தெரியாத செயலிகள் அல்லது அனுமதிகள் ஏதேனும் உள்ளதா என அமைப்புகளில் பார்க்கவும்.\n` +
        `5. **முழுமையான Antivirus ஸ்கேன் இயக்கவும்** — நம்பகமான பாதுகாப்பு மென்பொருள் மூலம் சாதனத்தை ஸ்கேன் செய்யவும்.`
      );
    }
    return (
      `🛡️ **Incident Containment: Suspicious File / Malware Infection**\n\n` +
      `Follow this containment checklist:\n\n` +
      `1. **Do NOT run or execute the file** — Do not double-click or grant installation permissions to the downloaded file.\n` +
      `2. **Disconnect from the network** — Turn off Wi-Fi and mobile data / disconnect Ethernet to prevent lateral movement or C2 communication.\n` +
      `3. **Permanently delete the file** — Delete the file and empty your Recycle Bin / Trash.\n` +
      `4. **Review installed applications & processes** — Check Task Manager (Windows) or Apps (Android/iOS) for unfamiliar applications.\n` +
      `5. **Perform a full antimalware scan** — Run a deep scan using Windows Defender or your trusted endpoint security solution.\n` +
      `6. **Change passwords from a known clean device** — If credentials may have been logged, update passwords using a different, clean device.`
    );
  }

  // 6. Account / Gmail Compromised
  if (
    /((gmail|email|account|fb|instagram|whatsapp).*(hackd|hacked|hack ayiduchu|takeover|locked out))|(my .* got (hackd|hacked))/i.test(l) &&
    !/what is|how to hack/i.test(l)
  ) {
    if (isTamil) {
      return (
        `🚨 **அவசர வழிகாட்டுதல்: கணக்கு / ஜிமெயில் ஹேக் செய்யப்பட்டது**\n\n` +
        `1. **அதிகாரப்பூர்வ மீட்பு பக்கம்:** \`accounts.google.com/signin/recovery\` அல்லது குறிப்பிட்ட சேவையின் கணக்கு மீட்பு பக்கத்திற்கு செல்லவும்.\n` +
        `2. **வலுவான கடவுச்சொல்:** புதிய 16+ எழுத்து கடவுச்சொல்லை அமைக்கவும்.\n` +
        `3. **அனைத்து சாதனங்களிலிருந்தும் Sign Out:** பாதுகாப்பு அமைப்புகளில் சென்று தெரியாத எல்லா சாதனங்களின் அமர்வுகளையும் ரத்து செய்யவும்.\n` +
        `4. **2FA அமைப்புகளை சரிபார்க்கவும்:** ஹேக்கரின் எண் அல்லது மின்னஞ்சல் சேர்க்கப்பட்டுள்ளதா என பார்க்கவும்.\n` +
        `5. **Email Forwarding சரிபார்க்கவும்:** உங்கள் மின்னஞ்சல்கள் ஹேக்கருக்கு தானாக செல்கிறதா என பார்க்கவும்.\n` +
        `6. **வங்கி கணக்கு கடவுச்சொற்களை மாற்றவும்:** இந்த மின்னஞ்சலுடன் இணைக்கப்பட்ட வங்கி கணக்குகளின் கடவுச்சொற்களை உடனே மாற்றவும்.`
      );
    }
    return (
      `🚨 **Immediate Incident Action: Account / Gmail Compromised**\n\n` +
      `Follow these emergency containment steps immediately:\n\n` +
      `1. **Go to Official Recovery:** Visit the service's official recovery portal (e.g. \`accounts.google.com/signin/recovery\`) from a clean device.\n` +
      `2. **Reset Master Password:** Create a strong, 16+ character unique passphrase.\n` +
      `3. **Sign Out Everywhere:** Revoke all active sessions via Security → "Manage all devices" → "Sign out of all sessions".\n` +
      `4. **Audit 2-Step Verification:** Ensure the attacker hasn't added their phone number, recovery email, or hardware key.\n` +
      `5. **Check Email Forwarding Rules:** Attackers often set silent forwarding rules in Gmail Settings → Forwarding to intercept future reset links.\n` +
      `6. **Update Financial & Critical Logins:** Immediately change passwords for your banking, Amazon, and social media accounts linked to this email.`
    );
  }

  return null;
}

/* ─── Intent Routing & Message Processor ─────────────────── */
interface ExtractedIndicator {
  type: "SMS" | "URL" | "EMAIL" | "CALL" | "IP" | "NONE";
  value: string;
}

function extractExplicitIndicator(text: string): ExtractedIndicator {
  const trimmed = text.trim();

  // "Is this SMS a scam? Your account will be blocked..."
  // "Analyze this SMS: ..."
  // "Check this SMS: ..."
  if (/^(?:is\s+this\s+(?:an?\s+)?(?:sms|message|text)(?:\s+(?:a\s+)?(?:scam|phishing|fraud|fake|malicious))?[\?\:\s]+|analyze\s+(?:this\s+)?(?:sms|message|text)[\:\s]+|scan\s+(?:this\s+)?(?:sms|message|text)[\:\s]+|check\s+(?:this\s+)?(?:sms|message|text)[\:\s]+|investigate\s+(?:this\s+)?(?:sms|message|text)[\:\s]+|review\s+(?:this\s+)?(?:sms|message|text)[\:\s]+)(.+)$/is.test(trimmed)) {
    const match = trimmed.match(/^(?:is\s+this\s+(?:an?\s+)?(?:sms|message|text)(?:\s+(?:a\s+)?(?:scam|phishing|fraud|fake|malicious))?[\?\:\s]+|analyze\s+(?:this\s+)?(?:sms|message|text)[\:\s]+|scan\s+(?:this\s+)?(?:sms|message|text)[\:\s]+|check\s+(?:this\s+)?(?:sms|message|text)[\:\s]+|investigate\s+(?:this\s+)?(?:sms|message|text)[\:\s]+|review\s+(?:this\s+)?(?:sms|message|text)[\:\s]+)(.+)$/is);
    if (match?.[1]) return { type: "SMS", value: match[1].trim() };
  }

  // "Analyze this URL: http://..."
  // "Is this URL safe? http://..."
  if (/^(?:is\s+this\s+(?:an?\s+)?(?:url|link|site|website)(?:\s+(?:a\s+)?(?:scam|phishing|fraud|fake|malicious|safe))?[\?\:\s]+|analyze\s+(?:this\s+)?(?:url|link|site|website)[\:\s]+|scan\s+(?:this\s+)?(?:url|link|site|website)[\:\s]+|check\s+(?:this\s+)?(?:url|link|site|website)[\:\s]+|investigate\s+(?:this\s+)?(?:url|link|site|website)[\:\s]+|review\s+(?:this\s+)?(?:url|link|site|website)[\:\s]+)(.+)$/is.test(trimmed)) {
    const match = trimmed.match(/^(?:is\s+this\s+(?:an?\s+)?(?:url|link|site|website)(?:\s+(?:a\s+)?(?:scam|phishing|fraud|fake|malicious|safe))?[\?\:\s]+|analyze\s+(?:this\s+)?(?:url|link|site|website)[\:\s]+|scan\s+(?:this\s+)?(?:url|link|site|website)[\:\s]+|check\s+(?:this\s+)?(?:url|link|site|website)[\:\s]+|investigate\s+(?:this\s+)?(?:url|link|site|website)[\:\s]+|review\s+(?:this\s+)?(?:url|link|site|website)[\:\s]+)(.+)$/is);
    if (match?.[1]) return { type: "URL", value: match[1].trim() };
  }

  // "Analyze this email: ..."
  // "Is this email a scam? ..."
  if (/^(?:is\s+this\s+(?:an?\s+)?(?:email|mail)(?:\s+(?:a\s+)?(?:scam|phishing|fraud|fake|malicious))?[\?\:\s]+|analyze\s+(?:this\s+)?(?:email|mail)[\:\s]+|scan\s+(?:this\s+)?(?:email|mail)[\:\s]+|check\s+(?:this\s+)?(?:email|mail)[\:\s]+|investigate\s+(?:this\s+)?(?:email|mail)[\:\s]+|review\s+(?:this\s+)?(?:email|mail)[\:\s]+)(.+)$/is.test(trimmed)) {
    const match = trimmed.match(/^(?:is\s+this\s+(?:an?\s+)?(?:email|mail)(?:\s+(?:a\s+)?(?:scam|phishing|fraud|fake|malicious))?[\?\:\s]+|analyze\s+(?:this\s+)?(?:email|mail)[\:\s]+|scan\s+(?:this\s+)?(?:email|mail)[\:\s]+|check\s+(?:this\s+)?(?:email|mail)[\:\s]+|investigate\s+(?:this\s+)?(?:email|mail)[\:\s]+|review\s+(?:this\s+)?(?:email|mail)[\:\s]+)(.+)$/is);
    if (match?.[1]) return { type: "EMAIL", value: match[1].trim() };
  }

  // "Analyze this phone: ..."
  // "Is this call a scam? ..."
  if (/^(?:is\s+this\s+(?:an?\s+)?(?:phone|call|number|phone number)(?:\s+(?:a\s+)?(?:scam|fraud|fake|spam|malicious))?[\?\:\s]+|analyze\s+(?:this\s+)?(?:phone|call|number|phone number)[\:\s]+|scan\s+(?:this\s+)?(?:phone|call|number|phone number)[\:\s]+|check\s+(?:this\s+)?(?:phone|call|number|phone number)[\:\s]+|investigate\s+(?:this\s+)?(?:phone|call|number|phone number)[\:\s]+|review\s+(?:this\s+)?(?:phone|call|number|phone number)[\:\s]+)(.+)$/is.test(trimmed)) {
    const match = trimmed.match(/^(?:is\s+this\s+(?:an?\s+)?(?:phone|call|number|phone number)(?:\s+(?:a\s+)?(?:scam|fraud|fake|spam|malicious))?[\?\:\s]+|analyze\s+(?:this\s+)?(?:phone|call|number|phone number)[\:\s]+|scan\s+(?:this\s+)?(?:phone|call|number|phone number)[\:\s]+|check\s+(?:this\s+)?(?:phone|call|number|phone number)[\:\s]+|investigate\s+(?:this\s+)?(?:phone|call|number|phone number)[\:\s]+|review\s+(?:this\s+)?(?:phone|call|number|phone number)[\:\s]+)(.+)$/is);
    if (match?.[1]) return { type: "CALL", value: match[1].trim() };
  }

  // "Check this IP: ..."
  // "Is this IP malicious? ..."
  if (/^(?:is\s+this\s+(?:an?\s+)?(?:ip|ip address)(?:\s+(?:a\s+)?(?:scam|fraud|malicious|safe|suspicious))?[\?\:\s]+|analyze\s+(?:this\s+)?(?:ip|ip address)[\:\s]+|scan\s+(?:this\s+)?(?:ip|ip address)[\:\s]+|check\s+(?:this\s+)?(?:ip|ip address)[\:\s]+|investigate\s+(?:this\s+)?(?:ip|ip address)[\:\s]+|review\s+(?:this\s+)?(?:ip|ip address)[\:\s]+)(.+)$/is.test(trimmed)) {
    const match = trimmed.match(/^(?:is\s+this\s+(?:an?\s+)?(?:ip|ip address)(?:\s+(?:a\s+)?(?:scam|fraud|malicious|safe|suspicious))?[\?\:\s]+|analyze\s+(?:this\s+)?(?:ip|ip address)[\:\s]+|scan\s+(?:this\s+)?(?:ip|ip address)[\:\s]+|check\s+(?:this\s+)?(?:ip|ip address)[\:\s]+|investigate\s+(?:this\s+)?(?:ip|ip address)[\:\s]+|review\s+(?:this\s+)?(?:ip|ip address)[\:\s]+)(.+)$/is);
    if (match?.[1]) return { type: "IP", value: match[1].trim() };
  }

  // Bare standalone indicators pasted directly (e.g. "http://example.com" or "185.220.101.5"):
  const wordCount = trimmed.split(/\s+/).length;

  // Standalone URL
  if (wordCount <= 2 && /^https?:\/\/[^\s]+$/i.test(trimmed)) {
    return { type: "URL", value: trimmed };
  }
  if (wordCount === 1 && /^[a-zA-Z0-9-]+\.(?:com|org|net|io|ru|xyz|tk|site|co|in|info|app|dev)(?:\/[^\s]*)?$/i.test(trimmed)) {
    return { type: "URL", value: trimmed };
  }

  // Standalone IPv4
  if (wordCount === 1 && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) {
    const octets = trimmed.split(".").map(Number);
    if (octets.every((o) => o >= 0 && o <= 255)) {
      return { type: "IP", value: trimmed };
    }
  }

  // Standalone Phone Number
  if (wordCount === 1 && /^(?:\+?91[\s-]?)?[6-9]\d{9}$/.test(trimmed.replace(/\s+/g, ""))) {
    return { type: "CALL", value: trimmed };
  }

  // Standalone Email
  if (wordCount === 1 && /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(trimmed)) {
    return { type: "EMAIL", value: trimmed };
  }

  return { type: "NONE", value: "" };
}

async function processChatMessage(
  text: string,
  activeThreatContext: ThreatContextData | null,
  sessionLanguage: SupportedLanguage = "en",
  conversationHistory: ChatMessage[] = []
): Promise<{ responseText: string; analysis?: ThreatAnalysisData; source: "GEMINI" | "LOCAL_FALLBACK" | "DETECTOR"; language?: SupportedLanguage }> {
  const trimmed = text.trim();
  const lower = trimmed.toLowerCase();
  const targetLang = resolveTargetLanguage(trimmed, sessionLanguage);
  const isTamil = targetLang === "ta" || targetLang === "tanglish";

  // ──────────────────────────────────────────────────────────
  // 1. ROUTING: Explain a Security Alert / Scan Context
  // ──────────────────────────────────────────────────────────
  if (
    /explain.*(alert|security alert|scan|result|latest scan)|விளக்குக|எச்சரிக்கை விளக்கம்/i.test(lower) &&
    !/explain (what is|how to|sql|xss|csrf|ddos|mitm|firewall|encryption|ransomware)/i.test(lower)
  ) {
    if (activeThreatContext) {
      const ctx = activeThreatContext;
      const explanationText = isTamil
        ? `🔍 **ஸ்கேன் முடிவின் விரிவான விளக்கம்:**\n\n` +
          `• **அச்சுறுத்தல் வகை:** ${ctx.type}\n` +
          `• **இலக்கு:** \`${ctx.input}\`\n` +
          `• **கண்டறிதல் முடிவு:** **${ctx.classification}**\n` +
          `• **நம்பகத்தன்மை:** ${ctx.confidence}\n` +
          `• **தீவிர நிலை:** ${ctx.severity}\n\n` +
          `**ஆதாரங்கள் & குறிகாட்டிகள்:**\n` +
          (ctx.evidence && ctx.evidence.length > 0 ? ctx.evidence.map((e) => `• ${e}`).join("\n") : "• VigiLock அச்சுறுத்தல் தரவுத்தளம் மற்றும் ML மாதிரி மூலம் சரிபார்க்கப்பட்டது.") +
          `\n\n**பரிந்துரைக்கப்பட்ட நடவடிக்கை:**\n${ctx.summary}`
        : `🔍 **VigiLock Scan Result Breakdown:**\n\n` +
          `• **Threat Type:** ${ctx.type}\n` +
          `• **Target Indicator:** \`${ctx.input}\`\n` +
          `• **Classification:** **${ctx.classification}**\n` +
          `• **Model Confidence:** ${ctx.confidence}\n` +
          `• **Risk Severity:** ${ctx.severity}\n\n` +
          `**Evidence & Indicators:**\n` +
          (ctx.evidence && ctx.evidence.length > 0 ? ctx.evidence.map((e) => `• ${e}`).join("\n") : "• Evaluated against VigiLock threat database and machine learning models.") +
          `\n\n**Recommended Defensive Action:**\n${ctx.summary}`;

      return { responseText: explanationText, source: "LOCAL_FALLBACK" };
    } else {
      const noContextText = isTamil
        ? `தற்போது எந்தவொரு நேரடி ஸ்கேன் முடிவும் இணைக்கப்படவில்லை.\n\nஏதேனும் புதிய உள்ளீட்டை ஸ்கேன் செய்ய:\n• உரைப்பெட்டியில் \`Analyze this URL: <url>\` அல்லது \`Analyze this SMS: <text>\` என தட்டச்சு செய்யவும்.\n• அல்லது Intelligence Center திரையிலிருந்து "Ask Cyber Sentinel AI about this result" பொத்தானைப் பயன்படுத்தவும்.`
        : `No active VigiLock scan result is currently loaded in this conversation.\n\nTo analyze a specific threat, you can:\n• Type \`Analyze this URL: <link>\` or \`Analyze this SMS: <message>\` below\n• Or click **"Ask Cyber Sentinel AI about this result"** from any result card in the Intelligence Center.`;

      return { responseText: noContextText, source: "LOCAL_FALLBACK" };
    }
  }

  // ──────────────────────────────────────────────────────────
  // 2. ROUTING: Explicit Threat Detector Invocations
  // ──────────────────────────────────────────────────────────
  const explicitIndicator = extractExplicitIndicator(trimmed);

  if (explicitIndicator.type === "CALL") {
    try {
      const callRes = await predictCallApi(explicitIndicator.value);
      const isScam =
        callRes.prediction === "SCAM" ||
        callRes.status === "SCAM" ||
        callRes.status === "HIGH RISK" ||
        callRes.status === "MALICIOUS";
      const isSuspicious = callRes.status === "SUSPICIOUS" || callRes.status === "SPAM";
      const isUnknown = callRes.status === "UNKNOWN" || !callRes.status || callRes.status === "UNVERIFIED";

      const status: "scam" | "suspicious" | "unknown" | "legitimate" = isScam
        ? "scam"
        : isSuspicious
        ? "suspicious"
        : isUnknown
        ? "unknown"
        : "legitimate";

      const confVal = normalizeConfidence(callRes.confidence);

      return {
        responseText: isTamil
          ? `📞 **தொலைபேசி எண் பகுப்பாய்வு முடிந்தது**: \`${callRes.phone}\``
          : isScam
          ? `🚨 **MALICIOUS CALL DETECTED** for \`${callRes.phone}\``
          : isSuspicious
          ? `⚠️ **SUSPICIOUS CALL ALERT** for \`${callRes.phone}\``
          : isUnknown
          ? `⚪ **UNVERIFIED CALLER** for \`${callRes.phone}\``
          : `🟢 **LEGITIMATE CALLER** for \`${callRes.phone}\``,
        analysis: {
          score: confVal,
          status,
          category: `Phone Intelligence (${callRes.status ?? "CHECK"})`,
          reasons: callRes.evidence && callRes.evidence.length > 0 ? callRes.evidence : [callRes.reason || "Caller intelligence records analyzed."],
          summary: callRes.recommendation || callRes.reason || "Verified caller intelligence records.",
          source: callRes.source || "VigiLock Call Threat Engine",
        },
        source: "DETECTOR",
      };
    } catch {
      return {
        responseText: isTamil
          ? `📞 **தொலைபேசி எண் பகுப்பாய்வு**: \`${explicitIndicator.value}\`\n\nJava Backend (போர்ட் 8081) இணைக்க முடியவில்லை.`
          : `📞 **Phone Analysis for \`${explicitIndicator.value}\`**\n\nUnable to reach backend service on port 8081.`,
        analysis: {
          score: null,
          status: "unknown",
          category: "Phone Intelligence",
          reasons: ["Backend connection error on port 8081."],
          summary: "Check that the Java backend server is running.",
          source: "Phone Threat Engine",
        },
        source: "DETECTOR",
      };
    }
  }

  if (explicitIndicator.type === "URL") {
    try {
      const res = await fetch(`${JAVA_BASE}/api/v1/detect/url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: explicitIndicator.value }),
        signal: AbortSignal.timeout(8000),
      });
      if (res.ok) {
        const data = (await res.json()) as Record<string, unknown>;
        const rawPred = String(data.prediction || data.status || "UNVERIFIED").toUpperCase();
        const isMal = rawPred === "MALICIOUS" || rawPred === "SCAM" || rawPred === "PHISHING";
        const isSusp = rawPred === "SUSPICIOUS";
        const isUnv = rawPred === "UNVERIFIED" || rawPred === "UNKNOWN";
        const status: "scam" | "suspicious" | "unknown" | "legitimate" = isMal
          ? "scam"
          : isSusp
          ? "suspicious"
          : isUnv
          ? "unknown"
          : "legitimate";

        const conf = normalizeConfidence(data.confidence as number);
        const evid = Array.isArray(data.evidence) ? (data.evidence as string[]) : [];

        return {
          responseText: isTamil
            ? `🔗 **URL பகுப்பாய்வு முடிந்தது**: \`${explicitIndicator.value}\``
            : isMal
            ? `🚨 **MALICIOUS PHISHING URL DETECTED**: \`${explicitIndicator.value}\``
            : isSusp
            ? `⚠️ **SUSPICIOUS URL WARNING**: \`${explicitIndicator.value}\``
            : isUnv
            ? `⚪ **UNVERIFIED URL**: \`${explicitIndicator.value}\``
            : `🟢 **LEGITIMATE URL**: \`${explicitIndicator.value}\``,
          analysis: {
            score: conf,
            status,
            category: "URL & Domain Threat Intelligence",
            reasons: evid.length > 0 ? evid : [`Evaluated URL domain reputation for: ${explicitIndicator.value}`],
            summary: String(data.recommended_action || "URL evaluation completed."),
            source: "URL Threat Engine (ML + Database)",
          },
          source: "DETECTOR",
        };
      }
    } catch { /* fallback */ }
  }

  if (explicitIndicator.type === "SMS") {
    try {
      const res = await fetch(`${JAVA_BASE}/api/v1/detect/sms`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sms: explicitIndicator.value, content: explicitIndicator.value }),
        signal: AbortSignal.timeout(8000),
      });
      if (res.ok) {
        const data = (await res.json()) as Record<string, unknown>;
        const rawPred = String(data.prediction || data.status || "UNVERIFIED").toUpperCase();
        const isMal = rawPred === "MALICIOUS" || rawPred === "SCAM";
        const isSusp = rawPred === "SUSPICIOUS";
        const isUnv = rawPred === "UNVERIFIED" || rawPred === "UNKNOWN";
        const status: "scam" | "suspicious" | "unknown" | "legitimate" = isMal
          ? "scam"
          : isSusp
          ? "suspicious"
          : isUnv
          ? "unknown"
          : "legitimate";

        const conf = normalizeConfidence(data.confidence as number);
        const evid = Array.isArray(data.evidence) ? (data.evidence as string[]) : [];

        return {
          responseText: isTamil
            ? `💬 **SMS பகுப்பாய்வு முடிந்தது**`
            : isMal
            ? `🚨 **MALICIOUS SCAM SMS DETECTED**`
            : isSusp
            ? `⚠️ **SUSPICIOUS SMS ALERT**`
            : isUnv
            ? `⚪ **UNVERIFIED SMS**`
            : `🟢 **LEGITIMATE SMS**`,
          analysis: {
            score: conf,
            status,
            category: String(data.category || "Scam Message Analysis"),
            reasons: evid.length > 0 ? evid : ["Evaluated message payload against scam detection models."],
            summary: String(data.recommended_action || "SMS evaluation completed."),
            source: "SMS Scam Engine (ML + Database)",
          },
          source: "DETECTOR",
        };
      }
    } catch {
      const localSms = analyzeSms(explicitIndicator.value);
      return {
        responseText: localSms.status === "scam"
          ? "🚨 **MALICIOUS SCAM SMS DETECTED**"
          : localSms.status === "suspicious"
          ? "⚠️ **SUSPICIOUS SMS ALERT**"
          : "🟢 **LEGITIMATE SMS**",
        analysis: {
          score: localSms.trustScore,
          status: localSms.status,
          category: localSms.category,
          reasons: localSms.reasons,
          summary: localSms.explanation,
          source: "SMS Scam Engine (Offline)",
        },
        source: "DETECTOR",
      };
    }
  }

  if (explicitIndicator.type === "EMAIL") {
    try {
      const res = await fetch(`${JAVA_BASE}/api/v1/detect/email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: explicitIndicator.value, content: explicitIndicator.value }),
        signal: AbortSignal.timeout(8000),
      });
      if (res.ok) {
        const data = (await res.json()) as Record<string, unknown>;
        const rawPred = String(data.prediction || data.status || "UNVERIFIED").toUpperCase();
        const isMal = rawPred === "MALICIOUS" || rawPred === "SCAM" || rawPred === "PHISHING";
        const isSusp = rawPred === "SUSPICIOUS";
        const isUnv = rawPred === "UNVERIFIED" || rawPred === "UNKNOWN";
        const status: "scam" | "suspicious" | "unknown" | "legitimate" = isMal
          ? "scam"
          : isSusp
          ? "suspicious"
          : isUnv
          ? "unknown"
          : "legitimate";

        const conf = normalizeConfidence(data.confidence as number);
        const evid = Array.isArray(data.evidence) ? (data.evidence as string[]) : [];

        return {
          responseText: isTamil
            ? `📧 **மின்னஞ்சல் பகுப்பாய்வு முடிந்தது**: \`${explicitIndicator.value}\``
            : isMal
            ? `🚨 **MALICIOUS EMAIL DETECTED**: \`${explicitIndicator.value}\``
            : isSusp
            ? `⚠️ **SUSPICIOUS EMAIL ALERT**: \`${explicitIndicator.value}\``
            : isUnv
            ? `⚪ **UNVERIFIED EMAIL**: \`${explicitIndicator.value}\``
            : `🟢 **LEGITIMATE EMAIL**: \`${explicitIndicator.value}\``,
          analysis: {
            score: conf,
            status,
            category: "Email Threat Intelligence",
            reasons: evid.length > 0 ? evid : [`Evaluated email sender reputation: ${explicitIndicator.value}`],
            summary: String(data.recommended_action || "Email evaluation completed."),
            source: "Email Threat Engine",
          },
          source: "DETECTOR",
        };
      }
    } catch { /* fallback */ }
  }

  if (explicitIndicator.type === "IP") {
    try {
      const res = await fetch(`${JAVA_BASE}/api/v1/detect/ip`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: explicitIndicator.value }),
        signal: AbortSignal.timeout(8000),
      });
      if (res.ok) {
        const data = (await res.json()) as Record<string, unknown>;
        const rawPred = String(data.prediction || data.status || "UNVERIFIED").toUpperCase();
        const isMal = rawPred === "MALICIOUS" || rawPred === "SCAM";
        const isSusp = rawPred === "SUSPICIOUS";
        const isUnv = rawPred === "UNVERIFIED" || rawPred === "UNKNOWN";
        const status: "scam" | "suspicious" | "unknown" | "legitimate" = isMal
          ? "scam"
          : isSusp
          ? "suspicious"
          : isUnv
          ? "unknown"
          : "legitimate";

        const conf = normalizeConfidence(data.confidence as number);
        const evid = Array.isArray(data.evidence) ? (data.evidence as string[]) : [];

        return {
          responseText: isTamil
            ? `🌐 **IP முகவரி பகுப்பாய்வு முடிந்தது**: \`${explicitIndicator.value}\``
            : isMal
            ? `🚨 **MALICIOUS IP DETECTED**: \`${explicitIndicator.value}\``
            : isSusp
            ? `⚠️ **SUSPICIOUS IP WARNING**: \`${explicitIndicator.value}\``
            : isUnv
            ? `⚪ **UNVERIFIED IP**: \`${explicitIndicator.value}\``
            : `🟢 **LEGITIMATE IP**: \`${explicitIndicator.value}\``,
          analysis: {
            score: conf,
            status,
            category: "IP Reputation & Intelligence",
            reasons: evid.length > 0 ? evid : [`Evaluated IP address reputation: ${explicitIndicator.value}`],
            summary: String(data.recommended_action || "IP evaluation completed."),
            source: "IP Threat Engine",
          },
          source: "DETECTOR",
        };
      }
    } catch { /* fallback */ }
  }


  // ──────────────────────────────────────────────────────────
  // 3. ROUTING: All remaining messages → Gemini AI
  //    Gemini handles everything: general questions, incidents,
  //    spelling errors, Tamil, Tanglish, follow-ups, topic changes.
  // ──────────────────────────────────────────────────────────
  // Convert ChatMessage[] → ChatHistoryMessage[] for the API
  const historyForApi: ChatHistoryMessage[] = conversationHistory.map((m) => ({
    sender: m.sender,
    text: m.text,
  }));

  // Convert ThreatContextData → ThreatContext for the API
  const threatCtxForApi: ThreatContext | null = activeThreatContext
    ? {
        type: activeThreatContext.type,
        input: activeThreatContext.input,
        classification: activeThreatContext.classification,
        confidence: activeThreatContext.confidence,
        severity: activeThreatContext.severity,
        evidence: activeThreatContext.evidence,
        summary: activeThreatContext.summary,
      }
    : null;

  const aiAnswer = await getCybersecurityAnswer(trimmed, sessionLanguage, historyForApi, threatCtxForApi);
  return { responseText: aiAnswer.text, source: aiAnswer.source, language: aiAnswer.language || targetLang };
}


/* ─── Main Chatbot Component ──────────────────────────────── */
function ChatbotPage() {
  // Settings & Language
  const [language, setLanguage] = useState<Language>(() => {
    try {
      const saved = localStorage.getItem(SETTINGS_STORAGE_KEY);
      if (saved) return JSON.parse(saved).language || "en";
    } catch { /* ignore */ }
    return "en";
  });

  const [voiceLang, setVoiceLang] = useState<VoiceLang>(() => {
    try {
      const saved = localStorage.getItem(SETTINGS_STORAGE_KEY);
      if (saved) return JSON.parse(saved).voiceLang || "en-IN";
    } catch { /* ignore */ }
    return "en-IN";
  });

  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  // Sessions & Messages in localStorage
  const [sessions, setSessions] = useState<ChatSession[]>(() => {
    try {
      const saved = localStorage.getItem(SESSIONS_STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch { /* ignore */ }
    const initialId = "sess_" + Date.now();
    return [
      {
        id: initialId,
        title: "New Conversation",
        preview: "Cyber Sentinel AI initialized",
        timestamp: "Just now",
        pinned: false,
        createdAt: Date.now(),
      },
    ];
  });

  const [activeSession, setActiveSession] = useState<string>(() => {
    return sessions[0]?.id || "sess_default";
  });

  const [messages, setMessages] = useState<Record<string, ChatMessage[]>>(() => {
    try {
      const saved = localStorage.getItem(MESSAGES_STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && typeof parsed === "object") return parsed;
      }
    } catch { /* ignore */ }
    const initialId = sessions[0]?.id || "sess_default";
    return {
      [initialId]: [
        {
          id: "m_init",
          sender: "ai",
          text:
            "Hello! 👋 I'm Cyber Sentinel AI — your interactive cybersecurity assistant.\n\nI can answer ANY cybersecurity question (e.g. *What is phishing?*, *How do I protect my bank account?*, *Explain SQL injection*), provide instant incident guidance, or explain VigiLock threat detection results.\n\nHow can I help you today?",
          timestamp: "Now",
        },
      ],
    };
  });

  // UI States
  const [searchQuery, setSearchQuery] = useState("");
  const [inputVal, setInputVal] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const [isListening, setIsListening] = useState(false);
  const [attachedImage, setAttachedImage] = useState<string | null>(null);

  // Active Threat Context (from scanner result cards)
  const [activeThreatContext, setActiveThreatContext] = useState<ThreatContextData | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const speechRecognitionRef = useRef<any>(null);
  const isSendingRef = useRef<boolean>(false);

  // Persist sessions
  useEffect(() => {
    try {
      localStorage.setItem(SESSIONS_STORAGE_KEY, JSON.stringify(sessions));
    } catch { /* ignore */ }
  }, [sessions]);

  // Persist messages
  useEffect(() => {
    try {
      localStorage.setItem(MESSAGES_STORAGE_KEY, JSON.stringify(messages));
    } catch { /* ignore */ }
  }, [messages]);

  // Persist settings
  useEffect(() => {
    try {
      localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify({ language, voiceLang }));
    } catch { /* ignore */ }
  }, [language, voiceLang]);

  // Check for incoming Threat Context from Intelligence Center scanner
  useEffect(() => {
    try {
      const rawContext = sessionStorage.getItem("vigilock_threat_context");
      if (rawContext) {
        const parsed = JSON.parse(rawContext) as ThreatContextData;
        setActiveThreatContext(parsed);
        sessionStorage.removeItem("vigilock_threat_context");
      }
    } catch { /* ignore */ }
  }, []);

  // Auto scroll to bottom
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, activeSession, isTyping]);

  const currentMessages = messages[activeSession] ?? [];

  // Filter sessions
  const filteredSessions = sessions.filter(
    (s) =>
      s.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.preview.toLowerCase().includes(searchQuery.toLowerCase())
  );
  const pinnedSessions = filteredSessions.filter((s) => s.pinned);
  const recentSessions = filteredSessions.filter((s) => !s.pinned);

  // 4 Standard Quick Actions
  const QUICK_ACTIONS = [
    {
      icon: ShieldAlert,
      label: language === "ta" ? "பாதுகாப்பு எச்சரிக்கையை விளக்குக" : "Explain a Security Alert",
      sub: language === "ta" ? "எச்சரிக்கை பகுப்பாய்வு விளக்கம்" : "Get detailed verdict breakdown",
      prompt: language === "ta" ? "பாதுகாப்பு எச்சரிக்கையை விளக்குக" : "Explain a Security Alert",
      color: "#4F7EF7",
      bg: "rgba(79,126,247,0.1)",
    },
    {
      icon: HelpCircle,
      label: language === "ta" ? "நான் என்ன செய்ய வேண்டும்?" : "What Should I Do?",
      sub: language === "ta" ? "உடனடி தற்காப்பு படிகள்" : "Immediate defensive steps",
      prompt: language === "ta" ? "நான் என்ன செய்ய வேண்டும்?" : "What Should I Do?",
      color: "#34A853",
      bg: "rgba(52,168,83,0.1)",
    },
    {
      icon: AlertTriangle,
      label: language === "ta" ? "நான் சந்தேகத்திற்குரிய இணைப்பைக் கிளிக் செய்தேன்" : "I Clicked a Suspicious Link",
      sub: language === "ta" ? "அவசர சம்பவம் வழிகாட்டுதல்" : "Incident containment checklist",
      prompt: language === "ta" ? "நான் ஒரு சந்தேகத்திற்குரிய இணைப்பைக் கிளிக் செய்தேன்" : "I Clicked a Suspicious Link",
      color: "#E05A52",
      bg: "rgba(224,90,82,0.1)",
    },
    {
      icon: Shield,
      label: language === "ta" ? "பாதுகாப்பு உதவி" : "Security Help",
      sub: language === "ta" ? "பொது இணைய பாதுகாப்பு உதவி" : "Cybersecurity guidance & FAQs",
      prompt: language === "ta" ? "பாதுகாப்பு உதவி" : "Security Help",
      color: "#E8A23C",
      bg: "rgba(232,162,60,0.1)",
    },
  ];

  /* ─── Handle Sending Messages ────────────────────────────── */
  const handleSend = async (textToSend?: string) => {
    if (isSendingRef.current || isTyping) return;

    const text = (textToSend ?? inputVal).trim();
    if (!text && !attachedImage) return;

    isSendingRef.current = true;
    const currentImg = attachedImage;
    setInputVal("");
    setAttachedImage(null);

    // Stop voice if listening
    if (isListening && speechRecognitionRef.current) {
      speechRecognitionRef.current.stop();
      setIsListening(false);
    }

    const targetSession = activeSession;
    const userDisplayText = text || (language === "ta" ? "[ஸ்கிரீன்ஷாட் இணைக்கப்பட்டுள்ளது]" : "[Screenshot Attached]");
    const isTa = language === "ta" || isTamilScript(userDisplayText);

    const newMsg: ChatMessage = {
      id: crypto.randomUUID(),
      sender: "user",
      text: userDisplayText,
      image: currentImg || undefined,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };

    setMessages((prev) => ({
      ...prev,
      [targetSession]: [...(prev[targetSession] ?? []), newMsg],
    }));

    // Update session title & preview if initial
    setSessions((prev) =>
      prev.map((s) => {
        if (s.id === targetSession) {
          const isDefaultTitle = s.title.startsWith("New Conversation") || s.title.startsWith("Analysis Session");
          const newTitle = isDefaultTitle ? (text.length > 25 ? text.slice(0, 25) + "…" : text || "Image Analysis") : s.title;
          return {
            ...s,
            title: newTitle,
            preview: (text || "Image uploaded").slice(0, 45),
            timestamp: "Just now",
          };
        }
        return s;
      })
    );

    setIsTyping(true);

    try {
      let responseText = "";
      let analysis: ThreatAnalysisData | undefined;
      let source: "GEMINI" | "LOCAL_FALLBACK" | "DETECTOR" = "GEMINI";

      let returnedLang: SupportedLanguage | undefined;

      if (currentImg && (!text || text === userDisplayText)) {
        responseText =
          isTa
            ? "படம் பெறப்பட்டது. என்னால் உரையை தானாக பிரித்தெடுக்க இயலவில்லை. தயவுசெய்து பகுப்பாய்வு செய்ய வேண்டிய உரை அல்லது குறிகாட்டியை உள்ளிடவும்."
            : "Image received. I can't extract text automatically yet. Please paste the text or relevant indicator so I can help analyze it.";
        source = "LOCAL_FALLBACK";
      } else {
        // Read latest history snapshot for targetSession
        const currentMsgs = messages[targetSession] ?? [];
        const history = [...currentMsgs, newMsg];
        const currentSessionObj = sessions.find((s) => s.id === targetSession);
        const sessionLang: SupportedLanguage = currentSessionObj?.language || (language === "ta" ? "ta" : "en");
        const res = await processChatMessage(text, activeThreatContext, sessionLang, history);
        responseText = res.responseText;
        analysis = res.analysis;
        source = res.source;
        returnedLang = res.language;
      }

      if (returnedLang) {
        setSessions((prev) =>
          prev.map((s) => (s.id === targetSession ? { ...s, language: returnedLang } : s))
        );
      }

      const aiMsg: ChatMessage = {
        id: crypto.randomUUID(),
        sender: "ai",
        text: responseText,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        analysis,
        source,
      };

      setMessages((prev) => ({
        ...prev,
        [targetSession]: [...(prev[targetSession] ?? []), aiMsg],
      }));
    } catch (err) {
      console.error("[CyberSentinel] handleSend error:", err);
      const aiMsg: ChatMessage = {
        id: crypto.randomUUID(),
        sender: "ai",
        text: isTa
          ? "AI சேவையை அணுகுவதில் சிக்கல் ஏற்பட்டுள்ளது. Java backend (port 8081) இயங்குகிறதா என சரிபார்த்து மீண்டும் முயற்சிக்கவும்."
          : "I'm temporarily unable to reach the AI service. Please ensure the Java backend is running on port 8081 and try again.",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        source: "LOCAL_FALLBACK",
      };
      setMessages((prev) => ({
        ...prev,
        [targetSession]: [...(prev[targetSession] ?? []), aiMsg],
      }));
    } finally {
      isSendingRef.current = false;
      setIsTyping(false);
    }
  };

  /* ─── Threat Context Explanation ─────────────────────────── */
  const handleExplainThreatContext = () => {
    if (!activeThreatContext) return;
    const isTa = language === "ta";
    const promptText = isTa ? "இந்த பாதுகாப்பு எச்சரிக்கையை விளக்குக" : "Explain this security alert";
    handleSend(promptText);
  };

  /* ─── New Chat ───────────────────────────────────────────── */
  const handleNewChat = () => {
    const newId = "sess_" + Date.now();
    const newSession: ChatSession = {
      id: newId,
      title: "New Conversation",
      preview: "Cyber Sentinel AI initialized",
      timestamp: "Just now",
      pinned: false,
      createdAt: Date.now(),
    };

    setSessions((prev) => [newSession, ...prev]);
    setMessages((prev) => ({
      ...prev,
      [newId]: [
        {
          id: crypto.randomUUID(),
          sender: "ai",
          text:
            language === "ta"
              ? "வணக்கம்! 👋 நான் Cyber Sentinel AI. உங்களுக்கு என்ன இணைய பாதுகாப்பு உதவி வேண்டும்?"
              : "Hello! 👋 I'm Cyber Sentinel AI. How can I assist you with cybersecurity, incident guidance, or threat analysis today?",
          timestamp: "Now",
        },
      ],
    }));
    setActiveSession(newId);
    setActiveThreatContext(null); // Clean isolation
    setInputVal("");
    setAttachedImage(null);
    if (isListening && speechRecognitionRef.current) {
      speechRecognitionRef.current.stop();
      setIsListening(false);
    }
  };

  /* ─── Delete Session ─────────────────────────────────────── */
  const handleDeleteSession = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSessions((prev) => {
      const updated = prev.filter((s) => s.id !== id);
      if (updated.length === 0) {
        const fallbackId = "sess_" + Date.now();
        const fallbackSession: ChatSession = {
          id: fallbackId,
          title: "New Conversation",
          preview: "Empty conversation started",
          timestamp: "Just now",
          pinned: false,
          createdAt: Date.now(),
        };
        setActiveSession(fallbackId);
        setMessages({
          [fallbackId]: [
            {
              id: crypto.randomUUID(),
              sender: "ai",
              text: "Hello! I'm Cyber Sentinel AI. How can I help you?",
              timestamp: "Now",
            },
          ],
        });
        return [fallbackSession];
      }
      if (activeSession === id) {
        setActiveSession(updated[0].id);
      }
      return updated;
    });

    setMessages((prev) => {
      const copy = { ...prev };
      delete copy[id];
      return copy;
    });
  };

  /* ─── Pin / Unpin ────────────────────────────────────────── */
  const handleTogglePin = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSessions((prev) =>
      prev.map((s) => (s.id === id ? { ...s, pinned: !s.pinned } : s))
    );
  };

  /* ─── Image Upload Handling ──────────────────────────────── */
  const handleImageSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (loadEv) => {
      if (loadEv.target?.result) {
        setAttachedImage(loadEv.target.result as string);
      }
    };
    reader.readAsDataURL(file);
    e.target.value = "";
  };

  /* ─── Voice Input (Web Speech API) ───────────────────────── */
  const toggleVoice = () => {
    if (isListening) {
      if (speechRecognitionRef.current) {
        speechRecognitionRef.current.stop();
      }
      setIsListening(false);
      return;
    }

    const SpeechRec = (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;
    if (!SpeechRec) {
      alert("Speech recognition is not supported in this browser. Please use Chrome, Edge, or Safari.");
      return;
    }

    try {
      const recognition = new SpeechRec();
      recognition.lang = voiceLang;
      recognition.interimResults = false;
      recognition.maxAlternatives = 1;

      recognition.onstart = () => {
        setIsListening(true);
      };

      recognition.onresult = (event: any) => {
        const transcript = event.results?.[0]?.[0]?.transcript || "";
        if (transcript) {
          setInputVal((prev) => (prev ? `${prev} ${transcript}` : transcript));
        }
      };

      recognition.onerror = () => {
        setIsListening(false);
      };

      recognition.onend = () => {
        setIsListening(false);
      };

      speechRecognitionRef.current = recognition;
      recognition.start();
    } catch {
      setIsListening(false);
    }
  };

  /* ─── Export Chat ────────────────────────────────────────── */
  const handleExportTxt = () => {
    const lines = currentMessages.map((m) => {
      const role = m.sender === "user" ? "USER" : "CYBER SENTINEL AI";
      return `[${m.timestamp}] ${role}:\n${m.text}\n`;
    });
    const content =
      `VigiLock — Cyber Sentinel AI Conversation Log\nExported on: ${new Date().toLocaleString()}\nSession: ${activeSession}\n\n` +
      lines.join("\n----------------------------------------\n\n");
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinel_chat_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportJson = () => {
    const data = {
      exportedAt: new Date().toISOString(),
      sessionId: activeSession,
      messages: currentMessages,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinel_chat_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  /* ─── Clear Chat / Clear All History ─────────────────────── */
  const handleClearCurrentChat = () => {
    setMessages((prev) => ({
      ...prev,
      [activeSession]: [
        {
          id: crypto.randomUUID(),
          sender: "ai",
          text: language === "ta" ? "அரட்டை அழிக்கப்பட்டது. நான் உங்களுக்கு எவ்வாறு உதவ முடியும்?" : "Chat cleared. How can I assist you?",
          timestamp: "Now",
        },
      ],
    }));
    setIsSettingsOpen(false);
  };

  const handleClearAllHistory = () => {
    const freshId = "sess_" + Date.now();
    const freshSession: ChatSession = {
      id: freshId,
      title: "New Conversation",
      preview: "Cyber Sentinel AI initialized",
      timestamp: "Just now",
      pinned: false,
      createdAt: Date.now(),
    };
    const freshMessages: Record<string, ChatMessage[]> = {
      [freshId]: [
        {
          id: "m_init",
          sender: "ai",
          text:
            language === "ta"
              ? "வணக்கம்! நான் Cyber Sentinel AI. உங்களுக்கு என்ன உதவி வேண்டும்?"
              : "Hello! I'm Cyber Sentinel AI. How can I help you?",
          timestamp: "Now",
        },
      ],
    };

    setSessions([freshSession]);
    setActiveSession(freshId);
    setMessages(freshMessages);
    localStorage.removeItem(SESSIONS_STORAGE_KEY);
    localStorage.removeItem(MESSAGES_STORAGE_KEY);
    setIsSettingsOpen(false);
  };

  return (
    <div className="flex h-[calc(100vh-64px)] overflow-hidden bg-[#F2EEE8] font-manrope">
      {/* Hidden File Input for Image Upload */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleImageSelect}
        accept="image/*"
        className="hidden"
      />

      {/* ── Chat History Sidebar ───────────────────────────── */}
      <aside className="hidden md:flex flex-col w-72 overflow-hidden border-r border-[#E4DEC6] bg-[#2E323A] text-white shrink-0">
        {/* Sidebar Header */}
        <div className="flex items-center justify-between border-b border-[#3e434f] px-4 py-3.5">
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-[#C48A5A] text-white">
              <Shield className="h-4.5 w-4.5" />
            </div>
            <span className="text-xs font-bold font-poppins tracking-wider uppercase text-gray-200">
              {language === "ta" ? "அரட்டை வரலாறு" : "Chat Logs"}
            </span>
          </div>
          <button
            onClick={handleNewChat}
            className="flex h-7 w-7 items-center justify-center rounded-lg bg-[#C48A5A] text-white hover:bg-[#C48A5A]/90 transition-colors shadow-sm"
            title="New Chat"
          >
            <Plus className="h-3.5 w-3.5" />
          </button>
        </div>

        {/* Search */}
        <div className="px-3 py-2 border-b border-[#3e434f]/40">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              placeholder={language === "ta" ? "வரலாற்றில் தேடுக..." : "Search chat history…"}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-xl border border-[#3e434f] bg-white/5 py-1.5 pl-8 pr-3 text-[11px] text-white outline-none focus:border-[#C48A5A] transition"
            />
          </div>
        </div>

        {/* Sessions list */}
        <div className="flex-1 overflow-y-auto px-2 py-3 space-y-4">
          {pinnedSessions.length > 0 && (
            <div>
              <p className="px-2 mb-1.5 text-[9px] font-bold uppercase tracking-widest text-gray-400 flex items-center gap-1">
                <Pin className="h-2.5 w-2.5 text-[#C48A5A]" /> {language === "ta" ? "முக்கியமானவை" : "Pinned"}
              </p>
              {pinnedSessions.map((s) => (
                <SessionItem
                  key={s.id}
                  session={s}
                  active={activeSession === s.id}
                  onClick={() => setActiveSession(s.id)}
                  onDelete={handleDeleteSession}
                  onPin={handleTogglePin}
                />
              ))}
            </div>
          )}

          <div>
            {pinnedSessions.length > 0 && (
              <p className="px-2 mb-1.5 text-[9px] font-bold uppercase tracking-widest text-gray-400 flex items-center gap-1">
                <Clock className="h-2.5 w-2.5" /> {language === "ta" ? "சமீபத்தியவை" : "Recent"}
              </p>
            )}
            {recentSessions.length === 0 && pinnedSessions.length === 0 ? (
              <p className="px-3 py-4 text-center text-xs text-gray-400 font-medium">
                {language === "ta" ? "வரலாறு இல்லை" : "No active chat logs."}
              </p>
            ) : (
              recentSessions.map((s) => (
                <SessionItem
                  key={s.id}
                  session={s}
                  active={activeSession === s.id}
                  onClick={() => setActiveSession(s.id)}
                  onDelete={handleDeleteSession}
                  onPin={handleTogglePin}
                />
              ))
            )}
          </div>
        </div>
      </aside>

      {/* ── Main Chat Layout ──────────────────────────────── */}
      <div className="flex flex-1 flex-col min-w-0 bg-[#F2EEE8] relative">
        <CyberWatermark />

        {/* Chat Header */}
        <header className="flex items-center justify-between border-b border-[#E4DEC6] bg-white px-5 py-3 shadow-sm z-10 shrink-0">
          <div className="flex items-center gap-3">
            <AIAvatar size={36} />
            <div>
              <h1 className="text-sm font-extrabold text-gray-800 font-poppins flex items-center gap-1.5">
                🤖 Cyber Sentinel AI
                <span className="inline-flex h-1.5 w-1.5 rounded-full bg-[#34A853] animate-pulse" />
              </h1>
              <p className="text-[10px] font-semibold text-gray-500 font-manrope">
                {language === "ta"
                  ? "உங்கள் அறிவார்ந்த சைபர் பாதுகாப்பு உதவியாளர்"
                  : "Your Intelligent Cybersecurity Assistant"}
              </p>
            </div>
          </div>

          {/* Quick Toolbar */}
          <div className="flex items-center gap-2">
            {/* Language Toggle */}
            <button
              onClick={() => {
                const nextLang = language === "en" ? "ta" : "en";
                setLanguage(nextLang);
                setVoiceLang(nextLang === "ta" ? "ta-IN" : "en-IN");
              }}
              className="flex items-center gap-1.5 rounded-xl border border-[#E4DEC6] bg-white px-2.5 py-1.5 text-[11px] font-bold text-gray-700 hover:bg-[#FAF8F5] transition-colors"
              title="Toggle Language (English / தமிழ்)"
            >
              <Languages className="h-3.5 w-3.5 text-[#C48A5A]" />
              {language === "en" ? "தமிழ்" : "English"}
            </button>

            {/* New Chat */}
            <button
              onClick={handleNewChat}
              className="flex items-center gap-1.5 rounded-xl border border-[#E4DEC6] bg-white px-3 py-1.5 text-[11px] font-bold text-gray-600 hover:bg-[#FAF8F5] hover:text-[#C48A5A] transition-colors"
            >
              <Plus className="h-3.5 w-3.5" /> {language === "ta" ? "புதிய அரட்டை" : "New Chat"}
            </button>

            {/* Export Actions */}
            <button
              onClick={handleExportTxt}
              className="hidden sm:flex items-center gap-1.5 rounded-xl border border-[#E4DEC6] bg-white px-3 py-1.5 text-[11px] font-bold text-gray-600 hover:bg-[#FAF8F5] transition-colors"
              title="Export as TXT"
            >
              <FileText className="h-3.5 w-3.5" /> TXT
            </button>
            <button
              onClick={handleExportJson}
              className="hidden sm:flex items-center gap-1.5 rounded-xl border border-[#E4DEC6] bg-white px-3 py-1.5 text-[11px] font-bold text-gray-600 hover:bg-[#FAF8F5] transition-colors"
              title="Export as JSON"
            >
              <FileJson className="h-3.5 w-3.5" /> JSON
            </button>

            {/* Settings Modal Toggle */}
            <button
              onClick={() => setIsSettingsOpen(true)}
              className="flex h-8 w-8 items-center justify-center rounded-xl border border-[#E4DEC6] bg-white text-gray-500 hover:bg-[#FAF8F5] transition-colors"
              title="Chatbot Settings"
            >
              <Settings className="h-4 w-4" />
            </button>

            <Link
              to="/dashboard"
              className="flex items-center gap-1.5 rounded-xl bg-[#2E323A] px-3 py-1.5 text-[11px] font-bold text-white hover:bg-[#2E323A]/90 transition-colors"
            >
              <ArrowLeft className="h-3.5 w-3.5" /> Back
            </Link>
          </div>
        </header>

        {/* Active Threat Intelligence Banner (if sent from Scanner) */}
        {activeThreatContext && (
          <div className="mx-4 mt-3 p-3.5 rounded-2xl bg-white border border-[#E05A52]/30 shadow-sm flex items-center justify-between gap-3 z-10">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-[#E05A52]/10 text-[#E05A52]">
                <ShieldAlert className="h-5 w-5" />
              </div>
              <div>
                <div className="text-xs font-bold text-gray-800">
                  {activeThreatContext.type} Result: <span className="text-[#E05A52] font-extrabold">{activeThreatContext.classification}</span> ({activeThreatContext.confidence})
                </div>
                <div className="text-[11px] text-gray-500 font-mono truncate max-w-md">
                  {activeThreatContext.input}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleExplainThreatContext}
                className="px-3 py-1.5 bg-[#2E323A] text-white text-xs font-bold rounded-xl hover:bg-[#C48A5A] transition shadow-sm"
              >
                Explain This Result
              </button>
              <button
                onClick={() => setActiveThreatContext(null)}
                className="p-1.5 text-gray-400 hover:text-gray-600 rounded-lg"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        {/* Chat Feed / Welcome Screen */}
        <div className="flex-1 overflow-y-auto px-4 py-6 space-y-6 z-10">
          {currentMessages.length <= 1 ? (
            /* Welcome Hero Page */
            <div className="max-w-2xl mx-auto flex flex-col items-center justify-center min-h-[70%] text-center gap-6 py-8">
              <div>
                <div className="mb-4 flex justify-center">
                  <AIAvatar size={64} />
                </div>
                <h2 className="text-xl font-extrabold text-gray-800 font-poppins">
                  🤖 Cyber Sentinel AI
                </h2>
                <p className="mt-2 text-xs font-semibold text-gray-500 max-w-md mx-auto leading-relaxed">
                  {language === "ta"
                    ? "உங்கள் AI சைபர் பாதுகாப்பு உதவியாளர். எந்தவொரு இணைய பாதுகாப்பு கேள்வியையும் கேளுங்கள் அல்லது அவசர பாதுகாப்பு வழிகாட்டுதல் பெறுங்கள்."
                    : "Your AI-powered cybersecurity assistant. Ask any cybersecurity question, explore defensive best practices, or get instant incident-response checklists."}
                </p>
              </div>

              {/* 4 Standard Action Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 w-full max-w-xl">
                {QUICK_ACTIONS.map((a) => {
                  const Icon = a.icon;
                  return (
                    <button
                      key={a.label}
                      onClick={() => handleSend(a.prompt)}
                      className="flex items-start gap-3 p-4 bg-white border border-[#E4DEC6]/60 rounded-2xl shadow-sm hover:shadow-md transition-all group text-left"
                      style={{ borderColor: `${a.color}25` }}
                    >
                      <div
                        className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl"
                        style={{ background: a.bg }}
                      >
                        <Icon className="h-5 w-5" style={{ color: a.color }} />
                      </div>
                      <div className="min-w-0">
                        <span className="text-xs font-bold text-gray-800 group-hover:text-[#C48A5A] transition-colors block">
                          {a.label}
                        </span>
                        <span className="text-[10px] text-gray-400 mt-0.5 block truncate">
                          {a.sub}
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          ) : (
            /* Messages List */
            <div className="max-w-3xl mx-auto space-y-6">
              {currentMessages.map((msg) => (
                <div
                  key={msg.id}
                  className={`flex gap-3.5 ${msg.sender === "user" ? "justify-end" : "justify-start"}`}
                >
                  {msg.sender === "ai" && <AIAvatar size={36} />}
                  <div className="max-w-[85%] space-y-1.5">
                    {msg.sender === "user" ? (
                      /* User text bubble */
                      <div className="bg-gradient-to-br from-[#4F7EF7] to-[#3a6ad4] text-white px-4 py-3 rounded-2xl rounded-tr-sm shadow-sm text-xs leading-relaxed font-medium space-y-2">
                        {msg.image && (
                          <div className="rounded-xl overflow-hidden border border-white/20 max-w-xs mb-2 bg-black/10">
                            <img src={msg.image} alt="Uploaded screenshot" className="w-full h-auto object-cover max-h-48" />
                          </div>
                        )}
                        <div>{msg.text}</div>
                      </div>
                    ) : (
                      /* AI response bubble */
                      <div className="bg-white border border-[#E4DEC6] rounded-2xl rounded-tl-sm shadow-sm overflow-hidden">
                        <div className="p-4 text-xs text-gray-700 leading-relaxed space-y-2">
                          {msg.text.split("\n").map((line, li) => {
                            if (line.startsWith("### ")) {
                              return (
                                <h3 key={li} className="text-[11px] font-extrabold text-gray-800 uppercase tracking-wide mt-2">
                                  {line.slice(4)}
                                </h3>
                              );
                            }
                            if (line.startsWith("## ")) {
                              return (
                                <h2 key={li} className="text-xs font-extrabold text-gray-900 mt-2">
                                  {line.slice(3)}
                                </h2>
                              );
                            }
                            if (line.startsWith("# ")) {
                              return (
                                <h1 key={li} className="text-sm font-extrabold text-gray-900 mt-2">
                                  {line.slice(2)}
                                </h1>
                              );
                            }
                            if (line.startsWith("• ") || line.startsWith("- ")) {
                              return (
                                <div key={li} className="flex items-start gap-2">
                                  <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-[#C48A5A]" />
                                  <span dangerouslySetInnerHTML={{ __html: line.slice(2).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>") }} />
                                </div>
                              );
                            }
                            if (/^\d+\. /.test(line)) {
                              const num = line.match(/^(\d+)\. /)?.[1];
                              return (
                                <div key={li} className="flex items-start gap-2">
                                  <span className="shrink-0 font-bold text-[#C48A5A] text-[10px] mt-0.5">{num}.</span>
                                  <span dangerouslySetInnerHTML={{ __html: line.replace(/^\d+\. /, "").replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>") }} />
                                </div>
                              );
                            }
                            if (line === "") return <div key={li} className="h-1" />;
                            return (
                              <p
                                key={li}
                                dangerouslySetInnerHTML={{
                                  __html: line
                                    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
                                    .replace(/\*(.+?)\*/g, "<em>$1</em>")
                                    .replace(/`(.+?)`/g, "<code class='bg-gray-100 px-1 rounded text-[10px] font-mono text-[#C48A5A]'>$1</code>"),
                                }}
                              />
                            );
                          })}
                        </div>

                        {/* Threat Analysis Card (Rendered ONLY when actual detector result exists) */}
                        {msg.analysis && (
                          <div className="mx-4 mb-4 border border-[#E4DEC6]/80 rounded-xl bg-[#FAF8F5] p-3.5 space-y-3">
                            <div className="flex items-center justify-between">
                              <span className="text-[9px] font-bold text-gray-400 uppercase tracking-wider font-poppins">
                                {msg.analysis.category}
                              </span>
                              <span
                                className="rounded-full px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-wider"
                                style={{
                                  color:
                                    msg.analysis.status === "scam"
                                      ? "#E05A52"
                                      : msg.analysis.status === "suspicious"
                                      ? "#E8A23C"
                                      : msg.analysis.status === "invalid" || msg.analysis.status === "unknown"
                                      ? "#6B7280"
                                      : "#34A853",
                                  background:
                                    msg.analysis.status === "scam"
                                      ? "#E05A5212"
                                      : msg.analysis.status === "suspicious"
                                      ? "#E8A23C12"
                                      : msg.analysis.status === "invalid" || msg.analysis.status === "unknown"
                                      ? "#6B728012"
                                      : "#34A85312",
                                  border: `1px solid ${
                                    msg.analysis.status === "scam"
                                      ? "#E05A5230"
                                      : msg.analysis.status === "suspicious"
                                      ? "#E8A23C30"
                                      : msg.analysis.status === "invalid" || msg.analysis.status === "unknown"
                                      ? "#6B728030"
                                      : "#34A85330"
                                  }`,
                                }}
                              >
                                {msg.analysis.status === "scam"
                                  ? "🚨 MALICIOUS"
                                  : msg.analysis.status === "suspicious"
                                  ? "🟠 SUSPICIOUS"
                                  : msg.analysis.status === "invalid"
                                  ? "⚪ INVALID"
                                  : msg.analysis.status === "unknown"
                                  ? "⚪ UNVERIFIED"
                                  : "🟢 LEGITIMATE"}
                              </span>
                            </div>

                            {/* Confidence Score */}
                            <div className="space-y-1">
                              <div className="flex items-center justify-between text-[10px] font-bold text-gray-500">
                                <span>Model Confidence</span>
                                <span>{msg.analysis.score !== null ? `${msg.analysis.score}%` : "N/A"}</span>
                              </div>
                              {msg.analysis.score !== null && (
                                <div className="h-1.5 w-full rounded-full bg-gray-200 overflow-hidden">
                                  <div
                                    className="h-full rounded-full transition-all duration-700"
                                    style={{
                                      width: `${msg.analysis.score}%`,
                                      background:
                                        msg.analysis.status === "scam"
                                          ? "linear-gradient(90deg,#E05A52,#C44)"
                                          : msg.analysis.status === "suspicious"
                                          ? "linear-gradient(90deg,#E8A23C,#D4922C)"
                                          : "linear-gradient(90deg,#34A853,#2d9547)",
                                    }}
                                  />
                                </div>
                              )}
                            </div>

                            {/* Evidence */}
                            {msg.analysis.reasons && msg.analysis.reasons.length > 0 && (
                              <div className="space-y-1 pt-0.5">
                                <span className="text-[9px] font-bold text-gray-400 uppercase tracking-widest block font-poppins">
                                  Evidence &amp; Indicators
                                </span>
                                <ul className="space-y-1">
                                  {msg.analysis.reasons.map((r, i) => (
                                    <li key={i} className="flex items-start gap-2 text-[10px] text-gray-600 leading-normal">
                                      <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-[#C48A5A]" />
                                      {r}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {/* Summary */}
                            {msg.analysis.summary && (
                              <div className="pt-2 border-t border-[#E4DEC6]/60 text-[10px] leading-relaxed text-gray-600">
                                <span className="font-bold text-gray-700">Recommended Action: </span>
                                {msg.analysis.summary}
                              </div>
                            )}

                            {msg.analysis.source && (
                              <div className="text-[9px] text-gray-400 font-mono">
                                Source: {msg.analysis.source}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                    <div className="text-[9px] text-gray-400 text-right px-1 mt-1">
                      {msg.timestamp}
                    </div>
                  </div>
                </div>
              ))}

              {/* Typing indicator */}
              {isTyping && (
                <div className="flex gap-3.5 justify-start">
                  <AIAvatar size={36} />
                  <div className="bg-white border border-[#E4DEC6] px-4 py-3 rounded-2xl rounded-tl-sm shadow-sm flex items-center gap-2">
                    {[0, 1, 2].map((i) => (
                      <span
                        key={i}
                        className="h-1.5 w-1.5 rounded-full bg-[#C48A5A] inline-block animate-bounce"
                        style={{ animationDelay: `${i * 0.15}s` }}
                      />
                    ))}
                    <span className="text-[10px] font-semibold text-gray-400 ml-1">
                      {language === "ta" ? "சிந்திக்கிறது…" : "Thinking…"}
                    </span>
                  </div>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>
          )}
        </div>

        {/* Image Attachment Preview */}
        {attachedImage && (
          <div className="px-4 py-2 border-t border-[#E4DEC6] bg-white/90 backdrop-blur-sm z-10 shrink-0">
            <div className="max-w-3xl mx-auto flex items-center gap-3">
              <div className="relative rounded-xl overflow-hidden border border-[#C48A5A] w-14 h-14 bg-gray-100 shadow-sm shrink-0">
                <img src={attachedImage} alt="Attached preview" className="w-full h-full object-cover" />
                <button
                  type="button"
                  onClick={() => setAttachedImage(null)}
                  className="absolute top-0.5 right-0.5 bg-black/70 hover:bg-black text-white rounded-full p-0.5 transition"
                  title="Remove image"
                >
                  <X className="h-3 w-3" />
                </button>
              </div>
              <div className="text-xs text-gray-600">
                <span className="font-bold block">Screenshot Attached</span>
                <span className="text-[10px] text-gray-400">Click send or enter text to accompany the image.</span>
              </div>
            </div>
          </div>
        )}

        {/* Input Form Box */}
        <div className="p-4 border-t border-[#E4DEC6] bg-white/70 backdrop-blur-sm z-10 shrink-0">
          <div className="max-w-3xl mx-auto relative">
            <textarea
              rows={2}
              value={inputVal}
              onChange={(e) => setInputVal(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  if (!isTyping && !isSendingRef.current) {
                    handleSend();
                  }
                }
              }}
              placeholder={
                isListening
                  ? language === "ta"
                    ? "கேட்கிறது... பேசவும்..."
                    : "Listening... speak into your microphone..."
                  : language === "ta"
                  ? "ஏதேனும் சைபர் பாதுகாப்பு கேள்வி அல்லது சந்தேகத்திற்குரிய விவரங்களை உள்ளிடவும்..."
                  : "Ask any cybersecurity question (e.g., What is phishing?, How to protect bank account?)..."
              }
              className={`w-full rounded-2xl border ${
                isListening ? "border-[#E05A52] ring-2 ring-[#E05A52]/20" : "border-[#E4DEC6]"
              } bg-white p-3 pr-28 text-xs font-semibold text-gray-800 placeholder-gray-400 outline-none shadow-sm focus:border-[#C48A5A] transition resize-none`}
            />

            {/* Toolbar Buttons */}
            <div className="absolute right-3.5 bottom-3.5 flex items-center gap-1.5">
              {/* Voice recognition */}
              <button
                type="button"
                onClick={toggleVoice}
                className={`p-1.5 rounded-xl transition ${
                  isListening
                    ? "bg-[#E05A52] text-white animate-pulse"
                    : "text-gray-400 hover:text-gray-600 hover:bg-[#FAF8F5]"
                }`}
                title={isListening ? "Stop listening" : `Voice input (${voiceLang})`}
              >
                {isListening ? <MicOff className="h-4 w-4" /> : <Mic className="h-4 w-4" />}
              </button>

              {/* Image upload */}
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-[#FAF8F5] rounded-xl transition"
                title="Upload screenshot"
              >
                <ImageIcon className="h-4 w-4" />
              </button>

              {/* Send button */}
              <button
                onClick={() => handleSend()}
                disabled={isTyping || (!inputVal.trim() && !attachedImage)}
                className="p-2 bg-[#C48A5A] disabled:bg-[#C48A5A]/50 text-white rounded-xl shadow-sm hover:bg-[#C48A5A]/90 transition"
              >
                <Send className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
          <div className="text-center text-[9px] text-gray-400 mt-2">
            Cyber Sentinel AI provides defensive guidance & cybersecurity education. Never share sensitive credentials.
          </div>
        </div>
      </div>

      {/* ── Chatbot Settings Modal ──────────────────────────── */}
      {isSettingsOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            className="w-full max-w-md bg-white rounded-2xl shadow-xl border border-[#E4DEC6] p-6 text-gray-800 space-y-5"
          >
            <div className="flex items-center justify-between pb-3 border-b border-[#E4DEC6]">
              <div className="flex items-center gap-2">
                <Settings className="h-5 w-5 text-[#C48A5A]" />
                <h3 className="font-bold text-sm text-gray-800 font-poppins">Cyber Sentinel AI Settings</h3>
              </div>
              <button onClick={() => setIsSettingsOpen(false)} className="text-gray-400 hover:text-gray-600 p-1">
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Language Preference */}
            <div className="space-y-2">
              <label className="text-xs font-bold text-gray-700 block">Response Language</label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setLanguage("en")}
                  className={`px-3 py-2 text-xs font-bold rounded-xl border transition ${
                    language === "en" ? "bg-[#C48A5A] text-white border-[#C48A5A]" : "bg-white text-gray-700 border-gray-200"
                  }`}
                >
                  English
                </button>
                <button
                  type="button"
                  onClick={() => setLanguage("ta")}
                  className={`px-3 py-2 text-xs font-bold rounded-xl border transition ${
                    language === "ta" ? "bg-[#C48A5A] text-white border-[#C48A5A]" : "bg-white text-gray-700 border-gray-200"
                  }`}
                >
                  தமிழ் (Tamil)
                </button>
              </div>
            </div>

            {/* Voice Input Language */}
            <div className="space-y-2">
              <label className="text-xs font-bold text-gray-700 block">Voice Recognition Dialect</label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setVoiceLang("en-IN")}
                  className={`px-3 py-2 text-xs font-bold rounded-xl border transition ${
                    voiceLang === "en-IN" ? "bg-[#2E323A] text-white border-[#2E323A]" : "bg-white text-gray-700 border-gray-200"
                  }`}
                >
                  English (India)
                </button>
                <button
                  type="button"
                  onClick={() => setVoiceLang("ta-IN")}
                  className={`px-3 py-2 text-xs font-bold rounded-xl border transition ${
                    voiceLang === "ta-IN" ? "bg-[#2E323A] text-white border-[#2E323A]" : "bg-white text-gray-700 border-gray-200"
                  }`}
                >
                  தமிழ் (India)
                </button>
              </div>
            </div>

            {/* History Management Actions */}
            <div className="space-y-2 pt-2 border-t border-gray-100">
              <label className="text-xs font-bold text-gray-700 block">Chat Storage Management</label>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={handleClearCurrentChat}
                  className="flex-1 px-3 py-2 text-xs font-bold text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-xl transition"
                >
                  Clear Current Chat
                </button>
                <button
                  type="button"
                  onClick={handleClearAllHistory}
                  className="flex-1 px-3 py-2 text-xs font-bold text-white bg-[#E05A52] hover:bg-[#c94942] rounded-xl transition"
                >
                  Clear All History
                </button>
              </div>
            </div>

            {/* Privacy Note */}
            <div className="p-3 bg-[#FAF8F5] border border-[#E4DEC6] rounded-xl flex items-start gap-2.5">
              <Info className="h-4 w-4 text-[#C48A5A] shrink-0 mt-0.5" />
              <p className="text-[10px] text-gray-600 leading-relaxed">
                Chatbot logs are cached locally in your browser (<code>localStorage</code>) and are independent of VigiLock database threat logs.
              </p>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  );
}

/* ─── Session Item Component ─────────────────────────────── */
function SessionItem({
  session,
  active,
  onClick,
  onDelete,
  onPin,
}: {
  session: ChatSession;
  active: boolean;
  onClick: () => void;
  onDelete: (id: string, e: React.MouseEvent) => void;
  onPin: (id: string, e: React.MouseEvent) => void;
}) {
  const [hover, setHover] = useState(false);

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      className={`group flex cursor-pointer items-start gap-2.5 rounded-xl px-2.5 py-2 mb-0.5 border transition-all ${
        active
          ? "bg-[#C48A5A]/15 border-[#C48A5A]/30 text-white"
          : "border-transparent text-gray-300 hover:bg-white/5 hover:text-white"
      }`}
    >
      <MessageSquare
        className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${active ? "text-[#C48A5A]" : "text-gray-400"}`}
      />
      <div className="flex-1 min-w-0">
        <p className={`truncate text-[11px] font-bold ${active ? "text-white" : "text-gray-300"} font-manrope`}>
          {session.title}
        </p>
        <p className="truncate text-[10px] text-gray-400 font-manrope mt-0.5">{session.preview}</p>
        <p className="text-[9px] text-gray-500 font-manrope mt-1">{session.timestamp}</p>
      </div>

      {hover && (
        <div className="flex items-center gap-0.5 shrink-0 ml-1">
          <button
            onClick={(e) => onPin(session.id, e)}
            className="flex h-5 w-5 items-center justify-center rounded-lg hover:bg-white/10 transition-colors"
            title={session.pinned ? "Unpin" : "Pin"}
          >
            <Pin className={`h-3 w-3 ${session.pinned ? "text-[#C48A5A]" : "text-gray-400"}`} />
          </button>
          <button
            onClick={(e) => onDelete(session.id, e)}
            className="flex h-5 w-5 items-center justify-center rounded-lg hover:bg-white/10 transition-colors"
            title="Delete chat"
          >
            <Trash2 className="h-3 w-3 text-[#E05A52]" />
          </button>
        </div>
      )}
    </div>
  );
}
