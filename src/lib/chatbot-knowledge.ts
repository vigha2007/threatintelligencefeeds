/**
 * Cyber Sentinel AI — Gemini-backed knowledge engine with multi-language and fallback support.
 *
 * Language routing:
 * - English input → English
 * - Tanglish input → TAMIL SCRIPT (தமிழ்), NOT Tanglish
 * - Tamil script input → TAMIL SCRIPT (தமிழ்)
 * - Explicit "Tanglish" request → Tanglish
 * - "Vanakkam" / "Vannakam" alone → English
 * - "Tamil la sollu" / "தமிழில் சொல்லுங்கள்" → Tamil script
 * - "Tanglish la sollu" → Tanglish
 * - "English la sollu" → English
 * - Maintain selected language for follow-ups
 */

import { JAVA_BASE } from "./intel-analyzers";

/** Shared interface used by chatbot.tsx for conversation history. */
export interface ChatHistoryMessage {
  sender: "user" | "ai";
  text: string;
}

export type ChatMode = "GENERAL_AI" | "INCIDENT" | "SCANNER_CONTEXT";

export type SupportedLanguage = "en" | "ta" | "tanglish";

export interface ThreatContext {
  type?: string;
  input?: string;
  classification?: string;
  confidence?: string;
  severity?: string;
  evidence?: string[];
  summary?: string;
}

export interface ChatAnswerResult {
  text: string;
  source: "GEMINI" | "LOCAL_FALLBACK";
  language?: SupportedLanguage;
}

export function containsTamilScript(text: string): boolean {
  return /[\u0B80-\u0BFF]/.test(text);
}

export function isTanglish(text: string): boolean {
  const l = text.toLowerCase();
  return /\b(na enna|pathi sollu|epdi|eppadi|panrathu|panradhu|pannunga|solunga|solla mudiyuma|irukku|enna|aagum|varum|theriyuma|kudukalama|pathukappu|thiruduvanga|aayiduchu|sollu|solla|solungo|mudiyuma|pannalama|pannalam|koodatha|koodathu|nalladha|nalladhu|thappu|therinjukanum|theriyala|engalukku|unakku|enakku|romba|konjam|edhukku|ethukku|enga|eppovum|apdi|ipdi|oru|sila|ella|ellam|mattum|matum|aana|aanaal|illa|illana|illai|nu sollu|la sollu|la explain pannu|paththi|solli thanga)\b/.test(l);
}

export function resolveTargetLanguage(message: string, sessionLanguage?: string): SupportedLanguage {
  const trimmed = message.trim();
  const lower = trimmed.toLowerCase();

  // 1. Explicit language command overrides
  if (/\b(tanglish la sollu|tanglish la explain pannu|tanglish la|in tanglish|tanglish please|tanglish)\b/i.test(lower)) {
    return "tanglish";
  }
  if (/\b(tamil la sollu|தமிழில் சொல்லுங்கள்|tamil la explain pannu|in tamil|tamil please|thamizh la sollu|thamizh la)\b/i.test(lower)) {
    return "ta";
  }
  if (/\b(english la sollu|in english|english please|english la explain pannu|english la)\b/i.test(lower)) {
    return "en";
  }

  // 2. Standalone Vanakkam / Vannakam alone -> MUST reply in English
  const cleanGreeting = lower.replace(/[^a-z\s]/g, "").trim();
  if (/^(vanakkam|vannakam|vanakkam ai|vannakkam|vanakkam assistant)$/i.test(cleanGreeting)) {
    return "en";
  }

  // 3. Tamil script in message -> Tamil script
  if (containsTamilScript(trimmed)) {
    return "ta";
  }

  // 4. Tanglish input -> Respond in TAMIL SCRIPT (தமிழ்), NOT Tanglish
  if (isTanglish(lower)) {
    return "ta";
  }

  // 5. Follow-up language persistence
  if (sessionLanguage === "tanglish") return "tanglish";
  if (sessionLanguage === "ta" || sessionLanguage === "tamil") {
    // If the query is an explicit English query without Tamil keywords, switch to English
    if (/^(what|wht|why|how|explain|is this|check this|can you|tell me|who|when|where)\b/i.test(lower) && !isTanglish(lower) && !containsTamilScript(lower)) {
      return "en";
    }
    return "ta";
  }

  return "en";
}

export const FRIENDLY_HIGH_DEMAND_MSG: Record<SupportedLanguage, string> = {
  en: "I am currently receiving a high volume of requests and taking a brief moment to process. Please try your question again in a moment, or ask about common topics like phishing, malware, password protection, or VPNs.",
  ta: "தற்போது அதிக எண்ணிக்கையிலான கோரிக்கைகள் வருவதால் செயலாக்க சிறிது நேரம் ஆகிறது. தயவுசெய்து சிறிது நேரம் கழித்து மீண்டும் முயற்சிக்கவும், அல்லது ஃபிஷிங், மால்வேர், கடவுச்சொல் பாதுகாப்பு போன்ற தலைப்புகள் குறித்து கேளுங்கள்.",
  tanglish: "Ippo niraya requests varathala konjam time aaguthu. Please konja neram kalichu try pannunga, illa phishing, malware, password safety pathi kelunga.",
};

function toApiHistory(
  history: ChatHistoryMessage[]
): Array<{ role: "user" | "assistant"; content: string }> {
  const recent = history.slice(-10);
  return recent.map((m) => ({
    role: m.sender === "user" ? "user" : "assistant",
    content: m.text,
  }));
}

export function isEducationalQuery(text: string): boolean {
  const l = text.toLowerCase().trim();
  return (
    /^(what|wht|wat|why|how|explain|define|tell me|meaning|difference|types of|can you explain|about)\b/i.test(l) ||
    /\b(na enna|artham enna|endral enna|epdi|eppadi)\b/i.test(l) ||
    (/\?$/.test(l) && !/\b(i clicked|i gave|i shared|my account was|hack aayiduchu)\b/i.test(l))
  );
}

export function detectIncidentMode(msg: string): boolean {
  if (isEducationalQuery(msg)) return false;
  const l = msg.toLowerCase();
  return (
    /clicked.*(link|url|website)|opened.*(link|site)|i clicked/i.test(l) ||
    /entered.*password|typed.*password|gave.*password|shared.*password/i.test(l) ||
    /shared.*otp|gave.*otp|told.*otp|sent.*otp/i.test(l) ||
    /gave.*(bank details|card details|cvv|upi pin)|entered.*(cvv|card number|upi pin)/i.test(l) ||
    /downloaded.*(file|apk|app|malware|exe)|installed.*(apk|app|software)/i.test(l) ||
    /account.*(was )?hacked|got (hackd|hacked)|my.*(gmail|email|fb|instagram|whatsapp).*(hack|hacked)/i.test(l) ||
    /naan suspicious link click panniten|OTP share panniten|account hack aayiduchu/i.test(l)
  );
}

export function getLocalEducationalFallback(
  text: string,
  mode: ChatMode = "GENERAL_AI",
  threatContext?: ThreatContext | null,
  lang: SupportedLanguage = "en"
): string | null {
  const norm = text.toLowerCase().replace(/[^a-z0-9\u0B80-\u0BFF\s]/g, " ").replace(/\s+/g, " ").trim();

  // Greetings
  if (/^(hello|hi|hey|greetings|good morning|good afternoon|good evening|vanakkam|vannakam|வணக்கம்)$/i.test(norm)) {
    if (lang === "ta") {
      return "வணக்கம்! 👋 நான் Cyber Sentinel AI — உங்கள் தனிப்பட்ட இணைய பாதுகாப்பு உதவியாளர்.\n\nஇணைய பாதுகாப்பு, தற்காப்பு நடவடிக்கைகள் மற்றும் எச்சரிக்கைகள் குறித்து நான் உங்களுக்கு எவ்வாறு உதவ முடியும்?";
    }
    if (lang === "tanglish") {
      return "Vanakkam! 👋 Naan Cyber Sentinel AI — unga interactive cybersecurity assistant.\n\nCybersecurity doubts, incident guidance, illa safety tips pathi ungalukku enna help venum?";
    }
    return "Hello! 👋 I'm Cyber Sentinel AI — your interactive cybersecurity assistant.\n\nHow can I help you today with cybersecurity concepts, incident response, or defensive security guidance?";
  }

  // Scanner explanation fallback
  if ((mode === "SCANNER_CONTEXT" || norm.includes("explain") || norm.includes("result")) && threatContext) {
    if (lang === "ta") {
      const evid = threatContext.evidence && threatContext.evidence.length > 0
        ? threatContext.evidence.map((e) => `• ${e}`).join("\n")
        : "• VigiLock அச்சுறுத்தல் தரவுத்தளம் மற்றும் ML மாதிரி மூலம் சரிபார்க்கப்பட்டது.";
      return (
        `🔍 **ஸ்கேன் முடிவின் விரிவான விளக்கம்:**\n\n` +
        `• **அச்சுறுத்தல் வகை:** ${threatContext.type || "அச்சுறுத்தல் குறியீடு"}\n` +
        `• **இலக்கு:** \`${threatContext.input || "Indicator"}\`\n` +
        `• **கண்டறிதல் முடிவு:** **${threatContext.classification || "Evaluated"}**\n` +
        `• **நம்பகத்தன்மை:** ${threatContext.confidence || "N/A"}\n` +
        `• **தீவிர நிலை:** ${threatContext.severity || "MEDIUM"}\n\n` +
        `**ஆதாரங்கள் & குறிகாட்டிகள்:**\n${evid}\n\n` +
        `**பரிந்துரைக்கப்பட்ட நடவடிக்கை:**\n${threatContext.summary || "நிலையான பாதுகாப்பு வழிமுறைகளைப் பின்பற்றவும்."}`
      );
    }
    const evid = threatContext.evidence && threatContext.evidence.length > 0
      ? threatContext.evidence.map((e) => `• ${e}`).join("\n")
      : "• Evaluated against VigiLock threat database and machine learning models.";
    return (
      `🔍 **VigiLock Scan Result Breakdown:**\n\n` +
      `• **Threat Type:** ${threatContext.type || "Threat Indicator"}\n` +
      `• **Target Indicator:** \`${threatContext.input || "Indicator"}\`\n` +
      `• **Classification:** **${threatContext.classification || "Evaluated"}**\n` +
      `• **Model Confidence:** ${threatContext.confidence || "N/A"}\n` +
      `• **Risk Severity:** ${threatContext.severity || "MEDIUM"}\n\n` +
      `**Evidence & Indicators:**\n${evid}\n\n` +
      `**Recommended Defensive Action:**\n${threatContext.summary || "Follow standard cybersecurity precautions."}`
    );
  }

  // 1. Cybersecurity
  if (/\b(what is cybersecurity|what is cyber security|wht is cybersecurity|cybersecurity|cyber security|explain cybersecurity|define cybersecurity|cybersecurity na enna|சைபர் பாதுகாப்பு என்றால் என்ன|சைபர் பாதுகாப்பு)\b/i.test(norm)) {
    if (lang === "ta") {
      return "சைபர் பாதுகாப்பு (Cybersecurity) என்பது கணினிகள், நெட்வொர்க்குகள், செயலிகள் மற்றும் முக்கியமான தனிப்பட்ட தரவுகளை அங்கீகரிக்கப்படாத அணுகல், தாக்குதல்கள், சேதம் அல்லது திருட்டிலிருந்து பாதுகாக்கும் நடைமுறையாகும்.\n\n" +
             "முக்கிய பாதுகாப்பு பிரிவுகள்:\n" +
             "• **நெட்வொர்க் பாதுகாப்பு:** கணினி நெட்வொர்க்குகளை ஊடுருவல்களிலிருந்து பாதுகாத்தல்\n" +
             "• **செயலி பாதுகாப்பு:** மென்பொருட்களில் பிழைகள் ஏற்படாமல் தடுத்தல்\n" +
             "• **தரவு பாதுகாப்பு:** முக்கியமான தனிநபர் மற்றும் நிறுவனத் தகவல்களைப் பாதுகாத்தல்\n" +
             "• **அடையாள மேலாண்மை:** அங்கீகரிக்கப்பட்ட நபர்கள் மட்டுமே அணுகுவதை உறுதிசெய்தல்\n\n" +
             "சுருக்கமாக, சைபர் பாதுகாப்பு உங்கள் சாதனங்கள் மற்றும் கணக்குகளை இணைய அச்சுறுத்தல்களிலிருந்து பாதுகாப்பாக வைக்கிறது.";
    }
    if (lang === "tanglish") {
      return "Cybersecurity na computers, networks, apps, and personal data-va unauthorized access and cyber attacks-la irundhu protect panra practice.\n\n" +
             "Main areas: Network Security, App Security, Data Protection, Identity Management.\n\n" +
             "Simple-ah sollanum na, cybersecurity unga accounts and devices-ah safe-ah vekkum.";
    }
    return (
      "Cybersecurity is the practice of protecting computers, networks, applications, and personal data from unauthorized access, attacks, damage, or theft.\n\n" +
      "It includes areas such as:\n" +
      "• **Network Security:** Securing computer networks from intruders and targeted attacks\n" +
      "• **Application Security:** Keeping software and devices free from vulnerabilities\n" +
      "• **Data Protection:** Safeguarding sensitive personal and organizational data\n" +
      "• **Identity & Access Management:** Ensuring only authorized users access systems\n" +
      "• **Threat Detection & Incident Response:** Rapidly identifying and neutralizing cyber threats\n\n" +
      "In simple terms, cybersecurity helps keep your devices, accounts, and information safe from cyber threats."
    );
  }

  // 2. Phishing
  if (/\b(what is phishing|what is phising|wht is phishing|phishing|phishing attack|define phishing|explain phishing|phishing na enna|spear phishing|smishing|vishing|ஃபிஷிங் என்றால் என்ன|ஃபிஷிங்)\b/i.test(norm)) {
    if (lang === "ta") {
      return "ஃபிஷிங் (Phishing) என்பது வங்கி, அரசு நிறுவனங்கள் அல்லது புகழ்பெற்ற சேவைகள் போல நடித்து, மின்னஞ்சல், எஸ்.எம்.எஸ் அல்லது போலி இணையதளங்கள் மூலம் கடவுச்சொல், OTP, வங்கி விவரங்களை ஏமாற்றிப் பறிக்கும் இணையத் தாக்குதல் ஆகும்.\n\n" +
             "முக்கிய ஃபிஷிங் வகைகள்:\n" +
             "• **மின்னஞ்சல் ஃபிஷிங்:** போலி இணைப்புகளுடன் வரும் ஏமாற்று மின்னஞ்சல்கள்\n" +
             "• **ஸ்மிஷிங் (SMS Phishing):** வங்கி கணக்கு முடக்கப்படும் என வரும் போலி குறுஞ்செய்திகள்\n" +
             "• **விஷிங் (Voice Phishing):** வங்கி அதிகாரிகள் போல் பேசி OTP கேட்கும் போலி அழைப்புகள்\n\n" +
             "எச்சரிக்கை அறிகுறிகள்: அவசரப்படுத்தும் வாசகங்கள், OTP/கடவுச்சொல் கோருதல், சந்தேகத்திற்கிடமான URL இணைப்புகள்.";
    }
    if (lang === "tanglish") {
      return "Phishing na hackers banks illa reputed companies maadhiri nadichu fake emails, SMS, illa websites moolama unga passwords, OTP, and bank details-ah thiruda try panra attack.\n\n" +
             "Common types: Email Phishing, Smishing (SMS), Vishing (Call).\n\n" +
             "Never share your OTP or click suspicious links in unverified messages!";
    }
    return (
      "Phishing is a type of cyber attack where attackers disguise themselves as trusted entities (such as banks, utility providers, or coworkers) via emails, text messages, or malicious websites to trick you into revealing sensitive information.\n\n" +
      "Common types of phishing:\n" +
      "• **Email Phishing:** Fake emails containing malicious links or attachments\n" +
      "• **Smishing (SMS Phishing):** Fake text messages claiming urgent account issues or rewards\n" +
      "• **Vishing (Voice Phishing):** Fraudulent phone calls impersonating authorities or bank agents\n\n" +
      "Key warning signs:\n" +
      "• Urgent threats ('Your account will be suspended in 24 hours')\n" +
      "• Requests to confirm passwords, OTPs, or credit card numbers\n" +
      "• Suspicious sender addresses and misspelled domain names."
    );
  }

  // 3. Email scam
  if (/\b(what is an email scam|what is email scam|wht is email scam|email scam|email fraud|explain email scam|define email scam|email scams|fake email|email scam na enna|மின்னஞ்சல் மோசடி என்றால் என்ன|மின்னஞ்சல் மோசடி)\b/i.test(norm)) {
    if (lang === "ta") {
      return "மின்னஞ்சல் மோசடி (Email Scam) என்பது இணைய குற்றவாளிகளால் பணம், கடவுச்சொல் அல்லது தனிப்பட்ட விவரங்களைத் திருடுவதற்காக அனுப்பப்படும் போலியான ஏமாற்று மின்னஞ்சல் ஆகும்.\n\n" +
             "பொதுவான வகைகள்:\n" +
             "• **பரிசு / லாட்டரி மோசடி:** பரிசு விழுந்துள்ளதாகக் கூறி முன் கூட்டியே பணம் கேட்பது\n" +
             "• **போலி இன்வாய்ஸ்:** ஆபத்தான கோப்புகளைத் திறக்கத் தூண்டுதல்\n" +
             "• **கணக்கு சரிபார்ப்பு மோசடி:** வங்கி கணக்கு முடங்கியுள்ளது என போலி இணைப்பு அனுப்புவது\n\n" +
             "பாதுகாப்பு குறிப்பு: எதிர்பாராத மின்னஞ்சல்களில் உள்ள இணைப்புகளைக் கிளிக் செய்யாதீர்கள் மற்றும் கோப்புகளைத் திறக்காதீர்கள்.";
    }
    if (lang === "tanglish") {
      return "Email Scam na cybercriminals unga kitta irundhu panam, confidential passwords, illa personal info-va thirudradhukku anuppura fake emails.\n\n" +
             "Common types: Lottery scams, fake invoices, CEO fraud, account block warning emails.\n\n" +
             "Safety tip: Unknown emails-la vara links-ah click pannathinga, unexpected files open pannathinga.";
    }
    return (
      "An email scam is a fraudulent email created by cybercriminals to deceive recipients into giving away money, confidential credentials, or downloading malicious software.\n\n" +
      "Common email scam formats:\n" +
      "• **Lottery / Prize Scams:** Claiming you have won a cash reward or sweepstake\n" +
      "• **Fake Invoices / Overdue Notices:** Urging you to open an infected PDF or pay a bogus bill\n" +
      "• **Business Email Compromise (BEC):** Impersonating senior executives to request urgent wire transfers\n" +
      "• **Account Verification Scams:** Fake warnings that your account has been locked\n\n" +
      "Defensive tip: Never open unexpected attachments or click links in unsolicited emails."
    );
  }

  // 4. Malware
  if (/\b(what is malware|malware|wht is malware|what is malicious software|explain malware|define malware|types of malware|malware na enna|மால்வேர் என்றால் என்ன|மால்வேர்)\b/i.test(norm)) {
    if (lang === "ta") {
      return "மால்வேர் (Malware) என்பது கணினி அல்லது ஸ்மார்ட்போன்களுக்கு சேதம் விளைவிக்கவும் தகவல்களைத் திருடவும் உருவாக்கப்பட்ட தீங்கிழைக்கும் மென்பொருளாகும்.\n\n" +
             "முக்கிய வகைகள்: வைரஸ்கள், வார்ம்கள், ட்ரோஜன்கள், ஸ்பைவேர், ரேன்சம்வேர்.\n\n" +
             "பாதுகாப்பு: சாதனங்களை எப்போதும் Updated ஆக வைத்திருங்கள் மற்றும் நம்பகமான Antivirus மென்பொருளைப் பயன்படுத்துங்கள்.";
    }
    if (lang === "tanglish") {
      return "Malware na devices and networks-ah damage panna and data thiruda develop panra harmful software (Viruses, Trojans, Spyware, Ransomware).\n\n" +
             "OS and apps-ah update pannunga, trusted antivirus use pannunga.";
    }
    return (
      "Malware (short for 'malicious software') is any intrusive software designed by cybercriminals to steal data, damage devices, or gain unauthorized access to computer systems.\n\n" +
      "Major types of malware:\n" +
      "• **Viruses:** Attach to clean files and propagate across systems\n" +
      "• **Worms:** Self-replicating malware that spreads across networks automatically\n" +
      "• **Trojans:** Disguised as legitimate software to deceive users into installing them\n" +
      "• **Spyware:** Secretly tracks keystrokes, passwords, and user activities\n" +
      "• **Ransomware:** Encrypts user data and demands payment for the recovery key\n\n" +
      "Protection: Keep operating systems updated, avoid unauthorized downloads, and maintain active endpoint protection."
    );
  }

  // 5. VPN
  if (/\b(what is a vpn|what is vpn|wht is vpn|vpn|vpn na enna|virtual private network|explain vpn|define vpn|how does vpn work|விபிஎன் என்றால் என்ன)\b/i.test(norm)) {
    if (lang === "ta") {
      return "VPN (Virtual Private Network) என்பது உங்கள் சாதனத்திற்கும் இணையத்திற்கும் இடையே பாதுகாப்பான, மறைகுறியாக்கப்பட்ட (Encrypted) தொடர்பை ஏற்படுத்தும் தொழில்நுட்பமாகும்.\n\n" +
             "முக்கிய நன்மைகள்:\n" +
             "• **தரவு பாதுகாப்பு:** பொது வைஃபை (Public Wi-Fi) பயன்படுத்தும்போது உங்கள் தரவுகளை யாரும் ஒட்டுக் கேட்க முடியாது\n" +
             "• **IP முகவரி மறைப்பு:** உங்கள் உண்மையான IP முகவரியை மறைத்து தனியுரிமையைப் பாதுகாக்கிறது.";
    }
    if (lang === "tanglish") {
      return "VPN (Virtual Private Network) na unga internet traffic-ah encrypt panni, real IP address-ah hide panra secure tool.\n\n" +
             "Public Wi-Fi-la safe browsing-ku VPN romba useful.";
    }
    return (
      "A VPN (Virtual Private Network) is a technology that creates a secure, encrypted connection (tunnel) between your device and the internet over an otherwise insecure network.\n\n" +
      "Key benefits:\n" +
      "• **Traffic Encryption:** Prevents eavesdropping on public Wi-Fi networks\n" +
      "• **IP Masking:** Hides your real IP address and replaces it with the VPN server's IP\n" +
      "• **Privacy:** Helps protect your browsing activity from local network snoopers and ISP monitoring\n\n" +
      "Note: A VPN does NOT protect against phishing websites, malware downloads, or passwords you willingly submit."
    );
  }

  return null;
}

export async function getCybersecurityAnswer(
  userMessage: string,
  sessionLanguage?: string,
  conversationHistory: ChatHistoryMessage[] = [],
  threatContext?: ThreatContext | null
): Promise<ChatAnswerResult> {

  let mode: ChatMode = "GENERAL_AI";
  if (threatContext && (
    userMessage.toLowerCase().includes("explain") ||
    userMessage.toLowerCase().includes("why") ||
    userMessage.toLowerCase().includes("what does") ||
    userMessage.toLowerCase().includes("what should") ||
    userMessage.toLowerCase().includes("result") ||
    userMessage.trim().length < 30
  )) {
    mode = "SCANNER_CONTEXT";
  } else if (detectIncidentMode(userMessage)) {
    mode = "INCIDENT";
  }

  const resolvedLang = resolveTargetLanguage(userMessage, sessionLanguage);

  try {
    const payload: Record<string, unknown> = {
      message: userMessage,
      conversationHistory: toApiHistory(conversationHistory),
      mode,
      threatContext: threatContext ?? null,
      language: resolvedLang,
    };

    const res = await fetch(`${JAVA_BASE}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(35000),
    });

    const data = (await res.json()) as {
      success: boolean;
      message: string;
      mode?: string;
      source?: "GEMINI" | "LOCAL_FALLBACK";
      language?: SupportedLanguage;
    };

    if (data.message && data.message.trim().length > 0) {
      return {
        text: data.message.trim(),
        source: data.source === "LOCAL_FALLBACK" ? "LOCAL_FALLBACK" : "GEMINI",
        language: data.language || resolvedLang,
      };
    }

    const fallback = getLocalEducationalFallback(userMessage, mode, threatContext, resolvedLang);
    if (fallback) {
      return { text: fallback, source: "LOCAL_FALLBACK", language: resolvedLang };
    }

    return {
      text: FRIENDLY_HIGH_DEMAND_MSG[resolvedLang] || FRIENDLY_HIGH_DEMAND_MSG.en,
      source: "LOCAL_FALLBACK",
      language: resolvedLang,
    };

  } catch (err: unknown) {
    console.warn("[CyberSentinel] Chat API request fallback triggered:", err);

    const fallback = getLocalEducationalFallback(userMessage, mode, threatContext, resolvedLang);
    if (fallback) {
      return { text: fallback, source: "LOCAL_FALLBACK", language: resolvedLang };
    }

    return {
      text: FRIENDLY_HIGH_DEMAND_MSG[resolvedLang] || FRIENDLY_HIGH_DEMAND_MSG.en,
      source: "LOCAL_FALLBACK",
      language: resolvedLang,
    };
  }
}
