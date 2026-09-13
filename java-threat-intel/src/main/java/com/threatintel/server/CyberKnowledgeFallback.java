package com.threatintel.server;

import java.util.*;
import java.util.regex.Pattern;

/**
 * CyberKnowledgeFallback — Local cybersecurity educational knowledge layer with multi-language support.
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
 */
public class CyberKnowledgeFallback {

    public static record FallbackResult(String text, boolean isKnown, String language) {}

    public static boolean containsTamilScript(String text) {
        if (text == null) return false;
        for (char c : text.toCharArray()) {
            if (c >= '\u0B80' && c <= '\u0BFF') return true;
        }
        return false;
    }

    public static boolean isTanglish(String text) {
        if (text == null) return false;
        String lower = text.toLowerCase();
        return lower.matches(".*\\b(na enna|pathi sollu|epdi|eppadi|panrathu|panradhu|pannunga|solunga|solla mudiyuma|irukku|enna|aagum|varum|theriyuma|kudukalama|pathukappu|thiruduvanga|aayiduchu|sollu|solla|solungo|mudiyuma|pannalama|pannalam|koodatha|koodathu|nalladha|nalladhu|thappu|therinjukanum|theriyala|engalukku|unakku|enakku|romba|konjam|edhukku|ethukku|enga|eppovum|apdi|ipdi|oru|sila|ella|ellam|mattum|matum|aana|aanaal|illa|illana|illai|nu sollu|la sollu|la explain pannu|paththi|solli thanga)\\b.*");
    }

    public static String resolveTargetLanguage(String message, String sessionLanguage) {
        if (message == null) message = "";
        String trimmed = message.trim();
        String lower = trimmed.toLowerCase();

        // 1. Explicit language command overrides
        if (lower.matches(".*\\b(tanglish la sollu|tanglish la explain pannu|tanglish la|in tanglish|tanglish please|tanglish)\\b.*")) {
            return "tanglish";
        }
        if (lower.matches(".*\\b(tamil la sollu|தமிழில் சொல்லுங்கள்|tamil la explain pannu|in tamil|tamil please|thamizh la sollu|thamizh la)\\b.*")) {
            return "ta";
        }
        if (lower.matches(".*\\b(english la sollu|in english|english please|english la explain pannu|english la)\\b.*")) {
            return "en";
        }

        // 2. Standalone Vanakkam / Vannakam alone -> MUST reply in English
        String cleanGreeting = lower.replaceAll("[^a-zA-Z\\s]", "").trim();
        if (cleanGreeting.matches("^(vanakkam|vannakam|vanakkam ai|vannakkam|vanakkam assistant)$")) {
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

        // 5. Respect session language for follow-ups if explicit
        if (sessionLanguage != null && !sessionLanguage.isBlank()) {
            if ("tanglish".equalsIgnoreCase(sessionLanguage)) return "tanglish";
            if ("ta".equalsIgnoreCase(sessionLanguage) || "tamil".equalsIgnoreCase(sessionLanguage)) {
                // If the user clearly typed a new English sentence with no Tamil words, switch to English
                if (isClearEnglishQuery(lower)) {
                    return "en";
                }
                return "ta";
            }
        }

        return "en";
    }

    private static boolean isClearEnglishQuery(String lower) {
        return lower.matches("^(what|wht|why|how|explain|is this|check this|can you|tell me|who|when|where)\\b.*") &&
               !isTanglish(lower) && !containsTamilScript(lower);
    }

    /**
     * Resolves an educational fallback answer in the appropriate target language.
     */
    public static FallbackResult getFallbackAnswer(
            String message,
            String mode,
            Map<String, Object> threatContext,
            String sessionLanguage) {

        if (message == null) message = "";
        String trimmed = message.trim();
        String lower = trimmed.toLowerCase();
        String targetLang = resolveTargetLanguage(trimmed, sessionLanguage);

        // 1. Common Greetings
        if (isGreeting(lower)) {
            return new FallbackResult(getGreetingResponse(lower, targetLang), true, targetLang);
        }

        // 2. Core Educational Knowledge Layer (Checked FIRST to avoid false incident classification)
        String educationalAnswer = matchEducationalTopic(lower, targetLang);
        if (educationalAnswer != null) {
            return new FallbackResult(educationalAnswer, true, targetLang);
        }

        // 3. Scanner Context Mode fallback
        if ("SCANNER_CONTEXT".equalsIgnoreCase(mode) || (threatContext != null && !threatContext.isEmpty() && isScannerExplanationQuery(lower))) {
            String scannerExpl = generateScannerContextFallback(threatContext, targetLang);
            if (scannerExpl != null) {
                return new FallbackResult(scannerExpl, true, targetLang);
            }
        }

        // 4. Incident Mode fallback (Only if genuine incident and NOT an educational question)
        if (("INCIDENT".equalsIgnoreCase(mode) || isIncidentReport(lower)) && !isEducationalQuery(lower)) {
            String incidentExpl = generateIncidentFallback(lower, targetLang);
            if (incidentExpl != null) {
                return new FallbackResult(incidentExpl, true, targetLang);
            }
        }

        // 5. Unknown question fallback
        return new FallbackResult(getHighDemandMessage(targetLang), false, targetLang);
    }

    private static boolean isGreeting(String text) {
        String cleaned = text.replaceAll("[^a-zA-Z\\u0B80-\\u0BFF\\s]", "").trim().toLowerCase();
        return cleaned.matches("^(hello|hi|hey|greetings|good morning|good afternoon|good evening|vanakkam|vannakam|வணக்கம்)$");
    }

    private static String getGreetingResponse(String text, String lang) {
        if ("ta".equalsIgnoreCase(lang)) {
            return "வணக்கம்! 👋 நான் Cyber Sentinel AI — உங்கள் தனிப்பட்ட இணைய பாதுகாப்பு உதவியாளர்.\n\n" +
                   "இணைய பாதுகாப்பு, தற்காப்பு நடவடிக்கைகள் மற்றும் எச்சரிக்கைகள் குறித்து நான் உங்களுக்கு எவ்வாறு உதவ முடியும்?";
        }
        if ("tanglish".equalsIgnoreCase(lang)) {
            return "Vanakkam! 👋 Naan Cyber Sentinel AI — unga interactive cybersecurity assistant.\n\n" +
                   "Cybersecurity doubts, incident guidance, illa safety tips pathi ungalukku enna help venum?";
        }
        return "Hello! 👋 I'm Cyber Sentinel AI — your interactive cybersecurity assistant.\n\n" +
               "How can I help you today with cybersecurity concepts, incident response, or defensive security guidance?";
    }

    private static String getHighDemandMessage(String lang) {
        if ("ta".equalsIgnoreCase(lang)) {
            return "தற்போது அதிக எண்ணிக்கையிலான கோரிக்கைகள் வருவதால் செயலாக்க சிறிது நேரம் ஆகிறது. " +
                   "தயவுசெய்து சிறிது நேரம் கழித்து மீண்டும் முயற்சிக்கவும், அல்லது ஃபிஷிங், மால்வேர், கடவுச்சொல் பாதுகாப்பு போன்ற தலைப்புகள் குறித்து கேளுங்கள்.";
        }
        if ("tanglish".equalsIgnoreCase(lang)) {
            return "Ippo niraya requests varathala konjam time aaguthu. " +
                   "Please konja neram kalichu try pannunga, illa phishing, malware, password safety pathi kelunga.";
        }
        return "I am currently receiving a high volume of requests and taking a brief moment to process. " +
               "Please try your question again in a moment, or ask about common topics like phishing, malware, password protection, or VPNs.";
    }

    private static boolean isEducationalQuery(String text) {
        return text.matches("^(what|wht|wat|why|how|explain|define|tell me|meaning|difference|types of|can you explain).*") ||
               text.contains("na enna") || text.contains("artham enna") || text.contains("endral enna");
    }

    private static boolean isScannerExplanationQuery(String text) {
        return text.contains("explain") || text.contains("why") || text.contains("result") || text.contains("scan");
    }

    private static boolean isIncidentReport(String text) {
        return (text.contains("clicked") && (text.contains("link") || text.contains("url") || text.contains("site"))) ||
               (text.contains("entered") && text.contains("password")) ||
               (text.contains("shared") && text.contains("otp")) ||
               (text.contains("gave") && (text.contains("bank") || text.contains("card") || text.contains("pin") || text.contains("cvv"))) ||
               (text.contains("downloaded") && (text.contains("file") || text.contains("apk") || text.contains("malware") || text.contains("app"))) ||
               (text.contains("hacked") || text.contains("hackd") || text.contains("compromised"));
    }

    /**
     * Matches user query against curated cybersecurity educational topics across English, Tamil script, and Tanglish.
     */
    private static String matchEducationalTopic(String text, String lang) {
        String norm = text.replaceAll("[^a-z0-9\\u0B80-\\u0BFF\\s]", " ").replaceAll("\\s+", " ").trim().toLowerCase();

        // 1. Cybersecurity
        if (matchesAny(norm,
                "what is cybersecurity", "what is cyber security", "wht is cybersecurity", "cybersecurity",
                "cyber security", "explain cybersecurity", "define cybersecurity", "cybersecurity na enna",
                "what does cybersecurity mean", "about cybersecurity", "சைபர் பாதுகாப்பு என்றால் என்ன", "சைபர் பாதுகாப்பு")) {
            if ("ta".equalsIgnoreCase(lang)) {
                return "சைபர் பாதுகாப்பு (Cybersecurity) என்பது கணினிகள், நெட்வொர்க்குகள், செயலிகள் மற்றும் முக்கியமான தனிப்பட்ட தரவுகளை அங்கீகரிக்கப்படாத அணுகல், தாக்குதல்கள், சேதம் அல்லது திருட்டிலிருந்து பாதுகாக்கும் நடைமுறையாகும்.\n\n" +
                       "முக்கிய பாதுகாப்பு பிரிவுகள்:\n" +
                       "• **நெட்வொர்க் பாதுகாப்பு (Network Security):** கணினி நெட்வொர்க்குகளை ஊடுருவல்களிலிருந்து பாதுகாத்தல்\n" +
                       "• **செயலி பாதுகாப்பு (Application Security):** மென்பொருட்களில் பிழைகள் மற்றும் பாதிப்புகள் ஏற்படாமல் தடுத்தல்\n" +
                       "• **தரவு பாதுகாப்பு (Data Protection):** முக்கியமான தனிநபர் மற்றும் நிறுவனத் தகவல்களைப் பாதுகாத்தல்\n" +
                       "• **அடையாள மேலாண்மை (Identity Management):** அங்கீகரிக்கப்பட்ட நபர்கள் மட்டுமே கணக்குகளை அணுகுவதை உறுதிசெய்தல்\n" +
                       "• **அச்சுறுத்தல் கண்டறிதல் (Threat Detection):** சைபர் தாக்குதல்களை உடனடியாகக் கண்டறிந்து முறியடித்தல்.\n\n" +
                       "சுருக்கமாக, சைபர் பாதுகாப்பு உங்கள் சாதனங்கள், கணக்குகள் மற்றும் தனிப்பட்ட தகவல்களை இணைய அச்சுறுத்தல்களிலிருந்து பாதுகாப்பாக வைக்கிறது.";
            }
            if ("tanglish".equalsIgnoreCase(lang)) {
                return "Cybersecurity na computers, networks, apps, and unga personal data-va unauthorized access, attacks, and theft-la irundhu protect panra practice.\n\n" +
                       "Mukkiyamana areas:\n" +
                       "• **Network Security:** Network-ah hackers kitta irundhu safe-ah vekkiradhu\n" +
                       "• **Application Security:** Software & apps-la vulnerabilities illama paathukiradhu\n" +
                       "• **Data Protection:** Important confidential data-va encrypt panni protect panradhu\n" +
                       "• **Identity Management:** Authorized users mattum login panna allow panradhu\n\n" +
                       "Simple-ah sollanum na, cybersecurity unga accounts and devices-ah cyber threats kitta irundhu secure-ah vekkum.";
            }
            return "Cybersecurity is the practice of protecting computers, networks, applications, and personal data from unauthorized access, attacks, damage, or theft.\n\n" +
                   "It includes areas such as:\n" +
                   "• **Network Security:** Securing computer networks from intruders and targeted attacks\n" +
                   "• **Application Security:** Keeping software and devices free from vulnerabilities\n" +
                   "• **Data Protection:** Safeguarding sensitive personal and organizational data\n" +
                   "• **Identity & Access Management:** Ensuring only authorized users access systems\n" +
                   "• **Threat Detection & Incident Response:** Rapidly identifying and neutralizing cyber threats\n\n" +
                   "In simple terms, cybersecurity helps keep your devices, accounts, and information safe from cyber threats.";
        }

        // 2. Phishing
        if (matchesAny(norm,
                "what is phishing", "what is phising", "wht is phishing", "phishing", "phishing attack",
                "define phishing", "explain phishing", "phishing na enna", "how does phishing work",
                "types of phishing", "spear phishing", "smishing", "vishing", "ஃபிஷிங் என்றால் என்ன", "ஃபிஷிங்")) {
            if ("ta".equalsIgnoreCase(lang)) {
                return "ஃபிஷிங் (Phishing) என்பது வங்கி, அரசு நிறுவனங்கள் அல்லது புகழ்பெற்ற சேவைகள் போல போலியாக நடித்து, மின்னஞ்சல், எஸ்.எம்.எஸ் அல்லது போலி இணையதளங்கள் மூலம் கடவுச்சொல், OTP, கிரெடிட் கார்டு எண்கள் போன்ற ரகசிய தகவல்களை ஏமாற்றிப் பறிக்கும் இணையத் தாக்குதல் ஆகும்.\n\n" +
                       "முக்கிய ஃபிஷிங் வகைகள்:\n" +
                       "• **மின்னஞ்சல் ஃபிஷிங் (Email Phishing):** போலி இணைப்புகளுடன் வரும் ஏமாற்று மின்னஞ்சல்கள்\n" +
                       "• **ஸ்மிஷிங் (SMS Phishing):** வங்கி கணக்கு முடக்கப்படும் என வரும் போலி குறுஞ்செய்திகள்\n" +
                       "• **விஷிங் (Voice Phishing):** வங்கி அதிகாரிகள் போல் பேசி OTP கேட்கும் போலி தொலைபேசி அழைப்புகள்\n\n" +
                       "எச்சரிக்கை அறிகுறிகள்:\n" +
                       "• அவசரப்படுத்தும் வாசகங்கள் ('24 மணி நேரத்தில் கணக்கு முடங்கும்')\n" +
                       "• கடவுச்சொல் அல்லது OTP பகிருமாறு கோருதல்\n" +
                       "• தவறான எழுத்துப் பிழைகள் கொண்ட சந்தேகத்திற்கிடமான URL இணைப்புகள்.";
            }
            if ("tanglish".equalsIgnoreCase(lang)) {
                return "Phishing na hackers banks, utility services, illa reputed companies maadhiri nadichu fake emails, SMS, illa websites moolama unga passwords, OTP, and bank details-ah thiruda try panra attack.\n\n" +
                       "Common types:\n" +
                       "• **Email Phishing:** Fake links and attachments irukura emails\n" +
                       "• **Smishing (SMS Phishing):** Account block aayidum nu vara fake SMS\n" +
                       "• **Vishing (Call Phishing):** Bank officer maadhiri pesi OTP kekkura fake calls\n\n" +
                       "Warning signs:\n" +
                       "• Urgent warning ('24 hours-la account suspend aagum')\n" +
                       "• OTP / Password share panna solli kekkuradhu\n" +
                       "• Suspicious sender email addresses and fake URLs.";
            }
            return "Phishing is a type of cyber attack where attackers disguise themselves as trusted entities (such as banks, utility providers, or coworkers) via emails, text messages, or malicious websites to trick you into revealing sensitive information.\n\n" +
                   "Common types of phishing:\n" +
                   "• **Email Phishing:** Fake emails containing malicious links or attachments\n" +
                   "• **Smishing (SMS Phishing):** Fake text messages claiming urgent account issues or rewards\n" +
                   "• **Vishing (Voice Phishing):** Fraudulent phone calls impersonating authorities or bank agents\n\n" +
                   "Key warning signs:\n" +
                   "• Urgent threats ('Your account will be suspended in 24 hours')\n" +
                   "• Requests to confirm passwords, OTPs, or credit card numbers\n" +
                   "• Suspicious sender addresses and misspelled domain names.";
        }

        // 3. Email scam
        if (matchesAny(norm,
                "what is an email scam", "what is email scam", "wht is email scam", "email scam",
                "email fraud", "explain email scam", "define email scam", "email scams", "fake email",
                "email scam na enna", "மின்னஞ்சல் மோசடி என்றால் என்ன", "மின்னஞ்சல் மோசடி")) {
            if ("ta".equalsIgnoreCase(lang)) {
                return "மின்னஞ்சல் மோசடி (Email Scam) என்பது இணைய குற்றவாளிகளால் பணம், கடவுச்சொல் அல்லது தனிப்பட்ட விவரங்களைத் திருடுவதற்காகவும், கணினியில் மால்வேரை நிறுவுவதற்காகவும் அனுப்பப்படும் போலியான ஏமாற்று மின்னஞ்சல் ஆகும்.\n\n" +
                       "பொதுவான மின்னஞ்சல் மோசடி வகைகள்:\n" +
                       "• **லாட்டரி / பரிசு மோசடி:** பெரும் தொகை பரிசு விழுந்துள்ளதாகக் கூறி முன் கூட்டியே கட்டணம் கேட்பது\n" +
                       "• **போலி இன்வாய்ஸ் / பில்கள்:** கணினியைப் பாதிக்கும் ஆபத்தான கோப்புகளைப் பதிவிறக்கத் தூண்டுதல்\n" +
                       "• **அலுவலக CEO மோசடி (BEC):** உயர் அதிகாரிகள் போல் நடித்து அவசரமாக பணப் பரிமாற்றம் செய்யக் கோருதல்\n" +
                       "• **கணக்கு சரிபார்ப்பு மோசடி:** வங்கி கணக்கு முடக்கப்பட்டுவிட்டது என போலி இணைப்பு அனுப்புவது\n\n" +
                       "பாதுகாப்பு குறிப்பு: எதிர்பாராத மின்னஞ்சல்களில் உள்ள இணைப்புகளைக் கிளிக் செய்யாதீர்கள் மற்றும் இணைக்கப்பட்ட கோப்புகளைத் திறக்காதீர்கள்.";
            }
            if ("tanglish".equalsIgnoreCase(lang)) {
                return "Email Scam na cybercriminals unga kitta irundhu panam, confidential passwords, illa personal info-va thirudradhukku anuppura fake emails.\n\n" +
                       "Common email scam types:\n" +
                       "• **Lottery / Prize Scams:** Cash prize win panniteenga nu solli processing fee kekkuradhu\n" +
                       "• **Fake Invoices / Bills:** Infected PDF/file open panna solli malware install panradhu\n" +
                       "• **CEO Fraud (BEC):** Top manager maadhiri pesi urgent money transfer keka varum emails\n" +
                       "• **Account Verification:** Bank account locked nu solli fake phishing link anupuradhu\n\n" +
                       "Safety tip: Unknown emails-la vara links-ah click pannathinga, unexpected attachments open pannathinga.";
            }
            return "An email scam is a fraudulent email created by cybercriminals to deceive recipients into giving away money, confidential credentials, or downloading malicious software.\n\n" +
                   "Common email scam formats:\n" +
                   "• **Lottery / Prize Scams:** Claiming you have won a cash reward or sweepstake\n" +
                   "• **Fake Invoices / Overdue Notices:** Urging you to open an infected PDF or pay a bogus bill\n" +
                   "• **Business Email Compromise (BEC):** Impersonating senior executives to request urgent wire transfers\n" +
                   "• **Account Verification Scams:** Fake warnings that your account has been locked\n\n" +
                   "Defensive tip: Never open unexpected attachments or click links in unsolicited emails.";
        }

        // 4. Malware
        if (matchesAny(norm,
                "what is malware", "malware", "wht is malware", "what is malicious software",
                "explain malware", "define malware", "types of malware", "malware na enna",
                "மால்வேர் என்றால் என்ன", "மால்வேர்")) {
            if ("ta".equalsIgnoreCase(lang)) {
                return "மால்வேர் (Malware - Malicious Software) என்பது கணினி, ஸ்மார்ட்போன் அல்லது நெட்வொர்க்குகளுக்கு சேதம் விளைவிக்கவும், ரகசியத் தகவல்களைத் திருடவும் உருவாக்கப்பட்ட தீங்கிழைக்கும் மென்பொருட்களின் பொதுவான பெயராகும்.\n\n" +
                       "முக்கிய மால்வேர் வகைகள்:\n" +
                       "• **வைரஸ்கள் (Viruses):** நல்ல கோப்புகளுடன் இணைந்து பிற கோப்புகளுக்கும் பரவும்\n" +
                       "• **வார்ம்கள் (Worms):** இணையம் வழியாக தானாகவே பரவி நெட்வொர்க்கை முடக்கும்\n" +
                       "• **ட்ரோஜன்கள் (Trojans):** பயனுள்ள மென்பொருள் போல் வேடமிட்டு சாதனத்திற்குள் நுழையும்\n" +
                       "• **ஸ்பைவேர் (Spyware):** நீங்கள் தட்டச்சு செய்யும் கடவுச்சொற்கள் மற்றும் செயல்பாடுகளை ரகசியமாகக் கண்காணிக்கும்\n" +
                       "• **ரேன்சம்வேர் (Ransomware):** உங்கள் கோப்புகளை முடக்கி, திறக்கப் பணம் கேட்கும்.\n\n" +
                       "பாதுகாப்பு: சாதனங்களை எப்போதும் Updated ஆக வைத்திருங்கள் மற்றும் நம்பகமான Antivirus மென்பொருளைப் பயன்படுத்துங்கள்.";
            }
            if ("tanglish".equalsIgnoreCase(lang)) {
                return "Malware (Malicious Software) na unga phone, laptop, illa networks-ah damage panna and secret data-va thiruda hackers develop panra harmful software.\n\n" +
                       "Major types:\n" +
                       "• **Viruses:** Normal files kooda attach aagi ellathulayum spread aagum\n" +
                       "• **Worms:** Network moolama automatically replicate aagi spread aagum\n" +
                       "• **Trojans:** Nalla app maadhiri nadichu device kulla enter aagum\n" +
                       "• **Spyware:** Unga passwords and typing activities-ah silently monitor pannum\n" +
                       "• **Ransomware:** Unga files-ah lock panni unlock panna ransom kekkum\n\n" +
                       "Protection: OS and apps-ah updated-ah vekkunga, trusted antivirus use pannunga.";
            }
            return "Malware (short for 'malicious software') is any intrusive software designed by cybercriminals to steal data, damage devices, or gain unauthorized access to computer systems.\n\n" +
                   "Major types of malware:\n" +
                   "• **Viruses:** Attach to clean files and propagate across systems\n" +
                   "• **Worms:** Self-replicating malware that spreads across networks automatically\n" +
                   "• **Trojans:** Disguised as legitimate software to deceive users into installing them\n" +
                   "• **Spyware:** Secretly tracks keystrokes, passwords, and user activities\n" +
                   "• **Ransomware:** Encrypts user data and demands payment for the recovery key\n\n" +
                   "Protection: Keep operating systems updated, avoid unauthorized downloads, and maintain active endpoint protection.";
        }

        // 5. Ransomware
        if (matchesAny(norm,
                "what is ransomware", "ransomware", "wht is ransomware", "ransomware attack",
                "explain ransomware", "define ransomware", "ransomware na enna", "ரேன்சம்வேர் என்றால் என்ன")) {
            if ("ta".equalsIgnoreCase(lang)) {
                return "ரேன்சம்வேர் (Ransomware) என்பது ஒரு ஆபத்தான மால்வேர் ஆகும். இது பாதிக்கப்பட்டவரின் கோப்புகள் அல்லது முழு கணினியையும் மறைகுறியாக்கம் (Encrypt) செய்து முடக்கிவிட்டு, அவற்றை மீண்டும் திறக்க பிணைப்பணம் (Ransom) கோரும்.\n\n" +
                       "இது எவ்வாறு பரவுகிறது:\n" +
                       "• ஆபத்தான மின்னஞ்சல் இணைப்புகள் மற்றும் போலி இணைப்புகள்\n" +
                       "• பாதுகாப்பு புதுப்பிப்பு இல்லாத பழைய மென்பொருட்கள்\n\n" +
                       "முக்கிய தற்காப்பு நடவடிக்கைகள்:\n" +
                       "• **3-2-1 காப்புப் பிரதி (Backup):** உங்கள் முக்கியமான கோப்புகளை எப்போதும் பாதுகாப்பான வெளிப்புற ஹார்ட் டிஸ்க் அல்லது கிளவுடில் Backup எடுத்து வையுங்கள்\n" +
                       "• தெரியாத நபர்கள் அனுப்பும் கோப்புகளைத் திறக்காதீர்கள்.";
            }
            return "Ransomware is a malicious program that encrypts a victim's files or locks their entire system, making it inaccessible until a ransom (typically in cryptocurrency) is paid to the attacker.\n\n" +
                   "How it spreads:\n" +
                   "• Malicious email attachments and phishing links\n" +
                   "• Unpatched vulnerabilities in software or operating systems\n" +
                   "• Compromised Remote Desktop Protocol (RDP) connections\n\n" +
                   "Best defenses against ransomware:\n" +
                   "• Follow the **3-2-1 backup strategy** (3 copies, 2 different media, 1 offsite/cloud)\n" +
                   "• Apply software and security patches regularly\n" +
                   "• Never enable macros on unsolicited documents.";
        }

        // 6. VPN
        if (matchesAny(norm,
                "what is a vpn", "what is vpn", "wht is vpn", "vpn", "vpn na enna", "virtual private network",
                "explain vpn", "define vpn", "how does vpn work", "விபிஎன் என்றால் என்ன")) {
            if ("ta".equalsIgnoreCase(lang)) {
                return "VPN (Virtual Private Network) என்பது உங்கள் சாதனத்திற்கும் இணையத்திற்கும் இடையே பாதுகாப்பான, மறைகுறியாக்கப்பட்ட (Encrypted) தொடர்பை ஏற்படுத்தும் தொழில்நுட்பமாகும்.\n\n" +
                       "முக்கிய நன்மைகள்:\n" +
                       "• **இணைய தரவு பாதுகாப்பு:** பொது வைஃபை (Public Wi-Fi) பயன்படுத்தும்போது உங்கள் தரவுகளை யாரும் ஒட்டுக் கேட்க முடியாது\n" +
                       "• **IP முகவரி மறைப்பு:** உங்கள் உண்மையான IP முகவரியை மறைத்து இணைய தனியுரிமையைப் பாதுகாக்கிறது\n\n" +
                       "குறிப்பு: VPN இணையப் போக்குவரத்தைப் பாதுகாக்கும், ஆனால் நீங்கள் சுயமாகத் திறக்கும் போலி இணையதளங்கள் அல்லது பதிவிறக்கும் வைரஸ்களிலிருந்து பாதுகாக்காது.";
            }
            if ("tanglish".equalsIgnoreCase(lang)) {
                return "VPN (Virtual Private Network) na unga device-kum internet-kum naduvula oru encrypted secure tunnel create panra tool.\n\n" +
                       "Main benefits:\n" +
                       "• **Data Encryption:** Public Wi-Fi-la use pannumbodhu hackers unga traffic-ah track panna mudiyadhu\n" +
                       "• **IP Masking:** Unga real IP address-ah hide panni privacy tharum\n\n" +
                       "Note: VPN data transit-ah mattum dhaan protect pannum, neengale phishing site open panni password potta VPN thadukka mudiyadhu.";
            }
            return "A VPN (Virtual Private Network) is a technology that creates a secure, encrypted connection (tunnel) between your device and the internet over an otherwise insecure network.\n\n" +
                   "Key benefits:\n" +
                   "• **Traffic Encryption:** Prevents eavesdropping on public Wi-Fi networks\n" +
                   "• **IP Masking:** Hides your real IP address and replaces it with the VPN server's IP\n" +
                   "• **Privacy:** Helps protect your browsing activity from local network snoopers and ISP monitoring\n\n" +
                   "Note: A VPN does NOT protect against phishing websites, malware downloads, or passwords you willingly submit.";
        }

        // 7. Firewall
        if (matchesAny(norm,
                "what is a firewall", "what is firewall", "wht is firewall", "firewall", "firewall na enna",
                "explain firewall", "define firewall", "ஃபயர்வால் என்றால் என்ன")) {
            if ("ta".equalsIgnoreCase(lang)) {
                return "ஃபயர்வால் (Firewall) என்பது கணினி நெட்வொர்க்கில் உள்வரும் மற்றும் வெளிச்செல்லும் இணைய போக்குவரத்தைக் கண்காணித்து, பாதுகாப்பு விதிகளின்படி ஆபத்தான இணைப்புகளைத் தடுக்கும் பாதுகாப்பு அமைப்பாகும்.\n\n" +
                       "இது எவ்வாறு பாதுகாக்கிறது:\n" +
                       "• அங்கீகரிக்கப்படாத வெளிப்புற இணைப்புகள் மற்றும் ஹேக்கர் தாக்குதல்களைத் தடுக்கிறது\n" +
                       "• சாதனத்தில் உள்ள மால்வேர் வெளியே தகவல்களை அனுப்புவதைத் தடுக்கிறது.";
            }
            return "A firewall is a network security system that monitors, filters, and controls incoming and outgoing network traffic based on predetermined security rules.\n\n" +
                   "How it protects:\n" +
                   "• **Barrier Defense:** Establishes a barrier between trusted internal networks and untrusted external networks (like the public Internet)\n" +
                   "• **Port & Packet Filtering:** Blocks unauthorized ports, malicious packets, and rogue scanning attempts\n" +
                   "• **Outbound Control:** Prevents malware installed on a device from connecting back to attacker command-and-control (C2) servers.";
        }

        // 8. IP Address
        if (matchesAny(norm,
                "what is an ip address", "what is ip address", "wht is ip address", "what is ip", "ip address", "ip",
                "ip na enna", "ip address na enna", "ஐபி முகவரி என்றால் என்ன")) {
            if ("ta".equalsIgnoreCase(lang)) {
                return "IP முகவரி (Internet Protocol Address) என்பது இணையத்தில் இணைக்கப்பட்டுள்ள ஒவ்வொரு சாதனத்திற்கும் (கம்ப்யூட்டர், மொபைல்) ஒதுக்கப்படும் தனித்துவமான எண் முகவரியாகும்.\n\n" +
                       "வகைகள்:\n" +
                       "• **IPv4:** 4 எண்களால் ஆனது (எ.கா: `192.168.1.1`)\n" +
                       "• **IPv6:** 128-பிட் மேம்பட்ட வடிவம்\n" +
                       "• **பொது ஐபி (Public IP):** இணையத்தில் சாதனத்தை அடையாளம் காட்டுகிறது\n" +
                       "• **தனிப்பட்ட ஐபி (Private IP):** உங்கள் வீட்டு வைஃபை நெட்வொர்க்கிற்குள் மட்டுமே பயன்படுத்தப்படுகிறது.";
            }
            return "An IP (Internet Protocol) address is a unique numerical identifier assigned to every device connected to a computer network that uses the Internet Protocol for communication.\n\n" +
                   "Main versions and types:\n" +
                   "• **IPv4:** 32-bit format written as four numbers (e.g., `192.168.1.1`)\n" +
                   "• **IPv6:** 128-bit format written in hexadecimal (e.g., `2001:0db8:85a3::8a2e:0370:7334`)\n" +
                   "• **Public IP:** Visible to external internet servers and websites\n" +
                   "• **Private IP:** Used exclusively within your home or local office network\n\n" +
                   "An IP address reveals general geographical region and Internet Service Provider (ISP), but does not directly disclose your personal identity or name.";
        }

        // 9. Suspicious URL / Link
        if (matchesAny(norm,
                "what is a suspicious url", "what is suspicious url", "wht is suspicious url", "suspicious url",
                "suspicious link", "malicious url", "what is a phishing link", "phishing link", "சந்தேகத்திற்கிடமான இணைப்பு என்றால் என்ன")) {
            if ("ta".equalsIgnoreCase(lang)) {
                return "சந்தேகத்திற்கிடமான URL (Suspicious URL) என்பது பயனர்களை ஏமாற்றி போலி தளங்களுக்கு அழைத்துச் சென்று ரகசிய தகவல்களைத் திருட அல்லது வைரஸ்களைப் பதிவிறக்க உருவாக்கப்பட்ட இணைய முகவரியாகும்.\n\n" +
                       "அடையாளம் காணும் வழிகள்:\n" +
                       "• **எழுத்துப் பிழைகள் (Typosquatting):** பிரசித்தி பெற்ற நிறுவன பெயர்களில் சிறிய எழுத்து மாற்றங்கள் (எ.கா: `micros0ft.com`)\n" +
                       "• **குறுகிய இணைப்புகள் (Shortened URLs):** உண்மையான தளத்தை மறைக்கும் `bit.ly` போன்ற இணைப்புகள்\n" +
                       "• Login அல்லது Payment பக்கங்களில் HTTPS இல்லாமல் வெறும் HTTP மட்டும் இருத்தல்.";
            }
            return "A suspicious URL is a web address designed to mislead users into visiting malicious websites that host phishing forms, malware downloads, or fraudulent services.\n\n" +
                   "Common indicators of a suspicious URL:\n" +
                   "• **Typosquatting:** Slight misspellings of famous brands (e.g., `micros0ft.com`, `paypa1-update.net`)\n" +
                   "• **Misleading Subdomains:** Adding genuine names as prefixes on strange domains (e.g., `paypal.com.account-verify.info`)\n" +
                   "• **Unusual TLDs:** High-risk free or cheap top-level domains used in bulk spam campaigns\n" +
                   "• **Obfuscated IP / Shorteners:** Using raw IP addresses or link shorteners to conceal the actual destination\n" +
                   "• **HTTP instead of HTTPS:** Lack of SSL encryption on login or checkout pages.";
        }

        // 10. OTP Phishing
        if (matchesAny(norm,
                "what is otp phishing", "what is otp scam", "wht is otp phishing", "otp phishing",
                "otp scam", "otp fraud", "otp na enna", "ஓடிபி மோசடி என்றால் என்ன")) {
            if ("ta".equalsIgnoreCase(lang)) {
                return "OTP ஃபிஷிங் என்பது சைபர் குற்றவாளிகள் வங்கி அதிகாரிகள் போல் நடித்து, உங்கள் மொபைலுக்கு வரும் ஒருமுறை கடவுச்சொல்லை (OTP) ஏமாற்றிப் பெற்று, உங்கள் பணத்தைத் திருடும் அல்லது கணக்கைக் கைப்பற்றும் மோசடியாகும்.\n\n" +
                       "பொன் விதி: எந்தவொரு உண்மையான வங்கியோ அல்லது அதிகாரியோ ஒருபோதும் உங்களிடம் தொலைபேசி அழைப்பிலோ அல்லது குறுஞ்செய்தியிலோ OTP கேட்க மாட்டார்கள். யாருடனும் OTP-ஐப் பகிராதீர்கள்!";
            }
            if ("tanglish".equalsIgnoreCase(lang)) {
                return "OTP Scam na cybercriminals bank officials maadhiri pesi unga mobile-ku vara One-Time Password-ah kettuvangi fraudulent transaction panra scam.\n\n" +
                       "Golden Rule: Endha legitimate bank-um unga OTP-ah call-layo message-layo keka maattanga. Eppavume OTP yarukitayum share pannathinga!";
            }
            return "OTP (One-Time Password) phishing occurs when cybercriminals deceive individuals into disclosing single-use security codes sent to their phone or email, allowing attackers to authorize fraudulent transactions or take over accounts.\n\n" +
                   "Common OTP scam tactics:\n" +
                   "• **Impersonation Calls:** Callers pretending to be bank officials claiming an urgent KYC update or suspicious debit\n" +
                   "• **Screen Sharing Scams:** Tricking victims into installing AnyDesk or TeamViewer so attackers view incoming OTPs\n" +
                   "• **Phishing Login Pages:** Fake portals that capture your username, password, and subsequent OTP in real time\n\n" +
                   "Golden Rule: Legitimate banks, tech companies, and customer support representatives will **NEVER** ask for your OTP.";
        }

        // 11. Social Engineering
        if (matchesAny(norm,
                "what is social engineering", "social engineering", "wht is social engineering",
                "social engineering na enna", "சோஷியல் இன்ஜினியரிங் என்றால் என்ன")) {
            if ("ta".equalsIgnoreCase(lang)) {
                return "சோஷியல் இன்ஜினியரிங் (Social Engineering) என்பது மனிதர்களின் பயம், பேராசை, அவசரம் அல்லது நம்பிக்கையைப் பயன்படுத்தி, அவர்களை ஏமாற்றி ரகசியத் தகவல்களைப் பெறும் உளவியல் ரீதியான சைபர் தாக்குதல் முறையாகும்.\n\n" +
                       "தற்காப்பு: எந்தவொரு அவசரக் கோரிக்கையையும் சரிபார்க்காமல் தனிப்பட்ட தகவல்களையோ பணத்தையோ பகிராதீர்கள்.";
            }
            return "Social engineering is the psychological manipulation of people into performing actions, divulging confidential information, or compromising security protocols.\n\n" +
                   "Common social engineering techniques:\n" +
                   "• **Pretexting:** Creating an invented scenario to gain the victim's trust\n" +
                   "• **Baiting:** Offering something enticing (e.g., free software, infected USB drives) to trap victims\n" +
                   "• **Urgency & Intimidation:** Forcing hurried decisions by threatening legal action or account suspension\n" +
                   "• **Quid Pro Quo:** Promising a service or benefit in exchange for sensitive information\n\n" +
                   "Defensive mindset: Always verify identities through an independent, trusted communication channel before acting.";
        }

        // 12. Protect Account
        if (matchesAny(norm,
                "how can i protect my account", "how to protect account", "how to protect my account",
                "how to secure account", "protect account", "account protection", "account security",
                "account epdi protect panrathu", "கணக்கை எவ்வாறு பாதுகாப்பது")) {
            if ("ta".equalsIgnoreCase(lang)) {
                return "உங்கள் இணைய மற்றும் வங்கி கணக்குகளைப் பாதுகாக்க முக்கிய வழிகள்:\n\n" +
                       "1. **வலுவான கடவுச்சொல்:** எழுத்துக்கள், எண்கள், குறியீடுகள் கலந்து 16+ எழுத்துக்களில் கடவுச்சொல் அமைக்கவும். ஒரே கடவுச்சொல்லை பல கணக்குகளுக்குப் பயன்படுத்தாதீர்கள்.\n" +
                       "2. **இருபடி சரிபார்ப்பு (2FA/MFA):** Authenticator ஆப் வழியான 2-Step Verification-ஐ இயக்கவும்.\n" +
                       "3. **OTP இரகசியமாக வைக்கவும்:** OTP மற்றும் UPI PIN-ஐ யாருடனும் பகிராதீர்கள்.\n" +
                       "4. **சாதன அமர்வுகள் (Active Sessions):** அறியப்படாத சாதனங்கள் ஏதேனும் கணக்கில் இணைக்கப்பட்டுள்ளதா என அவ்வப்போது சரிபார்க்கவும்.";
            }
            if ("tanglish".equalsIgnoreCase(lang)) {
                return "Unga accounts-ah protect panna mukkiyamana tips:\n\n" +
                       "1. **Strong Password:** 16+ characters letters, numbers, symbols mix panni strong-ah vekkunga. Same password multiple accounts-ku use pannathinga.\n" +
                       "2. **Enable 2FA:** Google Authenticator maadhiri 2-Step Verification on pannunga.\n" +
                       "3. **Never Share OTP:** OTP and UPI PIN epavume yarukum solladheenga.\n" +
                       "4. **Review Logged in Devices:** Account settings-la ungalukku theriyadha devices iruka nu check panni remove pannunga.";
            }
            return "To protect your online and financial accounts from unauthorized access:\n\n" +
                   "1. **Use Long, Unique Passphrases:** Minimum 16 characters combining uppercase, lowercase, numbers, and symbols. Never reuse passwords across accounts.\n" +
                   "2. **Enable Multi-Factor Authentication (MFA):** Use Authenticator apps (Google Authenticator, Microsoft Authenticator) or security hardware keys.\n" +
                   "3. **Use a Reputable Password Manager:** Avoid writing passwords down or storing them in plain text.\n" +
                   "4. **Never Share OTPs or PINs:** Treat OTPs like cash — never read them over the phone or forward them.\n" +
                   "5. **Review Connected Devices & Active Sessions:** Check your account settings periodically and log out of unfamiliar devices.\n" +
                   "6. **Keep Recovery Information Updated:** Ensure backup email and phone numbers are current.";
        }

        return null;
    }

    private static boolean matchesAny(String text, String... patterns) {
        for (String p : patterns) {
            if (text.equals(p) || text.startsWith(p + " ") || text.endsWith(" " + p) || text.contains(" " + p + " ")) {
                return true;
            }
            if (Pattern.compile("\\b" + Pattern.quote(p) + "\\b").matcher(text).find()) {
                return true;
            }
        }
        return false;
    }

    private static String generateScannerContextFallback(Map<String, Object> ctx, String lang) {
        if (ctx == null || ctx.isEmpty()) return null;

        String type = String.valueOf(ctx.getOrDefault("type", "Threat Indicator"));
        String input = String.valueOf(ctx.getOrDefault("input", "Indicator"));
        String classification = String.valueOf(ctx.getOrDefault("classification", "Evaluated"));
        String confidence = String.valueOf(ctx.getOrDefault("confidence", "N/A"));
        String severity = String.valueOf(ctx.getOrDefault("severity", "MEDIUM"));
        String summary = String.valueOf(ctx.getOrDefault("summary", "Review security recommendation."));

        if ("ta".equalsIgnoreCase(lang)) {
            StringBuilder sb = new StringBuilder();
            sb.append("🔍 **ஸ்கேன் முடிவின் விரிவான விளக்கம்:**\n\n");
            sb.append("• **அச்சுறுத்தல் வகை:** ").append(type).append("\n");
            sb.append("• **இலக்கு:** `").append(input).append("`\n");
            sb.append("• **கண்டறிதல் முடிவு:** **").append(classification).append("**\n");
            sb.append("• **நம்பகத்தன்மை:** ").append(confidence).append("\n");
            sb.append("• **தீவிர நிலை:** ").append(severity).append("\n\n");

            Object evidRaw = ctx.get("evidence");
            if (evidRaw instanceof List<?> evidList && !evidList.isEmpty()) {
                sb.append("**ஆதாரங்கள் & குறிகாட்டிகள்:**\n");
                for (Object e : evidList) {
                    sb.append("• ").append(String.valueOf(e)).append("\n");
                }
                sb.append("\n");
            }

            sb.append("**பரிந்துரைக்கப்பட்ட நடவடிக்கை:**\n").append(summary);
            return sb.toString();
        }

        StringBuilder sb = new StringBuilder();
        sb.append("🔍 **VigiLock Scan Result Breakdown:**\n\n");
        sb.append("• **Threat Type:** ").append(type).append("\n");
        sb.append("• **Target Indicator:** `").append(input).append("`\n");
        sb.append("• **Classification:** **").append(classification).append("**\n");
        sb.append("• **Confidence:** ").append(confidence).append("\n");
        sb.append("• **Severity:** ").append(severity).append("\n\n");

        Object evidRaw = ctx.get("evidence");
        if (evidRaw instanceof List<?> evidList && !evidList.isEmpty()) {
            sb.append("**Evidence & Indicators:**\n");
            for (Object e : evidList) {
                sb.append("• ").append(String.valueOf(e)).append("\n");
            }
            sb.append("\n");
        }

        sb.append("**Recommended Action:**\n").append(summary);
        return sb.toString();
    }

    private static String generateIncidentFallback(String lower, String lang) {
        boolean isTa = "ta".equalsIgnoreCase(lang);

        if (lower.contains("link") || lower.contains("url") || lower.contains("site")) {
            if (isTa) {
                return "🛡️ **சந்தேகத்திற்கிடமான இணைப்பைக் கிளிக் செய்ததற்கான உடனடி வழிகாட்டுதல்:**\n\n" +
                       "1. **உலாவியின் பக்கத்தை உடனே மூடவும்** — அந்த தளத்திலிருந்து உடனடியாக வெளியேறவும்.\n" +
                       "2. **எந்த தகவலையும் உள்ளிட வேண்டாம்** — கடவுச்சொல், OTP அல்லது தனிப்பட்ட விவரங்களை உள்ளிடாதீர்கள்.\n" +
                       "3. **பதிவிறக்கம் செய்யப்பட்ட கோப்புகளை நீக்கவும்** — ஏதேனும் கோப்பு தானாக பதிவிறக்கப்பட்டால் திறக்காமல் நீக்கவும்.\n" +
                       "4. **முழுமையான Antivirus ஸ்கேன் இயக்கவும்** — சாதனத்தில் பாதுகாப்பு ஸ்கேன் இயக்கவும்.";
            }
            return "🛡️ **Immediate Incident Guidance: Suspicious Link Clicked**\n\n" +
                   "Follow these immediate containment steps:\n\n" +
                   "1. **Close the website/tab immediately** — Disconnect from the destination page.\n" +
                   "2. **Do not enter any information** — Never submit passwords, PINs, OTPs, or personal data on the opened page.\n" +
                   "3. **Delete any downloaded files** — If a file downloaded automatically, do NOT open or run it. Delete it from Downloads.\n" +
                   "4. **Clear browser cache & cookies** — Clear cookies and cached site data in your browser settings.\n" +
                   "5. **Run a full security scan** — Run a trusted antivirus or antimalware scan on your device.\n" +
                   "6. **Monitor your accounts** — Keep an eye on your banking and primary email for unauthorized login notifications.";
        }

        if (lower.contains("password")) {
            if (isTa) {
                return "🚨 **அவசர வழிகாட்டுதல்: கடவுச்சொல் வெளிப்பட்டது**\n\n" +
                       "1. **கடவுச்சொல்லை உடனே மாற்றவும்** — அதிகாரப்பூர்வ தளத்திற்குச் சென்று புதிய வலுவான கடவுச்சொல்லை அமைக்கவும்.\n" +
                       "2. **அனைத்து சாதனங்களிலிருந்தும் Sign out செய்யவும்** — கணக்கு அமைப்புகளில் சென்று மற்ற அமர்வுகளை ரத்து செய்யவும்.\n" +
                       "3. **2-Step Verification ஆன் செய்யவும்** — Authenticator ஆப் வழியான பாதுகாப்பை செயல்படுத்தவும்.";
            }
            return "🚨 **Urgent Action Required: Compromised Password**\n\n" +
                   "Take these immediate containment actions:\n\n" +
                   "1. **Change your password immediately** — Go directly to the official service website and reset your password.\n" +
                   "2. **Update any reused passwords** — If you reused this password across other accounts, change those immediately.\n" +
                   "3. **Terminate all active sessions** — Use the 'Sign out of all devices' or 'Revoke sessions' security feature in account settings.\n" +
                   "4. **Enable Two-Factor Authentication (2FA)** — Activate an authenticator app (Google Authenticator, Authy).\n" +
                   "5. **Review recovery methods** — Confirm that recovery email addresses and phone numbers have not been altered.";
        }

        if (lower.contains("otp")) {
            if (isTa) {
                return "🚨 **அதிதீவிர எச்சரிக்கை: OTP பகிரப்பட்டது**\n\n" +
                       "1. **வங்கி உதவி மையத்தை உடனே அழைக்கவும்** — கார்டின் பின்புறம் உள்ள அதிகாரப்பூர்வ எண்ணை அழைக்கவும்.\n" +
                       "2. **கார்டை தற்காலிகமாக முடக்கவும்** — மொபைல் பேங்கிங் ஆப்பில் Card & UPI பரிவர்த்தனைகளை Block செய்யவும்.\n" +
                       "3. **1930 எண்ணில் புகார் அளிக்கவும்** — இந்தியாவில் நிதி சைபர் மோசடி உதவி எண்ணான **1930**-ஐ அழைக்கவும் அல்லது **cybercrime.gov.in** தளத்தில் புகார் அளிக்கவும்.";
            }
            return "🚨 **Critical Alert: OTP Compromised**\n\n" +
                   "Act immediately to protect your funds and accounts:\n\n" +
                   "1. **Contact your bank/service provider right now** — Call the official customer helpline on the back of your card.\n" +
                   "2. **Freeze card & net-banking transactions** — Use your mobile banking app to temporarily block debit/credit cards and UPI transfers.\n" +
                   "3. **Audit transaction history** — Check your account balance and mini-statement for unauthorized debit transactions.\n" +
                   "4. **File an immediate report** — In India, dial **1930** immediately for financial cyber fraud or report at **cybercrime.gov.in**.\n" +
                   "5. **Golden Rule**: Legitimate organizations and banks will NEVER ask you to read out or share an OTP.";
        }

        return null;
    }
}
