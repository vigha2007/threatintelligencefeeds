import { e as enumType, o as objectType, s as stringType, n as numberType } from "../_libs/zod.mjs";
const severityEnum = enumType(["critical", "high", "medium", "low"]);
const threatTypeEnum = enumType([
  "phishing_url",
  "spam_call",
  "email_scam",
  "malicious_ip",
  "scam_message",
  "other"
]);
const entities = {
  threats: {
    key: "threats",
    label: "Threats",
    singular: "Threat",
    dateColumn: "detected_at",
    fields: [
      { name: "title", label: "Title", type: "text", required: true },
      { name: "type", label: "Type", type: "enum", required: true, options: threatTypeEnum.options },
      { name: "severity", label: "Severity", type: "severity", required: true },
      { name: "description", label: "Description", type: "textarea" },
      { name: "source", label: "Source", type: "text" }
    ],
    schema: objectType({
      title: stringType().min(1).max(255),
      type: threatTypeEnum,
      severity: severityEnum,
      description: stringType().max(2e3).optional().nullable(),
      source: stringType().max(255).optional().nullable()
    })
  },
  phishing_urls: {
    key: "phishing_urls",
    label: "Phishing URLs",
    singular: "Phishing URL",
    dateColumn: "blocked_at",
    fields: [
      { name: "url", label: "URL", type: "text", required: true },
      { name: "domain", label: "Domain", type: "text" },
      { name: "severity", label: "Severity", type: "severity", required: true },
      { name: "notes", label: "Notes", type: "textarea" }
    ],
    schema: objectType({
      url: stringType().min(1).max(2048),
      domain: stringType().max(255).optional().nullable(),
      severity: severityEnum,
      notes: stringType().max(1e3).optional().nullable()
    })
  },
  spam_calls: {
    key: "spam_calls",
    label: "Spam Calls",
    singular: "Spam Call",
    dateColumn: "reported_at",
    fields: [
      { name: "phone_number", label: "Phone Number", type: "text", required: true },
      { name: "country", label: "Country", type: "text" },
      { name: "severity", label: "Severity", type: "severity", required: true },
      { name: "pattern", label: "Pattern / Notes", type: "textarea" }
    ],
    schema: objectType({
      phone_number: stringType().min(1).max(64),
      country: stringType().max(64).optional().nullable(),
      severity: severityEnum,
      pattern: stringType().max(500).optional().nullable()
    })
  },
  email_scams: {
    key: "email_scams",
    label: "Email Scams",
    singular: "Email Scam",
    dateColumn: "detected_at",
    fields: [
      { name: "sender", label: "Sender", type: "text", required: true },
      { name: "subject", label: "Subject", type: "text" },
      { name: "category", label: "Category", type: "text" },
      { name: "severity", label: "Severity", type: "severity", required: true },
      { name: "recipients_count", label: "Recipients", type: "number" }
    ],
    schema: objectType({
      sender: stringType().min(1).max(255),
      subject: stringType().max(500).optional().nullable(),
      category: stringType().max(64).optional().nullable(),
      severity: severityEnum,
      recipients_count: numberType().int().min(1).max(1e6).optional()
    })
  },
  malicious_ips: {
    key: "malicious_ips",
    label: "Malicious IPs",
    singular: "Malicious IP",
    dateColumn: "last_seen",
    fields: [
      { name: "ip_address", label: "IP Address", type: "text", required: true },
      { name: "country", label: "Country", type: "text" },
      { name: "threat_type", label: "Threat Type", type: "text" },
      { name: "severity", label: "Severity", type: "severity", required: true }
    ],
    schema: objectType({
      ip_address: stringType().min(1).max(64),
      country: stringType().max(64).optional().nullable(),
      threat_type: stringType().max(128).optional().nullable(),
      severity: severityEnum
    })
  },
  scam_messages: {
    key: "scam_messages",
    label: "Scam Messages",
    singular: "Scam Message",
    dateColumn: "detected_at",
    fields: [
      { name: "channel", label: "Channel", type: "enum", options: ["sms", "whatsapp", "telegram", "other"], required: true },
      { name: "sender", label: "Sender", type: "text" },
      { name: "content", label: "Content", type: "textarea", required: true },
      { name: "severity", label: "Severity", type: "severity", required: true }
    ],
    schema: objectType({
      channel: enumType(["sms", "whatsapp", "telegram", "other"]),
      sender: stringType().max(128).optional().nullable(),
      content: stringType().min(1).max(4e3),
      severity: severityEnum
    })
  }
};
const allEntityKeys = Object.keys(entities);
export {
  allEntityKeys as a,
  entities as e,
  severityEnum as s
};
