// Shared metadata for each threat entity (used by CRUD server fns and UI).
import { z } from "zod";

export const severityEnum = z.enum(["critical", "high", "medium", "low"]);
export type Severity = z.infer<typeof severityEnum>;

export const threatTypeEnum = z.enum([
  "phishing_url",
  "spam_call",
  "email_scam",
  "malicious_ip",
  "scam_message",
  "other",
]);

export type EntityKey =
  | "threats"
  | "phishing_urls"
  | "spam_calls"
  | "email_scams"
  | "malicious_ips"
  | "scam_messages";

export interface FieldDef {
  name: string;
  label: string;
  type: "text" | "textarea" | "severity" | "enum" | "number";
  required?: boolean;
  options?: string[]; // for enum
}

export interface EntityDef {
  key: EntityKey;
  label: string;
  singular: string;
  dateColumn: string;
  fields: FieldDef[];
  schema: z.ZodObject<z.ZodRawShape>;
}

export const entities: Record<EntityKey, EntityDef> = {
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
      { name: "source", label: "Source", type: "text" },
    ],
    schema: z.object({
      title: z.string().min(1).max(255),
      type: threatTypeEnum,
      severity: severityEnum,
      description: z.string().max(2000).optional().nullable(),
      source: z.string().max(255).optional().nullable(),
    }),
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
      { name: "notes", label: "Notes", type: "textarea" },
    ],
    schema: z.object({
      url: z.string().min(1).max(2048),
      domain: z.string().max(255).optional().nullable(),
      severity: severityEnum,
      notes: z.string().max(1000).optional().nullable(),
    }),
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
      { name: "pattern", label: "Pattern / Notes", type: "textarea" },
    ],
    schema: z.object({
      phone_number: z.string().min(1).max(64),
      country: z.string().max(64).optional().nullable(),
      severity: severityEnum,
      pattern: z.string().max(500).optional().nullable(),
    }),
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
      { name: "recipients_count", label: "Recipients", type: "number" },
    ],
    schema: z.object({
      sender: z.string().min(1).max(255),
      subject: z.string().max(500).optional().nullable(),
      category: z.string().max(64).optional().nullable(),
      severity: severityEnum,
      recipients_count: z.number().int().min(1).max(1000000).optional(),
    }),
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
      { name: "severity", label: "Severity", type: "severity", required: true },
    ],
    schema: z.object({
      ip_address: z.string().min(1).max(64),
      country: z.string().max(64).optional().nullable(),
      threat_type: z.string().max(128).optional().nullable(),
      severity: severityEnum,
    }),
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
      { name: "severity", label: "Severity", type: "severity", required: true },
    ],
    schema: z.object({
      channel: z.enum(["sms", "whatsapp", "telegram", "other"]),
      sender: z.string().max(128).optional().nullable(),
      content: z.string().min(1).max(4000),
      severity: severityEnum,
    }),
  },
};

export const allEntityKeys: EntityKey[] = Object.keys(entities) as EntityKey[];
