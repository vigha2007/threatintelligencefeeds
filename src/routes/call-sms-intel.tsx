import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { motion, AnimatePresence } from "framer-motion";
import {
  Phone, MessageSquare, Loader2, ShieldAlert, ShieldCheck, ShieldQuestion,
  Globe, Signal, Clock, Link2, AlertTriangle, Activity,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ParticlesBackground } from "@/components/particles-background";
import {
  analyzePhone, analyzeSms, statusToSeverity,
  type PhoneAnalysis, type SmsAnalysis, type RiskStatus,
} from "@/lib/intel-analyzers";
import { createEntity, listEntity } from "@/lib/entities.functions";

export const Route = createFileRoute("/call-sms-intel")({
  head: () => ({
    meta: [
      { title: "Call & SMS Intelligence — Scam Detector AI" },
      { name: "description", content: "Analyze phone numbers and SMS content for scams, phishing, OTP fraud, and malicious links in real time." },
    ],
  }),
  component: IntelPage,
});

const statusStyles: Record<RiskStatus, { color: string; bg: string; border: string; label: string; icon: typeof ShieldAlert }> = {
  scam: { color: "#FF4D4D", bg: "rgba(255,77,77,0.12)", border: "rgba(255,77,77,0.5)", label: "Scam", icon: ShieldAlert },
  suspicious: { color: "#FFB020", bg: "rgba(255,176,32,0.12)", border: "rgba(255,176,32,0.5)", label: "Suspicious", icon: ShieldQuestion },
  safe: { color: "#00FFA3", bg: "rgba(0,255,163,0.12)", border: "rgba(0,255,163,0.5)", label: "Safe", icon: ShieldCheck },
};

interface LogItem {
  id: string;
  ts: string;
  type: "Spam Call" | "Scam SMS";
  target: string;
  score: number;
  status: RiskStatus;
}

function IntelPage() {
  const qc = useQueryClient();
  const create = useServerFn(createEntity);
  const list = useServerFn(listEntity);

  const [phone, setPhone] = useState("");
  const [sms, setSms] = useState("");
  const [phoneResult, setPhoneResult] = useState<PhoneAnalysis | null>(null);
  const [smsResult, setSmsResult] = useState<SmsAnalysis | null>(null);
  const [localLog, setLocalLog] = useState<LogItem[]>([]);

  // Pull recent rows from DB so log reflects persisted intel
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
      await new Promise((r) => setTimeout(r, 700));
      const result = analyzePhone(value);
      try {
        await create({
          data: {
            entity: "spam_calls",
            values: {
              phone_number: result.normalized || value,
              country: result.country,
              severity: statusToSeverity(result.status, result.riskScore),
              pattern: `${result.numberType} · ${result.carrier} · risk ${result.riskScore}% · ${result.reasons[0] ?? ""}`.slice(0, 500),
            },
          },
        });
      } catch { /* persistence is best-effort */ }
      return result;
    },
    onSuccess: (r) => {
      setPhoneResult(r);
      setLocalLog((l) => [{ id: crypto.randomUUID(), ts: r.checkedAt, type: "Spam Call", target: r.phoneNumber, score: r.riskScore, status: r.status }, ...l].slice(0, 50));
      toast[r.status === "scam" ? "error" : r.status === "suspicious" ? "warning" : "success"](`${r.phoneNumber} — ${statusStyles[r.status].label} (${r.riskScore}%)`);
      qc.invalidateQueries({ queryKey: ["entity", "spam_calls"] });
      qc.invalidateQueries({ queryKey: ["dashboard-metrics"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const smsMutation = useMutation({
    mutationFn: async (text: string) => {
      await new Promise((r) => setTimeout(r, 700));
      const result = analyzeSms(text);
      try {
        await create({
          data: {
            entity: "scam_messages",
            values: {
              channel: "sms",
              sender: "Unknown",
              content: text.slice(0, 4000),
              severity: statusToSeverity(result.status, result.riskScore),
            },
          },
        });
      } catch { /* best-effort */ }
      return { result, text };
    },
    onSuccess: ({ result, text }) => {
      setSmsResult(result);
      setLocalLog((l) => [{ id: crypto.randomUUID(), ts: result.checkedAt, type: "Scam SMS", target: text.slice(0, 60) + (text.length > 60 ? "…" : ""), score: result.riskScore, status: result.status }, ...l].slice(0, 50));
      toast[result.status === "scam" ? "error" : result.status === "suspicious" ? "warning" : "success"](`SMS — ${result.category} (${result.riskScore}%)`);
      qc.invalidateQueries({ queryKey: ["entity", "scam_messages"] });
      qc.invalidateQueries({ queryKey: ["dashboard-metrics"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // Merge DB rows + local log into a unified table
  const dbLog: LogItem[] = [
    ...((recentCalls.data?.rows ?? []) as Array<Record<string, unknown>>).map((r) => ({
      id: `c-${String(r.id)}`,
      ts: String(r.reported_at ?? new Date().toISOString()),
      type: "Spam Call" as const,
      target: String(r.phone_number ?? ""),
      score: severityToScore(String(r.severity ?? "low")),
      status: severityToStatus(String(r.severity ?? "low")),
    })),
    ...((recentMessages.data?.rows ?? []) as Array<Record<string, unknown>>).map((r) => ({
      id: `m-${String(r.id)}`,
      ts: String(r.detected_at ?? new Date().toISOString()),
      type: "Scam SMS" as const,
      target: String(r.content ?? "").slice(0, 60),
      score: severityToScore(String(r.severity ?? "low")),
      status: severityToStatus(String(r.severity ?? "low")),
    })),
  ];
  const log = [...localLog, ...dbLog]
    .filter((v, i, a) => a.findIndex((x) => x.id === v.id) === i)
    .sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime())
    .slice(0, 25);

  return (
    <div className="relative min-h-screen overflow-hidden">
      <div className="absolute inset-0 -z-10"><ParticlesBackground /></div>

      <section className="mx-auto max-w-7xl px-4 pt-10 sm:px-6 lg:px-8">
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="glass-strong relative overflow-hidden rounded-2xl p-6 sm:p-8">
          <div className="absolute -right-16 -top-16 h-56 w-56 rounded-full bg-[#7B61FF] opacity-20 blur-3xl" />
          <div className="absolute -bottom-16 -left-16 h-56 w-56 rounded-full bg-[#00D4FF] opacity-20 blur-3xl" />
          <div className="relative">
            <div className="inline-flex items-center gap-2 rounded-full border border-[#00D4FF]/40 bg-[#00D4FF]/10 px-3 py-1 text-xs font-semibold text-[#00D4FF]">
              <Activity className="h-3 w-3" /> Call & SMS Intelligence Module
            </div>
            <h1 className="mt-4 text-3xl font-bold text-white sm:text-4xl">
              <span aria-hidden>📡</span>{" "}
              <span className="bg-gradient-to-r from-[#00D4FF] via-[#7B61FF] to-[#00FFA3] bg-clip-text text-transparent">Spam Call & SMS Threat Analysis</span>
            </h1>
            <p className="mt-2 text-sm text-muted-foreground">
              Analyze suspicious phone numbers and SMS content. Results are stored and reflected in your live dashboard metrics.
            </p>
          </div>
        </motion.div>
      </section>

      <section className="mx-auto mt-8 grid max-w-7xl grid-cols-1 gap-6 px-4 sm:px-6 lg:grid-cols-2 lg:px-8">
        {/* PHONE ANALYZER */}
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="glass rounded-2xl p-6">
          <div className="mb-4 flex items-center gap-2">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#00D4FF]/15 ring-1 ring-[#00D4FF]/40">
              <Phone className="h-5 w-5 text-[#00D4FF]" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-white">Spam Call Detection</h2>
              <p className="text-xs text-muted-foreground">Enter any phone number to validate and risk-score it.</p>
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
              placeholder="+1 415 555 0199"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              maxLength={32}
              className="bg-white/5"
            />
            <Button type="submit" disabled={phoneMutation.isPending} className="bg-[#00D4FF] text-[#0A0F1F] hover:bg-[#00D4FF]/90">
              {phoneMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Analyze Number"}
            </Button>
          </form>

          <AnimatePresence mode="wait">
            {phoneMutation.isPending && <ScanLoader key="pl" label="Querying threat intelligence feeds…" />}
            {phoneResult && !phoneMutation.isPending && (
              <motion.div key="pr" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-5 space-y-4">
                <StatusBanner score={phoneResult.riskScore} status={phoneResult.status} />
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <InfoCell icon={Phone} label="Phone Number" value={phoneResult.phoneNumber} />
                  <InfoCell icon={AlertTriangle} label="Spam Reports" value={phoneResult.reports.toLocaleString()} />
                  <InfoCell icon={Globe} label="Country" value={phoneResult.country} />
                  <InfoCell icon={Signal} label="Carrier" value={phoneResult.carrier} />
                  <InfoCell icon={Phone} label="Number Type" value={phoneResult.numberType} />
                  <InfoCell icon={Clock} label="Last Checked" value={new Date(phoneResult.checkedAt).toLocaleTimeString()} />
                </div>
                <ReasonList reasons={phoneResult.reasons} />
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {/* SMS ANALYZER */}
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0, transition: { delay: 0.05 } }} className="glass rounded-2xl p-6">
          <div className="mb-4 flex items-center gap-2">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#7B61FF]/15 ring-1 ring-[#7B61FF]/40">
              <MessageSquare className="h-5 w-5 text-[#7B61FF]" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-white">SMS Scam Detection</h2>
              <p className="text-xs text-muted-foreground">Paste SMS content to detect phishing, OTP scams, fraud & malicious links.</p>
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
              placeholder="Your account has been suspended. Click here to verify: http://bit.ly/xyz"
              value={sms}
              onChange={(e) => setSms(e.target.value)}
              maxLength={4000}
              rows={4}
              className="resize-none bg-white/5"
            />
            <Button type="submit" disabled={smsMutation.isPending} className="w-full bg-[#7B61FF] text-white hover:bg-[#7B61FF]/90">
              {smsMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Analyze SMS"}
            </Button>
          </form>

          <AnimatePresence mode="wait">
            {smsMutation.isPending && <ScanLoader key="sl" label="Scanning content & extracting indicators…" />}
            {smsResult && !smsMutation.isPending && (
              <motion.div key="sr" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-5 space-y-4">
                <StatusBanner score={smsResult.riskScore} status={smsResult.status} />
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <InfoCell icon={AlertTriangle} label="Threat Level" value={smsResult.threatLevel} />
                  <InfoCell icon={ShieldAlert} label="Category" value={smsResult.category} />
                </div>
                {smsResult.urls.length > 0 && (
                  <div>
                    <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Extracted URLs</div>
                    <div className="space-y-1">
                      {smsResult.urls.map((u, i) => (
                        <div key={i} className="flex items-center gap-2 rounded-md border border-[#FF4D4D]/30 bg-[#FF4D4D]/[0.06] px-3 py-1.5 text-xs text-[#FF8080]">
                          <Link2 className="h-3 w-3 shrink-0" />
                          <span className="truncate">{u}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                <ReasonList reasons={smsResult.reasons} />
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      </section>

      {/* LIVE THREAT LOG */}
      <section className="mx-auto mt-10 max-w-7xl px-4 pb-16 sm:px-6 lg:px-8">
        <motion.div initial={{ opacity: 0, y: 12 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="glass rounded-2xl p-6">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-[#00FFA3]" />
              <h2 className="text-lg font-semibold text-white">Threat Intelligence Log</h2>
            </div>
            <span className="text-xs text-muted-foreground">Live · Last {log.length} events</span>
          </div>
          {log.length === 0 ? (
            <div className="rounded-xl border border-white/5 bg-white/[0.02] p-8 text-center text-sm text-muted-foreground">
              No events yet. Run an analysis above to populate the log.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>Threat Type</TableHead>
                    <TableHead>Phone / SMS</TableHead>
                    <TableHead>Risk Score</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {log.map((row) => {
                    const s = statusStyles[row.status];
                    return (
                      <TableRow key={row.id}>
                        <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{new Date(row.ts).toLocaleString()}</TableCell>
                        <TableCell className="text-sm text-white/90">{row.type}</TableCell>
                        <TableCell className="max-w-[320px] truncate text-sm text-white/80">{row.target}</TableCell>
                        <TableCell>
                          <span className="font-mono text-sm font-semibold" style={{ color: s.color }}>{row.score}%</span>
                        </TableCell>
                        <TableCell>
                          <span className="rounded-full px-2 py-0.5 text-[10px] font-bold uppercase" style={{ background: s.bg, color: s.color, border: `1px solid ${s.border}` }}>
                            {s.label}
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

function StatusBanner({ score, status }: { score: number; status: RiskStatus }) {
  const s = statusStyles[status];
  const Icon = s.icon;
  return (
    <div className="relative overflow-hidden rounded-xl p-4" style={{ background: s.bg, border: `1px solid ${s.border}` }}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Icon className="h-6 w-6" style={{ color: s.color }} />
          <div>
            <div className="text-xs uppercase tracking-wider text-muted-foreground">Status</div>
            <div className="text-lg font-bold" style={{ color: s.color }}>{s.label}</div>
          </div>
        </div>
        <div className="text-right">
          <div className="text-xs uppercase tracking-wider text-muted-foreground">Risk Score</div>
          <div className="text-3xl font-bold tabular-nums" style={{ color: s.color }}>{score}%</div>
        </div>
      </div>
      <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/5">
        <motion.div initial={{ width: 0 }} animate={{ width: `${score}%` }} transition={{ duration: 0.8, ease: "easeOut" }} className="h-full rounded-full" style={{ background: s.color, boxShadow: `0 0 10px ${s.color}99` }} />
      </div>
    </div>
  );
}

function InfoCell({ icon: Icon, label, value }: { icon: typeof Phone; label: string; value: string }) {
  return (
    <div className="rounded-lg border border-white/5 bg-white/[0.02] p-3">
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
        <Icon className="h-3 w-3" /> {label}
      </div>
      <div className="mt-1 truncate text-sm font-medium text-white">{value}</div>
    </div>
  );
}

function ReasonList({ reasons }: { reasons: string[] }) {
  return (
    <div>
      <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Why this was flagged</div>
      <ul className="space-y-1">
        {reasons.map((r, i) => (
          <li key={i} className="flex items-start gap-2 text-xs text-white/80">
            <span className="mt-1 h-1 w-1 shrink-0 rounded-full bg-[#00D4FF]" /> {r}
          </li>
        ))}
      </ul>
    </div>
  );
}

function ScanLoader({ label }: { label: string }) {
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="mt-5 rounded-xl border border-[#00D4FF]/30 bg-[#00D4FF]/[0.05] p-4">
      <div className="flex items-center gap-3 text-sm text-[#00D4FF]">
        <Loader2 className="h-4 w-4 animate-spin" /> {label}
      </div>
      <div className="mt-3 h-1 overflow-hidden rounded-full bg-white/5">
        <motion.div animate={{ x: ["-100%", "100%"] }} transition={{ duration: 1.2, repeat: Infinity, ease: "easeInOut" }} className="h-full w-1/3 rounded-full bg-gradient-to-r from-transparent via-[#00D4FF] to-transparent" />
      </div>
    </motion.div>
  );
}

function severityToScore(sev: string): number {
  return sev === "critical" ? 92 : sev === "high" ? 78 : sev === "medium" ? 55 : 18;
}
function severityToStatus(sev: string): RiskStatus {
  return sev === "critical" || sev === "high" ? "scam" : sev === "medium" ? "suspicious" : "safe";
}
