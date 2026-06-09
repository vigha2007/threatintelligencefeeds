import { createFileRoute } from "@tanstack/react-router";
import { motion } from "framer-motion";
import {
  Shield, MessageSquare, Phone, Link2, Globe, Mail,
  TrendingUp, TrendingDown, Activity, AlertTriangle, AlertOctagon, Info, CheckCircle2,
} from "lucide-react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar, Legend,
} from "recharts";
import { ParticlesBackground } from "@/components/particles-background";
import { FloatingChatButton } from "@/components/floating-chat-button";
import { SiteFooter } from "@/components/site-footer";
import { useCountUp } from "@/hooks/use-count-up";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Threat Intelligence Feeds — Scam Detector AI" },
      { name: "description", content: "Monitor scam activity, phishing threats, malicious indicators and AI-powered security insights in one place." },
      { property: "og:title", content: "Threat Intelligence Feeds — Scam Detector AI" },
      { property: "og:description", content: "Real-Time Scam Detection, Threat Monitoring & Security Analytics." },
    ],
  }),
  component: Dashboard,
});

const metrics = [
  { icon: Shield, emoji: "🛡️", label: "Total Threats Detected Today", value: 247, trend: 12.4, color: "#00D4FF" },
  { icon: MessageSquare, emoji: "💬", label: "Scam Messages Analyzed", value: 1894, trend: 8.1, color: "#7B61FF" },
  { icon: Phone, emoji: "📞", label: "Suspicious Calls Flagged", value: 83, trend: -3.2, color: "#FFB020" },
  { icon: Link2, emoji: "🔗", label: "Phishing URLs Blocked", value: 521, trend: 22.7, color: "#FF4D4D" },
  { icon: Globe, emoji: "🌐", label: "Malicious IPs Tracked", value: 142, trend: 4.5, color: "#00FFA3" },
  { icon: Mail, emoji: "📧", label: "Email Scams Detected", value: 376, trend: 15.3, color: "#00D4FF" },
];

const recentActivity = [
  { type: "Email Scam", desc: "Fake invoice from \"PayPal Billing\" — 18 recipients", sev: "Critical", time: "2 min ago", icon: Mail },
  { type: "Phishing URL", desc: "secure-bank-login[.]xyz blocked at gateway", sev: "High", time: "6 min ago", icon: Link2 },
  { type: "Scam Message", desc: "SMS impersonating delivery service", sev: "High", time: "11 min ago", icon: MessageSquare },
  { type: "Suspicious Call", desc: "Robocall pattern matched IRS scam profile", sev: "Medium", time: "23 min ago", icon: Phone },
  { type: "Email Scam", desc: "Gift card request from spoofed CEO domain", sev: "Critical", time: "34 min ago", icon: Mail },
  { type: "Phishing URL", desc: "office365-renewal[.]top quarantined", sev: "High", time: "48 min ago", icon: Link2 },
  { type: "Scam Message", desc: "Crypto giveaway impersonation flagged", sev: "Low", time: "1 hr ago", icon: MessageSquare },
];

const severity = [
  { name: "Critical", count: 38, color: "#FF4D4D", icon: AlertOctagon },
  { name: "High", count: 96, color: "#FFB020", icon: AlertTriangle },
  { name: "Medium", count: 184, color: "#7B61FF", icon: Info },
  { name: "Low", count: 312, color: "#00FFA3", icon: CheckCircle2 },
];

const trendData = Array.from({ length: 14 }, (_, i) => ({
  day: `D${i + 1}`,
  threats: Math.round(120 + Math.sin(i / 1.6) * 60 + Math.random() * 40),
  phishing: Math.round(80 + Math.cos(i / 2) * 40 + Math.random() * 30),
}));

const categoryData = [
  { name: "Phishing", value: 521, color: "#FF4D4D" },
  { name: "Email Scams", value: 376, color: "#00D4FF" },
  { name: "Scam Msgs", value: 1894, color: "#7B61FF" },
  { name: "Calls", value: 83, color: "#FFB020" },
  { name: "Malicious IPs", value: 142, color: "#00FFA3" },
];

const dailyData = Array.from({ length: 7 }, (_, i) => ({
  day: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][i],
  detections: Math.round(180 + Math.random() * 220),
}));

function MetricCard({ m, idx }: { m: typeof metrics[0]; idx: number }) {
  const Icon = m.icon;
  const v = useCountUp(m.value, 1500 + idx * 120);
  const up = m.trend >= 0;
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: idx * 0.08, duration: 0.5 }}
      whileHover={{ y: -4, scale: 1.01 }}
      className="glass relative overflow-hidden rounded-2xl p-6 transition-shadow hover:shadow-[0_20px_60px_rgba(0,212,255,0.18)]"
    >
      <div
        className="absolute -right-10 -top-10 h-40 w-40 rounded-full opacity-20 blur-3xl"
        style={{ background: m.color }}
      />
      <div className="relative flex items-start justify-between">
        <div
          className="flex h-12 w-12 items-center justify-center rounded-xl"
          style={{ background: `${m.color}22`, border: `1px solid ${m.color}55` }}
        >
          <Icon className="h-6 w-6" style={{ color: m.color }} />
        </div>
        <div className={`flex items-center gap-1 rounded-full px-2 py-1 text-xs font-semibold ${up ? "text-[#00FFA3]" : "text-[#FF4D4D]"}`}
          style={{ background: up ? "rgba(0,255,163,0.1)" : "rgba(255,77,77,0.1)" }}>
          {up ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
          {Math.abs(m.trend)}%
        </div>
      </div>
      <div className="relative mt-5">
        <div className="text-4xl font-bold tracking-tight tabular-nums text-white">
          {v.toLocaleString()}
        </div>
        <div className="mt-2 text-sm text-muted-foreground">
          <span className="mr-1">{m.emoji}</span>{m.label}
        </div>
      </div>
    </motion.div>
  );
}

function sevColor(s: string) {
  return s === "Critical" ? "#FF4D4D" : s === "High" ? "#FFB020" : s === "Medium" ? "#7B61FF" : "#00FFA3";
}

function Dashboard() {
  const totalSev = severity.reduce((a, b) => a + b.count, 0);

  return (
    <div className="relative min-h-screen overflow-hidden">
      {/* Hero */}
      <section className="relative">
        <div className="absolute inset-0 -z-10">
          <ParticlesBackground />
        </div>
        <div className="mx-auto max-w-7xl px-4 pb-12 pt-16 sm:px-6 sm:pt-24 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7 }}
            className="glass-strong relative overflow-hidden rounded-3xl p-8 sm:p-14"
          >
            <div className="absolute -left-20 -top-20 h-72 w-72 rounded-full bg-[#00D4FF] opacity-20 blur-3xl" />
            <div className="absolute -bottom-20 -right-20 h-72 w-72 rounded-full bg-[#7B61FF] opacity-20 blur-3xl" />
            <div className="relative">
              <div className="inline-flex items-center gap-2 rounded-full border border-[#00FFA3]/40 bg-[#00FFA3]/10 px-3 py-1 text-xs font-semibold text-[#00FFA3]">
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[#00FFA3] opacity-75" />
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-[#00FFA3]" />
                </span>
                LIVE · SOC Monitoring Active
              </div>
              <h1 className="mt-6 text-4xl font-bold tracking-tight text-white sm:text-6xl">
                <span aria-hidden>🛡️</span>{" "}
                <span className="bg-gradient-to-r from-[#00D4FF] via-[#7B61FF] to-[#00D4FF] bg-clip-text text-transparent">
                  Threat Intelligence Feeds
                </span>
              </h1>
              <p className="mt-4 text-lg font-medium text-white/90 sm:text-xl">
                Real-Time Scam Detection, Threat Monitoring &amp; Security Analytics
              </p>
              <p className="mt-3 max-w-3xl text-base text-muted-foreground">
                Monitor scam activity, phishing threats, malicious indicators and AI-powered security insights in one place.
              </p>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Metrics */}
      <section className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {metrics.map((m, i) => <MetricCard key={m.label} m={m} idx={i} />)}
        </div>
      </section>

      {/* Activity + Severity */}
      <section className="mx-auto mt-12 grid max-w-7xl grid-cols-1 gap-6 px-4 sm:px-6 lg:grid-cols-3 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
          className="glass rounded-2xl p-6 lg:col-span-2"
        >
          <div className="mb-5 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-[#00D4FF]" />
              <h2 className="text-lg font-semibold text-white">Recent Threat Activity</h2>
            </div>
            <span className="text-xs text-muted-foreground">Last 60 minutes</span>
          </div>
          <ul className="space-y-2">
            {recentActivity.map((a, i) => {
              const Icon = a.icon;
              const c = sevColor(a.sev);
              return (
                <motion.li
                  key={i}
                  initial={{ opacity: 0, x: -10 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }}
                  transition={{ delay: i * 0.05 }}
                  className="flex items-center gap-4 rounded-xl border border-white/5 bg-white/[0.02] p-3 transition-colors hover:bg-white/[0.05]"
                >
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg"
                    style={{ background: `${c}1f`, border: `1px solid ${c}55` }}>
                    <Icon className="h-4 w-4" style={{ color: c }} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-white">{a.type}</span>
                      <span className="rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider"
                        style={{ background: `${c}1f`, color: c }}>
                        {a.sev}
                      </span>
                    </div>
                    <p className="truncate text-sm text-muted-foreground">{a.desc}</p>
                  </div>
                  <span className="shrink-0 text-xs text-muted-foreground">{a.time}</span>
                </motion.li>
              );
            })}
          </ul>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
          className="glass rounded-2xl p-6"
        >
          <h2 className="mb-5 text-lg font-semibold text-white">Threat Severity Distribution</h2>
          <div className="space-y-4">
            {severity.map((s) => {
              const Icon = s.icon;
              const pct = Math.round((s.count / totalSev) * 100);
              return (
                <div key={s.name}>
                  <div className="mb-2 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Icon className="h-4 w-4" style={{ color: s.color }} />
                      <span className="text-sm font-medium text-white">{s.name}</span>
                    </div>
                    <span className="text-sm tabular-nums text-muted-foreground">
                      {s.count} <span className="text-xs">({pct}%)</span>
                    </span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-white/5">
                    <motion.div
                      initial={{ width: 0 }}
                      whileInView={{ width: `${pct}%` }}
                      viewport={{ once: true }}
                      transition={{ duration: 1, ease: "easeOut" }}
                      className="h-full rounded-full"
                      style={{ background: s.color, boxShadow: `0 0 12px ${s.color}99` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="mt-6 rounded-xl border border-[#00FFA3]/30 bg-[#00FFA3]/[0.06] p-4">
            <div className="flex items-center gap-2">
              <span className="relative flex h-2.5 w-2.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[#00FFA3] opacity-75" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-[#00FFA3]" />
              </span>
              <span className="text-sm font-semibold text-[#00FFA3]">🟢 Monitoring Active</span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">Real-Time Protection Enabled · 24/7 coverage</p>
          </div>
        </motion.div>
      </section>

      {/* Analytics */}
      <section className="mx-auto mt-12 max-w-7xl px-4 sm:px-6 lg:px-8">
        <h2 className="mb-5 text-lg font-semibold text-white">Analytics</h2>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <motion.div
            initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
            className="glass rounded-2xl p-6 lg:col-span-2"
          >
            <h3 className="mb-4 text-sm font-semibold text-white">Threat Trend (14 days)</h3>
            <div className="h-72">
              <ResponsiveContainer>
                <LineChart data={trendData}>
                  <defs>
                    <linearGradient id="g1" x1="0" x2="1" y1="0" y2="0">
                      <stop offset="0%" stopColor="#00D4FF" />
                      <stop offset="100%" stopColor="#7B61FF" />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="rgba(255,255,255,0.06)" />
                  <XAxis dataKey="day" stroke="#7a8aa6" fontSize={11} />
                  <YAxis stroke="#7a8aa6" fontSize={11} />
                  <Tooltip contentStyle={{ background: "#0A0F1F", border: "1px solid rgba(0,212,255,0.3)", borderRadius: 12 }} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Line type="monotone" dataKey="threats" stroke="url(#g1)" strokeWidth={3} dot={{ fill: "#00D4FF", r: 3 }} />
                  <Line type="monotone" dataKey="phishing" stroke="#FF4D4D" strokeWidth={2} dot={{ fill: "#FF4D4D", r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
            className="glass rounded-2xl p-6"
          >
            <h3 className="mb-4 text-sm font-semibold text-white">Threat Categories</h3>
            <div className="h-72">
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={categoryData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={95} paddingAngle={3}>
                    {categoryData.map((c) => <Cell key={c.name} fill={c.color} stroke="transparent" />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#0A0F1F", border: "1px solid rgba(0,212,255,0.3)", borderRadius: 12 }} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
            className="glass rounded-2xl p-6"
          >
            <h3 className="mb-4 text-sm font-semibold text-white">Daily Detections</h3>
            <div className="h-72">
              <ResponsiveContainer>
                <BarChart data={dailyData}>
                  <defs>
                    <linearGradient id="g2" x1="0" x2="0" y1="0" y2="1">
                      <stop offset="0%" stopColor="#00D4FF" />
                      <stop offset="100%" stopColor="#7B61FF" />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="rgba(255,255,255,0.06)" />
                  <XAxis dataKey="day" stroke="#7a8aa6" fontSize={11} />
                  <YAxis stroke="#7a8aa6" fontSize={11} />
                  <Tooltip cursor={{ fill: "rgba(0,212,255,0.06)" }} contentStyle={{ background: "#0A0F1F", border: "1px solid rgba(0,212,255,0.3)", borderRadius: 12 }} />
                  <Bar dataKey="detections" fill="url(#g2)" radius={[8, 8, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </motion.div>
        </div>
      </section>

      <SiteFooter />
      <FloatingChatButton />
    </div>
  );
}
