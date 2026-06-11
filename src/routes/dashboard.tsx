import { createFileRoute, Link } from "@tanstack/react-router";
import { useSuspenseQuery, queryOptions } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
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
import { getDashboardMetrics } from "@/lib/dashboard.functions";

const metricsQuery = () =>
  queryOptions({
    queryKey: ["dashboard-metrics"],
    queryFn: () => getDashboardMetrics(),
    staleTime: 30_000,
  });

export const Route = createFileRoute("/dashboard")({
  head: () => ({
    meta: [
      { title: "Threat Intelligence Feeds — Scam Detector AI" },
      { name: "description", content: "Real-time scam detection, threat monitoring and security analytics computed from your stored intelligence." },
    ],
  }),
  loader: ({ context }) => context.queryClient.ensureQueryData(metricsQuery()),
  component: Dashboard,
  errorComponent: ({ error }) => (
    <div className="p-12 text-center text-muted-foreground">Failed to load metrics: {error.message}</div>
  ),
});

const metricConfig = [
  { key: "threats", icon: Shield, emoji: "🛡️", label: "Total Threats Detected", color: "#00D4FF" },
  { key: "scam_messages", icon: MessageSquare, emoji: "💬", label: "Scam Messages Analyzed", color: "#7B61FF" },
  { key: "spam_calls", icon: Phone, emoji: "📞", label: "Suspicious Calls Flagged", color: "#FFB020" },
  { key: "phishing_urls", icon: Link2, emoji: "🔗", label: "Phishing URLs Blocked", color: "#FF4D4D" },
  { key: "malicious_ips", icon: Globe, emoji: "🌐", label: "Malicious IPs Tracked", color: "#00FFA3" },
  { key: "email_scams", icon: Mail, emoji: "📧", label: "Email Scams Detected", color: "#00D4FF" },
] as const;

const severityMeta = [
  { name: "critical", label: "Critical", color: "#FF4D4D", icon: AlertOctagon },
  { name: "high", label: "High", color: "#FFB020", icon: AlertTriangle },
  { name: "medium", label: "Medium", color: "#7B61FF", icon: Info },
  { name: "low", label: "Low", color: "#00FFA3", icon: CheckCircle2 },
] as const;

function MetricCard({ value, label, emoji, icon: Icon, color, trend, idx }: {
  value: number; label: string; emoji: string; icon: typeof Shield; color: string; trend: number; idx: number;
}) {
  const v = useCountUp(value, 1200 + idx * 100);
  const up = trend >= 0;
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
      transition={{ delay: idx * 0.08, duration: 0.5 }}
      whileHover={{ y: -4, scale: 1.01 }}
      className="glass relative overflow-hidden rounded-2xl p-6 transition-shadow hover:shadow-[0_20px_60px_rgba(0,212,255,0.18)]"
    >
      <div className="absolute -right-10 -top-10 h-40 w-40 rounded-full opacity-20 blur-3xl" style={{ background: color }} />
      <div className="relative flex items-start justify-between">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl" style={{ background: `${color}22`, border: `1px solid ${color}55` }}>
          <Icon className="h-6 w-6" style={{ color }} />
        </div>
        <div className={`flex items-center gap-1 rounded-full px-2 py-1 text-xs font-semibold ${up ? "text-[#00FFA3]" : "text-[#FF4D4D]"}`}
          style={{ background: up ? "rgba(0,255,163,0.1)" : "rgba(255,77,77,0.1)" }}>
          {up ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
          {Math.abs(trend)}%
        </div>
      </div>
      <div className="relative mt-5">
        <div className="text-4xl font-bold tracking-tight tabular-nums text-white">{v.toLocaleString()}</div>
        <div className="mt-2 text-sm text-muted-foreground"><span className="mr-1">{emoji}</span>{label}</div>
      </div>
    </motion.div>
  );
}

function sevColor(s: string) {
  const k = s.toLowerCase();
  return k === "critical" ? "#FF4D4D" : k === "high" ? "#FFB020" : k === "medium" ? "#7B61FF" : "#00FFA3";
}

function Dashboard() {
  const fetcher = useServerFn(getDashboardMetrics);
  const { data } = useSuspenseQuery({ ...metricsQuery(), queryFn: () => fetcher() });

  const metricsByKey = Object.fromEntries(data.metrics.map((m) => [m.table, m]));
  const totalSev = severityMeta.reduce((a, b) => a + (data.severity[b.name] ?? 0), 0);

  return (
    <div className="relative min-h-screen overflow-hidden">
      <section className="relative">
        <div className="absolute inset-0 -z-10"><ParticlesBackground /></div>
        <div className="mx-auto max-w-7xl px-4 pb-12 pt-12 sm:px-6 sm:pt-16 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7 }}
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
                All metrics below are computed from your stored threat intelligence records.
              </p>
            </div>
          </motion.div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {metricConfig.map((m, i) => {
            const stat = metricsByKey[m.key];
            return (
              <MetricCard
                key={m.key}
                idx={i}
                value={stat?.total ?? 0}
                label={m.label}
                emoji={m.emoji}
                icon={m.icon}
                color={m.color}
                trend={stat?.trend ?? 0}
              />
            );
          })}
        </div>
      </section>

      <section className="mx-auto mt-12 grid max-w-7xl grid-cols-1 gap-6 px-4 sm:px-6 lg:grid-cols-3 lg:px-8">
        <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="glass rounded-2xl p-6 lg:col-span-2">
          <div className="mb-5 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-[#00D4FF]" />
              <h2 className="text-lg font-semibold text-white">Recent Threat Activity</h2>
            </div>
            <span className="text-xs text-muted-foreground">Last 60 minutes</span>
          </div>
          {data.recentActivity.length === 0 ? (
            <div className="rounded-xl border border-white/5 bg-white/[0.02] p-8 text-center text-sm text-muted-foreground">
              No activity in the last 60 minutes. Add records from the management pages or via the API.
            </div>
          ) : (
            <ul className="space-y-2">
              {data.recentActivity.map((a, i) => {
                const c = sevColor(a.sev);
                return (
                  <motion.li key={i}
                    initial={{ opacity: 0, x: -10 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.04 }}
                    className="flex items-center gap-4 rounded-xl border border-white/5 bg-white/[0.02] p-3 transition-colors hover:bg-white/[0.05]">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg" style={{ background: `${c}1f`, border: `1px solid ${c}55` }}>
                      <AlertTriangle className="h-4 w-4" style={{ color: c }} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-white">{a.type}</span>
                        <span className="rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider" style={{ background: `${c}1f`, color: c }}>{a.sev}</span>
                      </div>
                      <p className="truncate text-sm text-muted-foreground">{a.desc}</p>
                    </div>
                    <span className="shrink-0 text-xs text-muted-foreground">{a.time}</span>
                  </motion.li>
                );
              })}
            </ul>
          )}
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="glass rounded-2xl p-6">
          <h2 className="mb-5 text-lg font-semibold text-white">Threat Severity Distribution</h2>
          <div className="space-y-4">
            {severityMeta.map((s) => {
              const Icon = s.icon;
              const count = data.severity[s.name] ?? 0;
              const pct = totalSev ? Math.round((count / totalSev) * 100) : 0;
              return (
                <div key={s.name}>
                  <div className="mb-2 flex items-center justify-between">
                    <div className="flex items-center gap-2"><Icon className="h-4 w-4" style={{ color: s.color }} /><span className="text-sm font-medium text-white">{s.label}</span></div>
                    <span className="text-sm tabular-nums text-muted-foreground">{count} <span className="text-xs">({pct}%)</span></span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-white/5">
                    <motion.div initial={{ width: 0 }} whileInView={{ width: `${pct}%` }} viewport={{ once: true }} transition={{ duration: 1, ease: "easeOut" }}
                      className="h-full rounded-full" style={{ background: s.color, boxShadow: `0 0 12px ${s.color}99` }} />
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
            <p className="mt-1 text-xs text-muted-foreground">
              <Link to="/threats" className="underline hover:text-white">Manage threats</Link> · <Link to="/chatbot" className="underline hover:text-white">Open chatbot</Link>
            </p>
          </div>
        </motion.div>
      </section>

      <section className="mx-auto mt-12 max-w-7xl px-4 sm:px-6 lg:px-8">
        <h2 className="mb-5 text-lg font-semibold text-white">Analytics</h2>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="glass rounded-2xl p-6 lg:col-span-2">
            <h3 className="mb-4 text-sm font-semibold text-white">Threat Trend (14 days)</h3>
            <div className="h-72">
              <ResponsiveContainer>
                <LineChart data={data.trendData}>
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

          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="glass rounded-2xl p-6">
            <h3 className="mb-4 text-sm font-semibold text-white">Threat Categories</h3>
            <div className="h-72">
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={data.categoryData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={95} paddingAngle={3}>
                    {data.categoryData.map((c) => <Cell key={c.name} fill={c.color} stroke="transparent" />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#0A0F1F", border: "1px solid rgba(0,212,255,0.3)", borderRadius: 12 }} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="glass rounded-2xl p-6">
            <h3 className="mb-4 text-sm font-semibold text-white">Daily Detections (last 7 days)</h3>
            <div className="h-72">
              <ResponsiveContainer>
                <BarChart data={data.dailyData}>
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
