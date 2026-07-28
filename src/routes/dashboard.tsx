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
    staleTime: 5 * 60_000,   // 5 min — won't re-fetch on navigate back
    gcTime:    30 * 60_000,  // 30 min — keeps data in cache even when component unmounts
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
  { key: "threats",          icon: Shield,        emoji: "🛡️", label: "Total Threats Detected",  color: "#C48A5A" },
  { key: "scam_messages",    icon: MessageSquare,  emoji: "💬", label: "Scam Messages Analyzed",  color: "#4F7EF7" },
  { key: "suspicious_calls", icon: Phone,          emoji: "📞", label: "Suspicious Calls Flagged", color: "#E8A23C" },
  { key: "phishing_urls",    icon: Link2,          emoji: "🔗", label: "Phishing URLs Blocked",    color: "#E05A52" },
  { key: "malicious_ips",    icon: Globe,          emoji: "🌐", label: "Malicious IPs Tracked",    color: "#4F7EF7" },
  { key: "email_scams",      icon: Mail,           emoji: "📧", label: "Email Scams Detected",     color: "#C48A5A" },
] as const;

const severityMeta = [
  { name: "critical", label: "Critical", color: "#E05A52", icon: AlertOctagon },
  { name: "high", label: "High", color: "#E8A23C", icon: AlertTriangle },
  { name: "medium", label: "Medium", color: "#4F7EF7", icon: Info },
  { name: "low", label: "Low", color: "#34A853", icon: CheckCircle2 },
] as const;

function CyberSecurityIllustration() {
  return (
    <svg className="w-full h-full max-h-[340px] mx-auto select-none" viewBox="0 0 500 500" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <radialGradient id="cyberGlow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#C48A5A" stopOpacity="0.25" />
          <stop offset="100%" stopColor="#FAF8F5" stopOpacity="0" />
        </radialGradient>
        <linearGradient id="shieldGrad" x1="0" x2="1" y1="0" y2="1">
          <stop offset="0%" stopColor="#4F7EF7" />
          <stop offset="100%" stopColor="#C48A5A" />
        </linearGradient>
      </defs>
      <circle cx="250" cy="250" r="220" fill="url(#cyberGlow)" />
      
      {/* Abstract Grid Map */}
      <path d="M100 250 H400 M150 180 H350 M150 320 H350 M250 100 V400 M180 150 Q250 110 320 150 M180 350 Q250 390 320 350" stroke="#E4DEC6" strokeWidth="1.5" strokeDasharray="5 5" opacity="0.6" />
      
      {/* Network Links */}
      <circle cx="150" cy="180" r="6" fill="#4F7EF7" />
      <circle cx="350" cy="180" r="6" fill="#C48A5A" />
      <circle cx="380" cy="280" r="4" fill="#34A853" />
      <circle cx="120" cy="290" r="5" fill="#E8A23C" />
      <line x1="150" y1="180" x2="250" y2="130" stroke="#E4DEC6" strokeWidth="1" />
      <line x1="350" y1="180" x2="250" y2="130" stroke="#E4DEC6" strokeWidth="1" />
      <line x1="380" y1="280" x2="350" y2="180" stroke="#E4DEC6" strokeWidth="1" />
      <line x1="120" y1="290" x2="150" y2="180" stroke="#E4DEC6" strokeWidth="1" />

      {/* Cyber Security Analyst Silhouette */}
      <path d="M190 390 C190 320 215 290 250 290 C285 290 310 320 310 390" fill="#2E323A" />
      <path d="M220 290 Q250 260 280 290" fill="#C48A5A" />
      <path d="M220 290 L250 240 L280 290 L250 310 Z" fill="#2E323A" opacity="0.95" />
      
      {/* Digital Shield overlay */}
      <path d="M210 190 Q250 170 290 190 V235 C290 265 250 290 250 290 C250 290 210 265 210 235 V190 Z" fill="url(#shieldGrad)" opacity="0.85" />
      
      {/* Padlock */}
      <rect x="242" y="215" width="16" height="12" rx="2" fill="white" />
      <path d="M245 215 V210 C245 207 250 205 250 205 C250 205 255 207 255 210 V215" stroke="white" strokeWidth="2" fill="none" />
      
      {/* Binary Overlay */}
      <text x="80" y="150" fill="#C48A5A" fontSize="12" fontFamily="monospace" opacity="0.5">01101</text>
      <text x="360" y="140" fill="#4F7EF7" fontSize="12" fontFamily="monospace" opacity="0.5">10010</text>
      <text x="70" y="320" fill="#34A853" fontSize="12" fontFamily="monospace" opacity="0.5">SECURE</text>
      <text x="350" y="340" fill="#E8A23C" fontSize="12" fontFamily="monospace" opacity="0.5">AI_DET</text>
    </svg>
  );
}

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
      className="relative overflow-hidden rounded-3xl bg-white p-6 border border-[#E4DEC6]/60 shadow-sm transition-all hover:shadow-md"
    >
      <div className="absolute -right-10 -top-10 h-40 w-40 rounded-full opacity-10 blur-3xl" style={{ background: color }} />
      <div className="relative flex items-start justify-between">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl" style={{ background: `${color}15`, border: `1px solid ${color}35` }}>
          <Icon className="h-6 w-6" style={{ color }} />
        </div>
        <div className={`flex items-center gap-1 rounded-full px-2 py-1 text-xs font-semibold ${up ? "text-[#34A853]" : "text-[#E05A52]"}`}
          style={{ background: up ? "rgba(52,168,83,0.1)" : "rgba(224,90,82,0.1)" }}>
          {up ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
          {Math.abs(trend)}%
        </div>
      </div>
      <div className="relative mt-5">
        <div className="text-4xl font-extrabold tracking-tight tabular-nums text-gray-800 font-poppins">{v.toLocaleString()}</div>
        <div className="mt-2 text-xs font-bold text-gray-500 font-manrope"><span className="mr-1">{emoji}</span>{label}</div>
      </div>
    </motion.div>
  );
}

function sevColor(s: string) {
  const k = s.toLowerCase();
  return k === "critical" ? "#E05A52" : k === "high" ? "#E8A23C" : k === "medium" ? "#4F7EF7" : "#34A853";
}

function Dashboard() {
  const fetcher = useServerFn(getDashboardMetrics);
  const { data } = useSuspenseQuery({ ...metricsQuery(), queryFn: () => fetcher() });

  const metricsByKey: Record<string, { total: number; trend: number; today: number; yesterday: number }> =
    Object.fromEntries(data.metrics.map((m) => [m.table, m]));

  const totalSev = severityMeta.reduce((a, b) => a + (data.severity[b.name] ?? 0), 0);

  return (
    <div className="relative min-h-screen pb-12">
      <section className="relative">
        <div className="absolute inset-0 -z-10"><ParticlesBackground /></div>
        <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7 }}
            className="relative overflow-hidden rounded-3xl bg-white border border-[#E4DEC6]/80 p-8 sm:p-12 shadow-sm"
          >
            <div className="absolute -left-20 -top-20 h-72 w-72 rounded-full bg-[#C48A5A] opacity-5 blur-3xl" />
            <div className="absolute -bottom-20 -right-20 h-72 w-72 rounded-full bg-[#4F7EF7] opacity-5 blur-3xl" />
            
            <div className="grid grid-cols-1 gap-8 md:grid-cols-2 items-center">
              {/* Left side text */}
              <div className="space-y-4">
                <div className="inline-flex items-center gap-2 rounded-full border border-[#34A853]/40 bg-[#34A853]/10 px-3 py-1 text-[10px] font-bold text-[#34A853] uppercase tracking-wider font-poppins">
                  <span className="relative flex h-2 w-2">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[#34A853] opacity-75" />
                    <span className="relative inline-flex h-2 w-2 rounded-full bg-[#34A853]" />
                  </span>
                  LIVE · SOC Monitoring Active
                </div>
                <h1 className="text-3xl font-extrabold tracking-tight text-gray-800 sm:text-5xl font-poppins">
                  Cyber Threat <br />
                  <span className="bg-gradient-to-r from-[#C48A5A] to-[#4F7EF7] bg-clip-text text-transparent">
                    Intelligence Platform
                  </span>
                </h1>
                <p className="text-sm font-medium text-gray-600 sm:text-base font-manrope leading-relaxed">
                  Real-time intelligence aggregation and AI monitoring. Check caller reputational trust, analyze SMS messages, URLs, IP addresses, and emails.
                </p>
                <div className="flex flex-wrap gap-3 pt-2">
                  <Link
                    to="/threats"
                    className="rounded-xl bg-[#C48A5A] px-5 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-[#C48A5A]/90 transition-all hover:translate-y-[-1px]"
                  >
                    View Threat Feed
                  </Link>
                  <Link
                    to="/call-sms-intel"
                    className="rounded-xl border border-[#C48A5A] px-5 py-2.5 text-xs font-bold text-[#C48A5A] hover:bg-[#C48A5A]/5 transition-all hover:translate-y-[-1px]"
                  >
                    Run Security Scan
                  </Link>
                </div>
              </div>

              {/* Right side illustration */}
              <div className="hidden md:block">
                <CyberSecurityIllustration />
              </div>
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
        {/* Recent Threat Activity */}
        <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="rounded-3xl bg-white border border-[#E4DEC6]/60 p-6 lg:col-span-2 shadow-sm">
          <div className="mb-5 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-[#C48A5A]" />
              <h2 className="text-md font-bold text-gray-800 font-poppins">Recent Threat Activity</h2>
            </div>
            <span className="text-xs text-gray-400 font-medium font-manrope">Last 60 minutes</span>
          </div>
          {data.recentActivity.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-[#E4DEC6] bg-[#FAF8F5] p-8 text-center text-xs font-semibold text-gray-500 font-manrope">
              No activity in the last 60 minutes. Add records from management pages or via API.
            </div>
          ) : (
            <ul className="space-y-2.5">
              {data.recentActivity.map((a, i) => {
                const c = sevColor(a.sev);
                return (
                  <motion.li key={i}
                    initial={{ opacity: 0, x: -10 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.04 }}
                    className="flex items-center gap-4 rounded-2xl border border-[#E4DEC6]/40 bg-[#FAF8F5]/50 p-3.5 transition-all hover:bg-[#FAF8F5]">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl" style={{ background: `${c}15`, border: `1px solid ${c}35` }}>
                      <AlertTriangle className="h-4 w-4" style={{ color: c }} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-gray-800 font-poppins">{a.type}</span>
                        <span className="rounded-full px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider font-poppins" style={{ background: `${c}15`, color: c }}>{a.sev}</span>
                      </div>
                      <p className="truncate text-xs text-gray-500 font-manrope mt-0.5">{a.desc}</p>
                    </div>
                    <span className="shrink-0 text-[10px] font-semibold text-gray-400 font-manrope">{a.time}</span>
                  </motion.li>
                );
              })}
            </ul>
          )}
        </motion.div>

        {/* Severity distribution & Status */}
        <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="rounded-3xl bg-white border border-[#E4DEC6]/60 p-6 shadow-sm flex flex-col justify-between">
          <div>
            <h2 className="mb-5 text-md font-bold text-gray-800 font-poppins">Threat Severity Distribution</h2>
            <div className="space-y-4">
              {severityMeta.map((s) => {
                const Icon = s.icon;
                const count = data.severity[s.name] ?? 0;
                const pct = totalSev ? Math.round((count / totalSev) * 100) : 0;
                return (
                  <div key={s.name}>
                    <div className="mb-2 flex items-center justify-between">
                      <div className="flex items-center gap-2"><Icon className="h-4 w-4" style={{ color: s.color }} /><span className="text-xs font-bold text-gray-700 font-manrope">{s.label}</span></div>
                      <span className="text-xs font-bold tabular-nums text-gray-500 font-manrope">{count} <span className="text-gray-400">({pct}%)</span></span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-gray-100">
                      <motion.div initial={{ width: 0 }} whileInView={{ width: `${pct}%` }} viewport={{ once: true }} transition={{ duration: 1, ease: "easeOut" }}
                        className="h-full rounded-full" style={{ background: s.color }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
          
          <div className="mt-6 rounded-2xl border border-[#34A853]/20 bg-[#34A853]/[0.04] p-4">
            <div className="flex items-center gap-2">
              <span className="relative flex h-2.5 w-2.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[#34A853] opacity-75" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-[#34A853]" />
              </span>
              <span className="text-xs font-bold text-[#34A853] font-poppins">🟢 Active Guard Status</span>
            </div>
            <p className="mt-1.5 text-[11px] font-medium text-gray-500 font-manrope leading-relaxed">
              <Link to="/threats" className="underline hover:text-gray-800">Threat records</Link> · <Link to="/chatbot" className="underline hover:text-gray-800">Launch chatbot</Link>
            </p>
          </div>
        </motion.div>
      </section>

      {/* Analytics Section */}
      <section className="mx-auto mt-12 max-w-7xl px-4 sm:px-6 lg:px-8">
        <h2 className="mb-5 text-md font-bold text-gray-800 font-poppins">Analytics Overview</h2>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Threat Trend */}
          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="rounded-3xl bg-white border border-[#E4DEC6]/60 p-6 lg:col-span-2 shadow-sm">
            <h3 className="mb-4 text-xs font-bold text-gray-500 uppercase tracking-wider font-manrope">Threat Trend (14 days)</h3>
            <div className="h-72">
              <ResponsiveContainer>
                <LineChart data={data.trendData}>
                  <defs>
                    <linearGradient id="g1" x1="0" x2="1" y1="0" y2="0">
                      <stop offset="0%" stopColor="#C48A5A" />
                      <stop offset="100%" stopColor="#4F7EF7" />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#f2eee8" />
                  <XAxis dataKey="day" stroke="#9E9E9E" fontSize={11} fontFamily="monospace" />
                  <YAxis stroke="#9E9E9E" fontSize={11} fontFamily="monospace" />
                  <Tooltip contentStyle={{ background: "#FFFFFF", border: "1px solid #E4DEC6", borderRadius: 16, fontSize: 12, fontFamily: "sans-serif" }} />
                  <Legend wrapperStyle={{ fontSize: 12, fontFamily: "sans-serif" }} />
                  <Line type="monotone" dataKey="threats" name="Total Threats" stroke="url(#g1)" strokeWidth={3} dot={{ fill: "#C48A5A", r: 4 }} />
                  <Line type="monotone" dataKey="phishing" name="Phishing Alerts" stroke="#E05A52" strokeWidth={2} dot={{ fill: "#E05A52", r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </motion.div>

          {/* Threat Categories Pie */}
          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="rounded-3xl bg-white border border-[#E4DEC6]/60 p-6 shadow-sm">
            <h3 className="mb-4 text-xs font-bold text-gray-500 uppercase tracking-wider font-manrope">Threat Categories</h3>
            <div className="h-72">
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={data.categoryData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={95} paddingAngle={3}>
                    {data.categoryData.map((c, index) => {
                      const colors = ["#C48A5A", "#4F7EF7", "#E8A23C", "#E05A52", "#34A853", "#8E24AA"];
                      const color = colors[index % colors.length];
                      return <Cell key={c.name} fill={color} stroke="transparent" />;
                    })}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#FFFFFF", border: "1px solid #E4DEC6", borderRadius: 16, fontSize: 12 }} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </motion.div>

          {/* Daily Detections Bar */}
          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="rounded-3xl bg-white border border-[#E4DEC6]/60 p-6 shadow-sm">
            <h3 className="mb-4 text-xs font-bold text-gray-500 uppercase tracking-wider font-manrope">Daily Detections (last 7 days)</h3>
            <div className="h-72">
              <ResponsiveContainer>
                <BarChart data={data.dailyData}>
                  <defs>
                    <linearGradient id="g2" x1="0" x2="0" y1="0" y2="1">
                      <stop offset="0%" stopColor="#4F7EF7" />
                      <stop offset="100%" stopColor="#C48A5A" />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#f2eee8" />
                  <XAxis dataKey="day" stroke="#9E9E9E" fontSize={11} fontFamily="monospace" />
                  <YAxis stroke="#9E9E9E" fontSize={11} fontFamily="monospace" />
                  <Tooltip cursor={{ fill: "rgba(196,138,90,0.04)" }} contentStyle={{ background: "#FFFFFF", border: "1px solid #E4DEC6", borderRadius: 16, fontSize: 12 }} />
                  <Bar dataKey="detections" name="Detections" fill="url(#g2)" radius={[8, 8, 0, 0]} />
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
