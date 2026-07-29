type Row = Record<string, string>;

const JAVA_BASE = import.meta.env.VITE_JAVA_BASE_URL || "http://localhost:8081";

function dayKey(d: Date) {
  return d.toISOString().slice(0, 10);
}

function capitalize(s: string) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

function relTime(d: Date, now: Date) {
  const sec = Math.max(1, Math.round((now.getTime() - d.getTime()) / 1000));
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min} min ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr} hr ago`;
  return `${Math.round(hr / 24)}d ago`;
}

async function fetchRows(name: string, limit = 200): Promise<Row[]> {
  try {
    const res = await fetch(`${JAVA_BASE}/api/v1/entity/${name}?limit=${limit}&offset=0`);
    if (!res.ok) return [];
    const data = await res.json();
    return (data.rows ?? []) as Row[];
  } catch {
    return [];
  }
}

export interface DashboardMetricsResult {
  metrics: { table: string; today: number; yesterday: number; total: number; trend: number }[];
  severity: Record<string, number>;
  trendData: { day: string; date: string; threats: number; phishing: number }[];
  dailyData: { day: string; detections: number }[];
  categoryData: { name: string; value: number; color: string }[];
  recentActivity: { type: string; desc: string; sev: string; time: string }[];
}

// Default mock metrics for client SPA preview / static deployment
const MOCK_METRICS: DashboardMetricsResult = {
  metrics: [
    { table: "threats", today: 14, yesterday: 10, total: 1240, trend: 40 },
    { table: "scam_messages", today: 28, yesterday: 22, total: 3890, trend: 27.3 },
    { table: "suspicious_calls", today: 19, yesterday: 15, total: 2150, trend: 26.7 },
    { table: "phishing_urls", today: 35, yesterday: 30, total: 4910, trend: 16.7 },
    { table: "malicious_ips", today: 8, yesterday: 12, total: 840, trend: -33.3 },
    { table: "email_scams", today: 11, yesterday: 9, total: 1670, trend: 22.2 },
  ],
  severity: {
    critical: 342,
    high: 890,
    medium: 1540,
    low: 4120,
  },
  trendData: Array.from({ length: 14 }).map((_, i) => ({
    day: `D${i + 1}`,
    date: new Date(Date.now() - (13 - i) * 86400000).toISOString().slice(0, 10),
    threats: Math.floor(20 + Math.random() * 30),
    phishing: Math.floor(15 + Math.random() * 25),
  })),
  dailyData: [
    { day: "Sun", detections: 42 },
    { day: "Mon", detections: 78 },
    { day: "Tue", detections: 95 },
    { day: "Wed", detections: 110 },
    { day: "Thu", detections: 88 },
    { day: "Fri", detections: 124 },
    { day: "Sat", detections: 65 },
  ],
  categoryData: [
    { name: "Threats", value: 1240, color: "#C48A5A" },
    { name: "Scam Msgs", value: 3890, color: "#4F7EF7" },
    { name: "Calls", value: 2150, color: "#E8A23C" },
    { name: "Phishing", value: 4910, color: "#E05A52" },
    { name: "Malicious IPs", value: 840, color: "#34A853" },
    { name: "Email Scams", value: 1670, color: "#8E24AA" },
  ],
  recentActivity: [
    { type: "Phishing", desc: "paypal-security-update.xyz flagged as phishing credential harvester", sev: "Critical", time: "2 min ago" },
    { type: "Calls", desc: "+91 98765 43210 flagged for automated utility bill scam robocall", sev: "High", time: "8 min ago" },
    { type: "Scam Msgs", desc: "Urgent KYC update required at bit.ly/fake-bank-auth", sev: "Critical", time: "15 min ago" },
    { type: "Malicious IPs", desc: "185.220.101.5 added to botnet C2 blocklist", sev: "High", time: "22 min ago" },
    { type: "Email Scams", desc: "Inheritance lottery payout claim email detected from temp-domain.org", sev: "Medium", time: "35 min ago" },
    { type: "Threats", desc: "Suspicious API access spike from unknown ISP autonomous system", sev: "Low", time: "50 min ago" },
  ],
};

export async function getDashboardMetrics(): Promise<DashboardMetricsResult> {
  const now = new Date();
  const startOfToday = new Date(now);
  startOfToday.setUTCHours(0, 0, 0, 0);
  const startOfYesterday = new Date(startOfToday);
  startOfYesterday.setUTCDate(startOfYesterday.getUTCDate() - 1);
  const since14d = new Date(now);
  since14d.setUTCDate(since14d.getUTCDate() - 13);
  since14d.setUTCHours(0, 0, 0, 0);

  try {
    const res = await fetch(`${JAVA_BASE}/api/v1/dashboard/metrics`, {
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) return MOCK_METRICS;
    const d = await res.json();
    const javaCounts = {
      threats:          Number(d.total_threats_detected  ?? d.threats          ?? 0),
      phishing_urls:    Number(d.phishing_urls_blocked   ?? d.phishing_urls    ?? 0),
      suspicious_calls: Number(d.suspicious_calls_flagged ?? d.suspicious_calls ?? 0),
      email_scams:      Number(d.email_scams_detected    ?? d.email_scams      ?? 0),
      malicious_ips:    Number(d.malicious_ips_tracked   ?? d.malicious_ips    ?? 0),
      scam_messages:    Number(d.scam_messages_analyzed  ?? d.scam_messages    ?? 0),
      critical_count:   Number(d.critical_count ?? 0),
      high_count:       Number(d.high_count     ?? 0),
      medium_count:     Number(d.medium_count   ?? 0),
      low_count:        Number(d.low_count      ?? 0),
    };

    const tables = [
      { name: "threats",          label: "Threats",      color: "#C48A5A" },
      { name: "scam_messages",    label: "Scam Msgs",    color: "#4F7EF7" },
      { name: "suspicious_calls", label: "Calls",        color: "#E8A23C" },
      { name: "phishing_urls",    label: "Phishing",     color: "#E05A52" },
      { name: "malicious_ips",    label: "Malicious IPs",color: "#34A853" },
      { name: "email_scams",      label: "Email Scams",  color: "#C48A5A" },
    ];

    const fetches = await Promise.all(
      tables.map(async (t) => ({ ...t, rows: await fetchRows(t.name, 200) }))
    );

    const countMap: Record<string, number> = {
      threats:          javaCounts.threats,
      phishing_urls:    javaCounts.phishing_urls,
      suspicious_calls: javaCounts.suspicious_calls,
      email_scams:      javaCounts.email_scams,
      malicious_ips:    javaCounts.malicious_ips,
      scam_messages:    javaCounts.scam_messages,
    };

    const metrics = fetches.map(({ name, rows }) => {
      let today = 0, yesterday = 0;
      for (const r of rows) {
        const rDate = r["detected_at"] || r["created_at"] || r["last_seen"];
        if (!rDate) continue;
        const d = new Date(rDate);
        if (d >= startOfToday) today++;
        else if (d >= startOfYesterday) yesterday++;
      }
      const total = countMap[name] ?? rows.length;
      const trend = yesterday === 0 ? (today > 0 ? 100 : 0) : ((today - yesterday) / yesterday) * 100;
      return { table: name, today, yesterday, total, trend: Math.round(trend * 10) / 10 };
    });

    const severity: Record<string, number> = {
      critical: javaCounts.critical_count,
      high:     javaCounts.high_count,
      medium:   javaCounts.medium_count,
      low:      javaCounts.low_count,
    };

    const dayKeys: string[] = [];
    for (let i = 0; i < 14; i++) {
      const d = new Date(since14d);
      d.setUTCDate(d.getUTCDate() + i);
      dayKeys.push(dayKey(d));
    }
    const threatsByDay: Record<string, number> = Object.fromEntries(dayKeys.map((k) => [k, 0]));
    const phishingByDay: Record<string, number> = Object.fromEntries(dayKeys.map((k) => [k, 0]));
    for (const f of fetches) {
      const target = f.name === "phishing_urls" ? phishingByDay : threatsByDay;
      for (const r of f.rows) {
        const rDate = r["detected_at"] || r["created_at"] || r["last_seen"];
        if (!rDate) continue;
        const k = dayKey(new Date(rDate));
        if (k in target) target[k]++;
      }
    }
    const trendData = dayKeys.map((k, i) => ({
      day: `D${i + 1}`, date: k,
      threats: threatsByDay[k], phishing: phishingByDay[k],
    }));

    const last7 = dayKeys.slice(-7);
    const labels = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const dailyData = last7.map((k) => {
      const d = new Date(k);
      return { day: labels[d.getUTCDay()], detections: (threatsByDay[k] ?? 0) + (phishingByDay[k] ?? 0) };
    });

    const categoryData = fetches.map((f) => ({
      name: f.label, value: countMap[f.name] ?? f.rows.length, color: f.color,
    }));

    type Recent = { type: string; desc: string; sev: string; time: string; sortKey: number };
    const recent: Recent[] = [];
    const descCols = ["description", "url", "content", "subject", "ip_address", "pattern", "phone_number", "sender"];
    for (const f of fetches) {
      for (const r of f.rows.slice(0, 20)) {
        const desc = descCols.map((c) => r[c]).filter(Boolean)[0] ?? f.label;
        const rDate = r["detected_at"] || r["created_at"] || r["last_seen"];
        if (!rDate) continue;
        const d = new Date(rDate);
        const sev = r["severity"] || r["threat_level"] || "Low";
        recent.push({
          type: f.label, desc: String(desc).slice(0, 300),
          sev: capitalize(String(sev)), time: relTime(d, now), sortKey: d.getTime(),
        });
      }
    }
    recent.sort((a, b) => b.sortKey - a.sortKey);

    return {
      metrics, severity, trendData, dailyData, categoryData,
      recentActivity: recent.slice(0, 10).map(({ sortKey: _s, ...r }) => r),
    };
  } catch {
    return MOCK_METRICS;
  }
}
