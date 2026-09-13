import { API_BASE_URL } from "./api-config";

type Row = Record<string, string>;

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
  const res = await fetch(
    `${API_BASE_URL}/api/v1/entity/${name}?limit=${limit}&offset=0`,
    { signal: AbortSignal.timeout(8000) }
  );
  if (!res.ok) return [];
  const data = await res.json();
  return (data.rows ?? data.content ?? []) as Row[];
}

export interface DashboardMetricsResult {
  metrics: { table: string; today: number; yesterday: number; total: number; trend: number }[];
  severity: Record<string, number>;
  trendData: { day: string; date: string; threats: number; phishing: number }[];
  dailyData: { day: string; detections: number }[];
  categoryData: { name: string; value: number; color: string }[];
  recentActivity: { type: string; desc: string; sev: string; time: string }[];
}

export class BackendUnavailableError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "BackendUnavailableError";
  }
}

export async function getDashboardMetrics(): Promise<DashboardMetricsResult> {
  const now = new Date();
  const startOfToday = new Date(now);
  startOfToday.setUTCHours(0, 0, 0, 0);
  const startOfYesterday = new Date(startOfToday);
  startOfYesterday.setUTCDate(startOfYesterday.getUTCDate() - 1);
  const since14d = new Date(now);
  since14d.setUTCDate(since14d.getUTCDate() - 13);
  since14d.setUTCHours(0, 0, 0, 0);

  // ── 1. Fetch dashboard counts from Java backend ───────────────────────────
  let res: Response;
  try {
    res = await fetch(`${API_BASE_URL}/api/v1/dashboard/metrics`, {
      signal: AbortSignal.timeout(8000),
    });
  } catch (err: unknown) {
    const isTimeout =
      err instanceof Error &&
      (err.name === "TimeoutError" || err.name === "AbortError");
    throw new BackendUnavailableError(
      isTimeout
        ? "Backend server unavailable — request timed out."
        : "Backend server unavailable — cannot connect to the Java server."
    );
  }

  if (!res.ok) {
    throw new BackendUnavailableError(
      res.status === 503
        ? "Database connection failed — backend returned 503."
        : `Backend error ${res.status}.`
    );
  }

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
    { name: "threats",          label: "Threats",       color: "#C48A5A" },
    { name: "scam_messages",    label: "Scam Msgs",     color: "#4F7EF7" },
    { name: "suspicious_calls", label: "Calls",         color: "#E8A23C" },
    { name: "phishing_urls",    label: "Phishing",      color: "#E05A52" },
    { name: "malicious_ips",    label: "Malicious IPs", color: "#34A853" },
    { name: "email_scams",      label: "Email Scams",   color: "#8E24AA" },
  ];

  // ── 2. Fetch recent rows for trend/activity data (best-effort) ────────────
  const fetches = await Promise.all(
    tables.map(async (t) => ({ ...t, rows: await fetchRows(t.name, 200).catch(() => [] as Row[]) }))
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
      const dt = new Date(rDate);
      if (dt >= startOfToday) today++;
      else if (dt >= startOfYesterday) yesterday++;
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
    const dt = new Date(since14d);
    dt.setUTCDate(dt.getUTCDate() + i);
    dayKeys.push(dayKey(dt));
  }
  const threatsByDay: Record<string, number>  = Object.fromEntries(dayKeys.map((k) => [k, 0]));
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
    const dt = new Date(k);
    return { day: labels[dt.getUTCDay()], detections: (threatsByDay[k] ?? 0) + (phishingByDay[k] ?? 0) };
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
      const dt = new Date(rDate);
      const sev = r["severity"] || r["threat_level"] || "Low";
      recent.push({
        type: f.label, desc: String(desc).slice(0, 300),
        sev: capitalize(String(sev)), time: relTime(dt, now), sortKey: dt.getTime(),
      });
    }
  }
  recent.sort((a, b) => b.sortKey - a.sortKey);

  return {
    metrics, severity, trendData, dailyData, categoryData,
    recentActivity: recent.slice(0, 10).map(({ sortKey: _s, ...r }) => r),
  };
}
