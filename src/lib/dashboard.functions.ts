import { createServerFn } from "@tanstack/react-start";
import { createClient } from "@supabase/supabase-js";

type Row = { detected_at: string; severity: string };

function dayKey(d: Date) {
  return d.toISOString().slice(0, 10);
}

function getSupabase() {
  return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_PUBLISHABLE_KEY!);
}

export const getDashboardMetrics = createServerFn({ method: "GET" })
  .handler(async () => {
    const supabase = getSupabase();
    const now = new Date();
    const startOfToday = new Date(now);
    startOfToday.setUTCHours(0, 0, 0, 0);
    const startOfYesterday = new Date(startOfToday);
    startOfYesterday.setUTCDate(startOfYesterday.getUTCDate() - 1);
    const since14d = new Date(now);
    since14d.setUTCDate(since14d.getUTCDate() - 13);
    since14d.setUTCHours(0, 0, 0, 0);

    const tables = [
      { name: "threats", date: "detected_at" },
      { name: "phishing_urls", date: "blocked_at" },
      { name: "spam_calls", date: "reported_at" },
      { name: "email_scams", date: "detected_at" },
      { name: "malicious_ips", date: "last_seen" },
      { name: "scam_messages", date: "detected_at" },
    ] as const;

    // Pull rows per table within 14 days for trend + counts
    const fetches = await Promise.all(
      tables.map(async (t) => {
        const { data, error } = await supabase
          .from(t.name)
          .select(`${t.date}, severity`)
          .gte(t.date, since14d.toISOString());
        if (error) throw new Error(`${t.name}: ${error.message}`);
        return { table: t.name, dateCol: t.date, rows: (data ?? []) as unknown as Array<Record<string, string>> };
      })
    );

    // Counts today vs yesterday per table
    const metrics = fetches.map(({ table, dateCol, rows }) => {
      let today = 0, yesterday = 0, total = 0;
      for (const r of rows) {
        const d = new Date(r[dateCol]);
        total++;
        if (d >= startOfToday) today++;
        else if (d >= startOfYesterday) yesterday++;
      }
      const trend = yesterday === 0 ? (today > 0 ? 100 : 0) : ((today - yesterday) / yesterday) * 100;
      return { table, today, yesterday, total, trend: Math.round(trend * 10) / 10 };
    });

    // Severity distribution (all rows in window)
    const severity = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
    for (const f of fetches) for (const r of f.rows) {
      const s = r.severity as string;
      if (s in severity) severity[s]++;
    }

    // 14-day trend (threats vs phishing)
    const dayKeys: string[] = [];
    for (let i = 0; i < 14; i++) {
      const d = new Date(since14d);
      d.setUTCDate(d.getUTCDate() + i);
      dayKeys.push(dayKey(d));
    }
    const threatsByDay: Record<string, number> = Object.fromEntries(dayKeys.map((k) => [k, 0]));
    const phishingByDay: Record<string, number> = Object.fromEntries(dayKeys.map((k) => [k, 0]));
    for (const f of fetches) {
      const target = f.table === "phishing_urls" ? phishingByDay : threatsByDay;
      for (const r of f.rows) {
        const k = dayKey(new Date(r[f.dateCol]));
        if (k in target) target[k]++;
      }
    }
    const trendData = dayKeys.map((k, i) => ({
      day: `D${i + 1}`,
      date: k,
      threats: threatsByDay[k],
      phishing: phishingByDay[k],
    }));

    // 7-day daily detections (sum all tables)
    const last7 = dayKeys.slice(-7);
    const labels = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
    const dailyData = last7.map((k) => {
      const d = new Date(k);
      const total = (threatsByDay[k] ?? 0) + (phishingByDay[k] ?? 0);
      return { day: labels[d.getUTCDay()], detections: total };
    });

    // Category breakdown (totals per table in window)
    const categoryLabels: Record<string, string> = {
      threats: "Threats",
      phishing_urls: "Phishing",
      spam_calls: "Calls",
      email_scams: "Email Scams",
      malicious_ips: "Malicious IPs",
      scam_messages: "Scam Msgs",
    };
    const categoryColors: Record<string, string> = {
      threats: "#00D4FF",
      phishing_urls: "#FF4D4D",
      spam_calls: "#FFB020",
      email_scams: "#00D4FF",
      malicious_ips: "#00FFA3",
      scam_messages: "#7B61FF",
    };
    const categoryData = fetches.map((f) => ({
      name: categoryLabels[f.table],
      value: f.rows.length,
      color: categoryColors[f.table],
    }));

    // Recent activity (last 60 min, joined and sorted)
    const since60 = new Date(now.getTime() - 60 * 60 * 1000).toISOString();
    type Recent = { type: string; desc: string; sev: string; time: string; sortKey: number };
    const recent: Recent[] = [];
    const pushRows = async (
      table: string,
      label: string,
      dateCol: string,
      descCols: string[]
    ) => {
      const sb = supabase as unknown as { from: (t: string) => { select: (s: string) => { gte: (c: string, v: string) => { order: (c: string, o: { ascending: boolean }) => { limit: (n: number) => Promise<{ data: unknown[] | null }> } } } } };
      const { data } = await sb
        .from(table)
        .select(`${dateCol}, severity, ${descCols.join(",")}`)
        .gte(dateCol, since60)
        .order(dateCol, { ascending: false })
        .limit(20);
      for (const r of (data ?? []) as unknown as Array<Record<string, string>>) {
        const desc = descCols.map((c) => r[c]).filter(Boolean).join(" — ") || label;
        const d = new Date(r[dateCol]);
        recent.push({
          type: label,
          desc,
          sev: capitalize(r.severity),
          time: relTime(d, now),
          sortKey: d.getTime(),
        });
      }
    };
    await Promise.all([
      pushRows("threats", "Threat", "detected_at", ["title", "description"]),
      pushRows("phishing_urls", "Phishing URL", "blocked_at", ["url"]),
      pushRows("spam_calls", "Suspicious Call", "reported_at", ["phone_number", "pattern"]),
      pushRows("email_scams", "Email Scam", "detected_at", ["subject", "sender"]),
      pushRows("malicious_ips", "Malicious IP", "last_seen", ["ip_address", "threat_type"]),
      pushRows("scam_messages", "Scam Message", "detected_at", ["content"]),
    ]);
    recent.sort((a, b) => b.sortKey - a.sortKey);

    return {
      metrics,
      severity,
      trendData,
      dailyData,
      categoryData,
      recentActivity: recent.slice(0, 10).map(({ sortKey: _s, ...r }) => r),
    };
  });

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
