import { c as createServerRpc } from "./createServerRpc-B6dqUJkk.mjs";
import { c as createServerFn } from "./server-DkvSOJyR.mjs";
import "../_libs/seroval.mjs";
import "../_libs/react.mjs";
import "node:async_hooks";
import "../_libs/h3-v2.mjs";
import "../_libs/rou3.mjs";
import "../_libs/srvx.mjs";
import "node:stream";
import "../_libs/tanstack__router-core.mjs";
import "../_libs/tanstack__history.mjs";
import "../_libs/cookie-es.mjs";
import "../_libs/seroval-plugins.mjs";
import "node:stream/web";
import "../_libs/tanstack__react-router.mjs";
import "../_libs/react-dom.mjs";
import "util";
import "crypto";
import "async_hooks";
import "stream";
import "../_libs/isbot.mjs";
const JAVA_BASE = process.env.JAVA_BASE_URL || "http://localhost:8081";
function dayKey(d) {
  return d.toISOString().slice(0, 10);
}
function capitalize(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}
function relTime(d, now) {
  const sec = Math.max(1, Math.round((now.getTime() - d.getTime()) / 1e3));
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min} min ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr} hr ago`;
  return `${Math.round(hr / 24)}d ago`;
}
async function fetchRows(name, limit = 200) {
  try {
    const res = await fetch(`${JAVA_BASE}/api/v1/entity/${name}?limit=${limit}&offset=0`);
    if (!res.ok) return [];
    const data = await res.json();
    return data.rows ?? [];
  } catch {
    return [];
  }
}
const getDashboardMetrics_createServerFn_handler = createServerRpc({
  id: "1368865c1b8c6db22208b504ac7be8edcc58776f1d3da3870041f567f0857630",
  name: "getDashboardMetrics",
  filename: "src/lib/dashboard.functions.ts"
}, (opts) => getDashboardMetrics.__executeServer(opts));
const getDashboardMetrics = createServerFn({
  method: "GET"
}).handler(getDashboardMetrics_createServerFn_handler, async () => {
  const now = /* @__PURE__ */ new Date();
  const startOfToday = new Date(now);
  startOfToday.setUTCHours(0, 0, 0, 0);
  const startOfYesterday = new Date(startOfToday);
  startOfYesterday.setUTCDate(startOfYesterday.getUTCDate() - 1);
  const since14d = new Date(now);
  since14d.setUTCDate(since14d.getUTCDate() - 13);
  since14d.setUTCHours(0, 0, 0, 0);
  let javaCounts = {
    threats: 0,
    phishing_urls: 0,
    suspicious_calls: 0,
    email_scams: 0,
    malicious_ips: 0,
    scam_messages: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0
  };
  try {
    const res = await fetch(`${JAVA_BASE}/api/v1/dashboard/metrics`);
    if (res.ok) {
      const d = await res.json();
      javaCounts = {
        threats: Number(d.total_threats_detected ?? d.threats ?? 0),
        phishing_urls: Number(d.phishing_urls_blocked ?? d.phishing_urls ?? 0),
        suspicious_calls: Number(d.suspicious_calls_flagged ?? d.suspicious_calls ?? 0),
        email_scams: Number(d.email_scams_detected ?? d.email_scams ?? 0),
        malicious_ips: Number(d.malicious_ips_tracked ?? d.malicious_ips ?? 0),
        scam_messages: Number(d.scam_messages_analyzed ?? d.scam_messages ?? 0),
        critical_count: Number(d.critical_count ?? 0),
        high_count: Number(d.high_count ?? 0),
        medium_count: Number(d.medium_count ?? 0),
        low_count: Number(d.low_count ?? 0)
      };
    }
  } catch {
  }
  const tables = [{
    name: "threats",
    label: "Threats",
    color: "#00D4FF"
  }, {
    name: "phishing_urls",
    label: "Phishing",
    color: "#FF4D4D"
  }, {
    name: "suspicious_calls",
    label: "Calls",
    color: "#FFB020"
  }, {
    name: "email_scams",
    label: "Email Scams",
    color: "#00D4FF"
  }, {
    name: "malicious_ips",
    label: "Malicious IPs",
    color: "#00FFA3"
  }, {
    name: "scam_messages",
    label: "Scam Msgs",
    color: "#7B61FF"
  }];
  const fetches = await Promise.all(tables.map(async (t) => ({
    ...t,
    rows: await fetchRows(t.name, 200)
  })));
  const countMap = {
    threats: javaCounts.threats,
    phishing_urls: javaCounts.phishing_urls,
    suspicious_calls: javaCounts.suspicious_calls,
    email_scams: javaCounts.email_scams,
    malicious_ips: javaCounts.malicious_ips,
    scam_messages: javaCounts.scam_messages
  };
  const metrics = fetches.map(({
    name,
    rows
  }) => {
    let today = 0, yesterday = 0;
    for (const r of rows) {
      const rDate = r["detected_at"] || r["created_at"] || r["last_seen"];
      if (!rDate) continue;
      const d = new Date(rDate);
      if (d >= startOfToday) today++;
      else if (d >= startOfYesterday) yesterday++;
    }
    const total = countMap[name] ?? rows.length;
    const trend = yesterday === 0 ? today > 0 ? 100 : 0 : (today - yesterday) / yesterday * 100;
    return {
      table: name,
      today,
      yesterday,
      total,
      trend: Math.round(trend * 10) / 10
    };
  });
  const severity = {
    critical: javaCounts.critical_count,
    high: javaCounts.high_count,
    medium: javaCounts.medium_count,
    low: javaCounts.low_count
  };
  const dayKeys = [];
  for (let i = 0; i < 14; i++) {
    const d = new Date(since14d);
    d.setUTCDate(d.getUTCDate() + i);
    dayKeys.push(dayKey(d));
  }
  const threatsByDay = Object.fromEntries(dayKeys.map((k) => [k, 0]));
  const phishingByDay = Object.fromEntries(dayKeys.map((k) => [k, 0]));
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
    day: `D${i + 1}`,
    date: k,
    threats: threatsByDay[k],
    phishing: phishingByDay[k]
  }));
  const last7 = dayKeys.slice(-7);
  const labels = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const dailyData = last7.map((k) => {
    const d = new Date(k);
    return {
      day: labels[d.getUTCDay()],
      detections: (threatsByDay[k] ?? 0) + (phishingByDay[k] ?? 0)
    };
  });
  const categoryData = fetches.map((f) => ({
    name: f.label,
    value: countMap[f.name] ?? f.rows.length,
    color: f.color
  }));
  const recent = [];
  const descCols = ["description", "url", "content", "subject", "ip_address", "pattern", "phone_number", "sender"];
  for (const f of fetches) {
    for (const r of f.rows.slice(0, 20)) {
      const desc = descCols.map((c) => r[c]).filter(Boolean)[0] ?? f.label;
      const rDate = r["detected_at"] || r["created_at"] || r["last_seen"];
      if (!rDate) continue;
      const d = new Date(rDate);
      const sev = r["severity"] || r["threat_level"] || "Low";
      recent.push({
        type: f.label,
        desc: String(desc).slice(0, 300),
        sev: capitalize(String(sev)),
        time: relTime(d, now),
        sortKey: d.getTime()
      });
    }
  }
  recent.sort((a, b) => b.sortKey - a.sortKey);
  return {
    metrics,
    severity,
    trendData,
    dailyData,
    categoryData,
    recentActivity: recent.slice(0, 10).map(({
      sortKey: _s,
      ...r
    }) => r)
  };
});
export {
  getDashboardMetrics_createServerFn_handler
};
