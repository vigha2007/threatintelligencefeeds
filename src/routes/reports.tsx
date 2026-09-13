import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  FileText, ArrowLeft, BarChart2, TrendingUp, Shield,
  Download, Loader2, AlertCircle, Database,
} from "lucide-react";
import { API_BASE_URL } from "@/lib/api-config";

export const Route = createFileRoute("/reports")({
  head: () => ({
    meta: [
      { title: "Reports — Threat Intelligence" },
      { name: "description", content: "Security intelligence reports, analytics, and export center for your threat monitoring platform." },
    ],
  }),
  component: ReportsPage,
});

interface MetricCounts {
  threats:             number;
  phishing_urls:       number;
  suspicious_calls:    number;
  email_scams:         number;
  malicious_ips:       number;
  scam_messages:       number;
  scam_detector_results: number;
  critical_count:      number;
  high_count:          number;
  medium_count:        number;
  low_count:           number;
}

async function fetchMetrics(): Promise<MetricCounts> {
  const res = await fetch(`${API_BASE_URL}/api/v1/dashboard/metrics`, {
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`Backend returned ${res.status}`);
  return res.json() as Promise<MetricCounts>;
}

const REPORT_CATEGORIES = [
  { icon: Shield,    label: "Threat Summary",    desc: "Weekly threat feed digest and severity breakdown",   color: "#C48A5A" },
  { icon: BarChart2, label: "Analytics Report",  desc: "Scam call and phishing trend analysis",              color: "#4F7EF7" },
  { icon: TrendingUp,label: "Risk Assessment",   desc: "IP reputation and malware indicator reports",        color: "#34A853" },
  { icon: FileText,  label: "Audit Logs",        desc: "Complete event log exports and audit trails",        color: "#E8A23C" },
];

const sevColors: Record<string, string> = {
  critical: "#E05A52", high: "#E8A23C", medium: "#4F7EF7", low: "#34A853",
};

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-2xl border border-[#E4DEC6] bg-white p-5 shadow-sm gap-1">
      <span
        className="text-2xl font-extrabold tabular-nums font-poppins"
        style={{ color }}
      >
        {value.toLocaleString()}
      </span>
      <span className="text-[11px] font-bold text-gray-500 font-manrope text-center">{label}</span>
    </div>
  );
}

function ReportsPage() {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["report-metrics"],
    queryFn:  fetchMetrics,
    staleTime: 5 * 60_000,
  });

  const totalRecords = data
    ? (data.threats ?? 0) + (data.phishing_urls ?? 0) + (data.suspicious_calls ?? 0) +
      (data.email_scams ?? 0) + (data.malicious_ips ?? 0) + (data.scam_messages ?? 0)
    : 0;

  return (
    <div className="mx-auto max-w-5xl px-4 py-10 sm:px-6 lg:px-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45 }}
        className="mb-8"
      >
        <Link
          to="/dashboard"
          className="mb-6 inline-flex items-center gap-1.5 text-xs font-bold text-gray-500 hover:text-[#C48A5A] transition-colors font-manrope"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to Dashboard
        </Link>

        <div className="flex items-center gap-4 mt-4">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-[#C48A5A]/10 border border-[#C48A5A]/25">
            <FileText className="h-7 w-7 text-[#C48A5A]" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold text-gray-800 font-poppins">📄 Reports</h1>
            <p className="text-xs font-semibold text-gray-500 font-manrope mt-0.5">
              Security intelligence reports and export center
            </p>
          </div>
        </div>
      </motion.div>

      {/* Live Database Summary */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, delay: 0.05 }}
        className="mb-6"
      >
        <p className="mb-3 text-[11px] font-bold uppercase tracking-wider text-gray-400 font-manrope">
          Live Database Summary
        </p>

        {isLoading ? (
          <div className="flex items-center justify-center rounded-3xl border border-[#E4DEC6] bg-white p-10 shadow-sm">
            <Loader2 className="h-6 w-6 animate-spin text-[#C48A5A]" />
            <span className="ml-2 text-xs font-semibold text-gray-400 font-manrope">Loading metrics from backend…</span>
          </div>
        ) : isError ? (
          <div className="flex items-center gap-3 rounded-3xl border border-[#E05A52]/30 bg-[#E05A52]/5 p-6 shadow-sm">
            <AlertCircle className="h-5 w-5 text-[#E05A52] shrink-0" />
            <div>
              <p className="text-sm font-bold text-[#E05A52] font-poppins">Backend server unavailable</p>
              <p className="text-xs font-semibold text-gray-500 font-manrope mt-0.5">
                {(error as Error)?.message ?? "Cannot connect to the Java backend on port 8081."}
              </p>
            </div>
          </div>
        ) : data ? (
          <>
            {/* Total banner */}
            <div className="mb-4 flex items-center gap-3 rounded-2xl border border-[#C48A5A]/20 bg-[#C48A5A]/5 px-5 py-3">
              <Database className="h-5 w-5 text-[#C48A5A] shrink-0" />
              <span className="text-sm font-bold text-gray-700 font-poppins">
                Total records in database:{" "}
                <span className="text-[#C48A5A]">{totalRecords.toLocaleString()}</span>
              </span>
            </div>
            {/* Entity counts */}
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              <StatCard label="Threats"           value={data.threats ?? 0}          color="#C48A5A" />
              <StatCard label="Phishing URLs"     value={data.phishing_urls ?? 0}    color="#E05A52" />
              <StatCard label="Suspicious Calls"  value={data.suspicious_calls ?? 0} color="#E8A23C" />
              <StatCard label="Email Scams"       value={data.email_scams ?? 0}      color="#8E24AA" />
              <StatCard label="Malicious IPs"     value={data.malicious_ips ?? 0}    color="#4F7EF7" />
              <StatCard label="Scam Messages"     value={data.scam_messages ?? 0}    color="#34A853" />
            </div>

            {/* Severity breakdown */}
            <div className="mt-4 grid grid-cols-4 gap-3">
              {[
                { key: "critical_count", label: "Critical" },
                { key: "high_count",     label: "High"     },
                { key: "medium_count",   label: "Medium"   },
                { key: "low_count",      label: "Low"      },
              ].map(({ key, label }) => (
                <div key={key} className="flex flex-col items-center justify-center rounded-2xl border border-[#E4DEC6] bg-white p-4 shadow-sm">
                  <span
                    className="text-lg font-extrabold tabular-nums font-poppins"
                    style={{ color: sevColors[label.toLowerCase()] }}
                  >
                    {(data[key as keyof MetricCounts] ?? 0).toLocaleString()}
                  </span>
                  <span className="text-[10px] font-bold uppercase tracking-wide font-manrope" style={{ color: sevColors[label.toLowerCase()] }}>
                    {label}
                  </span>
                </div>
              ))}
            </div>
          </>
        ) : null}
      </motion.div>

      {/* Under development banner */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, delay: 0.12 }}
        className="mb-8 rounded-3xl border border-[#E4DEC6] bg-white p-8 shadow-sm text-center"
      >
        <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-[#FAF8F5] border border-[#E4DEC6]">
          <BarChart2 className="h-8 w-8 text-[#C48A5A]" />
        </div>
        <h2 className="text-lg font-extrabold text-gray-800 font-poppins mb-2">
          Export & Reports Module
        </h2>
        <p className="text-sm font-semibold text-gray-500 font-manrope max-w-sm mx-auto leading-relaxed">
          PDF exports, scheduled reports, and advanced analytics will be available here soon. Database statistics above are live.
        </p>
        <div className="mt-6 inline-flex items-center gap-2 rounded-full border border-[#E8A23C]/30 bg-[#E8A23C]/10 px-4 py-2">
          <span className="h-1.5 w-1.5 rounded-full bg-[#E8A23C] animate-pulse" />
          <span className="text-[11px] font-bold text-[#E8A23C] font-manrope">Export Coming Soon</span>
        </div>
      </motion.div>

      {/* Preview cards */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, delay: 0.2 }}
      >
        <p className="mb-4 text-[11px] font-bold uppercase tracking-wider text-gray-400 font-manrope">
          Planned Report Types
        </p>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {REPORT_CATEGORIES.map((cat) => {
            const Icon = cat.icon;
            return (
              <motion.div
                key={cat.label}
                whileHover={{ y: -2 }}
                className="flex items-start gap-4 rounded-2xl border border-[#E4DEC6] bg-white p-5 shadow-sm opacity-60 cursor-not-allowed"
              >
                <div
                  className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl"
                  style={{ background: `${cat.color}15` }}
                >
                  <Icon className="h-5 w-5" style={{ color: cat.color }} />
                </div>
                <div>
                  <p className="text-xs font-bold text-gray-700 font-poppins">{cat.label}</p>
                  <p className="mt-0.5 text-[10px] font-semibold text-gray-400 font-manrope">{cat.desc}</p>
                </div>
                <Download className="ml-auto h-4 w-4 text-gray-300 shrink-0 mt-0.5" />
              </motion.div>
            );
          })}
        </div>
      </motion.div>

      {/* Back button */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.4, delay: 0.35 }}
        className="mt-8 flex justify-center"
      >
        <Link
          to="/dashboard"
          className="inline-flex items-center gap-2 rounded-2xl bg-[#C48A5A] px-6 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-[#C48A5A]/90 transition-colors font-poppins"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to Dashboard
        </Link>
      </motion.div>
    </div>
  );
}
