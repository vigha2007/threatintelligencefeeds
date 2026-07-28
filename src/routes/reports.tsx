import { createFileRoute, Link } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { FileText, ArrowLeft, BarChart2, TrendingUp, Shield, Download } from "lucide-react";

export const Route = createFileRoute("/reports")({
  head: () => ({
    meta: [
      { title: "Reports — Threat Intelligence" },
      { name: "description", content: "Security intelligence reports and analytics for your threat monitoring platform." },
    ],
  }),
  component: ReportsPage,
});

const REPORT_CATEGORIES = [
  { icon: Shield, label: "Threat Summary", desc: "Weekly threat feed digest and severity breakdown", color: "#C48A5A" },
  { icon: BarChart2, label: "Analytics Report", desc: "Scam call and phishing trend analysis", color: "#4F7EF7" },
  { icon: TrendingUp, label: "Risk Assessment", desc: "IP reputation and malware indicator reports", color: "#34A853" },
  { icon: FileText, label: "Audit Logs", desc: "Complete event log exports and audit trails", color: "#E8A23C" },
];

function ReportsPage() {
  return (
    <div className="mx-auto max-w-4xl px-4 py-12 sm:px-6 lg:px-8">
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

      {/* Under development banner */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, delay: 0.1 }}
        className="mb-8 rounded-3xl border border-[#E4DEC6] bg-white p-8 shadow-sm text-center"
      >
        <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-[#FAF8F5] border border-[#E4DEC6]">
          <BarChart2 className="h-8 w-8 text-[#C48A5A]" />
        </div>
        <h2 className="text-lg font-extrabold text-gray-800 font-poppins mb-2">
          Module Under Development
        </h2>
        <p className="text-sm font-semibold text-gray-500 font-manrope max-w-sm mx-auto leading-relaxed">
          The Reports module is currently being built. Advanced analytics, PDF exports, and scheduled reports will be available here soon.
        </p>
        <div className="mt-6 inline-flex items-center gap-2 rounded-full border border-[#E8A23C]/30 bg-[#E8A23C]/10 px-4 py-2">
          <span className="h-1.5 w-1.5 rounded-full bg-[#E8A23C] animate-pulse" />
          <span className="text-[11px] font-bold text-[#E8A23C] font-manrope">Coming Soon</span>
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
