import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { motion } from "framer-motion";
import {
  BarChart3,
  ArrowLeft,
  Award,
  TrendingUp,
  Cpu,
  Layers,
  Zap,
  CheckCircle2,
  AlertCircle,
  Clock,
  FileCheck,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { ParticlesBackground } from "@/components/particles-background";
import { SiteFooter } from "@/components/site-footer";

export const Route = createFileRoute("/model-comparison")({
  head: () => ({
    meta: [
      { title: "Model Performance Comparison — Threat Intelligence" },
      {
        name: "description",
        content:
          "Verified evaluation metrics, confusion matrices, and split benchmarks for trained threat detection models.",
      },
    ],
  }),
  component: ModelComparisonPage,
});

/* ─── VERIFIED DATA — sourced strictly from existing project files ─── */

/* ML/models/model_metadata.json */
const DOMAIN_MODELS = [
  {
    domain: "SMS / Scam Messages",
    task: "Text Classification",
    model: "TF-IDF + XGBoost",
    dataset: "scam_messages.csv",
    samples: 8609,
    accuracy: 97.60,
    precision: 96.62,
    recall: 98.01,
    f1: 97.31,
    rocAuc: 99.69,
    latency: 18.0,
    tp: 3746, tn: 4656, fp: 131, fn: 76,
    color: "#4F7EF7",
    tag: "text",
  },
  {
    domain: "Email Scams",
    task: "Text Classification",
    model: "TF-IDF + CatBoost",
    dataset: "email_scams.csv",
    samples: 7362,
    accuracy: 97.00,
    precision: 95.58,
    recall: 97.77,
    f1: 96.66,
    rocAuc: 99.58,
    latency: 32.6,
    tp: 3202, tn: 3939, fp: 148, fn: 73,
    color: "#8E24AA",
    tag: "text",
  },
  {
    domain: "Phishing URLs",
    task: "URL Classification",
    model: "Lexical + XGBoost",
    dataset: "phishing_urls.csv",
    samples: 23980,
    accuracy: 92.57,
    precision: 94.21,
    recall: 80.07,
    f1: 86.57,
    rocAuc: 97.31,
    latency: 42.0,
    tp: 5745, tn: 16472, fp: 353, fn: 1430,
    color: "#E05A52",
    tag: "url",
  },
  {
    domain: "Malicious IPs",
    task: "IP/Network Classification",
    model: "Lexical/Net + XGBoost",
    dataset: "malicious_ips.csv",
    samples: 24000,
    accuracy: 91.75,
    precision: 97.51,
    recall: 90.52,
    f1: 93.89,
    rocAuc: 96.53,
    latency: 21.7,
    tp: 15208, tn: 6812, fp: 388, fn: 1592,
    color: "#34A853",
    tag: "ip",
  },
  {
    domain: "Suspicious Calls",
    task: "Tabular Classification",
    model: "Tabular + Random Forest",
    dataset: "suspicious_calls_india_50000_synthetic.csv",
    samples: 10000,
    accuracy: 57.06,
    precision: 30.42,
    recall: 32.88,
    f1: 31.60,
    rocAuc: 50.27,
    latency: 73.3,
    tp: 992, tn: 4714, fp: 2269, fn: 2025,
    color: "#E8A23C",
    tag: "call",
  },
];

/* ML/reports/model_comparison.md + ML/evaluation/metrics.json */
const UNIFIED_SPLITS = [
  {
    label: "80:20 Split",
    testSamples: 258412,
    rows: [
      { model: "XGBoost", winner: true,  accuracy: 90.67, precision: 88.34, recall: 90.68, f1: 89.49, rocAuc: 97.35, trainTime: "221.1s", inferTime: "3.02s" },
      { model: "CatBoost", winner: false, accuracy: 90.55, precision: 88.66, recall: 89.94, f1: 89.30, rocAuc: 97.16, trainTime: "915.0s", inferTime: "1.06s" },
    ],
  },
  {
    label: "70:30 Split",
    testSamples: 387618,
    rows: [
      { model: "XGBoost", winner: true,  accuracy: 90.71, precision: 88.48, recall: 90.60, f1: 89.53, rocAuc: 97.39, trainTime: "405.6s", inferTime: "3.75s" },
      { model: "CatBoost", winner: false, accuracy: 90.57, precision: 88.70, recall: 89.94, f1: 89.31, rocAuc: 97.17, trainTime: "1276.4s", inferTime: "1.34s" },
    ],
  },
  {
    label: "60:40 Split",
    testSamples: 516824,
    rows: [
      { model: "XGBoost", winner: true,  accuracy: 90.72, precision: 88.36, recall: 90.77, f1: 89.55, rocAuc: 97.38, trainTime: "373.5s", inferTime: "4.80s" },
      { model: "CatBoost", winner: false, accuracy: 90.59, precision: 88.70, recall: 89.98, f1: 89.34, rocAuc: 97.18, trainTime: "1437.9s", inferTime: "3.41s" },
    ],
  },
];

/* ML/evaluation/comparison_report.json */
const TEXT_H2H = [
  { model: "CatBoost", accuracy: 98.32, precision: 98.04, recall: 97.94, f1: 97.99, rocAuc: 99.84, highlight: true },
  { model: "XGBoost",  accuracy: 98.24, precision: 97.94, recall: 97.85, f1: 97.90, rocAuc: 99.82, highlight: false },
];

const ARCHITECTURES = [
  {
    name: "XGBoost",
    type: "Gradient Boosted Decision Trees",
    features: "TF-IDF 5,000 + 34 Lexical features",
    domains: "SMS, URL, IP, Unified Corpus",
    status: "Active Production",
    statusColor: "#34A853",
    note: "Primary classifier — highest Recall (90.68%) & best avg F1 across all splits.",
    hasMetrics: true,
  },
  {
    name: "CatBoost",
    type: "Categorical Oblivious Decision Trees",
    features: "Ordered Boosting + TF-IDF vectors",
    domains: "Email, Text Benchmark, SIEM Scoring",
    status: "Active Production",
    statusColor: "#34A853",
    note: "Best Precision (98.04%) on text benchmark. Calibrated probabilities for SOC scoring.",
    hasMetrics: true,
  },
  {
    name: "Random Forest",
    type: "Ensemble Bagging (Decision Trees)",
    features: "Tabular phone metadata features",
    domains: "Suspicious Calls / Caller Intelligence",
    status: "Active Baseline",
    statusColor: "#E8A23C",
    note: "Evaluated on synthetic call telemetry (57.06% accuracy). Real-world dataset underway.",
    hasMetrics: true,
  },
  {
    name: "LSTM (Hybrid)",
    type: "Recurrent Neural Network (PyTorch)",
    features: "Sequential token embeddings",
    domains: "ML/hybrid_model.py — soft voting hybrid",
    status: "N/A — Architecture Defined",
    statusColor: "#8E24AA",
    note: "LSTMClassifier + Random Forest soft-voting exists in codebase. No standalone evaluation file in active repo.",
    hasMetrics: false,
  },
  {
    name: "DistilBERT",
    type: "Transformer / Pre-trained LM",
    features: "Sub-word WordPiece (768-dim)",
    domains: "N/A (Historical experimentation)",
    status: "N/A — Not In Pipeline",
    statusColor: "#9E9E9E",
    note: "No model weights (.pt/.bin) or evaluation logs retained after pipeline migration to XGBoost/CatBoost.",
    hasMetrics: false,
  },
];

/* ─── Helpers ─── */
function pct(v: number) { return `${v.toFixed(2)}%`; }
function na() { return <span className="text-gray-400 italic text-[11px]">N/A</span>; }

function MetricPill({ value, highlight }: { value: string; highlight?: boolean }) {
  return (
    <span className={`font-extrabold font-poppins ${highlight ? "text-[#C48A5A]" : "text-gray-800"}`}>
      {value}
    </span>
  );
}

function SectionHeader({ icon: Icon, num, title, subtitle, badge }: {
  icon: typeof BarChart3; num: string; title: string; subtitle: string; badge?: string;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3 border-b border-[#E4DEC6]/60 pb-4">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-extrabold text-[#C48A5A] bg-[#C48A5A]/10 rounded-md px-2 py-0.5 font-poppins">{num}</span>
          <Icon className="h-4.5 w-4.5 text-[#C48A5A]" />
          <h2 className="text-base font-bold text-gray-800 font-poppins">{title}</h2>
        </div>
        <p className="text-xs font-semibold text-gray-500 font-manrope ml-1">{subtitle}</p>
      </div>
      {badge && (
        <span className="rounded-xl bg-[#FAF8F5] border border-[#E4DEC6] px-3 py-1 text-[11px] font-bold text-gray-600 font-poppins">
          {badge}
        </span>
      )}
    </div>
  );
}

function TableWrapper({ children }: { children: React.ReactNode }) {
  return (
    <div className="overflow-x-auto rounded-2xl border border-[#E4DEC6]/70">
      <table className="w-full text-left text-[12px] font-manrope border-collapse min-w-[700px]">
        {children}
      </table>
    </div>
  );
}

function THead({ cols }: { cols: string[] }) {
  return (
    <thead>
      <tr className="bg-[#FAF8F5] border-b border-[#E4DEC6]/70 text-[11px] font-bold uppercase tracking-wide text-gray-500 font-poppins">
        {cols.map((c, i) => (
          <th key={i} className={`px-4 py-3 ${i > 0 ? "text-right" : ""}`}>{c}</th>
        ))}
      </tr>
    </thead>
  );
}

/* ─── MAIN PAGE ─── */
function ModelComparisonPage() {
  const [split, setSplit] = useState(0);
  const current = UNIFIED_SPLITS[split];

  /* chart data for master corpus */
  const masterChart = [
    { m: "Accuracy",  XGBoost: 90.67, CatBoost: 90.55 },
    { m: "Precision", XGBoost: 88.34, CatBoost: 88.66 },
    { m: "Recall",    XGBoost: 90.68, CatBoost: 89.94 },
    { m: "F1-Score",  XGBoost: 89.49, CatBoost: 89.30 },
    { m: "ROC-AUC",   XGBoost: 97.35, CatBoost: 97.16 },
  ];

  const textChart = [
    { m: "Accuracy",  CatBoost: 98.32, XGBoost: 98.24 },
    { m: "Precision", CatBoost: 98.04, XGBoost: 97.94 },
    { m: "Recall",    CatBoost: 97.94, XGBoost: 97.85 },
    { m: "F1-Score",  CatBoost: 97.99, XGBoost: 97.90 },
    { m: "ROC-AUC",   CatBoost: 99.84, XGBoost: 99.82 },
  ];

  return (
    <div className="relative min-h-screen pb-16">
      <div className="absolute inset-0 -z-10"><ParticlesBackground /></div>

      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">

        {/* ── Page Header ── */}
        <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
          <Link to="/dashboard" className="inline-flex items-center gap-1.5 text-xs font-bold text-gray-500 hover:text-[#C48A5A] transition-colors font-manrope mb-5">
            <ArrowLeft className="h-3.5 w-3.5" /> Back to Dashboard
          </Link>

          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-[#C48A5A]/10 border border-[#C48A5A]/25">
                <BarChart3 className="h-7 w-7 text-[#C48A5A]" />
              </div>
              <div>
                <h1 className="text-2xl sm:text-3xl font-extrabold text-gray-800 font-poppins tracking-tight">
                  Model Performance Comparison
                </h1>
                <p className="text-xs font-semibold text-gray-500 font-manrope mt-1">
                  Performance of trained models evaluated on the available test datasets.
                </p>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-[#34A853]/40 bg-[#34A853]/10 px-3 py-1 text-[11px] font-bold text-[#34A853] font-poppins">
                <span className="h-1.5 w-1.5 rounded-full bg-[#34A853] animate-pulse" />
                VERIFIED EVALUATION RESULTS
              </span>
              <span className="rounded-full border border-[#C48A5A]/30 bg-[#C48A5A]/10 px-3 py-1 text-[11px] font-bold text-[#C48A5A] font-poppins">
                1,292,058 Records Tested
              </span>
            </div>
          </div>
        </motion.div>

        {/* ═══════════════════════════════════════════════════════
            SECTION 1 — DOMAIN-SPECIFIC PRODUCTION MODELS TABLE
        ═══════════════════════════════════════════════════════ */}
        <motion.div initial={{ opacity: 0, y: 18 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
          className="rounded-3xl bg-white border border-[#E4DEC6]/80 p-6 sm:p-8 shadow-sm">

          <SectionHeader
            icon={Zap}
            num="01"
            title="Domain-Specific Production Models"
            subtitle="Verified from ML/models/model_metadata.json · Task-separated — NOT combined"
            badge="5 Independent Classifiers"
          />

          <TableWrapper>
            <THead cols={["Threat Domain", "Task", "Winning Model", "Dataset", "Test Samples", "Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC", "Latency"]} />
            <tbody className="divide-y divide-[#E4DEC6]/40">
              {DOMAIN_MODELS.map((r) => (
                <tr key={r.domain} className="hover:bg-[#FAF8F5]/70 transition-colors">
                  <td className="px-4 py-3.5 font-bold text-gray-800">
                    <div className="flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full shrink-0" style={{ background: r.color }} />
                      <span className="font-poppins">{r.domain}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3.5 text-gray-500 text-[11px]">{r.task}</td>
                  <td className="px-4 py-3.5">
                    <span className="rounded-md px-2 py-0.5 text-[11px] font-extrabold font-poppins whitespace-nowrap"
                      style={{ background: `${r.color}18`, color: r.color }}>
                      {r.model}
                    </span>
                  </td>
                  <td className="px-4 py-3.5 font-mono text-[11px] text-gray-400">{r.dataset}</td>
                  <td className="px-4 py-3.5 text-right font-mono font-semibold text-gray-700">
                    {r.samples.toLocaleString()}
                  </td>
                  <td className="px-4 py-3.5 text-right font-extrabold text-gray-900 font-poppins">{pct(r.accuracy)}</td>
                  <td className="px-4 py-3.5 text-right text-gray-700 font-semibold">{pct(r.precision)}</td>
                  <td className="px-4 py-3.5 text-right text-gray-700 font-semibold">{pct(r.recall)}</td>
                  <td className="px-4 py-3.5 text-right font-extrabold text-[#C48A5A] font-poppins">{pct(r.f1)}</td>
                  <td className="px-4 py-3.5 text-right font-semibold text-[#4F7EF7]">{pct(r.rocAuc)}</td>
                  <td className="px-4 py-3.5 text-right font-mono text-gray-500">{r.latency} ms</td>
                </tr>
              ))}
            </tbody>
          </TableWrapper>

          {/* Confusion Matrix Sub-table */}
          <div className="mt-8">
            <h3 className="mb-4 flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-gray-500 font-poppins">
              <Layers className="h-4 w-4 text-[#C48A5A]" />
              Confusion Matrix — Actual Verified Counts (TP / FP / FN / TN)
            </h3>
            <div className="overflow-x-auto rounded-2xl border border-[#E4DEC6]/70">
              <table className="w-full text-[12px] font-manrope border-collapse min-w-[600px]">
                <thead>
                  <tr className="bg-[#FAF8F5] border-b border-[#E4DEC6]/70 text-[11px] font-bold uppercase tracking-wide text-gray-500 font-poppins">
                    <th className="px-4 py-3 text-left">Threat Domain</th>
                    <th className="px-4 py-3 text-left">Model</th>
                    <th className="px-4 py-3 text-right">Test N</th>
                    <th className="px-4 py-3 text-right text-[#34A853]">✔ True Positive</th>
                    <th className="px-4 py-3 text-right text-[#4F7EF7]">✔ True Negative</th>
                    <th className="px-4 py-3 text-right text-[#E8A23C]">✘ False Positive</th>
                    <th className="px-4 py-3 text-right text-[#E05A52]">✘ False Negative</th>
                    <th className="px-4 py-3 text-right">FP Rate</th>
                    <th className="px-4 py-3 text-right">FN Rate</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E4DEC6]/40">
                  {DOMAIN_MODELS.map((r) => {
                    const fpRate = ((r.fp / r.samples) * 100).toFixed(2);
                    const fnRate = ((r.fn / r.samples) * 100).toFixed(2);
                    return (
                      <tr key={r.domain} className="hover:bg-[#FAF8F5]/70 transition-colors">
                        <td className="px-4 py-3 font-bold text-gray-800">
                          <div className="flex items-center gap-2">
                            <span className="h-2 w-2 rounded-full" style={{ background: r.color }} />
                            {r.domain}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-[11px] font-semibold text-gray-600">{r.model}</td>
                        <td className="px-4 py-3 text-right font-mono text-gray-600">{r.samples.toLocaleString()}</td>
                        <td className="px-4 py-3 text-right font-extrabold text-[#34A853] font-poppins">{r.tp.toLocaleString()}</td>
                        <td className="px-4 py-3 text-right font-extrabold text-[#4F7EF7] font-poppins">{r.tn.toLocaleString()}</td>
                        <td className="px-4 py-3 text-right font-semibold text-[#E8A23C]">{r.fp.toLocaleString()}</td>
                        <td className="px-4 py-3 text-right font-semibold text-[#E05A52]">{r.fn.toLocaleString()}</td>
                        <td className="px-4 py-3 text-right font-mono text-gray-500">{fpRate}%</td>
                        <td className="px-4 py-3 text-right font-mono text-gray-500">{fnRate}%</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </motion.div>

        {/* ═══════════════════════════════════════════════════════
            SECTION 2 — UNIFIED MASTER CORPUS BENCHMARK
        ═══════════════════════════════════════════════════════ */}
        <motion.div initial={{ opacity: 0, y: 18 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
          className="rounded-3xl bg-white border border-[#E4DEC6]/80 p-6 sm:p-8 shadow-sm">

          <SectionHeader
            icon={Award}
            num="02"
            title="Unified Master Corpus Benchmark — 1,292,058 Records"
            subtitle="Source: ML/reports/model_comparison.md · 5,034 features (TF-IDF 5,000 + 34 lexical)"
            badge="XGBoost vs CatBoost"
          />

          {/* Split Switcher */}
          <div className="mb-5 flex items-center gap-1.5 rounded-xl border border-[#E4DEC6] bg-[#FAF8F5] p-1 w-fit">
            {UNIFIED_SPLITS.map((s, idx) => (
              <button key={s.label} onClick={() => setSplit(idx)}
                className={`rounded-lg px-4 py-1.5 text-xs font-bold transition-all font-poppins ${
                  split === idx ? "bg-[#C48A5A] text-white shadow-sm" : "text-gray-500 hover:text-gray-800"
                }`}>
                {s.label}
              </button>
            ))}
          </div>

          <div className="mb-3 flex items-center gap-2">
            <FileCheck className="h-4 w-4 text-[#34A853]" />
            <span className="text-xs font-semibold text-gray-500 font-manrope">
              Test samples: <strong className="text-gray-800">{current.testSamples.toLocaleString()}</strong> ·
              Dataset: 1,292,058 records total · Binary classification (0 = Benign, 1 = Malicious)
            </span>
          </div>

          <TableWrapper>
            <THead cols={["Model", "Rank", "Test Samples", "Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC", "Train Time", "Inference Time"]} />
            <tbody className="divide-y divide-[#E4DEC6]/40">
              {current.rows.map((r) => (
                <tr key={r.model}
                  className={`transition-colors ${r.winner ? "bg-[#34A853]/[0.03] hover:bg-[#34A853]/[0.06]" : "hover:bg-[#FAF8F5]/70"}`}>
                  <td className="px-4 py-3.5 font-bold text-gray-800 font-poppins">
                    <div className="flex items-center gap-2">
                      {r.winner && <span className="rounded-md bg-[#34A853]/15 text-[#34A853] px-1.5 py-0.5 text-[9px] font-extrabold uppercase font-poppins">Winner</span>}
                      {r.model}
                    </div>
                  </td>
                  <td className="px-4 py-3.5 text-gray-600 text-[11px]">{r.winner ? "🥇 Best Overall" : "🥈 Runner-up"}</td>
                  <td className="px-4 py-3.5 text-right font-mono text-gray-600">{current.testSamples.toLocaleString()}</td>
                  <td className="px-4 py-3.5 text-right font-extrabold text-gray-900 font-poppins">{pct(r.accuracy)}</td>
                  <td className="px-4 py-3.5 text-right text-gray-700 font-semibold">{pct(r.precision)}</td>
                  <td className="px-4 py-3.5 text-right text-gray-700 font-semibold">{pct(r.recall)}</td>
                  <td className="px-4 py-3.5 text-right font-extrabold text-[#C48A5A] font-poppins">{pct(r.f1)}</td>
                  <td className="px-4 py-3.5 text-right font-semibold text-[#4F7EF7]">{pct(r.rocAuc)}</td>
                  <td className="px-4 py-3.5 text-right font-mono text-gray-500">{r.trainTime}</td>
                  <td className="px-4 py-3.5 text-right font-mono text-gray-500">{r.inferTime}</td>
                </tr>
              ))}
            </tbody>
          </TableWrapper>

          {/* All-splits summary table */}
          <div className="mt-6">
            <h3 className="mb-3 text-xs font-bold uppercase tracking-wider text-gray-500 font-poppins">
              All Splits — F1-Score & ROC-AUC Summary
            </h3>
            <div className="overflow-x-auto rounded-2xl border border-[#E4DEC6]/70">
              <table className="w-full text-[12px] font-manrope border-collapse min-w-[520px]">
                <thead>
                  <tr className="bg-[#FAF8F5] border-b border-[#E4DEC6]/70 text-[11px] font-bold uppercase tracking-wide text-gray-500 font-poppins">
                    <th className="px-4 py-3 text-left">Split</th>
                    <th className="px-4 py-3 text-right">XGBoost Accuracy</th>
                    <th className="px-4 py-3 text-right">XGBoost F1</th>
                    <th className="px-4 py-3 text-right">XGBoost ROC-AUC</th>
                    <th className="px-4 py-3 text-right">CatBoost Accuracy</th>
                    <th className="px-4 py-3 text-right">CatBoost F1</th>
                    <th className="px-4 py-3 text-right">CatBoost ROC-AUC</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E4DEC6]/40">
                  {UNIFIED_SPLITS.map((s) => {
                    const xgb = s.rows[0];
                    const cat = s.rows[1];
                    return (
                      <tr key={s.label} className="hover:bg-[#FAF8F5]/70 transition-colors">
                        <td className="px-4 py-3 font-bold text-gray-800 font-poppins">{s.label}</td>
                        <td className="px-4 py-3 text-right font-semibold text-gray-700">{pct(xgb.accuracy)}</td>
                        <td className="px-4 py-3 text-right font-extrabold text-[#C48A5A] font-poppins">{pct(xgb.f1)}</td>
                        <td className="px-4 py-3 text-right font-semibold text-[#4F7EF7]">{pct(xgb.rocAuc)}</td>
                        <td className="px-4 py-3 text-right font-semibold text-gray-700">{pct(cat.accuracy)}</td>
                        <td className="px-4 py-3 text-right font-extrabold text-[#C48A5A] font-poppins">{pct(cat.f1)}</td>
                        <td className="px-4 py-3 text-right font-semibold text-[#4F7EF7]">{pct(cat.rocAuc)}</td>
                      </tr>
                    );
                  })}
                  {/* Avg row */}
                  <tr className="bg-[#C48A5A]/[0.04] border-t-2 border-[#C48A5A]/20 font-bold">
                    <td className="px-4 py-3 text-[#C48A5A] font-poppins">Avg (all splits)</td>
                    <td className="px-4 py-3 text-right text-gray-700">90.70%</td>
                    <td className="px-4 py-3 text-right text-[#C48A5A] font-poppins">89.52%</td>
                    <td className="px-4 py-3 text-right text-[#4F7EF7]">97.37%</td>
                    <td className="px-4 py-3 text-right text-gray-700">90.57%</td>
                    <td className="px-4 py-3 text-right text-[#C48A5A] font-poppins">89.32%</td>
                    <td className="px-4 py-3 text-right text-[#4F7EF7]">97.17%</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Chart */}
          <div className="mt-6 rounded-2xl border border-[#E4DEC6]/70 bg-[#FAF8F5]/50 p-5">
            <h4 className="mb-3 text-xs font-bold uppercase tracking-wider text-gray-600 font-poppins">
              80:20 Split — Visual Metric Comparison (XGBoost vs CatBoost)
            </h4>
            <div className="h-60">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={masterChart} margin={{ top: 8, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid stroke="#f2eee8" />
                  <XAxis dataKey="m" stroke="#8E8E93" fontSize={11} fontFamily="sans-serif" />
                  <YAxis domain={[80, 100]} stroke="#8E8E93" fontSize={11} fontFamily="sans-serif" />
                  <Tooltip contentStyle={{ background: "#FFFFFF", border: "1px solid #E4DEC6", borderRadius: 12, fontSize: 12 }} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Bar dataKey="XGBoost" name="XGBoost 🥇" fill="#C48A5A" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="CatBoost" name="CatBoost 🥈" fill="#4F7EF7" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </motion.div>

        {/* ═══════════════════════════════════════════════════════
            SECTION 3 — TEXT SCAM CLASSIFIER HEAD-TO-HEAD
        ═══════════════════════════════════════════════════════ */}
        <motion.div initial={{ opacity: 0, y: 18 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
          className="rounded-3xl bg-white border border-[#E4DEC6]/80 p-6 sm:p-8 shadow-sm">

          <SectionHeader
            icon={TrendingUp}
            num="03"
            title="Text Scam Classifier — Head-to-Head Benchmark"
            subtitle="Source: ML/evaluation/comparison_report.json · Same text corpus · Direct comparison only"
            badge="NLP Text Task"
          />

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2 items-start">
            <TableWrapper>
              <THead cols={["Model", "Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC"]} />
              <tbody className="divide-y divide-[#E4DEC6]/40">
                {TEXT_H2H.map((r) => (
                  <tr key={r.model}
                    className={`transition-colors ${r.highlight ? "bg-[#8E24AA]/[0.03] hover:bg-[#8E24AA]/[0.06]" : "hover:bg-[#FAF8F5]/70"}`}>
                    <td className="px-4 py-3.5 font-bold text-gray-800 font-poppins">
                      <div className="flex items-center gap-2">
                        {r.highlight && <span className="rounded-md bg-[#8E24AA]/15 text-[#8E24AA] px-1.5 py-0.5 text-[9px] font-extrabold uppercase">Best</span>}
                        {r.model}
                      </div>
                    </td>
                    <td className="px-4 py-3.5 text-right font-extrabold text-gray-900 font-poppins">{pct(r.accuracy)}</td>
                    <td className="px-4 py-3.5 text-right text-gray-700 font-semibold">{pct(r.precision)}</td>
                    <td className="px-4 py-3.5 text-right text-gray-700 font-semibold">{pct(r.recall)}</td>
                    <td className="px-4 py-3.5 text-right font-extrabold text-[#C48A5A] font-poppins">{pct(r.f1)}</td>
                    <td className="px-4 py-3.5 text-right font-semibold text-[#4F7EF7]">{pct(r.rocAuc)}</td>
                  </tr>
                ))}
              </tbody>
            </TableWrapper>

            <div className="rounded-2xl border border-[#E4DEC6]/70 bg-[#FAF8F5]/50 p-5">
              <h4 className="mb-3 text-xs font-bold uppercase tracking-wider text-gray-600 font-poppins">
                Text Classification Metrics (Y-axis: 95–100%)
              </h4>
              <div className="h-52">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={textChart} margin={{ top: 8, right: 10, left: -20, bottom: 0 }}>
                    <CartesianGrid stroke="#f2eee8" />
                    <XAxis dataKey="m" stroke="#8E8E93" fontSize={11} fontFamily="sans-serif" />
                    <YAxis domain={[95, 100]} stroke="#8E8E93" fontSize={11} fontFamily="sans-serif" />
                    <Tooltip contentStyle={{ background: "#FFFFFF", border: "1px solid #E4DEC6", borderRadius: 12, fontSize: 12 }} />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    <Bar dataKey="CatBoost" name="CatBoost (Best)" fill="#8E24AA" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="XGBoost" name="XGBoost" fill="#C48A5A" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        </motion.div>

        {/* ═══════════════════════════════════════════════════════
            SECTION 4 — MODEL ARCHITECTURE & REGISTRY TABLE
        ═══════════════════════════════════════════════════════ */}
        <motion.div initial={{ opacity: 0, y: 18 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
          className="rounded-3xl bg-white border border-[#E4DEC6]/80 p-6 sm:p-8 shadow-sm">

          <SectionHeader
            icon={Cpu}
            num="04"
            title="Model Architecture & Pipeline Status Registry"
            subtitle="All architectures evaluated, attempted, or referenced in the Threat Intelligence repository"
            badge="Zero Fabricated Metrics"
          />

          {/* Architecture Registry Table */}
          <TableWrapper>
            <THead cols={["Architecture", "Type", "Feature Space", "Applicable Domains", "Pipeline Status", "Standalone Eval Metrics"]} />
            <tbody className="divide-y divide-[#E4DEC6]/40">
              {ARCHITECTURES.map((a) => (
                <tr key={a.name} className="hover:bg-[#FAF8F5]/70 transition-colors">
                  <td className="px-4 py-3.5 font-bold text-gray-800 font-poppins whitespace-nowrap">{a.name}</td>
                  <td className="px-4 py-3.5 text-gray-600 text-[11px] max-w-[160px]">{a.type}</td>
                  <td className="px-4 py-3.5 text-gray-500 text-[11px] max-w-[180px]">{a.features}</td>
                  <td className="px-4 py-3.5 text-gray-600 text-[11px] max-w-[180px]">{a.domains}</td>
                  <td className="px-4 py-3.5">
                    <span className="rounded-full px-2.5 py-0.5 text-[10px] font-bold font-poppins whitespace-nowrap"
                      style={{ background: `${a.statusColor}18`, color: a.statusColor }}>
                      {a.status}
                    </span>
                  </td>
                  <td className="px-4 py-3.5 text-center">
                    {a.hasMetrics
                      ? <span className="inline-flex items-center gap-1 text-[#34A853] font-semibold text-[11px]"><CheckCircle2 className="h-3.5 w-3.5" /> Available</span>
                      : <span className="inline-flex items-center gap-1 text-[#9E9E9E] font-semibold text-[11px]"><AlertCircle className="h-3.5 w-3.5" /> N/A</span>
                    }
                  </td>
                </tr>
              ))}
            </tbody>
          </TableWrapper>

          {/* Architecture detail notes */}
          <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {ARCHITECTURES.map((a) => (
              <div key={a.name}
                className="rounded-2xl border border-[#E4DEC6]/70 bg-[#FAF8F5]/40 p-4 hover:bg-[#FAF8F5] transition-colors">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-bold text-gray-800 font-poppins">{a.name}</span>
                  <span className="rounded-full px-2 py-0.5 text-[10px] font-bold font-poppins"
                    style={{ background: `${a.statusColor}18`, color: a.statusColor }}>
                    {a.hasMetrics ? "Evaluated" : "N/A"}
                  </span>
                </div>
                <p className="text-[11px] text-gray-500 font-manrope leading-relaxed">{a.note}</p>
              </div>
            ))}
          </div>
        </motion.div>

        {/* ═══════════════════════════════════════════════════════
            DISCLAIMER BANNER
        ═══════════════════════════════════════════════════════ */}
        <div className="rounded-2xl border border-[#E4DEC6]/70 bg-[#FAF8F5] p-4 flex items-start gap-3 text-xs text-gray-500 font-manrope">
          <AlertCircle className="h-4 w-4 shrink-0 text-[#C48A5A] mt-0.5" />
          <div>
            <strong className="text-gray-700 font-poppins">Data Integrity Note:</strong>{" "}
            All metrics displayed on this page are sourced exclusively from existing project evaluation files
            (<code className="text-[#C48A5A]">ML/models/model_metadata.json</code>,{" "}
            <code className="text-[#C48A5A]">ML/evaluation/metrics.json</code>,{" "}
            <code className="text-[#C48A5A]">ML/evaluation/comparison_report.json</code>,{" "}
            <code className="text-[#C48A5A]">ML/reports/model_comparison.md</code>).
            No metrics have been fabricated, estimated, or randomized. No model weights were modified.
          </div>
        </div>

        {/* Footer CTA */}
        <div className="flex flex-wrap items-center justify-between gap-4 rounded-3xl border border-[#C48A5A]/30 bg-[#C48A5A]/5 p-6">
          <div>
            <h3 className="text-base font-bold text-gray-800 font-poppins">Explore Live Threat Detection</h3>
            <p className="text-xs font-semibold text-gray-500 font-manrope mt-0.5">
              Test detection algorithms in real-time using the multi-channel security scanner.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <Link to="/call-sms-intel"
              className="rounded-xl bg-[#C48A5A] px-5 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-[#C48A5A]/90 transition-all font-manrope">
              Run Security Scanner
            </Link>
            <Link to="/threats"
              className="rounded-xl border border-[#C48A5A] px-5 py-2.5 text-xs font-bold text-[#C48A5A] hover:bg-[#C48A5A]/5 transition-all font-manrope">
              View Threat Feed
            </Link>
          </div>
        </div>

      </div>
      <SiteFooter />
    </div>
  );
}
