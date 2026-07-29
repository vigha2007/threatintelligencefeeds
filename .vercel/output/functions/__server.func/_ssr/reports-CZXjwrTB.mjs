import { j as jsxRuntimeExports } from "../_libs/react.mjs";
import { L as Link } from "../_libs/tanstack__react-router.mjs";
import { m as motion } from "../_libs/framer-motion.mjs";
import { A as ArrowLeft, F as FileText, r as ChartNoAxesColumn, S as Shield, s as TrendingUp, t as Download } from "../_libs/lucide-react.mjs";
import "../_libs/tanstack__router-core.mjs";
import "../_libs/tanstack__history.mjs";
import "../_libs/cookie-es.mjs";
import "../_libs/seroval.mjs";
import "../_libs/seroval-plugins.mjs";
import "node:stream/web";
import "node:stream";
import "../_libs/react-dom.mjs";
import "util";
import "crypto";
import "async_hooks";
import "stream";
import "../_libs/isbot.mjs";
import "../_libs/motion-dom.mjs";
import "../_libs/motion-utils.mjs";
const REPORT_CATEGORIES = [{
  icon: Shield,
  label: "Threat Summary",
  desc: "Weekly threat feed digest and severity breakdown",
  color: "#C48A5A"
}, {
  icon: ChartNoAxesColumn,
  label: "Analytics Report",
  desc: "Scam call and phishing trend analysis",
  color: "#4F7EF7"
}, {
  icon: TrendingUp,
  label: "Risk Assessment",
  desc: "IP reputation and malware indicator reports",
  color: "#34A853"
}, {
  icon: FileText,
  label: "Audit Logs",
  desc: "Complete event log exports and audit trails",
  color: "#E8A23C"
}];
function ReportsPage() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mx-auto max-w-4xl px-4 py-12 sm:px-6 lg:px-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(motion.div, { initial: {
      opacity: 0,
      y: 16
    }, animate: {
      opacity: 1,
      y: 0
    }, transition: {
      duration: 0.45
    }, className: "mb-8", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(Link, { to: "/dashboard", className: "mb-6 inline-flex items-center gap-1.5 text-xs font-bold text-gray-500 hover:text-[#C48A5A] transition-colors font-manrope", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(ArrowLeft, { className: "h-3.5 w-3.5" }),
        " Back to Dashboard"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-4 mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex h-14 w-14 items-center justify-center rounded-2xl bg-[#C48A5A]/10 border border-[#C48A5A]/25", children: /* @__PURE__ */ jsxRuntimeExports.jsx(FileText, { className: "h-7 w-7 text-[#C48A5A]" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-2xl font-extrabold text-gray-800 font-poppins", children: "📄 Reports" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold text-gray-500 font-manrope mt-0.5", children: "Security intelligence reports and export center" })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(motion.div, { initial: {
      opacity: 0,
      y: 12
    }, animate: {
      opacity: 1,
      y: 0
    }, transition: {
      duration: 0.45,
      delay: 0.1
    }, className: "mb-8 rounded-3xl border border-[#E4DEC6] bg-white p-8 shadow-sm text-center", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-[#FAF8F5] border border-[#E4DEC6]", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ChartNoAxesColumn, { className: "h-8 w-8 text-[#C48A5A]" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-extrabold text-gray-800 font-poppins mb-2", children: "Module Under Development" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-gray-500 font-manrope max-w-sm mx-auto leading-relaxed", children: "The Reports module is currently being built. Advanced analytics, PDF exports, and scheduled reports will be available here soon." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 inline-flex items-center gap-2 rounded-full border border-[#E8A23C]/30 bg-[#E8A23C]/10 px-4 py-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-1.5 w-1.5 rounded-full bg-[#E8A23C] animate-pulse" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-bold text-[#E8A23C] font-manrope", children: "Coming Soon" })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(motion.div, { initial: {
      opacity: 0,
      y: 12
    }, animate: {
      opacity: 1,
      y: 0
    }, transition: {
      duration: 0.45,
      delay: 0.2
    }, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mb-4 text-[11px] font-bold uppercase tracking-wider text-gray-400 font-manrope", children: "Planned Report Types" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-1 gap-4 sm:grid-cols-2", children: REPORT_CATEGORIES.map((cat) => {
        const Icon = cat.icon;
        return /* @__PURE__ */ jsxRuntimeExports.jsxs(motion.div, { whileHover: {
          y: -2
        }, className: "flex items-start gap-4 rounded-2xl border border-[#E4DEC6] bg-white p-5 shadow-sm opacity-60 cursor-not-allowed", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex h-10 w-10 shrink-0 items-center justify-center rounded-xl", style: {
            background: `${cat.color}15`
          }, children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-5 w-5", style: {
            color: cat.color
          } }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold text-gray-700 font-poppins", children: cat.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-[10px] font-semibold text-gray-400 font-manrope", children: cat.desc })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Download, { className: "ml-auto h-4 w-4 text-gray-300 shrink-0 mt-0.5" })
        ] }, cat.label);
      }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(motion.div, { initial: {
      opacity: 0
    }, animate: {
      opacity: 1
    }, transition: {
      duration: 0.4,
      delay: 0.35
    }, className: "mt-8 flex justify-center", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(Link, { to: "/dashboard", className: "inline-flex items-center gap-2 rounded-2xl bg-[#C48A5A] px-6 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-[#C48A5A]/90 transition-colors font-poppins", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(ArrowLeft, { className: "h-3.5 w-3.5" }),
      " Back to Dashboard"
    ] }) })
  ] });
}
export {
  ReportsPage as component
};
