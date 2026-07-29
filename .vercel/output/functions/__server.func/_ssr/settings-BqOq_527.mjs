import { j as jsxRuntimeExports } from "../_libs/react.mjs";
import { L as Link } from "../_libs/tanstack__react-router.mjs";
import { m as motion } from "../_libs/framer-motion.mjs";
import { A as ArrowLeft, e as Settings, B as Bell, S as Shield, D as Database, p as Palette, G as Globe, q as Lock } from "../_libs/lucide-react.mjs";
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
const SETTINGS_SECTIONS = [{
  icon: Bell,
  label: "Notifications",
  desc: "Configure alert thresholds and notification channels",
  color: "#C48A5A"
}, {
  icon: Shield,
  label: "Security",
  desc: "API keys, authentication and access control settings",
  color: "#E05A52"
}, {
  icon: Database,
  label: "Data Sources",
  desc: "Manage connected threat intelligence feeds",
  color: "#4F7EF7"
}, {
  icon: Palette,
  label: "Appearance",
  desc: "Theme preferences, layout and display density",
  color: "#7C5CBF"
}, {
  icon: Globe,
  label: "Integrations",
  desc: "Third-party SIEM, SOAR and ticketing connections",
  color: "#34A853"
}, {
  icon: Lock,
  label: "Privacy & Audit",
  desc: "Data retention policies and compliance settings",
  color: "#E8A23C"
}];
function SettingsPage() {
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
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex h-14 w-14 items-center justify-center rounded-2xl bg-[#4F7EF7]/10 border border-[#4F7EF7]/25", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Settings, { className: "h-7 w-7 text-[#4F7EF7]" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-2xl font-extrabold text-gray-800 font-poppins", children: "⚙️ Settings" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold text-gray-500 font-manrope mt-0.5", children: "Platform configuration and preferences" })
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
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-[#FAF8F5] border border-[#E4DEC6]", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Settings, { className: "h-8 w-8 text-[#4F7EF7]" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-extrabold text-gray-800 font-poppins mb-2", children: "Module Under Development" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-gray-500 font-manrope max-w-sm mx-auto leading-relaxed", children: "The Settings module is currently being configured. Full control over notifications, integrations, security policies, and appearance will be available here soon." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 inline-flex items-center gap-2 rounded-full border border-[#4F7EF7]/30 bg-[#4F7EF7]/10 px-4 py-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-1.5 w-1.5 rounded-full bg-[#4F7EF7] animate-pulse" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-bold text-[#4F7EF7] font-manrope", children: "Coming Soon" })
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
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mb-4 text-[11px] font-bold uppercase tracking-wider text-gray-400 font-manrope", children: "Planned Settings Sections" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-1 gap-4 sm:grid-cols-2", children: SETTINGS_SECTIONS.map((section) => {
        const Icon = section.icon;
        return /* @__PURE__ */ jsxRuntimeExports.jsxs(motion.div, { whileHover: {
          y: -2
        }, className: "flex items-start gap-4 rounded-2xl border border-[#E4DEC6] bg-white p-5 shadow-sm opacity-60 cursor-not-allowed", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex h-10 w-10 shrink-0 items-center justify-center rounded-xl", style: {
            background: `${section.color}15`
          }, children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-5 w-5", style: {
            color: section.color
          } }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold text-gray-700 font-poppins", children: section.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-[10px] font-semibold text-gray-400 font-manrope", children: section.desc })
          ] })
        ] }, section.label);
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
  SettingsPage as component
};
