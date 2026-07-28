import { createFileRoute, Link } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { Settings, ArrowLeft, Bell, Shield, Database, Palette, Globe, Lock } from "lucide-react";

export const Route = createFileRoute("/settings")({
  head: () => ({
    meta: [
      { title: "Settings — Threat Intelligence" },
      { name: "description", content: "Configure your Threat Intelligence platform settings and preferences." },
    ],
  }),
  component: SettingsPage,
});

const SETTINGS_SECTIONS = [
  { icon: Bell,     label: "Notifications",     desc: "Configure alert thresholds and notification channels", color: "#C48A5A" },
  { icon: Shield,   label: "Security",           desc: "API keys, authentication and access control settings", color: "#E05A52" },
  { icon: Database, label: "Data Sources",       desc: "Manage connected threat intelligence feeds", color: "#4F7EF7" },
  { icon: Palette,  label: "Appearance",         desc: "Theme preferences, layout and display density", color: "#7C5CBF" },
  { icon: Globe,    label: "Integrations",       desc: "Third-party SIEM, SOAR and ticketing connections", color: "#34A853" },
  { icon: Lock,     label: "Privacy & Audit",    desc: "Data retention policies and compliance settings", color: "#E8A23C" },
];

function SettingsPage() {
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
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-[#4F7EF7]/10 border border-[#4F7EF7]/25">
            <Settings className="h-7 w-7 text-[#4F7EF7]" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold text-gray-800 font-poppins">⚙️ Settings</h1>
            <p className="text-xs font-semibold text-gray-500 font-manrope mt-0.5">
              Platform configuration and preferences
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
          <Settings className="h-8 w-8 text-[#4F7EF7]" />
        </div>
        <h2 className="text-lg font-extrabold text-gray-800 font-poppins mb-2">
          Module Under Development
        </h2>
        <p className="text-sm font-semibold text-gray-500 font-manrope max-w-sm mx-auto leading-relaxed">
          The Settings module is currently being configured. Full control over notifications, integrations, security policies, and appearance will be available here soon.
        </p>
        <div className="mt-6 inline-flex items-center gap-2 rounded-full border border-[#4F7EF7]/30 bg-[#4F7EF7]/10 px-4 py-2">
          <span className="h-1.5 w-1.5 rounded-full bg-[#4F7EF7] animate-pulse" />
          <span className="text-[11px] font-bold text-[#4F7EF7] font-manrope">Coming Soon</span>
        </div>
      </motion.div>

      {/* Settings section previews */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, delay: 0.2 }}
      >
        <p className="mb-4 text-[11px] font-bold uppercase tracking-wider text-gray-400 font-manrope">
          Planned Settings Sections
        </p>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {SETTINGS_SECTIONS.map((section) => {
            const Icon = section.icon;
            return (
              <motion.div
                key={section.label}
                whileHover={{ y: -2 }}
                className="flex items-start gap-4 rounded-2xl border border-[#E4DEC6] bg-white p-5 shadow-sm opacity-60 cursor-not-allowed"
              >
                <div
                  className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl"
                  style={{ background: `${section.color}15` }}
                >
                  <Icon className="h-5 w-5" style={{ color: section.color }} />
                </div>
                <div>
                  <p className="text-xs font-bold text-gray-700 font-poppins">{section.label}</p>
                  <p className="mt-0.5 text-[10px] font-semibold text-gray-400 font-manrope">{section.desc}</p>
                </div>
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
