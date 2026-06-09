import { createFileRoute, Link } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { ArrowLeft, Shield } from "lucide-react";
import { SiteFooter } from "@/components/site-footer";
import { CHATBOT_URL } from "@/lib/chatbot-config";

export const Route = createFileRoute("/chatbot")({
  head: () => ({
    meta: [
      { title: "Scam Detector AI — Chatbot" },
      { name: "description", content: "Detect Scam Emails, Messages, Calls & Phishing Links Instantly." },
      { property: "og:title", content: "Scam Detector AI — Chatbot" },
      { property: "og:description", content: "Analyze emails, messages, calls and URLs for scam indicators in real time." },
    ],
  }),
  component: ChatbotPage,
});

function ChatbotPage() {
  return (
    <div className="relative min-h-screen">
      {/* Header */}
      <header className="relative z-10 mx-auto max-w-7xl px-4 pt-8 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
          className="glass flex items-center justify-between gap-4 rounded-2xl p-4 sm:p-5"
        >
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-gradient-to-br from-[#00D4FF] to-[#7B61FF] glow-cyan">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <div>
              <div className="text-base font-bold text-white sm:text-lg">
                <span aria-hidden>🛡️</span> Scam Detector AI
              </div>
              <p className="text-xs text-muted-foreground sm:text-sm">
                Detect Scam Emails, Messages, Calls &amp; Phishing Links Instantly
              </p>
            </div>
          </div>
          <Link
            to="/"
            className="inline-flex items-center gap-2 rounded-full border border-[#00D4FF]/40 bg-[#00D4FF]/10 px-3 py-2 text-sm font-medium text-[#00D4FF] transition-all hover:bg-[#00D4FF]/20 hover:glow-cyan sm:px-4"
          >
            <ArrowLeft className="h-4 w-4" />
            <span className="hidden sm:inline">Back to Dashboard</span>
            <span className="sm:hidden">Back</span>
          </Link>
        </motion.div>
      </header>

      <main className="mx-auto max-w-7xl px-4 py-4 sm:px-6 lg:px-8">
        {/* Welcome — compact */}
        <motion.section
          initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="glass relative overflow-hidden rounded-2xl px-4 py-3 sm:px-6 sm:py-4"
        >
          <div className="relative flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2">
              <span className="text-lg" aria-hidden>🛡️</span>
              <h1 className="text-sm font-bold text-white sm:text-base">Scam Detector AI</h1>
            </div>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
              <span className="inline-flex items-center gap-1"><span aria-hidden>📧</span> Emails</span>
              <span className="inline-flex items-center gap-1"><span aria-hidden>💬</span> Messages</span>
              <span className="inline-flex items-center gap-1"><span aria-hidden>📞</span> Calls</span>
              <span className="inline-flex items-center gap-1"><span aria-hidden>🔗</span> URLs</span>
              <span className="inline-flex items-center gap-1"><span aria-hidden>⚠️</span> Phishing</span>
            </div>
            <p className="w-full text-xs text-muted-foreground sm:w-auto sm:text-sm">Paste content below for analysis.</p>
          </div>
        </motion.section>

        {/* Chatbot iframe container */}
        <motion.section
          initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="glass mt-3 overflow-hidden rounded-3xl p-2 sm:p-3"
        >
          <div className="flex items-center justify-between border-b border-white/5 px-4 py-3">
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-[#FF4D4D]" />
              <span className="h-3 w-3 rounded-full bg-[#FFB020]" />
              <span className="h-3 w-3 rounded-full bg-[#00FFA3]" />
              <span className="ml-3 text-xs font-medium text-muted-foreground">
                scam-detector.ai · secure session
              </span>
            </div>
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#00FFA3]">
              <span className="h-2 w-2 animate-pulse-dot rounded-full bg-[#00FFA3]" />
              Online
            </span>
          </div>
          <div className="overflow-hidden rounded-2xl bg-[#0A0F1F]">
            <iframe
              src={CHATBOT_URL}
              width="100%"
              height="900px"
              frameBorder="0"
              allowFullScreen
              title="Scam Detector AI Chatbot"
              className="block w-full"
              style={{ minHeight: "900px" }}
            />
          </div>
        </motion.section>
      </main>

      <SiteFooter />
    </div>
  );
}
