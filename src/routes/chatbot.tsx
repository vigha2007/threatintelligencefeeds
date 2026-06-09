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
    <div className="relative flex h-screen flex-col">
      {/* Compact Header */}
      <header className="relative z-10 mx-auto w-full max-w-7xl shrink-0 px-4 pt-2 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
          className="glass flex items-center justify-between gap-3 rounded-2xl p-2.5 sm:p-3"
        >
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-[#00D4FF] to-[#7B61FF] glow-cyan">
              <Shield className="h-4 w-4 text-white" />
            </div>
            <div>
              <div className="text-sm font-bold text-white sm:text-base">
                <span aria-hidden>🛡️</span> Scam Detector AI
              </div>
              <p className="text-[11px] leading-tight text-muted-foreground sm:text-xs">
                Detect scams, phishing &amp; fraud instantly.
              </p>
            </div>
          </div>
          <Link
            to="/"
            className="inline-flex items-center gap-1.5 rounded-full border border-[#00D4FF]/40 bg-[#00D4FF]/10 px-2.5 py-1.5 text-xs font-medium text-[#00D4FF] transition-all hover:bg-[#00D4FF]/20 hover:glow-cyan sm:px-3"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">Back to Dashboard</span>
            <span className="sm:hidden">Back</span>
          </Link>
        </motion.div>
      </header>

      {/* Chatbot iframe — fills remaining viewport */}
      <main className="mx-auto flex w-full max-w-7xl flex-1 flex-col px-4 pb-2 pt-2 sm:px-6 sm:pb-3 sm:pt-3 lg:px-8">
        <motion.section
          initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="glass flex flex-1 flex-col overflow-hidden rounded-2xl sm:rounded-3xl"
        >
          <div className="flex shrink-0 items-center justify-between border-b border-white/5 px-4 py-2">
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-[#FF4D4D]" />
              <span className="h-2.5 w-2.5 rounded-full bg-[#FFB020]" />
              <span className="h-2.5 w-2.5 rounded-full bg-[#00FFA3]" />
              <span className="ml-2 text-[11px] font-medium text-muted-foreground">
                scam-detector.ai · secure session
              </span>
            </div>
            <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-[#00FFA3]">
              <span className="h-1.5 w-1.5 animate-pulse-dot rounded-full bg-[#00FFA3]" />
              Online
            </span>
          </div>
          <div className="flex-1 overflow-hidden bg-[#0A0F1F]">
            <iframe
              src={CHATBOT_URL}
              width="100%"
              height="100%"
              frameBorder="0"
              allowFullScreen
              title="Scam Detector AI Chatbot"
              className="block h-full w-full"
            />
          </div>
        </motion.section>
      </main>

      {/* Minimal footer */}
      <footer className="relative z-10 shrink-0 border-t border-white/5 py-2 text-center">
        <p className="text-[11px] text-muted-foreground">
          Powered by Scam Detector AI <span aria-hidden>🛡️</span>
        </p>
      </footer>
    </div>
  );
}
