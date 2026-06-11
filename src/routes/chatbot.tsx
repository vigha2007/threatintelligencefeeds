import { createFileRoute, Link } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { Shield, ArrowLeft } from "lucide-react";
import { CHATBOT_URL } from "@/lib/chatbot-config";

export const Route = createFileRoute("/chatbot")({
  head: () => ({
    meta: [
      { title: "Chatbot — Scam Detector AI" },
      { name: "description", content: "Analyze suspicious content with the Scam Detector AI chatbot." },
    ],
  }),
  component: ChatbotPage,
});

function ChatbotPage() {
  return (
    <div className="flex h-[calc(100vh-57px)] flex-col bg-[#0A0F1F]">
      <header className="border-b border-white/5 bg-white/[0.02]">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-3 px-4 py-2.5 sm:px-6 sm:py-3 lg:px-8">
          <motion.div initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} className="flex items-center gap-2 min-w-0">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-[#00D4FF] to-[#7B61FF]">
              <Shield className="h-4 w-4 text-white" />
            </div>
            <div className="min-w-0">
              <h1 className="truncate text-sm font-semibold text-white sm:text-base">🛡️ Scam Detector AI</h1>
              <p className="truncate text-[11px] text-muted-foreground sm:text-xs">Detect scams, phishing &amp; fraud instantly.</p>
            </div>
          </motion.div>
          <Link to="/dashboard" className="flex shrink-0 items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-2.5 py-1.5 text-xs font-medium text-white transition-colors hover:bg-white/10">
            <ArrowLeft className="h-3.5 w-3.5" /> <span className="hidden sm:inline">Back to Dashboard</span>
          </Link>
        </div>
      </header>
      <main className="flex-1 overflow-hidden">
        <iframe
          src={CHATBOT_URL}
          width="100%"
          height="100%"
          style={{ border: 0, display: "block" }}
          allowFullScreen
          title="Scam Detector AI Chatbot"
        />
      </main>
    </div>
  );
}
