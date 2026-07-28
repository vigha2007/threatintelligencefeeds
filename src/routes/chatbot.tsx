import { createFileRoute, Link } from "@tanstack/react-router";
import { motion, AnimatePresence } from "framer-motion";
import { useState, useRef, useEffect } from "react";
import {
  Shield,
  Plus,
  Search,
  Download,
  Settings,
  Pin,
  Trash2,
  ChevronRight,
  Phone,
  Globe,
  Mail,
  MapPin,
  AlertTriangle,
  BookOpen,
  MessageSquare,
  Clock,
  Send,
  Paperclip,
  Mic,
  Image as ImageIcon,
  ArrowLeft,
  Loader2,
  CheckCircle,
  AlertCircle,
  MoreHorizontal,
  ChevronDown,
} from "lucide-react";
import { analyzeSms } from "../lib/intel-analyzers";

export const Route = createFileRoute("/chatbot")({
  head: () => ({
    meta: [
      { title: "Cyber Sentinel AI — Threat Intelligence" },
      { name: "description", content: "Premium AI-powered cybersecurity assistant for threat analysis, phishing detection, and intelligence." },
    ],
  }),
  component: ChatbotPage,
});

/* ─── Types ─────────────────────────────────────────────── */
interface ChatSession {
  id: string;
  title: string;
  preview: string;
  timestamp: string;
  pinned: boolean;
}

interface ChatMessage {
  id: string;
  sender: "user" | "ai";
  text: string;
  timestamp: string;
  analysis?: {
    score: number;
    status: "legitimate" | "suspicious" | "scam";
    category: string;
    reasons: string[];
    summary: string;
  };
}

/* ─── Static demo sessions ───────────────────────────────── */
const INITIAL_SESSIONS: ChatSession[] = [
  { id: "s1", title: "Phone scam analysis", preview: "+91 9876543210 — suspicious call", timestamp: "2m ago", pinned: true },
  { id: "s2", title: "Phishing URL scan", preview: "paypal-secure-login.ru flagged", timestamp: "1h ago", pinned: true },
  { id: "s3", title: "Email threat check", preview: "prize@giveaway.tk is malicious", timestamp: "3h ago", pinned: false },
  { id: "s4", title: "IP reputation lookup", preview: "45.142.212.100 — C2 server", timestamp: "Yesterday", pinned: false },
];

/* ─── Quick-action cards ─────────────────────────────────── */
const QUICK_ACTIONS = [
  { icon: Phone,     label: "Analyze Phone Number",  color: "#C48A5A", bg: "#C48A5A15", text: "+91 98765 43210" },
  { icon: Globe,     label: "Scan URL",               color: "#4F7EF7", bg: "#4F7EF715", text: "secure-login-update.xyz" },
  { icon: Mail,      label: "Analyze Email",          color: "#34A853", bg: "#34A85315", text: "Dear customer, your bank account has been suspended. Please click here to restore access." },
  { icon: MapPin,    label: "Check IP Address",       color: "#E8A23C", bg: "#E8A23C15", text: "185.220.101.5" },
  { icon: AlertTriangle, label: "Latest Threats",    color: "#E05A52", bg: "#E05A5215", text: "What are the latest cybersecurity threats today?" },
  { icon: BookOpen,  label: "Learn Cybersecurity",   color: "#7C5CBF", bg: "#7C5CBF15", text: "What are the best practices for protecting against phishing and identity theft?" },
];

/* ─── SVG watermark illustration ────────────────────────── */
function CyberWatermark() {
  return (
    <svg
      className="absolute inset-0 w-full h-full pointer-events-none select-none"
      viewBox="0 0 800 600"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <path d="M400 120 L460 150 L460 220 Q460 270 400 300 Q340 270 340 220 L340 150 Z" fill="#C48A5A" opacity="0.05" />
      <path d="M400 138 L448 163 L448 218 Q448 260 400 286 Q352 260 352 218 L352 163 Z" stroke="#C48A5A" strokeWidth="1.5" opacity="0.07" fill="none" />
      <rect x="387" y="210" width="26" height="20" rx="3" fill="#C48A5A" opacity="0.06" />
      <circle cx="160" cy="180" r="6" fill="#4F7EF7" opacity="0.05" />
      <circle cx="200" cy="280" r="4" fill="#4F7EF7" opacity="0.04" />
      <circle cx="640" cy="160" r="6" fill="#4F7EF7" opacity="0.05" />
      <circle cx="670" cy="280" r="4" fill="#34A853" opacity="0.04" />
      <line x1="160" y1="180" x2="340" y2="180" stroke="#4F7EF7" strokeWidth="0.8" opacity="0.04" strokeDasharray="4 4" />
      <line x1="460" y1="180" x2="640" y2="180" stroke="#4F7EF7" strokeWidth="0.8" opacity="0.04" strokeDasharray="4 4" />
      <circle cx="400" cy="460" r="70" stroke="#4F7EF7" strokeWidth="1" opacity="0.03" fill="none" />
    </svg>
  );
}

/* ─── AI Avatar ──────────────────────────────────────────── */
function AIAvatar({ size = 32 }: { size?: number }) {
  return (
    <div
      className="flex shrink-0 items-center justify-center rounded-full"
      style={{
        width: size, height: size,
        background: "linear-gradient(135deg, #C48A5A 0%, #E8A23C 50%, #4F7EF7 100%)",
        boxShadow: "0 2px 8px rgba(196,138,90,0.25)",
      }}
    >
      <Shield style={{ width: size * 0.45, height: size * 0.45, color: "white" }} />
    </div>
  );
}

/* ─── Response Generator ─────────────────────────────────── */
function generateAIResponse(userInput: string) {
  const text = userInput.trim();
  const lower = text.toLowerCase();

  // Regular expressions
  const phoneRegex = /^(\+?\d{1,4}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}$|^\+?\d{10,12}$/;
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const genericUrlRegex = /\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b/g;
  const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;

  let score = 90;
  let status: "legitimate" | "suspicious" | "scam" = "legitimate";
  let category = "Security Check";
  let reasons: string[] = [];
  let summary = "";

  // 1. IP address check
  if (ipRegex.test(text)) {
    const ip = text.match(ipRegex)![0];
    category = "IP Address Analysis";
    const lastOctet = parseInt(ip.split(".").pop() || "0");
    if (lastOctet % 2 === 0 || lastOctet > 200) {
      score = 18;
      status = "scam";
      reasons = [
        "IP address belongs to a VPS provider frequently abused for C2 servers.",
        "Multiple reports flag active port scanning from this source.",
        "Listed in community blocklists for malicious bot activity.",
      ];
      summary = `The IP address ${ip} is flagged as a high-risk malicious host. It is currently associated with scanning and botnet infrastructure.`;
    } else {
      score = 90;
      status = "legitimate";
      reasons = [
        "Clean reputation on global threat intelligence feeds.",
        "No historical record of malicious activity or spam delivery.",
        "Belongs to a reputable cloud provider network.",
      ];
      summary = `The IP address ${ip} appears clean. No malicious indicators or alerts exist in the security database.`;
    }
  }
  // 2. Phone number check
  else if (phoneRegex.test(text) || lower.includes("+91") || lower.includes("phone number")) {
    category = "Phone Intelligence";
    const digits = text.replace(/\D/g, "");
    if (digits.includes("98765") || digits.includes("8800") || digits.endsWith("1") || digits.endsWith("3")) {
      score = 22;
      status = "scam";
      reasons = [
        "VoIP line — commonly used for robocalls and caller ID spoofing.",
        "Multiple community reports of utility or bank representative spoofing.",
        "High-frequency automated dialing patterns detected.",
      ];
      summary = "This phone number has been flagged as a scam caller mimicking customer support channels. We recommend blocklisting this caller.";
    } else {
      score = 88;
      status = "legitimate";
      reasons = [
        "Registered mobile subscriber line with standard carrier verification.",
        "No telemarketing or fraudulent behavior reports in our database.",
        "Clean activity record for the last 180 days.",
      ];
      summary = "This caller number appears legitimate. No scam or spam alerts are associated with this record.";
    }
  }
  // 3. URL check
  else if (urlRegex.test(text) || genericUrlRegex.test(text)) {
    category = "URL Inspection";
    const url = text.match(urlRegex)?.[0] || text.match(genericUrlRegex)?.[0] || text;
    if (
      lower.includes("login") ||
      lower.includes("secure") ||
      lower.includes("update") ||
      lower.includes("bank") ||
      lower.includes("paypal") ||
      lower.includes(".ru") ||
      lower.includes(".xyz") ||
      lower.includes("verify")
    ) {
      score = 12;
      status = "scam";
      reasons = [
        "Domain mimics standard banking and payment portal layouts (phishing lookalike).",
        "Domain age is extremely young (less than 30 days old).",
        "Uses a suspicious top-level domain frequently associated with spam campaigns.",
      ];
      summary = `The URL "${url}" is highly likely to be a phishing threat designed to harvest login credentials. Do not click this link or provide details.`;
    } else {
      score = 94;
      status = "legitimate";
      reasons = [
        "Domain is globally ranked with a solid historical reputation.",
        "Valid SSL/TLS certificate issued by an established authority.",
        "No malicious redirects or drive-by payload indicators found.",
      ];
      summary = `The URL "${url}" is safe and secure. It passes all automated security reputation scans.`;
    }
  }
  // 4. Conversational question fallbacks
  else if (lower.includes("latest") || lower.includes("new threats") || lower.includes("campaigns")) {
    category = "Threat Briefing";
    score = 100;
    status = "legitimate";
    reasons = [
      "SecOps live feed up to date.",
    ];
    summary = "Active Threat Briefing:\n• High activity of OTP bypass scams mimicking courier services.\n• LockBit 3.0 campaigns targeting standard vulnerability endpoints.\n• Spoofed VoIP calls targeting regional mobile users. Keep endpoints patched and monitor logs.";
  }
  else if (lower.includes("how") && (lower.includes("phishing") || lower.includes("protect"))) {
    category = "Security Advisory";
    score = 100;
    status = "legitimate";
    reasons = ["Cybersecurity Best Practices"];
    summary = "Protection Guide:\n1. Verify Sender: Always double-check sender addresses and domain spellings.\n2. Never Share Secrets: Real institutions will never ask for passwords or OTPs over text/call.\n3. Verify Links: Use a scanner (like our URL Intelligence tool) before opening unsolicited links.";
  }
  // 5. Default SMS/Email analyzer rules
  else {
    const analysis = analyzeSms(text);
    score = analysis.trustScore;
    status = analysis.status;
    category = analysis.category;
    reasons = analysis.reasons;
    summary = analysis.explanation;
  }

  return {
    score,
    status,
    category,
    reasons,
    summary,
  };
}

/* ─── Main Component ─────────────────────────────────────── */
function ChatbotPage() {
  const [sessions, setSessions] = useState<ChatSession[]>(INITIAL_SESSIONS);
  const [activeSession, setActiveSession] = useState<string>("s1");
  const [searchQuery, setSearchQuery] = useState("");
  const [inputVal, setInputVal] = useState("");
  const [isTyping, setIsTyping] = useState(false);

  // Map of session messages
  const [messages, setMessages] = useState<Record<string, ChatMessage[]>>({
    s1: [
      {
        id: "m1",
        sender: "ai",
        text: "Hello Analyst! I am Cyber Sentinel AI. Send me any suspicious phone number, email, message, URL, or IP address, and I will analyze its threat indicators.",
        timestamp: "10:30 AM",
      },
      {
        id: "m2",
        sender: "user",
        text: "+91 98765 43210",
        timestamp: "10:31 AM",
      },
      {
        id: "m3",
        sender: "ai",
        text: "Here is the Threat Intelligence analysis for the caller ID:",
        timestamp: "10:31 AM",
        analysis: {
          score: 22,
          status: "scam",
          category: "Phone Intelligence",
          reasons: [
            "VoIP line — commonly used for robocalls and caller ID spoofing.",
            "Multiple community reports of utility or bank representative spoofing.",
            "High-frequency automated dialing patterns detected.",
          ],
          summary: "This phone number has been flagged as a scam caller mimicking customer support channels. We recommend blocklisting this caller.",
        },
      },
    ],
    s2: [
      {
        id: "m4",
        sender: "ai",
        text: "Send me any suspicious link or website domain to scan.",
        timestamp: "9:15 AM",
      },
    ],
  });

  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, activeSession, isTyping]);

  const currentMessages = messages[activeSession] ?? [];

  // Filter sessions by search query
  const filteredSessions = sessions.filter(
    (s) =>
      s.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.preview.toLowerCase().includes(searchQuery.toLowerCase())
  );
  const pinnedSessions = filteredSessions.filter((s) => s.pinned);
  const recentSessions = filteredSessions.filter((s) => !s.pinned);

  const handleSend = (textToSend?: string) => {
    const text = (textToSend ?? inputVal).trim();
    if (!text) return;

    setInputVal("");

    const newMsg: ChatMessage = {
      id: crypto.randomUUID(),
      sender: "user",
      text,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };

    // Update messages
    setMessages((prev) => ({
      ...prev,
      [activeSession]: [...(prev[activeSession] ?? []), newMsg],
    }));

    // Update session preview
    setSessions((prev) =>
      prev.map((s) =>
        s.id === activeSession
          ? { ...s, preview: text.slice(0, 45) + (text.length > 45 ? "…" : "") }
          : s
      )
    );

    // Trigger AI response
    setIsTyping(true);
    setTimeout(() => {
      const response = generateAIResponse(text);
      const aiMsg: ChatMessage = {
        id: crypto.randomUUID(),
        sender: "ai",
        text: response.status === "scam"
          ? "⚠️ High Risk Threat Detected. Please review the security indicators below:"
          : response.status === "suspicious"
          ? "⚠️ Suspicious Activity Warning. Indicators suggest caution is required:"
          : "✅ Analysis Clean. No threat indicators were found for this entity:",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        analysis: response,
      };

      setMessages((prev) => ({
        ...prev,
        [activeSession]: [...(prev[activeSession] ?? []), aiMsg],
      }));
      setIsTyping(false);
    }, 1500);
  };

  const createNewChat = () => {
    const id = "s_" + Date.now();
    const newSession: ChatSession = {
      id,
      title: `Analysis Session ${sessions.length + 1}`,
      preview: "Empty conversation started",
      timestamp: "Just now",
      pinned: false,
    };

    setSessions((prev) => [newSession, ...prev]);
    setMessages((prev) => ({
      ...prev,
      [id]: [
        {
          id: crypto.randomUUID(),
          sender: "ai",
          text: "Hello Analyst! I am Cyber Sentinel AI. Send me any suspicious phone number, email, message, URL, or IP address, and I will analyze its threat indicators.",
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        },
      ],
    }));
    setActiveSession(id);
  };

  const deleteSession = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSessions((prev) => prev.filter((s) => s.id !== id));
    if (activeSession === id) {
      const remaining = sessions.filter((s) => s.id !== id);
      if (remaining.length > 0) {
        setActiveSession(remaining[0].id);
      }
    }
  };

  const togglePin = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSessions((prev) =>
      prev.map((s) => (s.id === id ? { ...s, pinned: !s.pinned } : s))
    );
  };

  return (
    <div className="flex h-[calc(100vh-64px)] overflow-hidden bg-[#F2EEE8] font-manrope">
      {/* ── Chat History Sidebar ───────────────────────────── */}
      <aside className="hidden md:flex flex-col w-72 overflow-hidden border-r border-[#E4DEC6] bg-[#2E323A] text-white shrink-0">
        {/* Sidebar Header */}
        <div className="flex items-center justify-between border-b border-[#3e434f] px-4 py-3.5">
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-[#C48A5A] text-white">
              <Shield className="h-4.5 w-4.5" />
            </div>
            <span className="text-xs font-bold font-poppins tracking-wider uppercase text-gray-200">
              Chat Logs
            </span>
          </div>
          <button
            onClick={createNewChat}
            className="flex h-7 w-7 items-center justify-center rounded-lg bg-[#C48A5A] text-white hover:bg-[#C48A5A]/90 transition-colors shadow-sm"
            title="New Chat"
          >
            <Plus className="h-3.5 w-3.5" />
          </button>
        </div>

        {/* Search */}
        <div className="px-3 py-2 border-b border-[#3e434f]/40">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              placeholder="Search chat history…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-xl border border-[#3e434f] bg-white/5 py-1.5 pl-8 pr-3 text-[11px] text-white outline-none focus:border-[#C48A5A] transition"
            />
          </div>
        </div>

        {/* Sessions list */}
        <div className="flex-1 overflow-y-auto px-2 py-3 space-y-4">
          {pinnedSessions.length > 0 && (
            <div>
              <p className="px-2 mb-1.5 text-[9px] font-bold uppercase tracking-widest text-gray-400 flex items-center gap-1">
                <Pin className="h-2.5 w-2.5 text-[#C48A5A]" /> Pinned
              </p>
              {pinnedSessions.map((s) => (
                <SessionItem
                  key={s.id}
                  session={s}
                  active={activeSession === s.id}
                  onClick={() => setActiveSession(s.id)}
                  onDelete={deleteSession}
                  onPin={togglePin}
                />
              ))}
            </div>
          )}

          <div>
            {pinnedSessions.length > 0 && (
              <p className="px-2 mb-1.5 text-[9px] font-bold uppercase tracking-widest text-gray-400 flex items-center gap-1">
                <Clock className="h-2.5 w-2.5" /> Recent
              </p>
            )}
            {recentSessions.length === 0 && pinnedSessions.length === 0 ? (
              <p className="px-3 py-4 text-center text-xs text-gray-400 font-medium">
                No active threat logs.
              </p>
            ) : (
              recentSessions.map((s) => (
                <SessionItem
                  key={s.id}
                  session={s}
                  active={activeSession === s.id}
                  onClick={() => setActiveSession(s.id)}
                  onDelete={deleteSession}
                  onPin={togglePin}
                />
              ))
            )}
          </div>
        </div>
      </aside>

      {/* ── Main Chat Layout ──────────────────────────────── */}
      <div className="flex flex-1 flex-col min-w-0 bg-[#F2EEE8] relative">
        {/* SVG illustration background watermark */}
        <CyberWatermark />

        {/* Chat Header */}
        <header className="flex items-center justify-between border-b border-[#E4DEC6] bg-white px-5 py-3 shadow-sm z-10 shrink-0">
          <div className="flex items-center gap-3">
            <AIAvatar size={36} />
            <div>
              <h1 className="text-sm font-extrabold text-gray-800 font-poppins flex items-center gap-1.5">
                🤖 Cyber Sentinel AI
                <span className="inline-flex h-1.5 w-1.5 rounded-full bg-[#34A853] animate-pulse" />
              </h1>
              <p className="text-[10px] font-semibold text-gray-500 font-manrope">
                Your Intelligent Cybersecurity Assistant
              </p>
            </div>
          </div>

          {/* Quick Toolbar */}
          <div className="flex items-center gap-2">
            <button
              onClick={createNewChat}
              className="flex items-center gap-1.5 rounded-xl border border-[#E4DEC6] bg-white px-3 py-1.5 text-[11px] font-bold text-gray-600 hover:bg-[#FAF8F5] hover:text-[#C48A5A] transition-colors"
            >
              <Plus className="h-3.5 w-3.5" /> New Chat
            </button>
            <button className="flex items-center gap-1.5 rounded-xl border border-[#E4DEC6] bg-white px-3 py-1.5 text-[11px] font-bold text-gray-600 hover:bg-[#FAF8F5] transition-colors">
              <Download className="h-3.5 w-3.5" /> Export Chat
            </button>
            <button className="flex h-8 w-8 items-center justify-center rounded-xl border border-[#E4DEC6] bg-white text-gray-500 hover:bg-[#FAF8F5] transition-colors">
              <Settings className="h-4 w-4" />
            </button>
            <Link
              to="/dashboard"
              className="flex items-center gap-1.5 rounded-xl bg-[#2E323A] px-3 py-1.5 text-[11px] font-bold text-white hover:bg-[#2E323A]/90 transition-colors"
            >
              <ArrowLeft className="h-3.5 w-3.5" /> Back
            </Link>
          </div>
        </header>

        {/* Chat Feed / Welcome Screen */}
        <div className="flex-1 overflow-y-auto px-4 py-6 space-y-6 z-10">
          {currentMessages.length <= 1 ? (
            /* Welcome Hero Page */
            <div className="max-w-2xl mx-auto flex flex-col items-center justify-center min-h-[70%] text-center gap-8 py-8">
              <div>
                <div className="mb-4 flex justify-center">
                  <AIAvatar size={64} />
                </div>
                <h2 className="text-xl font-extrabold text-gray-800 font-poppins">
                  🤖 Cyber Sentinel AI
                </h2>
                <p className="mt-2 text-xs font-semibold text-gray-500 max-w-md mx-auto leading-relaxed">
                  How can I help protect you today? Paste a suspicious caller ID, URL link, email content, or general network indicator to perform real-time security scoring.
                </p>
              </div>

              {/* Action Cards */}
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3 w-full">
                {QUICK_ACTIONS.map((a) => {
                  const Icon = a.icon;
                  return (
                    <button
                      key={a.label}
                      onClick={() => setInputVal(a.text)}
                      className="flex flex-col items-start text-left p-3.5 bg-white border border-[#E4DEC6]/60 rounded-2xl shadow-sm hover:shadow-md transition-all group"
                      style={{ borderColor: `${a.color}25` }}
                    >
                      <div
                        className="flex h-8 w-8 items-center justify-center rounded-xl mb-3"
                        style={{ background: a.bg }}
                      >
                        <Icon className="h-4 w-4" style={{ color: a.color }} />
                      </div>
                      <span className="text-[11px] font-bold text-gray-700 leading-snug group-hover:text-[#C48A5A] transition-colors">
                        {a.label}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          ) : (
            /* Messages List */
            <div className="max-w-3xl mx-auto space-y-6">
              {currentMessages.map((msg) => (
                <div
                  key={msg.id}
                  className={`flex gap-3.5 ${msg.sender === "user" ? "justify-end" : "justify-start"}`}
                >
                  {msg.sender === "ai" && <AIAvatar size={36} />}
                  <div className="max-w-[85%] space-y-1.5">
                    {msg.sender === "user" ? (
                      /* User text bubble */
                      <div className="bg-gradient-to-br from-[#4F7EF7] to-[#3a6ad4] text-white px-4 py-3 rounded-2xl rounded-tr-sm shadow-sm text-xs leading-relaxed font-medium">
                        {msg.text}
                      </div>
                    ) : (
                      /* AI card response */
                      <div className="bg-white border border-[#E4DEC6] p-4.5 rounded-2xl rounded-tl-sm shadow-sm space-y-4">
                        <div className="text-xs text-gray-700 leading-relaxed">
                          {msg.text}
                        </div>

                        {/* If analysis exists, display score panel */}
                        {msg.analysis && (
                          <div className="border border-[#E4DEC6]/80 rounded-2xl bg-[#FAF8F5] p-4 space-y-3">
                            <div className="flex items-center justify-between">
                              <span className="text-[9px] font-bold text-gray-400 uppercase tracking-wider font-poppins">
                                {msg.analysis.category}
                              </span>
                              <span
                                className="rounded-full px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-wider"
                                style={{
                                  color: msg.analysis.status === "scam" ? "#E05A52" : msg.analysis.status === "suspicious" ? "#E8A23C" : "#34A853",
                                  background: msg.analysis.status === "scam" ? "#E05A5210" : msg.analysis.status === "suspicious" ? "#E8A23C10" : "#34A85310",
                                  border: `1px solid ${msg.analysis.status === "scam" ? "#E05A5220" : msg.analysis.status === "suspicious" ? "#E8A23C20" : "#34A85320"}`,
                                }}
                              >
                                {msg.analysis.status}
                              </span>
                            </div>

                            {/* Trust score gauge */}
                            <div className="space-y-1">
                              <div className="flex items-center justify-between text-[11px] font-bold text-gray-600">
                                <span>Security Trust Score</span>
                                <span>{msg.analysis.score}%</span>
                              </div>
                              <div className="h-2 w-full rounded-full bg-gray-200 overflow-hidden">
                                <div
                                  className="h-full rounded-full transition-all duration-500"
                                  style={{
                                    width: `${msg.analysis.score}%`,
                                    background: msg.analysis.status === "scam" ? "#E05A52" : msg.analysis.status === "suspicious" ? "#E8A23C" : "#34A853",
                                  }}
                                />
                              </div>
                            </div>

                            {/* Evidence list */}
                            {msg.analysis.reasons.length > 0 && (
                              <div className="space-y-1.5 pt-1">
                                <span className="text-[9px] font-bold text-gray-400 uppercase tracking-widest block font-poppins">
                                  Evidence &amp; Threat Indicators
                                </span>
                                <ul className="space-y-1">
                                  {msg.analysis.reasons.map((r, i) => (
                                    <li key={i} className="flex items-start gap-2 text-[10px] text-gray-600 leading-normal">
                                      <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-[#C48A5A]" />
                                      {r}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {/* Detailed explanation summary */}
                            <div className="pt-2 border-t border-[#E4DEC6]/60 text-[10px] leading-relaxed text-gray-500 font-medium italic">
                              {msg.analysis.summary}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                    <div className="text-[9px] text-gray-400 text-right px-1">
                      {msg.timestamp}
                    </div>
                  </div>
                </div>
              ))}

              {/* Typing indicator */}
              {isTyping && (
                <div className="flex gap-3.5 justify-start">
                  <AIAvatar size={36} />
                  <div className="bg-white border border-[#E4DEC6] px-4 py-3 rounded-2xl rounded-tl-sm shadow-sm flex items-center gap-1.5">
                    {[0, 1, 2].map((i) => (
                      <span
                        key={i}
                        className="h-1.5 w-1.5 rounded-full bg-[#C48A5A] inline-block animate-bounce"
                        style={{
                          animationDelay: `${i * 0.2}s`,
                        }}
                      />
                    ))}
                    <span className="text-[10px] font-bold text-gray-400 ml-1">Analyzing indicators…</span>
                  </div>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>
          )}
        </div>

        {/* Input Form Box */}
        <div className="p-4 border-t border-[#E4DEC6] bg-white/70 backdrop-blur-sm z-10 shrink-0">
          <div className="max-w-3xl mx-auto relative">
            <textarea
              rows={2}
              value={inputVal}
              onChange={(e) => setInputVal(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  handleSend();
                }
              }}
              placeholder="Paste a suspicious call, SMS, email payload, or URL to score threat level..."
              className="w-full rounded-2xl border border-[#E4DEC6] bg-white p-3 pr-28 text-xs font-semibold text-gray-800 placeholder-gray-400 outline-none shadow-sm focus:border-[#C48A5A] transition resize-none"
            />
            {/* Toolbar Buttons */}
            <div className="absolute right-3.5 bottom-3.5 flex items-center gap-2">
              <button
                type="button"
                className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-[#FAF8F5] rounded-xl transition"
                title="Attach file"
              >
                <Paperclip className="h-4 w-4" />
              </button>
              <button
                type="button"
                className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-[#FAF8F5] rounded-xl transition"
                title="Voice input"
              >
                <Mic className="h-4 w-4" />
              </button>
              <button
                type="button"
                className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-[#FAF8F5] rounded-xl transition"
                title="Image upload"
              >
                <ImageIcon className="h-4 w-4" />
              </button>
              <button
                onClick={() => handleSend()}
                disabled={!inputVal.trim()}
                className="p-2 bg-[#C48A5A] disabled:bg-[#C48A5A]/50 text-white rounded-xl shadow-sm hover:bg-[#C48A5A]/90 transition"
              >
                <Send className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
          <div className="text-center text-[9px] text-gray-400 mt-2">
            Powered by AI — always verify indicators before clicking links or returning calls.
          </div>
        </div>
      </div>
    </div>
  );
}

/* ─── Session Item Component ─────────────────────────────── */
function SessionItem({
  session,
  active,
  onClick,
  onDelete,
  onPin,
}: {
  session: ChatSession;
  active: boolean;
  onClick: () => void;
  onDelete: (id: string, e: React.MouseEvent) => void;
  onPin: (id: string, e: React.MouseEvent) => void;
}) {
  const [hover, setHover] = useState(false);

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      className={`group flex cursor-pointer items-start gap-2.5 rounded-xl px-2.5 py-2 mb-0.5 border transition-all ${
        active
          ? "bg-[#C48A5A]/15 border-[#C48A5A]/30 text-white"
          : "border-transparent text-gray-300 hover:bg-white/5 hover:text-white"
      }`}
    >
      <MessageSquare
        className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${active ? "text-[#C48A5A]" : "text-gray-400"}`}
      />
      <div className="flex-1 min-w-0">
        <p className={`truncate text-[11px] font-bold ${active ? "text-white" : "text-gray-300"} font-manrope`}>
          {session.title}
        </p>
        <p className="truncate text-[10px] text-gray-400 font-manrope mt-0.5">{session.preview}</p>
        <p className="text-[9px] text-gray-500 font-manrope mt-1">{session.timestamp}</p>
      </div>

      {/* Action buttons (Pin/Delete) shown on hover */}
      {hover && (
        <div className="flex items-center gap-0.5 shrink-0 ml-1">
          <button
            onClick={(e) => onPin(session.id, e)}
            className="flex h-5 w-5 items-center justify-center rounded-lg hover:bg-white/10 transition-colors"
            title={session.pinned ? "Unpin" : "Pin"}
          >
            <Pin className={`h-3 w-3 ${session.pinned ? "text-[#C48A5A]" : "text-gray-400"}`} />
          </button>
          <button
            onClick={(e) => onDelete(session.id, e)}
            className="flex h-5 w-5 items-center justify-center rounded-lg hover:bg-white/10 transition-colors"
            title="Delete chat"
          >
            <Trash2 className="h-3 w-3 text-[#E05A52]" />
          </button>
        </div>
      )}
    </div>
  );
}
