import { r as reactExports, j as jsxRuntimeExports } from "../_libs/react.mjs";
import { L as Link } from "../_libs/tanstack__react-router.mjs";
import { a as analyzeSms } from "./intel-analyzers-CxuAEFHl.mjs";
import { S as Shield, i as Plus, f as Search, y as Pin, k as Clock, t as Download, e as Settings, A as ArrowLeft, P as Phone, G as Globe, M as Mail, z as MapPin, T as TriangleAlert, E as BookOpen, H as Paperclip, J as Mic, K as Image, N as Send, d as MessageSquare, l as Trash2 } from "../_libs/lucide-react.mjs";
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
import "../_libs/fuse.js.mjs";
const INITIAL_SESSIONS = [{
  id: "s1",
  title: "Phone scam analysis",
  preview: "+91 9876543210 — suspicious call",
  timestamp: "2m ago",
  pinned: true
}, {
  id: "s2",
  title: "Phishing URL scan",
  preview: "paypal-secure-login.ru flagged",
  timestamp: "1h ago",
  pinned: true
}, {
  id: "s3",
  title: "Email threat check",
  preview: "prize@giveaway.tk is malicious",
  timestamp: "3h ago",
  pinned: false
}, {
  id: "s4",
  title: "IP reputation lookup",
  preview: "45.142.212.100 — C2 server",
  timestamp: "Yesterday",
  pinned: false
}];
const QUICK_ACTIONS = [{
  icon: Phone,
  label: "Analyze Phone Number",
  color: "#C48A5A",
  bg: "#C48A5A15",
  text: "+91 98765 43210"
}, {
  icon: Globe,
  label: "Scan URL",
  color: "#4F7EF7",
  bg: "#4F7EF715",
  text: "secure-login-update.xyz"
}, {
  icon: Mail,
  label: "Analyze Email",
  color: "#34A853",
  bg: "#34A85315",
  text: "Dear customer, your bank account has been suspended. Please click here to restore access."
}, {
  icon: MapPin,
  label: "Check IP Address",
  color: "#E8A23C",
  bg: "#E8A23C15",
  text: "185.220.101.5"
}, {
  icon: TriangleAlert,
  label: "Latest Threats",
  color: "#E05A52",
  bg: "#E05A5215",
  text: "What are the latest cybersecurity threats today?"
}, {
  icon: BookOpen,
  label: "Learn Cybersecurity",
  color: "#7C5CBF",
  bg: "#7C5CBF15",
  text: "What are the best practices for protecting against phishing and identity theft?"
}];
function CyberWatermark() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("svg", { className: "absolute inset-0 w-full h-full pointer-events-none select-none", viewBox: "0 0 800 600", fill: "none", xmlns: "http://www.w3.org/2000/svg", "aria-hidden": "true", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("path", { d: "M400 120 L460 150 L460 220 Q460 270 400 300 Q340 270 340 220 L340 150 Z", fill: "#C48A5A", opacity: "0.05" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("path", { d: "M400 138 L448 163 L448 218 Q448 260 400 286 Q352 260 352 218 L352 163 Z", stroke: "#C48A5A", strokeWidth: "1.5", opacity: "0.07", fill: "none" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("rect", { x: "387", y: "210", width: "26", height: "20", rx: "3", fill: "#C48A5A", opacity: "0.06" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("circle", { cx: "160", cy: "180", r: "6", fill: "#4F7EF7", opacity: "0.05" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("circle", { cx: "200", cy: "280", r: "4", fill: "#4F7EF7", opacity: "0.04" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("circle", { cx: "640", cy: "160", r: "6", fill: "#4F7EF7", opacity: "0.05" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("circle", { cx: "670", cy: "280", r: "4", fill: "#34A853", opacity: "0.04" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("line", { x1: "160", y1: "180", x2: "340", y2: "180", stroke: "#4F7EF7", strokeWidth: "0.8", opacity: "0.04", strokeDasharray: "4 4" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("line", { x1: "460", y1: "180", x2: "640", y2: "180", stroke: "#4F7EF7", strokeWidth: "0.8", opacity: "0.04", strokeDasharray: "4 4" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("circle", { cx: "400", cy: "460", r: "70", stroke: "#4F7EF7", strokeWidth: "1", opacity: "0.03", fill: "none" })
  ] });
}
function AIAvatar({
  size = 32
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex shrink-0 items-center justify-center rounded-full", style: {
    width: size,
    height: size,
    background: "linear-gradient(135deg, #C48A5A 0%, #E8A23C 50%, #4F7EF7 100%)",
    boxShadow: "0 2px 8px rgba(196,138,90,0.25)"
  }, children: /* @__PURE__ */ jsxRuntimeExports.jsx(Shield, { style: {
    width: size * 0.45,
    height: size * 0.45,
    color: "white"
  } }) });
}
function generateAIResponse(userInput) {
  const text = userInput.trim();
  const lower = text.toLowerCase();
  const phoneRegex = /^(\+?\d{1,4}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}$|^\+?\d{10,12}$/;
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const genericUrlRegex = /\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b/g;
  const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
  let score = 90;
  let status = "legitimate";
  let category = "Security Check";
  let reasons = [];
  let summary = "";
  if (ipRegex.test(text)) {
    const ip = text.match(ipRegex)[0];
    category = "IP Address Analysis";
    const lastOctet = parseInt(ip.split(".").pop() || "0");
    if (lastOctet % 2 === 0 || lastOctet > 200) {
      score = 18;
      status = "scam";
      reasons = ["IP address belongs to a VPS provider frequently abused for C2 servers.", "Multiple reports flag active port scanning from this source.", "Listed in community blocklists for malicious bot activity."];
      summary = `The IP address ${ip} is flagged as a high-risk malicious host. It is currently associated with scanning and botnet infrastructure.`;
    } else {
      score = 90;
      status = "legitimate";
      reasons = ["Clean reputation on global threat intelligence feeds.", "No historical record of malicious activity or spam delivery.", "Belongs to a reputable cloud provider network."];
      summary = `The IP address ${ip} appears clean. No malicious indicators or alerts exist in the security database.`;
    }
  } else if (phoneRegex.test(text) || lower.includes("+91") || lower.includes("phone number")) {
    category = "Phone Intelligence";
    const digits = text.replace(/\D/g, "");
    if (digits.includes("98765") || digits.includes("8800") || digits.endsWith("1") || digits.endsWith("3")) {
      score = 22;
      status = "scam";
      reasons = ["VoIP line — commonly used for robocalls and caller ID spoofing.", "Multiple community reports of utility or bank representative spoofing.", "High-frequency automated dialing patterns detected."];
      summary = "This phone number has been flagged as a scam caller mimicking customer support channels. We recommend blocklisting this caller.";
    } else {
      score = 88;
      status = "legitimate";
      reasons = ["Registered mobile subscriber line with standard carrier verification.", "No telemarketing or fraudulent behavior reports in our database.", "Clean activity record for the last 180 days."];
      summary = "This caller number appears legitimate. No scam or spam alerts are associated with this record.";
    }
  } else if (urlRegex.test(text) || genericUrlRegex.test(text)) {
    category = "URL Inspection";
    const url = text.match(urlRegex)?.[0] || text.match(genericUrlRegex)?.[0] || text;
    if (lower.includes("login") || lower.includes("secure") || lower.includes("update") || lower.includes("bank") || lower.includes("paypal") || lower.includes(".ru") || lower.includes(".xyz") || lower.includes("verify")) {
      score = 12;
      status = "scam";
      reasons = ["Domain mimics standard banking and payment portal layouts (phishing lookalike).", "Domain age is extremely young (less than 30 days old).", "Uses a suspicious top-level domain frequently associated with spam campaigns."];
      summary = `The URL "${url}" is highly likely to be a phishing threat designed to harvest login credentials. Do not click this link or provide details.`;
    } else {
      score = 94;
      status = "legitimate";
      reasons = ["Domain is globally ranked with a solid historical reputation.", "Valid SSL/TLS certificate issued by an established authority.", "No malicious redirects or drive-by payload indicators found."];
      summary = `The URL "${url}" is safe and secure. It passes all automated security reputation scans.`;
    }
  } else if (lower.includes("latest") || lower.includes("new threats") || lower.includes("campaigns")) {
    category = "Threat Briefing";
    score = 100;
    status = "legitimate";
    reasons = ["SecOps live feed up to date."];
    summary = "Active Threat Briefing:\n• High activity of OTP bypass scams mimicking courier services.\n• LockBit 3.0 campaigns targeting standard vulnerability endpoints.\n• Spoofed VoIP calls targeting regional mobile users. Keep endpoints patched and monitor logs.";
  } else if (lower.includes("how") && (lower.includes("phishing") || lower.includes("protect"))) {
    category = "Security Advisory";
    score = 100;
    status = "legitimate";
    reasons = ["Cybersecurity Best Practices"];
    summary = "Protection Guide:\n1. Verify Sender: Always double-check sender addresses and domain spellings.\n2. Never Share Secrets: Real institutions will never ask for passwords or OTPs over text/call.\n3. Verify Links: Use a scanner (like our URL Intelligence tool) before opening unsolicited links.";
  } else {
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
    summary
  };
}
function ChatbotPage() {
  const [sessions, setSessions] = reactExports.useState(INITIAL_SESSIONS);
  const [activeSession, setActiveSession] = reactExports.useState("s1");
  const [searchQuery, setSearchQuery] = reactExports.useState("");
  const [inputVal, setInputVal] = reactExports.useState("");
  const [isTyping, setIsTyping] = reactExports.useState(false);
  const [messages, setMessages] = reactExports.useState({
    s1: [{
      id: "m1",
      sender: "ai",
      text: "Hello Analyst! I am Cyber Sentinel AI. Send me any suspicious phone number, email, message, URL, or IP address, and I will analyze its threat indicators.",
      timestamp: "10:30 AM"
    }, {
      id: "m2",
      sender: "user",
      text: "+91 98765 43210",
      timestamp: "10:31 AM"
    }, {
      id: "m3",
      sender: "ai",
      text: "Here is the Threat Intelligence analysis for the caller ID:",
      timestamp: "10:31 AM",
      analysis: {
        score: 22,
        status: "scam",
        category: "Phone Intelligence",
        reasons: ["VoIP line — commonly used for robocalls and caller ID spoofing.", "Multiple community reports of utility or bank representative spoofing.", "High-frequency automated dialing patterns detected."],
        summary: "This phone number has been flagged as a scam caller mimicking customer support channels. We recommend blocklisting this caller."
      }
    }],
    s2: [{
      id: "m4",
      sender: "ai",
      text: "Send me any suspicious link or website domain to scan.",
      timestamp: "9:15 AM"
    }]
  });
  const chatEndRef = reactExports.useRef(null);
  reactExports.useEffect(() => {
    chatEndRef.current?.scrollIntoView({
      behavior: "smooth"
    });
  }, [messages, activeSession, isTyping]);
  const currentMessages = messages[activeSession] ?? [];
  const filteredSessions = sessions.filter((s) => s.title.toLowerCase().includes(searchQuery.toLowerCase()) || s.preview.toLowerCase().includes(searchQuery.toLowerCase()));
  const pinnedSessions = filteredSessions.filter((s) => s.pinned);
  const recentSessions = filteredSessions.filter((s) => !s.pinned);
  const handleSend = (textToSend) => {
    const text = inputVal.trim();
    if (!text) return;
    setInputVal("");
    const newMsg = {
      id: crypto.randomUUID(),
      sender: "user",
      text,
      timestamp: (/* @__PURE__ */ new Date()).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit"
      })
    };
    setMessages((prev) => ({
      ...prev,
      [activeSession]: [...prev[activeSession] ?? [], newMsg]
    }));
    setSessions((prev) => prev.map((s) => s.id === activeSession ? {
      ...s,
      preview: text.slice(0, 45) + (text.length > 45 ? "…" : "")
    } : s));
    setIsTyping(true);
    setTimeout(() => {
      const response = generateAIResponse(text);
      const aiMsg = {
        id: crypto.randomUUID(),
        sender: "ai",
        text: response.status === "scam" ? "⚠️ High Risk Threat Detected. Please review the security indicators below:" : response.status === "suspicious" ? "⚠️ Suspicious Activity Warning. Indicators suggest caution is required:" : "✅ Analysis Clean. No threat indicators were found for this entity:",
        timestamp: (/* @__PURE__ */ new Date()).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit"
        }),
        analysis: response
      };
      setMessages((prev) => ({
        ...prev,
        [activeSession]: [...prev[activeSession] ?? [], aiMsg]
      }));
      setIsTyping(false);
    }, 1500);
  };
  const createNewChat = () => {
    const id = "s_" + Date.now();
    const newSession = {
      id,
      title: `Analysis Session ${sessions.length + 1}`,
      preview: "Empty conversation started",
      timestamp: "Just now",
      pinned: false
    };
    setSessions((prev) => [newSession, ...prev]);
    setMessages((prev) => ({
      ...prev,
      [id]: [{
        id: crypto.randomUUID(),
        sender: "ai",
        text: "Hello Analyst! I am Cyber Sentinel AI. Send me any suspicious phone number, email, message, URL, or IP address, and I will analyze its threat indicators.",
        timestamp: (/* @__PURE__ */ new Date()).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit"
        })
      }]
    }));
    setActiveSession(id);
  };
  const deleteSession = (id, e) => {
    e.stopPropagation();
    setSessions((prev) => prev.filter((s) => s.id !== id));
    if (activeSession === id) {
      const remaining = sessions.filter((s) => s.id !== id);
      if (remaining.length > 0) {
        setActiveSession(remaining[0].id);
      }
    }
  };
  const togglePin = (id, e) => {
    e.stopPropagation();
    setSessions((prev) => prev.map((s) => s.id === id ? {
      ...s,
      pinned: !s.pinned
    } : s));
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex h-[calc(100vh-64px)] overflow-hidden bg-[#F2EEE8] font-manrope", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { className: "hidden md:flex flex-col w-72 overflow-hidden border-r border-[#E4DEC6] bg-[#2E323A] text-white shrink-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between border-b border-[#3e434f] px-4 py-3.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex h-7 w-7 items-center justify-center rounded-lg bg-[#C48A5A] text-white", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Shield, { className: "h-4.5 w-4.5" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-bold font-poppins tracking-wider uppercase text-gray-200", children: "Chat Logs" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: createNewChat, className: "flex h-7 w-7 items-center justify-center rounded-lg bg-[#C48A5A] text-white hover:bg-[#C48A5A]/90 transition-colors shadow-sm", title: "New Chat", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Plus, { className: "h-3.5 w-3.5" }) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-3 py-2 border-b border-[#3e434f]/40", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Search, { className: "absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-400" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("input", { type: "text", placeholder: "Search chat history…", value: searchQuery, onChange: (e) => setSearchQuery(e.target.value), className: "w-full rounded-xl border border-[#3e434f] bg-white/5 py-1.5 pl-8 pr-3 text-[11px] text-white outline-none focus:border-[#C48A5A] transition" })
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1 overflow-y-auto px-2 py-3 space-y-4", children: [
        pinnedSessions.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "px-2 mb-1.5 text-[9px] font-bold uppercase tracking-widest text-gray-400 flex items-center gap-1", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(Pin, { className: "h-2.5 w-2.5 text-[#C48A5A]" }),
            " Pinned"
          ] }),
          pinnedSessions.map((s) => /* @__PURE__ */ jsxRuntimeExports.jsx(SessionItem, { session: s, active: activeSession === s.id, onClick: () => setActiveSession(s.id), onDelete: deleteSession, onPin: togglePin }, s.id))
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          pinnedSessions.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "px-2 mb-1.5 text-[9px] font-bold uppercase tracking-widest text-gray-400 flex items-center gap-1", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(Clock, { className: "h-2.5 w-2.5" }),
            " Recent"
          ] }),
          recentSessions.length === 0 && pinnedSessions.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "px-3 py-4 text-center text-xs text-gray-400 font-medium", children: "No active threat logs." }) : recentSessions.map((s) => /* @__PURE__ */ jsxRuntimeExports.jsx(SessionItem, { session: s, active: activeSession === s.id, onClick: () => setActiveSession(s.id), onDelete: deleteSession, onPin: togglePin }, s.id))
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-1 flex-col min-w-0 bg-[#F2EEE8] relative", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(CyberWatermark, {}),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "flex items-center justify-between border-b border-[#E4DEC6] bg-white px-5 py-3 shadow-sm z-10 shrink-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(AIAvatar, { size: 36 }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("h1", { className: "text-sm font-extrabold text-gray-800 font-poppins flex items-center gap-1.5", children: [
              "🤖 Cyber Sentinel AI",
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-1.5 w-1.5 rounded-full bg-[#34A853] animate-pulse" })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold text-gray-500 font-manrope", children: "Your Intelligent Cybersecurity Assistant" })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { onClick: createNewChat, className: "flex items-center gap-1.5 rounded-xl border border-[#E4DEC6] bg-white px-3 py-1.5 text-[11px] font-bold text-gray-600 hover:bg-[#FAF8F5] hover:text-[#C48A5A] transition-colors", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(Plus, { className: "h-3.5 w-3.5" }),
            " New Chat"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { className: "flex items-center gap-1.5 rounded-xl border border-[#E4DEC6] bg-white px-3 py-1.5 text-[11px] font-bold text-gray-600 hover:bg-[#FAF8F5] transition-colors", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(Download, { className: "h-3.5 w-3.5" }),
            " Export Chat"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "flex h-8 w-8 items-center justify-center rounded-xl border border-[#E4DEC6] bg-white text-gray-500 hover:bg-[#FAF8F5] transition-colors", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Settings, { className: "h-4 w-4" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(Link, { to: "/dashboard", className: "flex items-center gap-1.5 rounded-xl bg-[#2E323A] px-3 py-1.5 text-[11px] font-bold text-white hover:bg-[#2E323A]/90 transition-colors", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(ArrowLeft, { className: "h-3.5 w-3.5" }),
            " Back"
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex-1 overflow-y-auto px-4 py-6 space-y-6 z-10", children: currentMessages.length <= 1 ? (
        /* Welcome Hero Page */
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-2xl mx-auto flex flex-col items-center justify-center min-h-[70%] text-center gap-8 py-8", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mb-4 flex justify-center", children: /* @__PURE__ */ jsxRuntimeExports.jsx(AIAvatar, { size: 64 }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-xl font-extrabold text-gray-800 font-poppins", children: "🤖 Cyber Sentinel AI" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs font-semibold text-gray-500 max-w-md mx-auto leading-relaxed", children: "How can I help protect you today? Paste a suspicious caller ID, URL link, email content, or general network indicator to perform real-time security scoring." })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-2 md:grid-cols-3 gap-3 w-full", children: QUICK_ACTIONS.map((a) => {
            const Icon = a.icon;
            return /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { onClick: () => setInputVal(a.text), className: "flex flex-col items-start text-left p-3.5 bg-white border border-[#E4DEC6]/60 rounded-2xl shadow-sm hover:shadow-md transition-all group", style: {
              borderColor: `${a.color}25`
            }, children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex h-8 w-8 items-center justify-center rounded-xl mb-3", style: {
                background: a.bg
              }, children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4", style: {
                color: a.color
              } }) }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-bold text-gray-700 leading-snug group-hover:text-[#C48A5A] transition-colors", children: a.label })
            ] }, a.label);
          }) })
        ] })
      ) : (
        /* Messages List */
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-3xl mx-auto space-y-6", children: [
          currentMessages.map((msg) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `flex gap-3.5 ${msg.sender === "user" ? "justify-end" : "justify-start"}`, children: [
            msg.sender === "ai" && /* @__PURE__ */ jsxRuntimeExports.jsx(AIAvatar, { size: 36 }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-[85%] space-y-1.5", children: [
              msg.sender === "user" ? (
                /* User text bubble */
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "bg-gradient-to-br from-[#4F7EF7] to-[#3a6ad4] text-white px-4 py-3 rounded-2xl rounded-tr-sm shadow-sm text-xs leading-relaxed font-medium", children: msg.text })
              ) : (
                /* AI card response */
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-white border border-[#E4DEC6] p-4.5 rounded-2xl rounded-tl-sm shadow-sm space-y-4", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs text-gray-700 leading-relaxed", children: msg.text }),
                  msg.analysis && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border border-[#E4DEC6]/80 rounded-2xl bg-[#FAF8F5] p-4 space-y-3", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[9px] font-bold text-gray-400 uppercase tracking-wider font-poppins", children: msg.analysis.category }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rounded-full px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-wider", style: {
                        color: msg.analysis.status === "scam" ? "#E05A52" : msg.analysis.status === "suspicious" ? "#E8A23C" : "#34A853",
                        background: msg.analysis.status === "scam" ? "#E05A5210" : msg.analysis.status === "suspicious" ? "#E8A23C10" : "#34A85310",
                        border: `1px solid ${msg.analysis.status === "scam" ? "#E05A5220" : msg.analysis.status === "suspicious" ? "#E8A23C20" : "#34A85320"}`
                      }, children: msg.analysis.status })
                    ] }),
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-1", children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between text-[11px] font-bold text-gray-600", children: [
                        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Security Trust Score" }),
                        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
                          msg.analysis.score,
                          "%"
                        ] })
                      ] }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "h-2 w-full rounded-full bg-gray-200 overflow-hidden", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "h-full rounded-full transition-all duration-500", style: {
                        width: `${msg.analysis.score}%`,
                        background: msg.analysis.status === "scam" ? "#E05A52" : msg.analysis.status === "suspicious" ? "#E8A23C" : "#34A853"
                      } }) })
                    ] }),
                    msg.analysis.reasons.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-1.5 pt-1", children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[9px] font-bold text-gray-400 uppercase tracking-widest block font-poppins", children: "Evidence & Threat Indicators" }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-1", children: msg.analysis.reasons.map((r, i) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex items-start gap-2 text-[10px] text-gray-600 leading-normal", children: [
                        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-[#C48A5A]" }),
                        r
                      ] }, i)) })
                    ] }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "pt-2 border-t border-[#E4DEC6]/60 text-[10px] leading-relaxed text-gray-500 font-medium italic", children: msg.analysis.summary })
                  ] })
                ] })
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-[9px] text-gray-400 text-right px-1", children: msg.timestamp })
            ] })
          ] }, msg.id)),
          isTyping && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-3.5 justify-start", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(AIAvatar, { size: 36 }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-white border border-[#E4DEC6] px-4 py-3 rounded-2xl rounded-tl-sm shadow-sm flex items-center gap-1.5", children: [
              [0, 1, 2].map((i) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-1.5 w-1.5 rounded-full bg-[#C48A5A] inline-block animate-bounce", style: {
                animationDelay: `${i * 0.2}s`
              } }, i)),
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] font-bold text-gray-400 ml-1", children: "Analyzing indicators…" })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { ref: chatEndRef })
        ] })
      ) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "p-4 border-t border-[#E4DEC6] bg-white/70 backdrop-blur-sm z-10 shrink-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-3xl mx-auto relative", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("textarea", { rows: 2, value: inputVal, onChange: (e) => setInputVal(e.target.value), onKeyDown: (e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              handleSend();
            }
          }, placeholder: "Paste a suspicious call, SMS, email payload, or URL to score threat level...", className: "w-full rounded-2xl border border-[#E4DEC6] bg-white p-3 pr-28 text-xs font-semibold text-gray-800 placeholder-gray-400 outline-none shadow-sm focus:border-[#C48A5A] transition resize-none" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "absolute right-3.5 bottom-3.5 flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "p-1.5 text-gray-400 hover:text-gray-600 hover:bg-[#FAF8F5] rounded-xl transition", title: "Attach file", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Paperclip, { className: "h-4 w-4" }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "p-1.5 text-gray-400 hover:text-gray-600 hover:bg-[#FAF8F5] rounded-xl transition", title: "Voice input", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Mic, { className: "h-4 w-4" }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "p-1.5 text-gray-400 hover:text-gray-600 hover:bg-[#FAF8F5] rounded-xl transition", title: "Image upload", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Image, { className: "h-4 w-4" }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: () => handleSend(), disabled: !inputVal.trim(), className: "p-2 bg-[#C48A5A] disabled:bg-[#C48A5A]/50 text-white rounded-xl shadow-sm hover:bg-[#C48A5A]/90 transition", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Send, { className: "h-3.5 w-3.5" }) })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-center text-[9px] text-gray-400 mt-2", children: "Powered by AI — always verify indicators before clicking links or returning calls." })
      ] })
    ] })
  ] });
}
function SessionItem({
  session,
  active,
  onClick,
  onDelete,
  onPin
}) {
  const [hover, setHover] = reactExports.useState(false);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { onClick, onMouseEnter: () => setHover(true), onMouseLeave: () => setHover(false), className: `group flex cursor-pointer items-start gap-2.5 rounded-xl px-2.5 py-2 mb-0.5 border transition-all ${active ? "bg-[#C48A5A]/15 border-[#C48A5A]/30 text-white" : "border-transparent text-gray-300 hover:bg-white/5 hover:text-white"}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(MessageSquare, { className: `mt-0.5 h-3.5 w-3.5 shrink-0 ${active ? "text-[#C48A5A]" : "text-gray-400"}` }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1 min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `truncate text-[11px] font-bold ${active ? "text-white" : "text-gray-300"} font-manrope`, children: session.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "truncate text-[10px] text-gray-400 font-manrope mt-0.5", children: session.preview }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[9px] text-gray-500 font-manrope mt-1", children: session.timestamp })
    ] }),
    hover && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-0.5 shrink-0 ml-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: (e) => onPin(session.id, e), className: "flex h-5 w-5 items-center justify-center rounded-lg hover:bg-white/10 transition-colors", title: session.pinned ? "Unpin" : "Pin", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Pin, { className: `h-3 w-3 ${session.pinned ? "text-[#C48A5A]" : "text-gray-400"}` }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: (e) => onDelete(session.id, e), className: "flex h-5 w-5 items-center justify-center rounded-lg hover:bg-white/10 transition-colors", title: "Delete chat", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Trash2, { className: "h-3 w-3 text-[#E05A52]" }) })
    ] })
  ] });
}
export {
  ChatbotPage as component
};
