import { useState, useEffect, useRef } from "react";
import { Link, useRouterState, useNavigate } from "@tanstack/react-router";
import {
  Shield,
  LayoutDashboard,
  MessageSquare,
  AlertTriangle,
  Link2,
  Phone,
  Mail,
  Globe,
  MessageCircle,
  Radar,
  Search,
  Bell,
  Settings,
  FileText,
  ChevronLeft,
  ChevronRight,
  Plus,
  X,
  Loader2,
  CheckCircle,
  AlertCircle,
  Info,
  Clock,
} from "lucide-react";

/* ─── Nav items ─────────────────────────────────────────── */
const navItems = [
  { to: "/dashboard",     label: "Dashboard",          icon: LayoutDashboard },
  { to: "/threats",       label: "Threat Feed",        icon: AlertTriangle },
  { to: "/phishing-urls", label: "URL Intelligence",   icon: Link2 },
  { to: "/email-scams",   label: "Email Intelligence", icon: Mail },
  { to: "/call-sms-intel",label: "Phone Intelligence", icon: Radar },
  { to: "/malicious-ips", label: "IP Intelligence",    icon: Globe },
  { to: "/spam-calls",    label: "Spam Calls DB",      icon: Phone },
  { to: "/scam-messages", label: "Scam Messages DB",   icon: MessageCircle },
  { to: "/chatbot",       label: "Security Chatbot",   icon: MessageSquare },
] as const;

/* ─── Notification types ────────────────────────────────── */
type NotifSeverity = "critical" | "warning" | "info" | "success";
interface Notification {
  id: string;
  title: string;
  description: string;
  timestamp: string;
  severity: NotifSeverity;
  read: boolean;
}

const INITIAL_NOTIFICATIONS: Notification[] = [
  {
    id: "n1",
    title: "Critical Threat Detected",
    description: "LockBit 3.0 ransomware indicators found in Threat Feed database.",
    timestamp: "2 min ago",
    severity: "critical",
    read: false,
  },
  {
    id: "n2",
    title: "New Phishing URL Added",
    description: "paypal-secure-login.ru has been added to phishing URL blocklist.",
    timestamp: "15 min ago",
    severity: "warning",
    read: false,
  },
  {
    id: "n3",
    title: "Scam Call Spike Detected",
    description: "Unusual spike in calls from +91 8800 region — 42 new entries today.",
    timestamp: "1 hr ago",
    severity: "warning",
    read: false,
  },
  {
    id: "n4",
    title: "Database Sync Completed",
    description: "20,000 Indian phone records successfully synced to the database.",
    timestamp: "3 hr ago",
    severity: "success",
    read: true,
  },
  {
    id: "n5",
    title: "API Integration Healthy",
    description: "Abstract Phone Validation API is responding normally.",
    timestamp: "Yesterday",
    severity: "info",
    read: true,
  },
];

const sevStyle: Record<NotifSeverity, { icon: typeof Info; color: string; bg: string }> = {
  critical: { icon: AlertCircle, color: "#E05A52", bg: "#E05A5212" },
  warning:  { icon: AlertTriangle, color: "#E8A23C", bg: "#E8A23C12" },
  success:  { icon: CheckCircle, color: "#34A853", bg: "#34A85312" },
  info:     { icon: Info, color: "#4F7EF7", bg: "#4F7EF712" },
};

/* ─── Search result type ────────────────────────────────── */
interface SearchResult {
  entity: string;
  label: string;
  value: string;
  severity?: string;
  route: string;
}

const ENTITY_LABELS: Record<string, string> = {
  threats:       "Threat Feed",
  phishing_urls: "Phishing URL",
  email_scams:   "Email Scam",
  malicious_ips: "Malicious IP",
  spam_calls:    "Spam Call",
  scam_messages: "Scam Message",
};

const ENTITY_ROUTES: Record<string, string> = {
  threats:       "/threats",
  phishing_urls: "/phishing-urls",
  email_scams:   "/email-scams",
  malicious_ips: "/malicious-ips",
  spam_calls:    "/spam-calls",
  scam_messages: "/scam-messages",
};

/* Derive primary display value from row */
function rowToValue(entity: string, row: Record<string, unknown>): string {
  const candidates = [
    row.phone_number, row.url, row.email, row.ip_address,
    row.threat_name, row.name, row.message, row.indicator, row.value,
  ];
  for (const c of candidates) {
    if (c && typeof c === "string") return c;
  }
  return String(Object.values(row).find((v) => v) ?? "—");
}

/* ─── Sidebar ───────────────────────────────────────────── */
export function Sidebar() {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [isCollapsed, setIsCollapsed] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem("sidebar-collapsed");
    if (saved === "true") setIsCollapsed(true);
  }, []);

  const toggleCollapse = () => {
    setIsCollapsed((prev) => {
      const next = !prev;
      localStorage.setItem("sidebar-collapsed", String(next));
      return next;
    });
  };

  return (
    <aside
      className={`sticky top-0 left-0 z-40 flex h-screen flex-col shrink-0 bg-[#2E323A] text-white/90 border-r border-[#3e434f] transition-all duration-300 ${
        isCollapsed ? "w-20" : "w-64"
      }`}
    >
      {/* Brand */}
      <div className="flex h-16 items-center justify-between border-b border-[#3e434f] px-4">
        <Link to="/dashboard" className="flex items-center gap-2 font-bold text-white">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[#C48A5A] text-white shadow-md">
            <Shield className="h-5 w-5" />
          </div>
          {!isCollapsed && (
            <span className="font-poppins text-sm tracking-wide text-white font-semibold">
              Scam Detector AI
            </span>
          )}
        </Link>
        <button
          onClick={toggleCollapse}
          className="flex h-7 w-7 items-center justify-center rounded-lg border border-[#3e434f] hover:bg-[#3e434f]/50 transition-colors"
        >
          {isCollapsed ? (
            <ChevronRight className="h-4 w-4 text-gray-400" />
          ) : (
            <ChevronLeft className="h-4 w-4 text-gray-400" />
          )}
        </button>
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-1.5 px-3 py-4 overflow-y-auto">
        {!isCollapsed && (
          <p className="px-3 mb-2 text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">
            Intelligence Feeds
          </p>
        )}
        {navItems.map((n) => {
          const Icon = n.icon;
          const active = pathname === n.to;
          return (
            <Link
              key={n.to}
              to={n.to}
              className={`flex items-center gap-3 rounded-xl px-3 py-2.5 text-xs font-semibold tracking-wide transition-all duration-150 ${
                active
                  ? "bg-[#C48A5A] text-white shadow-lg shadow-[#C48A5A]/25"
                  : "text-gray-300 hover:bg-white/5 hover:text-white"
              }`}
            >
              <Icon className={`h-4.5 w-4.5 shrink-0 ${active ? "text-white" : "text-gray-400"}`} />
              {!isCollapsed && <span className="font-manrope">{n.label}</span>}
            </Link>
          );
        })}
      </nav>

      {/* Footer links — Reports & Settings now have correct routes */}
      <div className="border-t border-[#3e434f] p-3 space-y-1">
        <Link
          to="/reports"
          className={`flex items-center gap-3 rounded-xl px-3 py-2 text-xs font-semibold transition-all ${
            pathname === "/reports"
              ? "bg-[#C48A5A] text-white"
              : "text-gray-300 hover:bg-white/5 hover:text-white"
          }`}
        >
          <FileText className="h-4.5 w-4.5 text-gray-400" />
          {!isCollapsed && <span className="font-manrope">Reports</span>}
        </Link>
        <Link
          to="/settings"
          className={`flex items-center gap-3 rounded-xl px-3 py-2 text-xs font-semibold transition-all ${
            pathname === "/settings"
              ? "bg-[#C48A5A] text-white"
              : "text-gray-300 hover:bg-white/5 hover:text-white"
          }`}
        >
          <Settings className="h-4.5 w-4.5 text-gray-400" />
          {!isCollapsed && <span className="font-manrope">Settings</span>}
        </Link>
      </div>
    </aside>
  );
}

/* ─── Top Header ────────────────────────────────────────── */
export function TopHeader() {
  const navigate = useNavigate();

  /* ── Search state ── */
  const [query, setQuery]           = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [searching, setSearching]   = useState(false);
  const [results, setResults]       = useState<SearchResult[]>([]);
  const [searchError, setSearchError] = useState<string | null>(null);
  const searchRef = useRef<HTMLDivElement>(null);

  /* ── Notification state ── */
  const [notifOpen, setNotifOpen]         = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>(INITIAL_NOTIFICATIONS);
  const notifRef = useRef<HTMLDivElement>(null);

  const unreadCount = notifications.filter((n) => !n.read).length;

  /* Close dropdowns on outside click */
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (searchRef.current && !searchRef.current.contains(e.target as Node)) {
        setSearchOpen(false);
      }
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setNotifOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  /* ── Search logic ── */
  async function runSearch(q: string) {
    const trimmed = q.trim();
    if (!trimmed) { setResults([]); setSearchOpen(false); return; }

    setSearching(true);
    setSearchError(null);
    setSearchOpen(true);

    const entities = [
      "threats", "phishing_urls", "email_scams",
      "malicious_ips", "spam_calls", "scam_messages",
    ];

    try {
      const allResults: SearchResult[] = [];

      await Promise.all(
        entities.map(async (entity) => {
          try {
            const res = await fetch(
              `/api/v1/entity/${entity}?limit=200&offset=0`
            );
            if (!res.ok) return;
            const json = await res.json();
            const rows: Record<string, unknown>[] = json.rows ?? [];
            const lower = trimmed.toLowerCase();

            for (const row of rows) {
              const matched = Object.values(row).some(
                (v) =>
                  v != null &&
                  String(v).toLowerCase().includes(lower)
              );
              if (matched) {
                allResults.push({
                  entity,
                  label: ENTITY_LABELS[entity] ?? entity,
                  value: rowToValue(entity, row),
                  severity: String(row.severity ?? ""),
                  route: ENTITY_ROUTES[entity] ?? "/dashboard",
                });
                if (allResults.length >= 20) break; // cap
              }
            }
          } catch {
            // silently skip per-entity failures
          }
        })
      );

      setResults(allResults);
    } catch {
      setSearchError("Search failed. Please try again.");
      setResults([]);
    } finally {
      setSearching(false);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") runSearch(query);
    if (e.key === "Escape") { setSearchOpen(false); setQuery(""); }
  }

  function markAllRead() {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  }

  function markRead(id: string) {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n))
    );
  }

  const sevColor: Record<NotifSeverity, string> = {
    critical: "#E05A52", warning: "#E8A23C", success: "#34A853", info: "#4F7EF7",
  };

  return (
    <header className="sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-[#E4DEC6] bg-[#FAF8F5] px-6 shadow-sm">

      {/* ── Global Search ── */}
      <div className="flex flex-1 items-center gap-4">
        <div ref={searchRef} className="relative w-full max-w-md">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
          <input
            id="global-search"
            type="text"
            placeholder="Search threats, URLs, emails, IPs, phone numbers…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            onFocus={() => { if (results.length > 0 || searchError) setSearchOpen(true); }}
            className="w-full rounded-full border border-[#E4DEC6] bg-white py-2 pl-10 pr-10 text-xs font-medium text-gray-800 outline-none shadow-sm transition-all focus:border-[#C48A5A] focus:ring-1 focus:ring-[#C48A5A]"
          />
          {/* Right side — loader or clear */}
          {searching ? (
            <Loader2 className="absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 animate-spin text-[#C48A5A]" />
          ) : query ? (
            <button
              onClick={() => { setQuery(""); setResults([]); setSearchOpen(false); }}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          ) : null}

          {/* ── Results Dropdown ── */}
          {searchOpen && (
            <div className="absolute left-0 top-full mt-2 w-full rounded-2xl border border-[#E4DEC6] bg-white shadow-lg z-50 overflow-hidden">
              {searchError ? (
                <div className="flex items-center gap-2 px-4 py-3 text-xs font-semibold text-[#E05A52]">
                  <AlertCircle className="h-4 w-4" /> {searchError}
                </div>
              ) : searching ? (
                <div className="flex items-center gap-2 px-4 py-4 text-xs font-semibold text-gray-500">
                  <Loader2 className="h-4 w-4 animate-spin text-[#C48A5A]" /> Searching across all intelligence feeds…
                </div>
              ) : results.length === 0 ? (
                <div className="px-4 py-5 text-center text-xs font-semibold text-gray-400 font-manrope">
                  No results found for <span className="text-[#C48A5A]">"{query}"</span>
                </div>
              ) : (
                <div className="max-h-72 overflow-y-auto">
                  <div className="px-4 py-2 border-b border-[#E4DEC6]">
                    <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope">
                      {results.length} result{results.length !== 1 ? "s" : ""} found
                    </p>
                  </div>
                  {results.map((r, i) => (
                    <button
                      key={i}
                      onClick={() => {
                        setSearchOpen(false);
                        setQuery("");
                        navigate({ to: r.route as any });
                      }}
                      className="flex w-full items-center gap-3 px-4 py-2.5 hover:bg-[#FAF8F5] text-left transition-colors border-b border-[#E4DEC6]/50 last:border-0"
                    >
                      <span
                        className="rounded-full px-2 py-0.5 text-[9px] font-bold uppercase tracking-wide shrink-0"
                        style={{
                          background: "#C48A5A15",
                          color: "#C48A5A",
                          border: "1px solid #C48A5A20",
                        }}
                      >
                        {r.label}
                      </span>
                      <span className="flex-1 min-w-0 truncate text-xs font-semibold text-gray-700 font-manrope">
                        {r.value}
                      </span>
                      {r.severity && (
                        <span
                          className="text-[9px] font-bold uppercase rounded-full px-1.5 py-0.5 shrink-0"
                          style={{
                            color: r.severity === "critical" ? "#E05A52"
                              : r.severity === "high" ? "#E8A23C"
                              : r.severity === "medium" ? "#4F7EF7"
                              : "#34A853",
                            background: r.severity === "critical" ? "#E05A5210"
                              : r.severity === "high" ? "#E8A23C10"
                              : r.severity === "medium" ? "#4F7EF710"
                              : "#34A85310",
                          }}
                        >
                          {r.severity}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* ── Right Side Controls ── */}
      <div className="flex items-center gap-4">
        {/* Quick Entry */}
        <Link
          to="/threats"
          className="hidden md:flex items-center gap-1.5 rounded-full bg-[#4F7EF7] px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-[#4F7EF7]/90 transition-all"
        >
          <Plus className="h-3.5 w-3.5" />
          Quick Entry
        </Link>

        {/* ── Notification Bell ── */}
        <div ref={notifRef} className="relative">
          <button
            id="notification-bell"
            onClick={() => setNotifOpen((v) => !v)}
            className="flex h-9 w-9 items-center justify-center rounded-full border border-[#E4DEC6] bg-white text-gray-600 shadow-sm hover:bg-gray-50 transition-colors"
            aria-label="Notifications"
          >
            <Bell className="h-4 w-4" />
            {unreadCount > 0 && (
              <span className="absolute right-0.5 top-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-[#E05A52] text-[8px] font-bold text-white border border-white">
                {unreadCount > 9 ? "9+" : unreadCount}
              </span>
            )}
          </button>

          {/* ── Notification Panel ── */}
          {notifOpen && (
            <div className="absolute right-0 top-full mt-2 w-80 rounded-2xl border border-[#E4DEC6] bg-white shadow-xl z-50 overflow-hidden">
              {/* Panel header */}
              <div className="flex items-center justify-between border-b border-[#E4DEC6] px-4 py-3">
                <div className="flex items-center gap-2">
                  <Bell className="h-4 w-4 text-[#C48A5A]" />
                  <span className="text-xs font-extrabold text-gray-800 font-poppins">Notifications</span>
                  {unreadCount > 0 && (
                    <span className="rounded-full bg-[#E05A52] px-1.5 py-0.5 text-[9px] font-bold text-white">
                      {unreadCount} new
                    </span>
                  )}
                </div>
                {unreadCount > 0 && (
                  <button
                    onClick={markAllRead}
                    className="text-[10px] font-bold text-[#4F7EF7] hover:underline font-manrope"
                  >
                    Mark all read
                  </button>
                )}
              </div>

              {/* Notification list */}
              <div className="max-h-80 overflow-y-auto divide-y divide-[#E4DEC6]/60">
                {notifications.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-8 text-center">
                    <Bell className="h-8 w-8 text-gray-200 mb-2" />
                    <p className="text-xs font-semibold text-gray-400 font-manrope">No new notifications</p>
                  </div>
                ) : (
                  notifications.map((n) => {
                    const cfg = sevStyle[n.severity];
                    const Icon = cfg.icon;
                    return (
                      <button
                        key={n.id}
                        onClick={() => markRead(n.id)}
                        className={`flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-[#FAF8F5] ${
                          !n.read ? "bg-[#FAF8F5]/60" : ""
                        }`}
                      >
                        <div
                          className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full"
                          style={{ background: cfg.bg }}
                        >
                          <Icon className="h-3.5 w-3.5" style={{ color: cfg.color }} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between gap-2">
                            <p className={`text-[11px] font-bold font-poppins truncate ${n.read ? "text-gray-600" : "text-gray-800"}`}>
                              {n.title}
                            </p>
                            {!n.read && (
                              <span className="h-1.5 w-1.5 rounded-full bg-[#E05A52] shrink-0" />
                            )}
                          </div>
                          <p className="mt-0.5 text-[10px] font-semibold text-gray-500 font-manrope leading-relaxed line-clamp-2">
                            {n.description}
                          </p>
                          <div className="mt-1 flex items-center gap-1 text-[9px] text-gray-400 font-manrope">
                            <Clock className="h-2.5 w-2.5" /> {n.timestamp}
                          </div>
                        </div>
                      </button>
                    );
                  })
                )}
              </div>

              {/* Panel footer */}
              <div className="border-t border-[#E4DEC6] px-4 py-2 text-center">
                <p className="text-[10px] font-semibold text-gray-400 font-manrope">
                  Notifications auto-refresh every session
                </p>
              </div>
            </div>
          )}
        </div>

        {/* User Profile */}
        <div className="flex items-center gap-2 border-l border-[#E4DEC6] pl-4">
          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-[#C48A5A] text-white font-bold text-xs shadow-sm">
            VI
          </div>
          <div className="hidden text-left md:block">
            <p className="text-xs font-bold text-gray-800 font-poppins">Analyst Vigha</p>
            <p className="text-[10px] font-bold text-gray-500 font-manrope">SecOps Team</p>
          </div>
        </div>
      </div>
    </header>
  );
}

/* Retain stub for backward compatibility */
export function SiteHeader() {
  return null;
}
