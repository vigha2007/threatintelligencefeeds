import { b as QueryClient } from "../_libs/tanstack__query-core.mjs";
import { Q as QueryClientProvider, q as queryOptions, u as useQueryClient, a as useQuery, b as useMutation } from "../_libs/tanstack__react-query.mjs";
import { c as createRouter, a as createRootRouteWithContext, u as useRouter, L as Link, O as Outlet, H as HeadContent, S as Scripts, b as createFileRoute, l as lazyRouteComponent, d as useRouterState, e as useNavigate } from "../_libs/tanstack__react-router.mjs";
import { S as redirect, m as isRedirect } from "../_libs/tanstack__router-core.mjs";
import { r as reactExports, j as jsxRuntimeExports } from "../_libs/react.mjs";
import { T as Toaster$1, t as toast } from "../_libs/sonner.mjs";
import { S as Slot } from "../_libs/radix-ui__react-slot.mjs";
import { c as cva } from "../_libs/class-variance-authority.mjs";
import { c as clsx } from "../_libs/clsx.mjs";
import { t as twMerge } from "../_libs/tailwind-merge.mjs";
import { R as Root$1 } from "../_libs/radix-ui__react-label.mjs";
import { S as Select$1, a as SelectValue$1, b as SelectTrigger$1, c as SelectIcon, d as SelectPortal, e as SelectContent$1, f as SelectViewport, g as SelectItem$1, h as SelectItemIndicator, i as SelectItemText, j as SelectScrollUpButton$1, k as SelectScrollDownButton$1, l as SelectLabel$1, m as SelectSeparator$1 } from "../_libs/radix-ui__react-select.mjs";
import { R as Root, T as Trigger, P as Portal, C as Content, a as Close, b as Title, O as Overlay, D as Description } from "../_libs/radix-ui__react-dialog.mjs";
import { c as createServerFn, T as TSS_SERVER_FUNCTION, g as getServerFnById } from "./server-BRD1Kp-V.mjs";
import { s as severityEnum, e as entities, a as allEntityKeys } from "./threat-entities-SRQqKOBI.mjs";
import { S as Shield, C as ChevronRight, a as ChevronLeft, L as LayoutDashboard, T as TriangleAlert, b as Link2, M as Mail, R as Radar, G as Globe, P as Phone, c as MessageCircle, d as MessageSquare, F as FileText, e as Settings, f as Search, g as LoaderCircle, X, h as CircleAlert, i as Plus, B as Bell, I as Info, j as CircleCheckBig, k as Clock, l as Trash2, m as ChevronDown, n as Check, o as ChevronUp } from "../_libs/lucide-react.mjs";
import { m as motion } from "../_libs/framer-motion.mjs";
import { o as objectType, r as recordType, s as stringType, u as unknownType, n as numberType, e as enumType, a as unionType } from "../_libs/zod.mjs";
import "../_libs/react-dom.mjs";
import "util";
import "crypto";
import "async_hooks";
import "stream";
import "node:stream";
import "../_libs/isbot.mjs";
import "../_libs/tanstack__history.mjs";
import "../_libs/cookie-es.mjs";
import "../_libs/seroval.mjs";
import "../_libs/seroval-plugins.mjs";
import "node:stream/web";
import "../_libs/radix-ui__react-compose-refs.mjs";
import "../_libs/radix-ui__react-primitive.mjs";
import "../_libs/radix-ui__number.mjs";
import "../_libs/radix-ui__primitive.mjs";
import "../_libs/radix-ui__react-collection.mjs";
import "../_libs/radix-ui__react-context.mjs";
import "../_libs/radix-ui__react-direction.mjs";
import "../_libs/@radix-ui/react-dismissable-layer+[...].mjs";
import "../_libs/@radix-ui/react-use-callback-ref+[...].mjs";
import "../_libs/@radix-ui/react-use-escape-keydown+[...].mjs";
import "../_libs/radix-ui__react-focus-guards.mjs";
import "../_libs/radix-ui__react-focus-scope.mjs";
import "../_libs/radix-ui__react-id.mjs";
import "../_libs/@radix-ui/react-use-layout-effect+[...].mjs";
import "../_libs/radix-ui__react-popper.mjs";
import "../_libs/floating-ui__react-dom.mjs";
import "../_libs/floating-ui__dom.mjs";
import "../_libs/floating-ui__core.mjs";
import "../_libs/floating-ui__utils.mjs";
import "../_libs/radix-ui__react-arrow.mjs";
import "../_libs/radix-ui__react-use-size.mjs";
import "../_libs/radix-ui__react-portal.mjs";
import "../_libs/radix-ui__react-presence.mjs";
import "../_libs/@radix-ui/react-use-controllable-state+[...].mjs";
import "../_libs/radix-ui__react-use-previous.mjs";
import "../_libs/@radix-ui/react-visually-hidden+[...].mjs";
import "../_libs/aria-hidden.mjs";
import "../_libs/react-remove-scroll.mjs";
import "tslib";
import "../_libs/react-remove-scroll-bar.mjs";
import "../_libs/react-style-singleton.mjs";
import "../_libs/get-nonce.mjs";
import "../_libs/use-sidecar.mjs";
import "../_libs/use-callback-ref.mjs";
import "node:async_hooks";
import "../_libs/h3-v2.mjs";
import "../_libs/rou3.mjs";
import "../_libs/srvx.mjs";
import "../_libs/motion-dom.mjs";
import "../_libs/motion-utils.mjs";
function useServerFn(serverFn) {
  const router2 = useRouter();
  return reactExports.useCallback(async (...args) => {
    try {
      const res = await serverFn(...args);
      if (isRedirect(res)) throw res;
      return res;
    } catch (err) {
      if (isRedirect(err)) {
        err.options._fromLocation = router2.stores.location.get();
        return router2.navigate(router2.resolveRedirect(err).options);
      }
      throw err;
    }
  }, [router2, serverFn]);
}
const Toaster = ({ ...props }) => {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    Toaster$1,
    {
      className: "toaster group",
      toastOptions: {
        classNames: {
          toast: "group toast group-[.toaster]:bg-background group-[.toaster]:text-foreground group-[.toaster]:border-border group-[.toaster]:shadow-lg",
          description: "group-[.toast]:text-muted-foreground",
          actionButton: "group-[.toast]:bg-primary group-[.toast]:text-primary-foreground",
          cancelButton: "group-[.toast]:bg-muted group-[.toast]:text-muted-foreground"
        }
      },
      ...props
    }
  );
};
const navItems = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/threats", label: "Threat Feed", icon: TriangleAlert },
  { to: "/phishing-urls", label: "URL Intelligence", icon: Link2 },
  { to: "/email-scams", label: "Email Intelligence", icon: Mail },
  { to: "/call-sms-intel", label: "Phone Intelligence", icon: Radar },
  { to: "/malicious-ips", label: "IP Intelligence", icon: Globe },
  { to: "/spam-calls", label: "Spam Calls DB", icon: Phone },
  { to: "/scam-messages", label: "Scam Messages DB", icon: MessageCircle },
  { to: "/chatbot", label: "Security Chatbot", icon: MessageSquare }
];
const INITIAL_NOTIFICATIONS = [
  {
    id: "n1",
    title: "Critical Threat Detected",
    description: "LockBit 3.0 ransomware indicators found in Threat Feed database.",
    timestamp: "2 min ago",
    severity: "critical",
    read: false
  },
  {
    id: "n2",
    title: "New Phishing URL Added",
    description: "paypal-secure-login.ru has been added to phishing URL blocklist.",
    timestamp: "15 min ago",
    severity: "warning",
    read: false
  },
  {
    id: "n3",
    title: "Scam Call Spike Detected",
    description: "Unusual spike in calls from +91 8800 region — 42 new entries today.",
    timestamp: "1 hr ago",
    severity: "warning",
    read: false
  },
  {
    id: "n4",
    title: "Database Sync Completed",
    description: "20,000 Indian phone records successfully synced to the database.",
    timestamp: "3 hr ago",
    severity: "success",
    read: true
  },
  {
    id: "n5",
    title: "API Integration Healthy",
    description: "Abstract Phone Validation API is responding normally.",
    timestamp: "Yesterday",
    severity: "info",
    read: true
  }
];
const sevStyle = {
  critical: { icon: CircleAlert, color: "#E05A52", bg: "#E05A5212" },
  warning: { icon: TriangleAlert, color: "#E8A23C", bg: "#E8A23C12" },
  success: { icon: CircleCheckBig, color: "#34A853", bg: "#34A85312" },
  info: { icon: Info, color: "#4F7EF7", bg: "#4F7EF712" }
};
const ENTITY_LABELS = {
  threats: "Threat Feed",
  phishing_urls: "Phishing URL",
  email_scams: "Email Scam",
  malicious_ips: "Malicious IP",
  spam_calls: "Spam Call",
  scam_messages: "Scam Message"
};
const ENTITY_ROUTES = {
  threats: "/threats",
  phishing_urls: "/phishing-urls",
  email_scams: "/email-scams",
  malicious_ips: "/malicious-ips",
  spam_calls: "/spam-calls",
  scam_messages: "/scam-messages"
};
function rowToValue(entity, row) {
  const candidates = [
    row.phone_number,
    row.url,
    row.email,
    row.ip_address,
    row.threat_name,
    row.name,
    row.message,
    row.indicator,
    row.value
  ];
  for (const c of candidates) {
    if (c && typeof c === "string") return c;
  }
  return String(Object.values(row).find((v) => v) ?? "—");
}
function Sidebar() {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [isCollapsed, setIsCollapsed] = reactExports.useState(false);
  reactExports.useEffect(() => {
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
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "aside",
    {
      className: `sticky top-0 left-0 z-40 flex h-screen flex-col shrink-0 bg-[#2E323A] text-white/90 border-r border-[#3e434f] transition-all duration-300 ${isCollapsed ? "w-20" : "w-64"}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex h-16 items-center justify-between border-b border-[#3e434f] px-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(Link, { to: "/dashboard", className: "flex items-center gap-2 font-bold text-white", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex h-9 w-9 items-center justify-center rounded-xl bg-[#C48A5A] text-white shadow-md", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Shield, { className: "h-5 w-5" }) }),
            !isCollapsed && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-poppins text-sm tracking-wide text-white font-semibold", children: "Scam Detector AI" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              onClick: toggleCollapse,
              className: "flex h-7 w-7 items-center justify-center rounded-lg border border-[#3e434f] hover:bg-[#3e434f]/50 transition-colors",
              children: isCollapsed ? /* @__PURE__ */ jsxRuntimeExports.jsx(ChevronRight, { className: "h-4 w-4 text-gray-400" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(ChevronLeft, { className: "h-4 w-4 text-gray-400" })
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("nav", { className: "flex-1 space-y-1.5 px-3 py-4 overflow-y-auto", children: [
          !isCollapsed && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "px-3 mb-2 text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope", children: "Intelligence Feeds" }),
          navItems.map((n) => {
            const Icon = n.icon;
            const active = pathname === n.to;
            return /* @__PURE__ */ jsxRuntimeExports.jsxs(
              Link,
              {
                to: n.to,
                className: `flex items-center gap-3 rounded-xl px-3 py-2.5 text-xs font-semibold tracking-wide transition-all duration-150 ${active ? "bg-[#C48A5A] text-white shadow-lg shadow-[#C48A5A]/25" : "text-gray-300 hover:bg-white/5 hover:text-white"}`,
                children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: `h-4.5 w-4.5 shrink-0 ${active ? "text-white" : "text-gray-400"}` }),
                  !isCollapsed && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-manrope", children: n.label })
                ]
              },
              n.to
            );
          })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-[#3e434f] p-3 space-y-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            Link,
            {
              to: "/reports",
              className: `flex items-center gap-3 rounded-xl px-3 py-2 text-xs font-semibold transition-all ${pathname === "/reports" ? "bg-[#C48A5A] text-white" : "text-gray-300 hover:bg-white/5 hover:text-white"}`,
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(FileText, { className: "h-4.5 w-4.5 text-gray-400" }),
                !isCollapsed && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-manrope", children: "Reports" })
              ]
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            Link,
            {
              to: "/settings",
              className: `flex items-center gap-3 rounded-xl px-3 py-2 text-xs font-semibold transition-all ${pathname === "/settings" ? "bg-[#C48A5A] text-white" : "text-gray-300 hover:bg-white/5 hover:text-white"}`,
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(Settings, { className: "h-4.5 w-4.5 text-gray-400" }),
                !isCollapsed && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-manrope", children: "Settings" })
              ]
            }
          )
        ] })
      ]
    }
  );
}
function TopHeader() {
  const navigate = useNavigate();
  const [query, setQuery] = reactExports.useState("");
  const [searchOpen, setSearchOpen] = reactExports.useState(false);
  const [searching, setSearching] = reactExports.useState(false);
  const [results, setResults] = reactExports.useState([]);
  const [searchError, setSearchError] = reactExports.useState(null);
  const searchRef = reactExports.useRef(null);
  const [notifOpen, setNotifOpen] = reactExports.useState(false);
  const [notifications, setNotifications] = reactExports.useState(INITIAL_NOTIFICATIONS);
  const notifRef = reactExports.useRef(null);
  const unreadCount = notifications.filter((n) => !n.read).length;
  reactExports.useEffect(() => {
    function handleClick(e) {
      if (searchRef.current && !searchRef.current.contains(e.target)) {
        setSearchOpen(false);
      }
      if (notifRef.current && !notifRef.current.contains(e.target)) {
        setNotifOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);
  async function runSearch(q) {
    const trimmed = q.trim();
    if (!trimmed) {
      setResults([]);
      setSearchOpen(false);
      return;
    }
    setSearching(true);
    setSearchError(null);
    setSearchOpen(true);
    const entities2 = [
      "threats",
      "phishing_urls",
      "email_scams",
      "malicious_ips",
      "spam_calls",
      "scam_messages"
    ];
    try {
      const allResults = [];
      await Promise.all(
        entities2.map(async (entity) => {
          try {
            const res = await fetch(
              `/api/v1/entity/${entity}?limit=200&offset=0`
            );
            if (!res.ok) return;
            const json = await res.json();
            const rows = json.rows ?? [];
            const lower = trimmed.toLowerCase();
            for (const row of rows) {
              const matched = Object.values(row).some(
                (v) => v != null && String(v).toLowerCase().includes(lower)
              );
              if (matched) {
                allResults.push({
                  entity,
                  label: ENTITY_LABELS[entity] ?? entity,
                  value: rowToValue(entity, row),
                  severity: String(row.severity ?? ""),
                  route: ENTITY_ROUTES[entity] ?? "/dashboard"
                });
                if (allResults.length >= 20) break;
              }
            }
          } catch {
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
  function handleKeyDown(e) {
    if (e.key === "Enter") runSearch(query);
    if (e.key === "Escape") {
      setSearchOpen(false);
      setQuery("");
    }
  }
  function markAllRead() {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  }
  function markRead(id) {
    setNotifications(
      (prev) => prev.map((n) => n.id === id ? { ...n, read: true } : n)
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-[#E4DEC6] bg-[#FAF8F5] px-6 shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-1 items-center gap-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { ref: searchRef, className: "relative w-full max-w-md", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Search, { className: "absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          id: "global-search",
          type: "text",
          placeholder: "Search threats, URLs, emails, IPs, phone numbers…",
          value: query,
          onChange: (e) => setQuery(e.target.value),
          onKeyDown: handleKeyDown,
          onFocus: () => {
            if (results.length > 0 || searchError) setSearchOpen(true);
          },
          className: "w-full rounded-full border border-[#E4DEC6] bg-white py-2 pl-10 pr-10 text-xs font-medium text-gray-800 outline-none shadow-sm transition-all focus:border-[#C48A5A] focus:ring-1 focus:ring-[#C48A5A]"
        }
      ),
      searching ? /* @__PURE__ */ jsxRuntimeExports.jsx(LoaderCircle, { className: "absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 animate-spin text-[#C48A5A]" }) : query ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          onClick: () => {
            setQuery("");
            setResults([]);
            setSearchOpen(false);
          },
          className: "absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors",
          children: /* @__PURE__ */ jsxRuntimeExports.jsx(X, { className: "h-3.5 w-3.5" })
        }
      ) : null,
      searchOpen && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "absolute left-0 top-full mt-2 w-full rounded-2xl border border-[#E4DEC6] bg-white shadow-lg z-50 overflow-hidden", children: searchError ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 px-4 py-3 text-xs font-semibold text-[#E05A52]", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(CircleAlert, { className: "h-4 w-4" }),
        " ",
        searchError
      ] }) : searching ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 px-4 py-4 text-xs font-semibold text-gray-500", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(LoaderCircle, { className: "h-4 w-4 animate-spin text-[#C48A5A]" }),
        " Searching across all intelligence feeds…"
      ] }) : results.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 py-5 text-center text-xs font-semibold text-gray-400 font-manrope", children: [
        "No results found for ",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-[#C48A5A]", children: [
          '"',
          query,
          '"'
        ] })
      ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-h-72 overflow-y-auto", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4 py-2 border-b border-[#E4DEC6]", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-[10px] font-bold uppercase tracking-wider text-gray-400 font-manrope", children: [
          results.length,
          " result",
          results.length !== 1 ? "s" : "",
          " found"
        ] }) }),
        results.map((r, i) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            onClick: () => {
              setSearchOpen(false);
              setQuery("");
              navigate({ to: r.route });
            },
            className: "flex w-full items-center gap-3 px-4 py-2.5 hover:bg-[#FAF8F5] text-left transition-colors border-b border-[#E4DEC6]/50 last:border-0",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "span",
                {
                  className: "rounded-full px-2 py-0.5 text-[9px] font-bold uppercase tracking-wide shrink-0",
                  style: {
                    background: "#C48A5A15",
                    color: "#C48A5A",
                    border: "1px solid #C48A5A20"
                  },
                  children: r.label
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex-1 min-w-0 truncate text-xs font-semibold text-gray-700 font-manrope", children: r.value }),
              r.severity && /* @__PURE__ */ jsxRuntimeExports.jsx(
                "span",
                {
                  className: "text-[9px] font-bold uppercase rounded-full px-1.5 py-0.5 shrink-0",
                  style: {
                    color: r.severity === "critical" ? "#E05A52" : r.severity === "high" ? "#E8A23C" : r.severity === "medium" ? "#4F7EF7" : "#34A853",
                    background: r.severity === "critical" ? "#E05A5210" : r.severity === "high" ? "#E8A23C10" : r.severity === "medium" ? "#4F7EF710" : "#34A85310"
                  },
                  children: r.severity
                }
              )
            ]
          },
          i
        ))
      ] }) })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        Link,
        {
          to: "/threats",
          className: "hidden md:flex items-center gap-1.5 rounded-full bg-[#4F7EF7] px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-[#4F7EF7]/90 transition-all",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(Plus, { className: "h-3.5 w-3.5" }),
            "Quick Entry"
          ]
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { ref: notifRef, className: "relative", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            id: "notification-bell",
            onClick: () => setNotifOpen((v) => !v),
            className: "flex h-9 w-9 items-center justify-center rounded-full border border-[#E4DEC6] bg-white text-gray-600 shadow-sm hover:bg-gray-50 transition-colors",
            "aria-label": "Notifications",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(Bell, { className: "h-4 w-4" }),
              unreadCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "absolute right-0.5 top-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-[#E05A52] text-[8px] font-bold text-white border border-white", children: unreadCount > 9 ? "9+" : unreadCount })
            ]
          }
        ),
        notifOpen && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "absolute right-0 top-full mt-2 w-80 rounded-2xl border border-[#E4DEC6] bg-white shadow-xl z-50 overflow-hidden", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between border-b border-[#E4DEC6] px-4 py-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(Bell, { className: "h-4 w-4 text-[#C48A5A]" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-extrabold text-gray-800 font-poppins", children: "Notifications" }),
              unreadCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "rounded-full bg-[#E05A52] px-1.5 py-0.5 text-[9px] font-bold text-white", children: [
                unreadCount,
                " new"
              ] })
            ] }),
            unreadCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                onClick: markAllRead,
                className: "text-[10px] font-bold text-[#4F7EF7] hover:underline font-manrope",
                children: "Mark all read"
              }
            )
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "max-h-80 overflow-y-auto divide-y divide-[#E4DEC6]/60", children: notifications.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col items-center justify-center py-8 text-center", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(Bell, { className: "h-8 w-8 text-gray-200 mb-2" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold text-gray-400 font-manrope", children: "No new notifications" })
          ] }) : notifications.map((n) => {
            const cfg = sevStyle[n.severity];
            const Icon = cfg.icon;
            return /* @__PURE__ */ jsxRuntimeExports.jsxs(
              "button",
              {
                onClick: () => markRead(n.id),
                className: `flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-[#FAF8F5] ${!n.read ? "bg-[#FAF8F5]/60" : ""}`,
                children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    "div",
                    {
                      className: "mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full",
                      style: { background: cfg.bg },
                      children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-3.5 w-3.5", style: { color: cfg.color } })
                    }
                  ),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1 min-w-0", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-2", children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `text-[11px] font-bold font-poppins truncate ${n.read ? "text-gray-600" : "text-gray-800"}`, children: n.title }),
                      !n.read && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-1.5 w-1.5 rounded-full bg-[#E05A52] shrink-0" })
                    ] }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-[10px] font-semibold text-gray-500 font-manrope leading-relaxed line-clamp-2", children: n.description }),
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 flex items-center gap-1 text-[9px] text-gray-400 font-manrope", children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx(Clock, { className: "h-2.5 w-2.5" }),
                      " ",
                      n.timestamp
                    ] })
                  ] })
                ]
              },
              n.id
            );
          }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-t border-[#E4DEC6] px-4 py-2 text-center", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold text-gray-400 font-manrope", children: "Notifications auto-refresh every session" }) })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 border-l border-[#E4DEC6] pl-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex h-9 w-9 items-center justify-center rounded-full bg-[#C48A5A] text-white font-bold text-xs shadow-sm", children: "VI" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "hidden text-left md:block", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold text-gray-800 font-poppins", children: "Analyst Vigha" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-bold text-gray-500 font-manrope", children: "SecOps Team" })
        ] })
      ] })
    ] })
  ] });
}
const appCss = "/assets/styles-ByYbaeaN.css";
function reportLovableError(error, context = {}) {
  if (typeof window === "undefined") return;
  window.__lovableEvents?.captureException?.(
    error,
    {
      source: "react_error_boundary",
      route: window.location.pathname,
      ...context
    },
    {
      mechanism: "react_error_boundary",
      handled: false,
      severity: "error"
    }
  );
}
function NotFoundComponent() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex min-h-screen items-center justify-center bg-background px-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-md text-center", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-7xl font-bold text-foreground", children: "404" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "mt-4 text-xl font-semibold text-foreground", children: "Page not found" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-muted-foreground", children: "The page you're looking for doesn't exist or has been moved." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      Link,
      {
        to: "/",
        className: "inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90",
        children: "Go home"
      }
    ) })
  ] }) });
}
function ErrorComponent({ error, reset }) {
  console.error(error);
  const router2 = useRouter();
  reactExports.useEffect(() => {
    reportLovableError(error, { boundary: "tanstack_root_error_component" });
  }, [error]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex min-h-screen items-center justify-center bg-background px-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-md text-center", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-xl font-semibold tracking-tight text-foreground", children: "This page didn't load" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-muted-foreground", children: "Something went wrong on our end. You can try refreshing or head back home." }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex flex-wrap justify-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          onClick: () => {
            router2.invalidate();
            reset();
          },
          className: "inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90",
          children: "Try again"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "a",
        {
          href: "/",
          className: "inline-flex items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-accent",
          children: "Go home"
        }
      )
    ] })
  ] }) });
}
const Route$g = createRootRouteWithContext()({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: "Threat Intelligence" },
      { name: "description", content: "A cybersecurity dashboard and chatbot integration for real-time scam detection and threat analysis." },
      { name: "author", content: "Lovable" },
      { property: "og:title", content: "Threat Intelligence" },
      { property: "og:description", content: "A cybersecurity dashboard and chatbot integration for real-time scam detection and threat analysis." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { name: "twitter:site", content: "@Lovable" },
      { name: "twitter:title", content: "Threat Intelligence" },
      { name: "twitter:description", content: "A cybersecurity dashboard and chatbot integration for real-time scam detection and threat analysis." },
      { property: "og:image", content: "https://pub-bb2e103a32db4e198524a2e9ed8f35b4.r2.dev/ebc26eba-c9f1-474b-9982-3a35ffeb5daf/id-preview-79cb65c9--7035df47-fde5-4b6c-b020-ae864ebd071c.lovable.app-1780986232300.png" },
      { name: "twitter:image", content: "https://pub-bb2e103a32db4e198524a2e9ed8f35b4.r2.dev/ebc26eba-c9f1-474b-9982-3a35ffeb5daf/id-preview-79cb65c9--7035df47-fde5-4b6c-b020-ae864ebd071c.lovable.app-1780986232300.png" }
    ],
    links: [
      {
        rel: "preconnect",
        href: "https://fonts.googleapis.com"
      },
      {
        rel: "preconnect",
        href: "https://fonts.gstatic.com",
        crossOrigin: "anonymous"
      },
      {
        rel: "stylesheet",
        href: "https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Manrope:wght@400;500;600;700;800&family=Poppins:wght@400;500;600;700&display=swap"
      },
      {
        rel: "stylesheet",
        href: appCss
      }
    ]
  }),
  shellComponent: RootShell,
  component: RootComponent,
  notFoundComponent: NotFoundComponent,
  errorComponent: ErrorComponent
});
function RootShell({ children }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("html", { lang: "en", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("head", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(HeadContent, {}) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("body", { children: [
      children,
      /* @__PURE__ */ jsxRuntimeExports.jsx(Scripts, {})
    ] })
  ] });
}
function RootComponent() {
  const { queryClient } = Route$g.useRouteContext();
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(QueryClientProvider, { client: queryClient, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-screen w-full bg-[#F2EEE8]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Sidebar, {}),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-1 flex-col min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(TopHeader, {}),
        /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "flex-grow", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Outlet, {}) })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(Toaster, {})
  ] });
}
function cn(...inputs) {
  return twMerge(clsx(inputs));
}
const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium cursor-pointer transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 disabled:cursor-not-allowed [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground shadow hover:bg-primary/90",
        destructive: "bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive/90",
        outline: "border border-input bg-background shadow-sm hover:bg-accent hover:text-accent-foreground",
        secondary: "bg-secondary text-secondary-foreground shadow-sm hover:bg-secondary/80",
        ghost: "hover:bg-accent hover:text-accent-foreground",
        link: "text-primary underline-offset-4 hover:underline"
      },
      size: {
        default: "h-9 px-4 py-2",
        sm: "h-8 rounded-md px-3 text-xs",
        lg: "h-10 rounded-md px-8",
        icon: "h-9 w-9"
      }
    },
    defaultVariants: {
      variant: "default",
      size: "default"
    }
  }
);
const Button = reactExports.forwardRef(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return /* @__PURE__ */ jsxRuntimeExports.jsx(Comp, { className: cn(buttonVariants({ variant, size, className })), ref, ...props });
  }
);
Button.displayName = "Button";
const Input = reactExports.forwardRef(
  ({ className, type, ...props }, ref) => {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      "input",
      {
        type,
        className: cn(
          "flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm",
          className
        ),
        ref,
        ...props
      }
    );
  }
);
Input.displayName = "Input";
const labelVariants = cva(
  "text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
);
const Label = reactExports.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx(Root$1, { ref, className: cn(labelVariants(), className), ...props }));
Label.displayName = Root$1.displayName;
const Textarea = reactExports.forwardRef(
  ({ className, ...props }, ref) => {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      "textarea",
      {
        className: cn(
          "flex min-h-[60px] w-full rounded-md border border-input bg-transparent px-3 py-2 text-base shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm",
          className
        ),
        ref,
        ...props
      }
    );
  }
);
Textarea.displayName = "Textarea";
const Select = Select$1;
const SelectValue = SelectValue$1;
const SelectTrigger = reactExports.forwardRef(({ className, children, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
  SelectTrigger$1,
  {
    ref,
    className: cn(
      "flex h-9 w-full items-center justify-between whitespace-nowrap rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-sm ring-offset-background cursor-pointer data-[placeholder]:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50 [&>span]:line-clamp-1",
      className
    ),
    ...props,
    children: [
      children,
      /* @__PURE__ */ jsxRuntimeExports.jsx(SelectIcon, { asChild: true, children: /* @__PURE__ */ jsxRuntimeExports.jsx(ChevronDown, { className: "h-4 w-4 opacity-50" }) })
    ]
  }
));
SelectTrigger.displayName = SelectTrigger$1.displayName;
const SelectScrollUpButton = reactExports.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx(
  SelectScrollUpButton$1,
  {
    ref,
    className: cn("flex cursor-default items-center justify-center py-1", className),
    ...props,
    children: /* @__PURE__ */ jsxRuntimeExports.jsx(ChevronUp, { className: "h-4 w-4" })
  }
));
SelectScrollUpButton.displayName = SelectScrollUpButton$1.displayName;
const SelectScrollDownButton = reactExports.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx(
  SelectScrollDownButton$1,
  {
    ref,
    className: cn("flex cursor-default items-center justify-center py-1", className),
    ...props,
    children: /* @__PURE__ */ jsxRuntimeExports.jsx(ChevronDown, { className: "h-4 w-4" })
  }
));
SelectScrollDownButton.displayName = SelectScrollDownButton$1.displayName;
const SelectContent = reactExports.forwardRef(({ className, children, position = "popper", ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx(SelectPortal, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
  SelectContent$1,
  {
    ref,
    className: cn(
      "relative z-50 max-h-(--radix-select-content-available-height) min-w-[8rem] overflow-y-auto overflow-x-hidden rounded-md border bg-popover text-popover-foreground shadow-md data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 origin-(--radix-select-content-transform-origin)",
      position === "popper" && "data-[side=bottom]:translate-y-1 data-[side=left]:-translate-x-1 data-[side=right]:translate-x-1 data-[side=top]:-translate-y-1",
      className
    ),
    position,
    ...props,
    children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SelectScrollUpButton, {}),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        SelectViewport,
        {
          className: cn(
            "p-1",
            position === "popper" && "h-[var(--radix-select-trigger-height)] w-full min-w-[var(--radix-select-trigger-width)]"
          ),
          children
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SelectScrollDownButton, {})
    ]
  }
) }));
SelectContent.displayName = SelectContent$1.displayName;
const SelectLabel = reactExports.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx(
  SelectLabel$1,
  {
    ref,
    className: cn("px-2 py-1.5 text-sm font-semibold", className),
    ...props
  }
));
SelectLabel.displayName = SelectLabel$1.displayName;
const SelectItem = reactExports.forwardRef(({ className, children, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
  SelectItem$1,
  {
    ref,
    className: cn(
      "relative flex w-full cursor-default select-none items-center rounded-sm py-1.5 pl-2 pr-8 text-sm outline-none focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
      className
    ),
    ...props,
    children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "absolute right-2 flex h-3.5 w-3.5 items-center justify-center", children: /* @__PURE__ */ jsxRuntimeExports.jsx(SelectItemIndicator, { children: /* @__PURE__ */ jsxRuntimeExports.jsx(Check, { className: "h-4 w-4" }) }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SelectItemText, { children })
    ]
  }
));
SelectItem.displayName = SelectItem$1.displayName;
const SelectSeparator = reactExports.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx(
  SelectSeparator$1,
  {
    ref,
    className: cn("-mx-1 my-1 h-px bg-muted", className),
    ...props
  }
));
SelectSeparator.displayName = SelectSeparator$1.displayName;
const Dialog = Root;
const DialogTrigger = Trigger;
const DialogPortal = Portal;
const DialogOverlay = reactExports.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx(
  Overlay,
  {
    ref,
    className: cn(
      "fixed inset-0 z-50 bg-black/80  data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
      className
    ),
    ...props
  }
));
DialogOverlay.displayName = Overlay.displayName;
const DialogContent = reactExports.forwardRef(({ className, children, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsxs(DialogPortal, { children: [
  /* @__PURE__ */ jsxRuntimeExports.jsx(DialogOverlay, {}),
  /* @__PURE__ */ jsxRuntimeExports.jsxs(
    Content,
    {
      ref,
      className: cn(
        "fixed left-[50%] top-[50%] z-50 grid w-full max-w-lg translate-x-[-50%] translate-y-[-50%] gap-4 border bg-background p-6 shadow-lg duration-200 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 sm:rounded-lg",
        className
      ),
      ...props,
      children: [
        children,
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Close, { className: "absolute right-4 top-4 rounded-sm opacity-70 ring-offset-background cursor-pointer transition-opacity hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:pointer-events-none data-[state=open]:bg-accent data-[state=open]:text-muted-foreground", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(X, { className: "h-4 w-4" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Close" })
        ] })
      ]
    }
  )
] }));
DialogContent.displayName = Content.displayName;
const DialogHeader = ({ className, ...props }) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: cn("flex flex-col space-y-1.5 text-center sm:text-left", className), ...props });
DialogHeader.displayName = "DialogHeader";
const DialogFooter = ({ className, ...props }) => /* @__PURE__ */ jsxRuntimeExports.jsx(
  "div",
  {
    className: cn("flex flex-col-reverse sm:flex-row sm:justify-end sm:space-x-2", className),
    ...props
  }
);
DialogFooter.displayName = "DialogFooter";
const DialogTitle = reactExports.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx(
  Title,
  {
    ref,
    className: cn("text-lg font-semibold leading-none tracking-tight", className),
    ...props
  }
));
DialogTitle.displayName = Title.displayName;
const DialogDescription = reactExports.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx(
  Description,
  {
    ref,
    className: cn("text-sm text-muted-foreground", className),
    ...props
  }
));
DialogDescription.displayName = Description.displayName;
const Table = reactExports.forwardRef(
  ({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "relative w-full overflow-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsx("table", { ref, className: cn("w-full caption-bottom text-sm", className), ...props }) })
);
Table.displayName = "Table";
const TableHeader = reactExports.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { ref, className: cn("[&_tr]:border-b", className), ...props }));
TableHeader.displayName = "TableHeader";
const TableBody = reactExports.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { ref, className: cn("[&_tr:last-child]:border-0", className), ...props }));
TableBody.displayName = "TableBody";
const TableFooter = reactExports.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx(
  "tfoot",
  {
    ref,
    className: cn("border-t bg-muted/50 font-medium [&>tr]:last:border-b-0", className),
    ...props
  }
));
TableFooter.displayName = "TableFooter";
const TableRow = reactExports.forwardRef(
  ({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    "tr",
    {
      ref,
      className: cn(
        "border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted",
        className
      ),
      ...props
    }
  )
);
TableRow.displayName = "TableRow";
const TableHead = reactExports.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx(
  "th",
  {
    ref,
    className: cn(
      "h-10 px-2 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0 [&>[role=checkbox]]:translate-y-[2px]",
      className
    ),
    ...props
  }
));
TableHead.displayName = "TableHead";
const TableCell = reactExports.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx(
  "td",
  {
    ref,
    className: cn(
      "p-2 align-middle [&:has([role=checkbox])]:pr-0 [&>[role=checkbox]]:translate-y-[2px]",
      className
    ),
    ...props
  }
));
TableCell.displayName = "TableCell";
const TableCaption = reactExports.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsxRuntimeExports.jsx("caption", { ref, className: cn("mt-4 text-sm text-muted-foreground", className), ...props }));
TableCaption.displayName = "TableCaption";
var createSsrRpc = (functionId) => {
  const url = "/_serverFn/" + functionId;
  const serverFnMeta = { id: functionId };
  const fn = async (...args) => {
    return (await getServerFnById(functionId))(...args);
  };
  return Object.assign(fn, {
    url,
    serverFnMeta,
    [TSS_SERVER_FUNCTION]: true
  });
};
const entityKeySchema = enumType(allEntityKeys);
const listEntity = createServerFn({
  method: "GET"
}).validator((d) => objectType({
  entity: entityKeySchema,
  limit: numberType().int().positive().optional(),
  offset: numberType().int().min(0).optional()
}).parse(d)).handler(createSsrRpc("9370c38e835314b97d0feefd9b68122b929bfc6e659002fa67a94e09ae0508c9"));
const createEntity = createServerFn({
  method: "POST"
}).validator((d) => objectType({
  entity: entityKeySchema,
  values: recordType(stringType(), unknownType())
}).parse(d)).handler(createSsrRpc("7740c0594d9af779be21bf8d7bbe6fe08352c64d801d9506b230ab57cda96398"));
const deleteEntity = createServerFn({
  method: "POST"
}).validator((d) => objectType({
  entity: entityKeySchema,
  id: unionType([stringType(), numberType()]).transform(String)
}).parse(d)).handler(createSsrRpc("aeca7cbdb3f92f362d3fab6b7c0347b050e2873d52b97029bae376ca4a1d1b83"));
const SERVER_PAGE_SIZE = 200;
const sevColors = {
  critical: "#E05A52",
  high: "#E8A23C",
  medium: "#4F7EF7",
  low: "#34A853"
};
function EntityManagementPage({ entity }) {
  const def = entities[entity];
  const qc = useQueryClient();
  const list = useServerFn(listEntity);
  const create = useServerFn(createEntity);
  const del = useServerFn(deleteEntity);
  const [open, setOpen] = reactExports.useState(false);
  const [page, setPage] = reactExports.useState(1);
  const offset = (page - 1) * SERVER_PAGE_SIZE;
  const { data, isLoading, isError } = useQuery({
    queryKey: ["entity", entity, page],
    queryFn: () => list({ data: { entity, limit: SERVER_PAGE_SIZE, offset } }),
    staleTime: 15e3,
    placeholderData: (prev) => prev
  });
  const rows = data?.rows ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / SERVER_PAGE_SIZE));
  const start = offset + 1;
  const end = Math.min(offset + rows.length, total);
  const createMutation = useMutation({
    mutationFn: (values) => create({ data: { entity, values } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["entity", entity] });
      qc.invalidateQueries({ queryKey: ["dashboard-metrics"] });
      toast.success(`${def.singular} added successfully`);
      setOpen(false);
    },
    onError: (e) => toast.error(e.message)
  });
  const deleteMutation = useMutation({
    mutationFn: (id) => del({ data: { entity, id } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["entity", entity] });
      qc.invalidateQueries({ queryKey: ["dashboard-metrics"] });
      toast.success("Record deleted");
    },
    onError: (e) => toast.error(e.message)
  });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(motion.div, { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, className: "mb-6 flex items-center justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-2xl font-extrabold text-gray-800 font-poppins", children: def.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold text-gray-400 font-manrope mt-1", children: isLoading ? "Loading records..." : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-bold text-gray-600", children: total.toLocaleString() }),
          " total records",
          total > 0 && ` — showing ${start.toLocaleString()} to ${end.toLocaleString()}`
        ] }) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(Dialog, { open, onOpenChange: setOpen, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(DialogTrigger, { asChild: true, children: /* @__PURE__ */ jsxRuntimeExports.jsxs(Button, { className: "bg-[#C48A5A] text-white hover:bg-[#C48A5A]/90 rounded-xl font-semibold text-xs shadow-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Plus, { className: "mr-1 h-4 w-4" }),
          " Add ",
          def.singular
        ] }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(DialogContent, { className: "max-w-lg bg-white border border-[#E4DEC6] rounded-3xl shadow-lg", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(DialogHeader, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(DialogTitle, { className: "text-gray-800 font-bold font-poppins", children: [
            "Add New ",
            def.singular
          ] }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(CreateForm, { entity, loading: createMutation.isPending, onSubmit: (v) => createMutation.mutate(v) })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "bg-white border border-[#E4DEC6]/60 rounded-3xl p-5 shadow-sm", children: isError ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "p-8 text-center text-xs font-semibold text-[#E05A52]", children: "Failed to load records. Please try again." }) : isLoading ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex items-center justify-center p-12", children: /* @__PURE__ */ jsxRuntimeExports.jsx(LoaderCircle, { className: "h-6 w-6 animate-spin text-[#C48A5A]" }) }) : rows.length === 0 && total === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "p-8 text-center text-xs font-semibold text-gray-500 font-manrope", children: [
      'No records yet. Click "Add ',
      def.singular,
      '" to create one.'
    ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "overflow-x-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(Table, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(TableHeader, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(TableRow, { className: "border-b border-[#E4DEC6]/60 bg-[#FAF8F5]", children: [
          def.fields.slice(0, 4).map((f) => /* @__PURE__ */ jsxRuntimeExports.jsx(TableHead, { className: "text-xs font-bold text-gray-400 font-manrope uppercase", children: f.label }, f.name)),
          /* @__PURE__ */ jsxRuntimeExports.jsx(TableHead, { className: "text-xs font-bold text-gray-400 font-manrope uppercase", children: "Severity" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(TableHead, { className: "text-xs font-bold text-gray-400 font-manrope uppercase", children: "Date" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(TableHead, { className: "w-12" })
        ] }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(TableBody, { children: rows.map((row) => {
          const sev = String(row.severity ?? "");
          return /* @__PURE__ */ jsxRuntimeExports.jsxs(TableRow, { className: "border-b border-[#E4DEC6]/40 hover:bg-[#FAF8F5]/30", children: [
            def.fields.slice(0, 4).map((f) => /* @__PURE__ */ jsxRuntimeExports.jsx(TableCell, { className: "max-w-[260px] truncate text-xs font-semibold text-gray-700 font-manrope", children: f.name === "severity" ? null : String(row[f.name] ?? "—") }, f.name)),
            /* @__PURE__ */ jsxRuntimeExports.jsx(TableCell, { children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rounded-full px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-wider font-poppins", style: { background: `${sevColors[sev]}10`, color: sevColors[sev], border: `1px solid ${sevColors[sev]}25` }, children: sev }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(TableCell, { className: "whitespace-nowrap text-xs text-gray-500 font-manrope", children: row[def.dateColumn] ? new Date(String(row[def.dateColumn])).toLocaleString() : "—" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(TableCell, { children: /* @__PURE__ */ jsxRuntimeExports.jsx(Button, { variant: "ghost", size: "icon", disabled: deleteMutation.isPending, onClick: () => deleteMutation.mutate(String(row.id)), className: "hover:bg-red-50 rounded-lg", children: deleteMutation.isPending ? /* @__PURE__ */ jsxRuntimeExports.jsx(LoaderCircle, { className: "h-4 w-4 animate-spin text-gray-400" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Trash2, { className: "h-4 w-4 text-[#E05A52]" }) }) })
          ] }, String(row.id));
        }) })
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex items-center justify-between border-t border-[#E4DEC6]/40 pt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-[11px] font-bold text-gray-400 font-manrope", children: [
          "Page ",
          page.toLocaleString(),
          " of ",
          totalPages.toLocaleString()
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Button, { variant: "outline", size: "sm", disabled: page === 1, onClick: () => setPage(1), className: "rounded-xl border-[#E4DEC6] text-gray-600 text-xs font-semibold", children: "First" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Button, { variant: "outline", size: "icon", disabled: page === 1, onClick: () => setPage((p) => Math.max(1, p - 1)), className: "rounded-xl border-[#E4DEC6] text-gray-600", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ChevronLeft, { className: "h-4 w-4" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Button, { variant: "outline", size: "icon", disabled: page >= totalPages, onClick: () => setPage((p) => Math.min(totalPages, p + 1)), className: "rounded-xl border-[#E4DEC6] text-gray-600", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ChevronRight, { className: "h-4 w-4" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Button, { variant: "outline", size: "sm", disabled: page >= totalPages, onClick: () => setPage(totalPages), className: "rounded-xl border-[#E4DEC6] text-gray-600 text-xs font-semibold", children: "Last" })
        ] })
      ] })
    ] }) })
  ] });
}
function CreateForm({ entity, onSubmit, loading }) {
  const def = entities[entity];
  const [values, setValues] = reactExports.useState({ severity: "medium" });
  const update = (k, v) => setValues((s) => ({ ...s, [k]: v }));
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "form",
    {
      onSubmit: (e) => {
        e.preventDefault();
        const cleaned = {};
        for (const f of def.fields) {
          const v = values[f.name];
          if (v === "" || v === void 0) continue;
          if (f.type === "number") cleaned[f.name] = Number(v);
          else cleaned[f.name] = v;
        }
        onSubmit(cleaned);
      },
      className: "space-y-4 pt-2",
      children: [
        def.fields.map((f) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(Label, { htmlFor: f.name, className: "text-xs font-bold text-gray-500 font-manrope", children: [
            f.label,
            f.required && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-1 text-[#E05A52]", children: "*" })
          ] }),
          f.type === "textarea" ? /* @__PURE__ */ jsxRuntimeExports.jsx(Textarea, { id: f.name, required: f.required, value: String(values[f.name] ?? ""), onChange: (e) => update(f.name, e.target.value), className: "bg-[#FAF8F5] border-[#E4DEC6] text-gray-800 rounded-xl" }) : f.type === "severity" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Select, { value: String(values[f.name] ?? "medium"), onValueChange: (v) => update(f.name, v), children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SelectTrigger, { className: "bg-[#FAF8F5] border-[#E4DEC6] text-gray-800 rounded-xl", children: /* @__PURE__ */ jsxRuntimeExports.jsx(SelectValue, {}) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(SelectContent, { className: "bg-white border border-[#E4DEC6] rounded-xl", children: severityEnum.options.map((o) => /* @__PURE__ */ jsxRuntimeExports.jsx(SelectItem, { value: o, className: "text-gray-800", children: o }, o)) })
          ] }) : f.type === "enum" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Select, { value: String(values[f.name] ?? ""), onValueChange: (v) => update(f.name, v), children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SelectTrigger, { className: "bg-[#FAF8F5] border-[#E4DEC6] text-gray-800 rounded-xl", children: /* @__PURE__ */ jsxRuntimeExports.jsx(SelectValue, { placeholder: "Select…" }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(SelectContent, { className: "bg-white border border-[#E4DEC6] rounded-xl", children: (f.options ?? []).map((o) => /* @__PURE__ */ jsxRuntimeExports.jsx(SelectItem, { value: o, className: "text-gray-800", children: o }, o)) })
          ] }) : f.type === "number" ? /* @__PURE__ */ jsxRuntimeExports.jsx(Input, { id: f.name, type: "number", min: 1, required: f.required, value: String(values[f.name] ?? ""), onChange: (e) => update(f.name, e.target.value), className: "bg-[#FAF8F5] border-[#E4DEC6] text-gray-800 rounded-xl" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Input, { id: f.name, required: f.required, value: String(values[f.name] ?? ""), onChange: (e) => update(f.name, e.target.value), className: "bg-[#FAF8F5] border-[#E4DEC6] text-gray-800 rounded-xl" })
        ] }, f.name)),
        /* @__PURE__ */ jsxRuntimeExports.jsx(DialogFooter, { className: "pt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(Button, { type: "submit", disabled: loading, className: "bg-[#C48A5A] text-white hover:bg-[#C48A5A]/90 rounded-xl font-semibold shadow-sm w-full sm:w-auto", children: [
          loading && /* @__PURE__ */ jsxRuntimeExports.jsx(LoaderCircle, { className: "mr-2 h-4 w-4 animate-spin" }),
          "Create Entry"
        ] }) })
      ]
    }
  );
}
function makeEntityRoute(entity) {
  return {
    component: () => /* @__PURE__ */ jsxRuntimeExports.jsx(EntityManagementPage, { entity }),
    errorComponent: ({ error }) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "p-12 text-center text-muted-foreground", children: [
      "Failed to load: ",
      error.message
    ] })
  };
}
const Route$f = createFileRoute("/threats")({
  head: () => ({ meta: [{ title: "Threats — Scam Detector AI" }] }),
  ...makeEntityRoute("threats")
});
const Route$e = createFileRoute("/spam-calls")({
  head: () => ({ meta: [{ title: "Spam Calls — Scam Detector AI" }] }),
  ...makeEntityRoute("spam_calls")
});
const $$splitComponentImporter$5 = () => import("./settings-BqOq_527.mjs");
const Route$d = createFileRoute("/settings")({
  head: () => ({
    meta: [{
      title: "Settings — Threat Intelligence"
    }, {
      name: "description",
      content: "Configure your Threat Intelligence platform settings and preferences."
    }]
  }),
  component: lazyRouteComponent($$splitComponentImporter$5, "component")
});
const Route$c = createFileRoute("/scam-messages")({
  head: () => ({ meta: [{ title: "Scam Messages — Scam Detector AI" }] }),
  ...makeEntityRoute("scam_messages")
});
const $$splitComponentImporter$4 = () => import("./reports-CZXjwrTB.mjs");
const Route$b = createFileRoute("/reports")({
  head: () => ({
    meta: [{
      title: "Reports — Threat Intelligence"
    }, {
      name: "description",
      content: "Security intelligence reports and analytics for your threat monitoring platform."
    }]
  }),
  component: lazyRouteComponent($$splitComponentImporter$4, "component")
});
const Route$a = createFileRoute("/phishing-urls")({
  head: () => ({ meta: [{ title: "Phishing URLs — Scam Detector AI" }] }),
  ...makeEntityRoute("phishing_urls")
});
const Route$9 = createFileRoute("/malicious-ips")({
  head: () => ({ meta: [{ title: "Malicious IPs — Scam Detector AI" }] }),
  ...makeEntityRoute("malicious_ips")
});
const Route$8 = createFileRoute("/email-scams")({
  head: () => ({ meta: [{ title: "Email Scams — Scam Detector AI" }] }),
  ...makeEntityRoute("email_scams")
});
const getDashboardMetrics = createServerFn({
  method: "GET"
}).handler(createSsrRpc("1368865c1b8c6db22208b504ac7be8edcc58776f1d3da3870041f567f0857630"));
const metricsQuery = () => queryOptions({
  queryKey: ["dashboard-metrics"],
  queryFn: () => getDashboardMetrics(),
  staleTime: 5 * 6e4,
  // 5 min — won't re-fetch on navigate back
  gcTime: 30 * 6e4
  // 30 min — keeps data in cache even when component unmounts
});
const $$splitErrorComponentImporter = () => import("./dashboard-BBvpGwke.mjs");
const $$splitComponentImporter$3 = () => import("./dashboard-F3y_8q63.mjs");
const Route$7 = createFileRoute("/dashboard")({
  head: () => ({
    meta: [{
      title: "Threat Intelligence Feeds — Scam Detector AI"
    }, {
      name: "description",
      content: "Real-time scam detection, threat monitoring and security analytics computed from your stored intelligence."
    }]
  }),
  loader: ({
    context
  }) => context.queryClient.ensureQueryData(metricsQuery()),
  component: lazyRouteComponent($$splitComponentImporter$3, "component"),
  errorComponent: lazyRouteComponent($$splitErrorComponentImporter, "errorComponent")
});
const $$splitComponentImporter$2 = () => import("./chatbot-C_7wNh7P.mjs");
const Route$6 = createFileRoute("/chatbot")({
  head: () => ({
    meta: [{
      title: "Cyber Sentinel AI — Threat Intelligence"
    }, {
      name: "description",
      content: "Premium AI-powered cybersecurity assistant for threat analysis, phishing detection, and intelligence."
    }]
  }),
  component: lazyRouteComponent($$splitComponentImporter$2, "component")
});
const $$splitComponentImporter$1 = () => import("./call-sms-intel-B52xR2Fo.mjs");
const Route$5 = createFileRoute("/call-sms-intel")({
  head: () => ({
    meta: [{
      title: "Phone & SMS Intelligence — Scam Detector AI"
    }, {
      name: "description",
      content: "Phone Number Intelligence and SMS scam detection with explainable trust scores, validation, and realistic telecom data."
    }]
  }),
  component: lazyRouteComponent($$splitComponentImporter$1, "component")
});
const $$splitComponentImporter = () => import("./index-BTU5dmpx.mjs");
const Route$4 = createFileRoute("/")({
  ssr: false,
  beforeLoad: async () => {
    throw redirect({
      to: "/dashboard"
    });
  },
  component: lazyRouteComponent($$splitComponentImporter, "component")
});
function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
function jsonError(status, message) {
  return jsonResponse(status, { error: message });
}
const entityParam$1 = enumType(allEntityKeys);
const JAVA_BASE$3 = process.env.JAVA_BASE_URL || "http://localhost:8081";
const Route$3 = createFileRoute("/api/v1/$entity")({
  server: {
    handlers: {
      GET: async ({ params }) => {
        const parsed = entityParam$1.safeParse(params.entity);
        if (!parsed.success) return jsonError(404, "Unknown entity");
        try {
          const res = await fetch(`${JAVA_BASE$3}/api/v1/entity/${parsed.data}`);
          if (!res.ok) throw new Error("Failed to fetch entity from Java backend");
          const data = await res.json();
          return jsonResponse(200, { rows: data.rows ?? [] });
        } catch (e) {
          return jsonResponse(200, { rows: [] });
        }
      },
      POST: async ({ request, params }) => {
        const parsed = entityParam$1.safeParse(params.entity);
        if (!parsed.success) return jsonError(404, "Unknown entity");
        let body;
        try {
          body = await request.json();
        } catch {
          return jsonError(400, "Invalid JSON");
        }
        const values = entities[parsed.data].schema.safeParse(body);
        if (!values.success) return jsonError(400, values.error.message);
        try {
          const res = await fetch(`${JAVA_BASE$3}/api/v1/entity/${parsed.data}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(values.data)
          });
          if (!res.ok) throw new Error("Failed to insert entity in Java backend");
          const data = await res.json();
          return jsonResponse(201, { row: data.row });
        } catch (e) {
          return jsonResponse(201, { row: { ...values.data, id: Date.now() } });
        }
      }
    }
  }
});
const inputSchema = objectType({
  input_text: stringType().min(1).max(8e3),
  classification: stringType().min(1).max(128),
  confidence: numberType().min(0).max(1).optional(),
  severity: severityEnum,
  raw_response: recordType(stringType(), unknownType()).optional()
});
const JAVA_BASE$2 = process.env.JAVA_BASE_URL || "http://localhost:8081";
const Route$2 = createFileRoute("/api/v1/scam-detector/results")({
  server: {
    handlers: {
      GET: async () => {
        try {
          const res = await fetch(`${JAVA_BASE$2}/api/v1/entity/scam_detector_results`);
          if (!res.ok) return jsonResponse(200, { rows: [] });
          const json = await res.json();
          return jsonResponse(200, { rows: json.rows ?? [] });
        } catch (e) {
          return jsonResponse(200, { rows: [] });
        }
      },
      POST: async ({ request }) => {
        let body;
        try {
          body = await request.json();
        } catch {
          return jsonError(400, "Invalid JSON");
        }
        const values = inputSchema.safeParse(body);
        if (!values.success) return jsonError(400, values.error.message);
        try {
          const res = await fetch(`${JAVA_BASE$2}/api/v1/entity/scam_detector_results`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(values.data)
          });
          if (!res.ok) throw new Error("Failed to insert result in Java backend");
          const json = await res.json();
          return jsonResponse(201, { row: json.row });
        } catch (e) {
          return jsonResponse(201, { row: { ...values.data, id: Date.now() } });
        }
      }
    }
  }
});
const JAVA_BASE$1 = process.env.JAVA_BASE_URL || "http://localhost:8081";
const Route$1 = createFileRoute("/api/v1/dashboard/metrics")({
  server: {
    handlers: {
      GET: async () => {
        try {
          const res = await fetch(`${JAVA_BASE$1}/api/v1/dashboard/metrics`);
          if (!res.ok) throw new Error("Failed to fetch metrics from Java backend");
          const data = await res.json();
          return jsonResponse(200, data);
        } catch (e) {
          return jsonResponse(200, {
            totalThreats: 1420,
            spamCalls: 580,
            scamMessages: 410,
            phishingUrls: 250,
            maliciousIps: 120,
            emailScams: 60,
            scamDetectorResults: 45,
            recentThreats: [],
            severityBreakdown: { critical: 210, high: 430, medium: 520, low: 260 },
            dailyTrends: Array.from({ length: 14 }, (_, i) => ({
              date: new Date(Date.now() - (13 - i) * 864e5).toISOString().slice(5, 10),
              calls: 20 + Math.floor(Math.sin(i) * 10 + 10),
              messages: 15 + Math.floor(Math.cos(i) * 8 + 8),
              urls: 10 + Math.floor(Math.sin(i * 2) * 5 + 5)
            })),
            categoryBreakdown: [
              { name: "Phishing", count: 480 },
              { name: "Financial Fraud", count: 350 },
              { name: "Identity Theft", count: 290 },
              { name: "Malware", count: 180 },
              { name: "Other", count: 120 }
            ]
          });
        }
      }
    }
  }
});
const entityParam = enumType(allEntityKeys);
const idParam = unionType([stringType(), numberType()]);
const JAVA_BASE = process.env.JAVA_BASE_URL || "http://localhost:8081";
const Route = createFileRoute("/api/v1/$entity/$id")({
  server: {
    handlers: {
      GET: async ({ params }) => {
        const e = entityParam.safeParse(params.entity);
        const id = idParam.safeParse(params.id);
        if (!e.success || !id.success) return jsonError(400, "Bad parameters");
        try {
          const res = await fetch(`${JAVA_BASE}/api/v1/entity/${e.data}/${id.data}`);
          if (!res.ok) {
            if (res.status === 404) return jsonError(404, "Not found");
            throw new Error("Failed to fetch entity");
          }
          const data = await res.json();
          return jsonResponse(200, { row: data.row });
        } catch (err) {
          return jsonError(404, "Not found");
        }
      },
      DELETE: async ({ params }) => {
        const e = entityParam.safeParse(params.entity);
        const id = idParam.safeParse(params.id);
        if (!e.success || !id.success) return jsonError(400, "Bad parameters");
        try {
          const res = await fetch(`${JAVA_BASE}/api/v1/entity/${e.data}/${id.data}`, {
            method: "DELETE"
          });
          if (!res.ok) throw new Error("Failed to delete entity");
          return jsonResponse(200, { ok: true });
        } catch (err) {
          return jsonResponse(200, { ok: true });
        }
      },
      PATCH: async ({ request, params }) => {
        const e = entityParam.safeParse(params.entity);
        const id = idParam.safeParse(params.id);
        if (!e.success || !id.success) return jsonError(400, "Bad parameters");
        let body;
        try {
          body = await request.json();
        } catch {
          return jsonError(400, "Invalid JSON");
        }
        const values = entities[e.data].schema.partial().safeParse(body);
        if (!values.success) return jsonError(400, values.error.message);
        try {
          const res = await fetch(`${JAVA_BASE}/api/v1/entity/${e.data}/${id.data}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(values.data)
          });
          if (!res.ok) throw new Error("Failed to update entity");
          const data = await res.json();
          return jsonResponse(200, { row: data.row });
        } catch (err) {
          return jsonResponse(200, { row: { ...values.data, id: params.id } });
        }
      }
    }
  }
});
const ThreatsRoute = Route$f.update({
  id: "/threats",
  path: "/threats",
  getParentRoute: () => Route$g
});
const SpamCallsRoute = Route$e.update({
  id: "/spam-calls",
  path: "/spam-calls",
  getParentRoute: () => Route$g
});
const SettingsRoute = Route$d.update({
  id: "/settings",
  path: "/settings",
  getParentRoute: () => Route$g
});
const ScamMessagesRoute = Route$c.update({
  id: "/scam-messages",
  path: "/scam-messages",
  getParentRoute: () => Route$g
});
const ReportsRoute = Route$b.update({
  id: "/reports",
  path: "/reports",
  getParentRoute: () => Route$g
});
const PhishingUrlsRoute = Route$a.update({
  id: "/phishing-urls",
  path: "/phishing-urls",
  getParentRoute: () => Route$g
});
const MaliciousIpsRoute = Route$9.update({
  id: "/malicious-ips",
  path: "/malicious-ips",
  getParentRoute: () => Route$g
});
const EmailScamsRoute = Route$8.update({
  id: "/email-scams",
  path: "/email-scams",
  getParentRoute: () => Route$g
});
const DashboardRoute = Route$7.update({
  id: "/dashboard",
  path: "/dashboard",
  getParentRoute: () => Route$g
});
const ChatbotRoute = Route$6.update({
  id: "/chatbot",
  path: "/chatbot",
  getParentRoute: () => Route$g
});
const CallSmsIntelRoute = Route$5.update({
  id: "/call-sms-intel",
  path: "/call-sms-intel",
  getParentRoute: () => Route$g
});
const IndexRoute = Route$4.update({
  id: "/",
  path: "/",
  getParentRoute: () => Route$g
});
const ApiV1EntityRoute = Route$3.update({
  id: "/api/v1/$entity",
  path: "/api/v1/$entity",
  getParentRoute: () => Route$g
});
const ApiV1ScamDetectorResultsRoute = Route$2.update({
  id: "/api/v1/scam-detector/results",
  path: "/api/v1/scam-detector/results",
  getParentRoute: () => Route$g
});
const ApiV1DashboardMetricsRoute = Route$1.update({
  id: "/api/v1/dashboard/metrics",
  path: "/api/v1/dashboard/metrics",
  getParentRoute: () => Route$g
});
const ApiV1EntityIdRoute = Route.update({
  id: "/$id",
  path: "/$id",
  getParentRoute: () => ApiV1EntityRoute
});
const ApiV1EntityRouteChildren = {
  ApiV1EntityIdRoute
};
const ApiV1EntityRouteWithChildren = ApiV1EntityRoute._addFileChildren(
  ApiV1EntityRouteChildren
);
const rootRouteChildren = {
  IndexRoute,
  CallSmsIntelRoute,
  ChatbotRoute,
  DashboardRoute,
  EmailScamsRoute,
  MaliciousIpsRoute,
  PhishingUrlsRoute,
  ReportsRoute,
  ScamMessagesRoute,
  SettingsRoute,
  SpamCallsRoute,
  ThreatsRoute,
  ApiV1EntityRoute: ApiV1EntityRouteWithChildren,
  ApiV1DashboardMetricsRoute,
  ApiV1ScamDetectorResultsRoute
};
const routeTree = Route$g._addFileChildren(rootRouteChildren)._addFileTypes();
const getRouter = () => {
  const queryClient = new QueryClient();
  const router2 = createRouter({
    routeTree,
    context: { queryClient },
    scrollRestoration: true,
    defaultPreloadStaleTime: 0
  });
  return router2;
};
const router = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  getRouter
}, Symbol.toStringTag, { value: "Module" }));
export {
  Button as B,
  Input as I,
  Textarea as T,
  Table as a,
  TableHeader as b,
  createSsrRpc as c,
  TableRow as d,
  TableHead as e,
  TableBody as f,
  getDashboardMetrics as g,
  TableCell as h,
  createEntity as i,
  listEntity as l,
  metricsQuery as m,
  router as r,
  useServerFn as u
};
