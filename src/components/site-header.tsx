import { Link, useRouterState } from "@tanstack/react-router";
import { Shield, LayoutDashboard, MessageSquare, AlertTriangle, Link2, Phone, Mail, Globe, MessageCircle, Radar } from "lucide-react";

const nav = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/call-sms-intel", label: "Call/SMS Intel", icon: Radar },
  { to: "/threats", label: "Threats", icon: AlertTriangle },
  { to: "/phishing-urls", label: "Phishing", icon: Link2 },
  { to: "/spam-calls", label: "Calls", icon: Phone },
  { to: "/email-scams", label: "Email", icon: Mail },
  { to: "/malicious-ips", label: "IPs", icon: Globe },
  { to: "/scam-messages", label: "Messages", icon: MessageCircle },
  { to: "/chatbot", label: "Chatbot", icon: MessageSquare },
] as const;

export function SiteHeader() {
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  return (
    <header className="sticky top-0 z-40 border-b border-white/5 bg-[#0A0F1F]/80 backdrop-blur-xl">
      <div className="mx-auto flex max-w-7xl items-center gap-4 px-4 py-3 sm:px-6 lg:px-8">
        <Link to="/" className="flex items-center gap-2 text-white">
          <Shield className="h-5 w-5 text-[#00D4FF]" />
          <span className="hidden text-sm font-semibold sm:inline">Scam Detector AI</span>
        </Link>
        <nav className="ml-2 flex flex-1 items-center gap-1 overflow-x-auto">
          {nav.map((n) => {
            const Icon = n.icon;
            const active = pathname === n.to;
            return (
              <Link
                key={n.to}
                to={n.to}
                className={`flex shrink-0 items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium transition-colors ${
                  active ? "bg-white/10 text-white" : "text-muted-foreground hover:bg-white/5 hover:text-white"
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                <span className="hidden md:inline">{n.label}</span>
              </Link>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
