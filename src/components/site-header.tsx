import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { Shield, LogOut, LayoutDashboard, MessageSquare, AlertTriangle, Link2, Phone, Mail, Globe, MessageCircle } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

const nav = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/threats", label: "Threats", icon: AlertTriangle },
  { to: "/phishing-urls", label: "Phishing", icon: Link2 },
  { to: "/spam-calls", label: "Calls", icon: Phone },
  { to: "/email-scams", label: "Email", icon: Mail },
  { to: "/malicious-ips", label: "IPs", icon: Globe },
  { to: "/scam-messages", label: "Messages", icon: MessageCircle },
  { to: "/chatbot", label: "Chatbot", icon: MessageSquare },
] as const;

export function SiteHeader() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  async function signOut() {
    await queryClient.cancelQueries();
    queryClient.clear();
    await supabase.auth.signOut();
    navigate({ to: "/auth", replace: true });
  }

  return (
    <header className="sticky top-0 z-40 border-b border-white/5 bg-[#0A0F1F]/80 backdrop-blur-xl">
      <div className="mx-auto flex max-w-7xl items-center gap-4 px-4 py-3 sm:px-6 lg:px-8">
        <Link to="/dashboard" className="flex items-center gap-2 text-white">
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
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" className="text-white">
              Account
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={signOut}>
              <LogOut className="mr-2 h-4 w-4" /> Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
