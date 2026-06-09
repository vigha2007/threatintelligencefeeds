import { Link } from "@tanstack/react-router";
import { Rocket } from "lucide-react";

export function FloatingChatButton() {
  return (
    <Link
      to="/chatbot"
      className="fixed bottom-6 right-6 z-50 flex items-center gap-2 rounded-full px-6 py-4 text-sm font-semibold text-white animate-float-pulse"
      style={{
        background: "linear-gradient(135deg, #00D4FF 0%, #7B61FF 100%)",
      }}
    >
      <Rocket className="h-5 w-5" />
      <span className="hidden sm:inline">Launch Scam Detector AI</span>
      <span className="sm:hidden">Launch AI</span>
    </Link>
  );
}
