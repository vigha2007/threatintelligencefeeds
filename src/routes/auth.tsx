import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { motion } from "framer-motion";
import { Shield, Loader2 } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ParticlesBackground } from "@/components/particles-background";
import { toast } from "sonner";

export const Route = createFileRoute("/auth")({
  head: () => ({
    meta: [
      { title: "Sign in — Scam Detector AI" },
      { name: "description", content: "Sign in or create an account to access the Threat Intelligence Platform." },
    ],
  }),
  component: AuthPage,
});

function friendlySignInError(message: string): string {
  const m = message.toLowerCase();
  if (m.includes("email not confirmed")) {
    return "Your email isn't confirmed yet. Check your inbox for the verification link, or use Resend below.";
  }
  if (m.includes("invalid login credentials") || m.includes("invalid_credentials")) {
    return "Invalid email or password.";
  }
  return message;
}

function friendlySignUpError(message: string): string {
  const m = message.toLowerCase();
  if (m.includes("already registered") || m.includes("already exists") || m.includes("user already")) {
    return "An account with this email already exists. Please sign in instead.";
  }
  if (m.includes("password")) return message;
  return message;
}

function AuthPage() {
  const navigate = useNavigate();
  const [tab, setTab] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [loading, setLoading] = useState(false);
  const [needsConfirmation, setNeedsConfirmation] = useState(false);
  const [resending, setResending] = useState(false);

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setNeedsConfirmation(false);
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    setLoading(false);
    if (error) {
      if (error.message.toLowerCase().includes("email not confirmed")) {
        setNeedsConfirmation(true);
      }
      return toast.error(friendlySignInError(error.message));
    }
    navigate({ to: "/dashboard" });
  };

  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        emailRedirectTo: window.location.origin + "/dashboard",
        data: { display_name: displayName || email.split("@")[0] },
      },
    });
    setLoading(false);
    if (error) return toast.error(friendlySignUpError(error.message));
    // If session is returned, email confirmation is disabled — sign in immediately.
    if (data.session) {
      toast.success("Account created. Welcome!");
      navigate({ to: "/dashboard" });
      return;
    }
    toast.success("Account created successfully. Please check your email and click the verification link before signing in.");
    setTab("signin");
    setNeedsConfirmation(true);
  };

  const handleResend = async () => {
    if (!email) return toast.error("Enter your email above first.");
    setResending(true);
    const { error } = await supabase.auth.resend({
      type: "signup",
      email,
      options: { emailRedirectTo: window.location.origin + "/dashboard" },
    });
    setResending(false);
    if (error) return toast.error(error.message);
    toast.success("Confirmation email resent. Please check your inbox.");
  };

  return (
    <div className="relative min-h-screen overflow-hidden">
      <div className="absolute inset-0 -z-10"><ParticlesBackground /></div>
      <div className="mx-auto flex min-h-screen max-w-md flex-col items-center justify-center px-4 py-12">
        <motion.div
          initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}
          className="glass-strong w-full overflow-hidden rounded-3xl p-8"
        >
          <div className="absolute -left-10 -top-10 h-40 w-40 rounded-full bg-[#00D4FF] opacity-20 blur-3xl" />
          <div className="absolute -bottom-10 -right-10 h-40 w-40 rounded-full bg-[#7B61FF] opacity-20 blur-3xl" />
          <div className="relative">
            <Link to="/" className="mb-6 flex items-center gap-2 text-white">
              <Shield className="h-6 w-6 text-[#00D4FF]" />
              <span className="text-lg font-semibold">Scam Detector AI</span>
            </Link>
            <h1 className="text-2xl font-bold text-white">Welcome</h1>
            <p className="mt-1 text-sm text-muted-foreground">Sign in to access Threat Intelligence.</p>

            <Tabs value={tab} onValueChange={(v) => { setTab(v as "signin" | "signup"); setNeedsConfirmation(false); }} className="mt-6">
              <TabsList className="grid w-full grid-cols-2 bg-white/5">
                <TabsTrigger value="signin">Sign in</TabsTrigger>
                <TabsTrigger value="signup">Sign up</TabsTrigger>
              </TabsList>
              <TabsContent value="signin">
                <form onSubmit={handleSignIn} className="mt-4 space-y-3">
                  <div>
                    <Label htmlFor="email-in">Email</Label>
                    <Input id="email-in" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
                  </div>
                  <div>
                    <Label htmlFor="pw-in">Password</Label>
                    <Input id="pw-in" type="password" required value={password} onChange={(e) => setPassword(e.target.value)} />
                  </div>
                  <Button type="submit" disabled={loading} className="w-full">
                    {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}Sign in
                  </Button>
                  {needsConfirmation && (
                    <div className="rounded-md border border-white/10 bg-white/5 p-3 text-xs text-muted-foreground">
                      Didn't get the email?
                      <Button
                        type="button" variant="link" size="sm"
                        className="ml-1 h-auto p-0 text-[#00D4FF]"
                        onClick={handleResend} disabled={resending}
                      >
                        {resending ? "Resending…" : "Resend confirmation email"}
                      </Button>
                    </div>
                  )}
                </form>
              </TabsContent>
              <TabsContent value="signup">
                <form onSubmit={handleSignUp} className="mt-4 space-y-3">
                  <div>
                    <Label htmlFor="dn">Display name</Label>
                    <Input id="dn" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
                  </div>
                  <div>
                    <Label htmlFor="email-up">Email</Label>
                    <Input id="email-up" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
                  </div>
                  <div>
                    <Label htmlFor="pw-up">Password</Label>
                    <Input id="pw-up" type="password" required minLength={6} value={password} onChange={(e) => setPassword(e.target.value)} />
                  </div>
                  <Button type="submit" disabled={loading} className="w-full">
                    {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}Create account
                  </Button>
                </form>
              </TabsContent>
            </Tabs>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
