
-- Enums
CREATE TYPE public.app_role AS ENUM ('admin', 'analyst', 'user');
CREATE TYPE public.threat_severity AS ENUM ('critical', 'high', 'medium', 'low');
CREATE TYPE public.threat_type AS ENUM ('phishing_url','spam_call','email_scam','malicious_ip','scam_message','other');

-- Profiles
CREATE TABLE public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  display_name TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.profiles TO authenticated;
GRANT ALL ON public.profiles TO service_role;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Profiles self read" ON public.profiles FOR SELECT TO authenticated USING (auth.uid() = id);
CREATE POLICY "Profiles self update" ON public.profiles FOR UPDATE TO authenticated USING (auth.uid() = id) WITH CHECK (auth.uid() = id);
CREATE POLICY "Profiles self insert" ON public.profiles FOR INSERT TO authenticated WITH CHECK (auth.uid() = id);

-- User Roles
CREATE TABLE public.user_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role public.app_role NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, role)
);
GRANT SELECT ON public.user_roles TO authenticated;
GRANT ALL ON public.user_roles TO service_role;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Roles self read" ON public.user_roles FOR SELECT TO authenticated USING (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION public.has_role(_user_id UUID, _role public.app_role)
RETURNS BOOLEAN LANGUAGE SQL STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM public.user_roles WHERE user_id = _user_id AND role = _role)
$$;

-- Auto-create profile + default user role on signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO public.profiles (id, display_name)
  VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data->>'display_name', split_part(NEW.email,'@',1)));
  INSERT INTO public.user_roles (user_id, role) VALUES (NEW.id, 'user');
  RETURN NEW;
END $$;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Generic threats
CREATE TABLE public.threats (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  type public.threat_type NOT NULL,
  severity public.threat_severity NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  source TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.threats TO authenticated;
GRANT ALL ON public.threats TO service_role;
ALTER TABLE public.threats ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Threats owner all" ON public.threats FOR ALL TO authenticated USING (auth.uid() = user_id OR public.has_role(auth.uid(),'admin')) WITH CHECK (auth.uid() = user_id);
CREATE INDEX threats_user_detected_idx ON public.threats (user_id, detected_at DESC);

-- Phishing URLs
CREATE TABLE public.phishing_urls (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  domain TEXT,
  severity public.threat_severity NOT NULL DEFAULT 'high',
  status TEXT NOT NULL DEFAULT 'blocked',
  notes TEXT,
  blocked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.phishing_urls TO authenticated;
GRANT ALL ON public.phishing_urls TO service_role;
ALTER TABLE public.phishing_urls ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Phish owner all" ON public.phishing_urls FOR ALL TO authenticated USING (auth.uid() = user_id OR public.has_role(auth.uid(),'admin')) WITH CHECK (auth.uid() = user_id);

-- Spam Calls
CREATE TABLE public.spam_calls (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  phone_number TEXT NOT NULL,
  country TEXT,
  severity public.threat_severity NOT NULL DEFAULT 'medium',
  pattern TEXT,
  reported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.spam_calls TO authenticated;
GRANT ALL ON public.spam_calls TO service_role;
ALTER TABLE public.spam_calls ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Calls owner all" ON public.spam_calls FOR ALL TO authenticated USING (auth.uid() = user_id OR public.has_role(auth.uid(),'admin')) WITH CHECK (auth.uid() = user_id);

-- Email Scams
CREATE TABLE public.email_scams (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  sender TEXT NOT NULL,
  subject TEXT,
  category TEXT,
  severity public.threat_severity NOT NULL DEFAULT 'high',
  recipients_count INT NOT NULL DEFAULT 1,
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.email_scams TO authenticated;
GRANT ALL ON public.email_scams TO service_role;
ALTER TABLE public.email_scams ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Email owner all" ON public.email_scams FOR ALL TO authenticated USING (auth.uid() = user_id OR public.has_role(auth.uid(),'admin')) WITH CHECK (auth.uid() = user_id);

-- Malicious IPs
CREATE TABLE public.malicious_ips (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  ip_address TEXT NOT NULL,
  country TEXT,
  threat_type TEXT,
  severity public.threat_severity NOT NULL DEFAULT 'medium',
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.malicious_ips TO authenticated;
GRANT ALL ON public.malicious_ips TO service_role;
ALTER TABLE public.malicious_ips ENABLE ROW LEVEL SECURITY;
CREATE POLICY "IPs owner all" ON public.malicious_ips FOR ALL TO authenticated USING (auth.uid() = user_id OR public.has_role(auth.uid(),'admin')) WITH CHECK (auth.uid() = user_id);

-- Scam Messages
CREATE TABLE public.scam_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  channel TEXT NOT NULL DEFAULT 'sms',
  sender TEXT,
  content TEXT NOT NULL,
  severity public.threat_severity NOT NULL DEFAULT 'medium',
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.scam_messages TO authenticated;
GRANT ALL ON public.scam_messages TO service_role;
ALTER TABLE public.scam_messages ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Msgs owner all" ON public.scam_messages FOR ALL TO authenticated USING (auth.uid() = user_id OR public.has_role(auth.uid(),'admin')) WITH CHECK (auth.uid() = user_id);

-- Scam Detector Results
CREATE TABLE public.scam_detector_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  input_text TEXT NOT NULL,
  classification TEXT NOT NULL,
  confidence NUMERIC,
  severity public.threat_severity NOT NULL DEFAULT 'medium',
  raw_response JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.scam_detector_results TO authenticated;
GRANT ALL ON public.scam_detector_results TO service_role;
ALTER TABLE public.scam_detector_results ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Results owner all" ON public.scam_detector_results FOR ALL TO authenticated USING (auth.uid() = user_id OR public.has_role(auth.uid(),'admin')) WITH CHECK (auth.uid() = user_id);
