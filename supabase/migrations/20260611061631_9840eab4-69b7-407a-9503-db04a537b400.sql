-- Make user_id nullable on all tables so the app works without authentication
ALTER TABLE public.threats ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE public.phishing_urls ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE public.spam_calls ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE public.email_scams ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE public.malicious_ips ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE public.scam_messages ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE public.scam_detector_results ALTER COLUMN user_id DROP NOT NULL;

-- Grant anonymous users full access to all threat tables
GRANT SELECT, INSERT, UPDATE, DELETE ON public.threats TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.phishing_urls TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.spam_calls TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.email_scams TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.malicious_ips TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.scam_messages TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.scam_detector_results TO anon;

-- Add public policies for anonymous access
CREATE POLICY "Anon can read threats" ON public.threats FOR SELECT TO anon USING (true);
CREATE POLICY "Anon can insert threats" ON public.threats FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "Anon can update threats" ON public.threats FOR UPDATE TO anon USING (true) WITH CHECK (true);
CREATE POLICY "Anon can delete threats" ON public.threats FOR DELETE TO anon USING (true);

CREATE POLICY "Anon can read phishing" ON public.phishing_urls FOR SELECT TO anon USING (true);
CREATE POLICY "Anon can insert phishing" ON public.phishing_urls FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "Anon can update phishing" ON public.phishing_urls FOR UPDATE TO anon USING (true) WITH CHECK (true);
CREATE POLICY "Anon can delete phishing" ON public.phishing_urls FOR DELETE TO anon USING (true);

CREATE POLICY "Anon can read spam_calls" ON public.spam_calls FOR SELECT TO anon USING (true);
CREATE POLICY "Anon can insert spam_calls" ON public.spam_calls FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "Anon can update spam_calls" ON public.spam_calls FOR UPDATE TO anon USING (true) WITH CHECK (true);
CREATE POLICY "Anon can delete spam_calls" ON public.spam_calls FOR DELETE TO anon USING (true);

CREATE POLICY "Anon can read email_scams" ON public.email_scams FOR SELECT TO anon USING (true);
CREATE POLICY "Anon can insert email_scams" ON public.email_scams FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "Anon can update email_scams" ON public.email_scams FOR UPDATE TO anon USING (true) WITH CHECK (true);
CREATE POLICY "Anon can delete email_scams" ON public.email_scams FOR DELETE TO anon USING (true);

CREATE POLICY "Anon can read malicious_ips" ON public.malicious_ips FOR SELECT TO anon USING (true);
CREATE POLICY "Anon can insert malicious_ips" ON public.malicious_ips FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "Anon can update malicious_ips" ON public.malicious_ips FOR UPDATE TO anon USING (true) WITH CHECK (true);
CREATE POLICY "Anon can delete malicious_ips" ON public.malicious_ips FOR DELETE TO anon USING (true);

CREATE POLICY "Anon can read scam_messages" ON public.scam_messages FOR SELECT TO anon USING (true);
CREATE POLICY "Anon can insert scam_messages" ON public.scam_messages FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "Anon can update scam_messages" ON public.scam_messages FOR UPDATE TO anon USING (true) WITH CHECK (true);
CREATE POLICY "Anon can delete scam_messages" ON public.scam_messages FOR DELETE TO anon USING (true);

CREATE POLICY "Anon can read scam_detector_results" ON public.scam_detector_results FOR SELECT TO anon USING (true);
CREATE POLICY "Anon can insert scam_detector_results" ON public.scam_detector_results FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "Anon can update scam_detector_results" ON public.scam_detector_results FOR UPDATE TO anon USING (true) WITH CHECK (true);
CREATE POLICY "Anon can delete scam_detector_results" ON public.scam_detector_results FOR DELETE TO anon USING (true);