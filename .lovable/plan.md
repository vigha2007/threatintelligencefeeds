## Goal
Turn the current frontend-only Scam Detector app into a full-stack Threat Intelligence Platform backed by Lovable Cloud, with authentication, persistent storage, dynamic dashboard metrics, and REST APIs — while keeping the existing UI design unchanged.

## 1. Enable Lovable Cloud
Provision the integrated backend (Postgres + Auth + server fns). All new server logic uses `createServerFn` (no Edge Functions).

## 2. Database Schema (migration)
Tables in `public`, all with RLS + grants:

- `profiles` (id uuid PK → auth.users, display_name, created_at)
- `user_roles` (user_id, role app_role enum: admin/analyst/user) + `has_role()` SECURITY DEFINER fn
- `threats` (id, user_id, type enum: phishing_url|spam_call|email_scam|malicious_ip|scam_message|other, severity enum: critical|high|medium|low, title, description, source, status, detected_at, created_at)
- `phishing_urls` (id, user_id, url, domain, severity, status, blocked_at, notes, created_at)
- `spam_calls` (id, user_id, phone_number, country, severity, pattern, reported_at, created_at)
- `email_scams` (id, user_id, sender, subject, severity, category, recipients_count, detected_at, created_at)
- `malicious_ips` (id, user_id, ip_address inet, country, severity, threat_type, last_seen, created_at)
- `scam_messages` (id, user_id, channel (sms/whatsapp/other), content, severity, sender, detected_at, created_at)
- `scam_detector_results` (id, user_id, input_text, classification, confidence numeric, severity, raw_response jsonb, created_at)

RLS: each user reads/writes own rows; admins read all (via `has_role`). Trigger auto-creates a profile row on signup.

## 3. Authentication
- `/auth` page with email + password (sign up / sign in tabs), styled with existing glassmorphism.
- Use the integration-managed `_authenticated/` layout to gate dashboard, chatbot, and any data routes.
- Root listener for `onAuthStateChange` (filter SIGNED_IN/OUT/USER_UPDATED) + sign-out hygiene in header.
- Add a top nav with user menu (display name, sign out).

## 4. Server Functions (`src/lib/*.functions.ts`)
All use `requireSupabaseAuth`:
- `getDashboardMetrics` — aggregates counts, today vs yesterday trend %, severity distribution, recent activity (last 60 min), 14-day threat trend, 7-day daily detections, category breakdown.
- `listThreats`, `createThreat`, `updateThreat`, `deleteThreat`.
- Same CRUD set for: phishing URLs, spam calls, email scams, malicious IPs, scam messages.
- `saveScamDetectorResult` — for chatbot result persistence (optional manual entry form on chatbot page since the iframe is external).

## 5. REST API Routes (`src/routes/api/v1/*`)
Authenticated via bearer token, JSON in/out, Zod-validated:
- `GET/POST /api/v1/threats`
- `GET/PATCH/DELETE /api/v1/threats/$id`
- Same shape for `/phishing-urls`, `/spam-calls`, `/email-scams`, `/malicious-ips`, `/scam-messages`
- `GET /api/v1/dashboard/metrics`
- `POST /api/v1/scam-detector/results`

Bearer auth via Supabase JWT verification; returns 401 on missing/invalid token.

## 6. Dashboard (existing `/` route, UI unchanged)
- Replace all hardcoded `metrics`, `recentActivity`, `severity`, `trendData`, `categoryData`, `dailyData` with data from `getDashboardMetrics` via TanStack Query (`useSuspenseQuery` + loader `ensureQueryData`).
- Empty-state handling: zeros render gracefully, no random fallbacks.
- Animated counters and charts continue to work, fed by real data.

## 7. Threat Management UI (new authenticated routes)
Minimal CRUD pages reusing existing glass styling so users can populate data:
- `/_authenticated/threats` — table + "Add threat" dialog
- `/_authenticated/phishing-urls`, `/spam-calls`, `/email-scams`, `/malicious-ips`, `/scam-messages` — same pattern
Sidebar/nav links added without altering the dashboard's hero/visuals.

## 8. Chatbot Page
- Keep iframe untouched.
- Below the iframe, add a small "Log analyzed result" form (input text + classification + severity) that calls `saveScamDetectorResult` so results land in the DB and feed analytics.

## 9. Cleanup
- Delete hardcoded arrays from `src/routes/index.tsx`.
- Remove `Math.random()` data generators.
- Keep existing colors, glass classes, animations, particle background, floating chat button, footer.

## Technical Notes
- Stack: TanStack Start + TanStack Query + Supabase (Lovable Cloud).
- All privileged server fns assert `requireSupabaseAuth`; admin-only ops also check `has_role(uid, 'admin')`.
- `supabaseAdmin` only used inside server-fn handlers via `await import(...)`.
- REST routes under `/api/v1/*` (NOT `/api/public/*` since they require auth).
- Zod validation on every input.
- Grants: `GRANT SELECT, INSERT, UPDATE, DELETE ... TO authenticated; GRANT ALL ... TO service_role` on every new table.

## Out of Scope
- Modifying the external chatbot or its detection logic.
- Visual redesign — UI tokens, glass, particles, charts remain as-is.
- Real-time websocket feeds (can be added later).

Confirm and I'll implement.