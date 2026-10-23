-- ScamSach database schema. Run once in Supabase: SQL Editor -> New query -> paste -> Run.
-- Safe to run again (uses IF NOT EXISTS / OR REPLACE).
--
-- Privacy by design:
--   * Only the MASKED message is stored (phone/account numbers/OTPs replaced).
--   * Only the backend (secret key) writes here. Row Level Security is ON for
--     every table, so the public (anon) key can read nothing except, for a
--     logged-in user, their own rows.

create table if not exists public.cases (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  created_at timestamptz not null default now(),
  verdict text not null check (verdict in ('scam', 'suspicious', 'likely_safe')),
  risk_score int not null,
  scam_type text not null,
  masked_message text not null,
  report jsonb not null
);
create index if not exists cases_user_created_idx on public.cases (user_id, created_at desc);

create table if not exists public.followups (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references public.cases (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  created_at timestamptz not null default now(),
  question text not null,
  answer text not null
);
create index if not exists followups_case_idx on public.followups (case_id, created_at);

-- Result cache, keyed by an HMAC of the message (the message itself is not stored).
create table if not exists public.check_cache (
  fingerprint text primary key,
  report jsonb not null,
  created_at timestamptz not null default now()
);
create index if not exists check_cache_created_idx on public.check_cache (created_at);

alter table public.cases enable row level security;
alter table public.followups enable row level security;
alter table public.check_cache enable row level security;

drop policy if exists "read own cases" on public.cases;
create policy "read own cases" on public.cases
  for select to authenticated using ((select auth.uid()) = user_id);

drop policy if exists "read own followups" on public.followups;
create policy "read own followups" on public.followups
  for select to authenticated using ((select auth.uid()) = user_id);
-- check_cache has no policies at all: only the backend can touch it.

-- Housekeeping: remove cache entries older than 2 days. Called by the backend's
-- daily keep-alive (see /health/deep) so no paid scheduler is needed.
create or replace function public.purge_old_cache() returns void
language sql security definer set search_path = public as $$
  delete from public.check_cache where created_at < now() - interval '2 days';
$$;
revoke all on function public.purge_old_cache() from public, anon, authenticated;
