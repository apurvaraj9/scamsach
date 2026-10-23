import { createClient, type SupabaseClient } from "@supabase/supabase-js";

// The publishable (anon) key is designed to be public; it can only do what
// Row Level Security allows. The secret key exists only on the backend.
const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;

let client: SupabaseClient | null = null;

export function getSupabase(): SupabaseClient | null {
  if (!url || !key) return null; // login is optional: the checker works without it
  if (!client) {
    client = createClient(url, key, {
      auth: { flowType: "pkce", persistSession: true, autoRefreshToken: true, detectSessionInUrl: true },
    });
  }
  return client;
}

export const authEnabled = Boolean(url && key);
