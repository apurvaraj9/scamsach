"use client";

import type { Session } from "@supabase/supabase-js";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { pingBackend } from "./api";
import { dict } from "./i18n";
import { getSupabase } from "./supabase";
import type { Lang } from "./types";

type BackendState = "checking" | "waking" | "ready" | "down";

interface AppState {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (typeof dict)["en"];
  session: Session | null;
  token: string | null;
  login: () => Promise<void>;
  logout: () => Promise<void>;
  backend: BackendState;
  waitForBackend: () => Promise<boolean>;
}

const Ctx = createContext<AppState | null>(null);
const WAKE_LIMIT_MS = 100_000;

export function AppProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>("en");
  const [session, setSession] = useState<Session | null>(null);
  const [backend, setBackend] = useState<BackendState>("checking");
  const waking = useRef<Promise<boolean> | null>(null);

  useEffect(() => {
    try {
      const saved = localStorage.getItem("scamsach-lang");
      if (saved === "hi" || saved === "en") setLangState(saved);
    } catch {
      /* storage unavailable: keep default */
    }
  }, []);

  const setLang = useCallback((l: Lang) => {
    setLangState(l);
    try {
      localStorage.setItem("scamsach-lang", l);
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    document.documentElement.lang = lang === "hi" ? "hi" : "en";
  }, [lang]);

  // Auth session
  useEffect(() => {
    const sb = getSupabase();
    if (!sb) return;
    sb.auth.getSession().then(({ data }) => setSession(data.session));
    const { data } = sb.auth.onAuthStateChange((_e, s) => setSession(s));
    return () => data.subscription.unsubscribe();
  }, []);

  // Wake the backend as soon as the page opens; keep polling while it boots.
  const waitForBackend = useCallback(() => {
    if (waking.current) return waking.current;
    waking.current = (async () => {
      const start = Date.now();
      if (await pingBackend(4000)) {
        setBackend("ready");
        return true;
      }
      setBackend("waking");
      while (Date.now() - start < WAKE_LIMIT_MS) {
        await new Promise((r) => setTimeout(r, 3000));
        if (await pingBackend(8000)) {
          setBackend("ready");
          return true;
        }
      }
      setBackend("down");
      waking.current = null; // allow a later retry
      return false;
    })();
    return waking.current;
  }, []);

  useEffect(() => {
    void waitForBackend();
  }, [waitForBackend]);

  const login = useCallback(async () => {
    const sb = getSupabase();
    if (!sb) return;
    await sb.auth.signInWithOAuth({ provider: "google", options: { redirectTo: `${window.location.origin}/history` } });
  }, []);

  const logout = useCallback(async () => {
    await getSupabase()?.auth.signOut();
  }, []);

  return (
    <Ctx.Provider
      value={{
        lang,
        setLang,
        t: dict[lang],
        session,
        token: session?.access_token ?? null,
        login,
        logout,
        backend,
        waitForBackend,
      }}
    >
      {children}
    </Ctx.Provider>
  );
}

export function useApp(): AppState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useApp must be used inside AppProvider");
  return v;
}
