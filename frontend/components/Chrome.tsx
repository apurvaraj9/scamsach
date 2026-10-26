"use client";

import Link from "next/link";
import { useApp } from "@/lib/app-context";
import { authEnabled } from "@/lib/supabase";
import { START_OVER_EVENT } from "@/lib/events";

export function Header() {
  const { t, lang, setLang, session, login, logout } = useApp();
  return (
    <header className="site-header">
      {/* Brand and the language switch stay on the first row everywhere; the
          text links share one consistent style and drop to a second row on phones. */}
      <div className="wrap header-row">
        <Link
          href="/"
          className="wordmark"
          aria-label="ScamSach home"
          onClick={() => window.dispatchEvent(new Event(START_OVER_EVENT))}
        >
          <span className="wordmark-scam">Scam</span>
          <span className="wordmark-sach">Sach</span>
        </Link>
        <nav className="header-nav" aria-label="Main">
          <Link href="/guide" className="nav-link">
            {t.guideLink}
          </Link>
          {authEnabled &&
            (session ? (
              <>
                <Link href="/history" className="nav-link">
                  {t.history}
                </Link>
                <button type="button" className="nav-link" onClick={() => void logout()}>
                  {t.logout}
                </button>
              </>
            ) : (
              <button type="button" className="nav-link" onClick={() => void login()}>
                {t.loginShort}
              </button>
            ))}
        </nav>
        <button
          type="button"
          className="lang-toggle"
          onClick={() => setLang(lang === "en" ? "hi" : "en")}
          aria-label={lang === "en" ? "हिंदी में देखें" : "View in English"}
        >
          {lang === "en" ? "हिंदी" : "English"}
        </button>
      </div>
    </header>
  );
}

export function WakeBanner() {
  const { backend, t, waitForBackend } = useApp();
  if (backend !== "waking" && backend !== "down") return null;
  return (
    <div className={`wake-banner ${backend}`} role="status" aria-live="polite">
      <div className="wrap">
        {backend === "waking" ? (
          <>
            <p className="wake-title">
              <span className="pulse" aria-hidden="true" /> {t.wakeTitle}
            </p>
            <p className="wake-body">{t.wakeBody}</p>
          </>
        ) : (
          <p className="wake-title">
            {t.wakeFailed}{" "}
            <button type="button" className="link-button inline" onClick={() => void waitForBackend()}>
              ↻
            </button>
          </p>
        )}
      </div>
    </div>
  );
}

export function Footer() {
  const { t } = useApp();
  return (
    <footer className="site-footer">
      <div className="wrap">
        <p>{t.footer}</p>
        <p className="muted">
          {t.sbAttribution}{" "}
          <Link href="/privacy">{t.privacyLink}</Link>
        </p>
      </div>
    </footer>
  );
}
