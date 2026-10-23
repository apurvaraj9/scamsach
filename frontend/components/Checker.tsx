"use client";

import { useEffect, useRef, useState } from "react";
import { ApiError, investigate } from "@/lib/api";
import { useApp } from "@/lib/app-context";
import { EXAMPLES } from "@/lib/i18n";
import { authEnabled } from "@/lib/supabase";
import type { PlanEvent, Report } from "@/lib/types";
import { CaseLog, type LogRow, mergeStep } from "./CaseLog";
import { ResultView } from "./ResultView";

const MAX = 2000;

export function Checker() {
  const { t, lang, token, session, waitForBackend, login } = useApp();
  const [message, setMessage] = useState("");
  const [checkedMessage, setCheckedMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [rows, setRows] = useState<LogRow[]>([]);
  const [plans, setPlans] = useState<PlanEvent[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => () => abortRef.current?.abort(), []);

  useEffect(() => {
    if (report) {
      resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      document.getElementById("verdict-title")?.focus({ preventScroll: true });
    }
  }, [report]);

  async function run(text: string) {
    const trimmed = text.trim();
    if (trimmed.length < 3) {
      setError(t.messageTooShort);
      return;
    }
    setBusy(true);
    setError(null);
    setRows([]);
    setPlans([]);
    setReport(null);
    setCheckedMessage(trimmed);
    const ready = await waitForBackend();
    if (!ready) {
      setBusy(false);
      setError(t.wakeFailed);
      return;
    }
    abortRef.current = new AbortController();
    try {
      await investigate(
        trimmed,
        token,
        {
          onStep: (s) => setRows((r) => mergeStep(r, s)),
          onPlan: (p) => setPlans((ps) => [...ps, p]),
          onResult: (rep) => setReport(rep),
        },
        abortRef.current.signal,
      );
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") return;
      if (e instanceof ApiError && e.status === 429) setError(`${t.tooMany} ${e.message}`);
      else if (e instanceof ApiError && e.message) setError(e.message);
      else setError(t.errorGeneric);
    } finally {
      setBusy(false);
    }
  }

  async function pasteFromClipboard() {
    try {
      const text = await navigator.clipboard.readText();
      if (text) setMessage(text.slice(0, MAX));
    } catch {
      document.getElementById("message")?.focus();
    }
  }

  function reset() {
    setReport(null);
    setRows([]);
    setPlans([]);
    setMessage("");
    window.scrollTo({ top: 0, behavior: "smooth" });
    document.getElementById("message")?.focus();
  }

  return (
    <>
      <section className="hero" aria-labelledby="hero-title">
        <h1 id="hero-title">{t.tagline}</h1>
        <p className="intro">{t.intro}</p>

        <form
          className="check-form"
          onSubmit={(e) => {
            e.preventDefault();
            void run(message);
          }}
        >
          <label htmlFor="message" className="field-label">
            {t.pasteLabel}
          </label>
          <textarea
            id="message"
            value={message}
            onChange={(e) => setMessage(e.target.value.slice(0, MAX))}
            placeholder={t.pastePlaceholder}
            rows={6}
            maxLength={MAX}
            disabled={busy}
            spellCheck={false}
          />
          <div className="form-row">
            <span className="muted small">
              {message.length}/{MAX}
            </span>
            <button type="button" className="link-button" onClick={() => void pasteFromClipboard()} disabled={busy}>
              {t.pasteButton}
            </button>
          </div>
          <button type="submit" className="btn btn-primary" disabled={busy || message.trim().length === 0}>
            {busy ? t.checking : t.check}
          </button>
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
        </form>

        <div className="examples">
          <p className="muted small">{t.examples}</p>
          <div className="chips">
            {EXAMPLES.map((ex) => (
              <button
                key={ex.text}
                type="button"
                className="chip"
                disabled={busy}
                onClick={() => {
                  setMessage(ex.text);
                  void run(ex.text);
                }}
              >
                {ex.label[lang]}
              </button>
            ))}
          </div>
        </div>
        <p className="privacy-note">{t.privacyNote}</p>
        {authEnabled && !session && (
          <p className="muted small">
            {t.loginForHistory}{" "}
            <button type="button" className="link-button inline" onClick={() => void login()}>
              {t.login}
            </button>
          </p>
        )}
      </section>

      {/* While checking, the live log is shown. Once the verdict is ready it goes
          first (what older users need), and the log stays below it as evidence. */}
      <div ref={resultRef}>{report && <ResultView report={report} originalMessage={checkedMessage} />}</div>
      {rows.length > 0 && <CaseLog rows={rows} plans={plans} />}
      {report && (
        <button type="button" className="btn btn-primary new-check" onClick={reset}>
          {t.newCheck}
        </button>
      )}
    </>
  );
}
