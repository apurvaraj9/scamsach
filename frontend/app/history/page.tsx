"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { deleteAllCases, listCases } from "@/lib/api";
import { useApp } from "@/lib/app-context";
import type { CaseSummary } from "@/lib/types";

export default function HistoryPage() {
  const { t, lang, token, session, login, waitForBackend } = useApp();
  const [cases, setCases] = useState<CaseSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    let alive = true;
    (async () => {
      await waitForBackend();
      try {
        const data = await listCases(token);
        if (alive) setCases(data.cases);
      } catch {
        if (alive) setError(t.errorGeneric);
      }
    })();
    return () => {
      alive = false;
    };
  }, [token, waitForBackend, t.errorGeneric]);

  if (!session) {
    return (
      <section className="page">
        <h1>{t.history}</h1>
        <p>{t.loginForHistory}</p>
        <button type="button" className="btn btn-primary" onClick={() => void login()}>
          {t.login}
        </button>
      </section>
    );
  }

  return (
    <section className="page">
      <h1>{t.history}</h1>
      {error && <p className="form-error">{error}</p>}
      {cases === null && !error && <p className="muted">{t.checking}</p>}
      {cases?.length === 0 && (
        <p>
          {t.emptyHistory} <Link href="/">{t.home}</Link>
        </p>
      )}
      {cases && cases.length > 0 && (
        <>
          <ul className="history-list">
            {cases.map((c) => (
              <li key={c.id}>
                <Link href={`/case/${c.id}`} className={`history-item hv-${c.verdict}`}>
                  <span className={`mini-stamp stamp-${c.verdict}`}>{t.verdictLabel[c.verdict]}</span>
                  <span className="history-snippet">{c.snippet}</span>
                  <span className="muted small">
                    {new Date(c.created_at).toLocaleString(lang === "hi" ? "hi-IN" : "en-IN", {
                      dateStyle: "medium",
                      timeStyle: "short",
                    })}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
          <button
            type="button"
            className="btn btn-danger-outline"
            onClick={async () => {
              if (!token || !window.confirm(t.deleteConfirm)) return;
              await deleteAllCases(token);
              setCases([]);
            }}
          >
            {t.deleteAll}
          </button>
        </>
      )}
    </section>
  );
}
