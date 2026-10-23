"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ResultView } from "@/components/ResultView";
import { askFollowup, deleteCase, getCase } from "@/lib/api";
import { useApp } from "@/lib/app-context";
import type { CaseDetail, Followup } from "@/lib/types";

export default function CasePage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { t, lang, token, session, login, waitForBackend } = useApp();
  const [data, setData] = useState<CaseDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [question, setQuestion] = useState("");
  const [asking, setAsking] = useState(false);
  const [thread, setThread] = useState<Followup[]>([]);

  useEffect(() => {
    if (!token || !id) return;
    let alive = true;
    (async () => {
      await waitForBackend();
      try {
        const c = await getCase(token, id);
        if (alive) {
          setData(c);
          setThread(c.followups);
        }
      } catch {
        if (alive) setError(t.errorGeneric);
      }
    })();
    return () => {
      alive = false;
    };
  }, [token, id, waitForBackend, t.errorGeneric]);

  if (!session) {
    return (
      <section className="page">
        <p>{t.loginNeeded}</p>
        <button type="button" className="btn btn-primary" onClick={() => void login()}>
          {t.login}
        </button>
      </section>
    );
  }

  async function ask(e: React.FormEvent) {
    e.preventDefault();
    if (!token || question.trim().length < 2) return;
    setAsking(true);
    try {
      const res = await askFollowup(token, id, question.trim(), lang);
      setThread((th) => [
        ...th,
        { id: String(Date.now()), created_at: new Date().toISOString(), question: question.trim(), answer: res.answer },
      ]);
      setQuestion("");
    } catch (err) {
      setError(err instanceof Error && err.message ? err.message : t.errorGeneric);
    } finally {
      setAsking(false);
    }
  }

  return (
    <section className="page">
      <p>
        <Link href="/history">{t.backToHistory}</Link>
      </p>
      {error && <p className="form-error">{error}</p>}
      {!data && !error && <p className="muted">{t.checking}</p>}
      {data && (
        <>
          <blockquote className="quoted-message">{data.report.masked_message}</blockquote>
          <ResultView report={data.report} />

          <section className="followup" aria-labelledby="ask-title">
            <h2 id="ask-title">{t.askTitle}</h2>
            {thread.map((f) => (
              <div key={f.id} className="qa">
                <p className="qa-q">{f.question}</p>
                <p className="qa-a">{f.answer}</p>
              </div>
            ))}
            <form onSubmit={ask} className="ask-form">
              <label htmlFor="q" className="sr-only">
                {t.askTitle}
              </label>
              <textarea
                id="q"
                rows={3}
                maxLength={500}
                value={question}
                placeholder={t.askPlaceholder}
                onChange={(e) => setQuestion(e.target.value)}
                disabled={asking}
              />
              <button type="submit" className="btn btn-primary" disabled={asking || question.trim().length < 2}>
                {asking ? t.asking : t.ask}
              </button>
            </form>
          </section>

          <button
            type="button"
            className="btn btn-danger-outline"
            onClick={async () => {
              if (!token || !window.confirm(t.deleteOneConfirm)) return;
              await deleteCase(token, id);
              router.push("/history");
            }}
          >
            {t.deleteOne}
          </button>
        </>
      )}
    </section>
  );
}
