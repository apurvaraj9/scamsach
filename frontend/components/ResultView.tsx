"use client";

import { useState } from "react";
import { useApp } from "@/lib/app-context";
import type { Report } from "@/lib/types";

function Stamp({ verdict, label }: { verdict: Report["verdict"]; label: string }) {
  return (
    <div className={`stamp stamp-${verdict}`} aria-hidden="true">
      <span className="stamp-inner">{label}</span>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const { t } = useApp();
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn btn-secondary"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 2500);
        } catch {
          /* clipboard blocked: the text is still selectable */
        }
      }}
    >
      {done ? t.copied : t.copy}
    </button>
  );
}

/** The verdict, what to do next, and the evidence. ``originalMessage`` is the
 * text the user pasted (kept only in this browser) and goes into the
 * ready-made report; for saved cases the masked copy is used instead. */
export function ResultView({ report, originalMessage }: { report: Report; originalMessage?: string }) {
  const { t, lang } = useApp();
  const [lost, setLost] = useState(false);
  const block = lost ? report.next_steps.money_lost : report.next_steps.no_loss;
  const reportText = block.report_text.replace("{MESSAGE}", originalMessage || report.masked_message);
  const flags = report.red_flags[lang] ?? [];
  const evidence = report.findings.filter((f) => f.signal !== "skipped");

  return (
    <section className={`result result-${report.verdict}`} aria-labelledby="verdict-title">
      <div className="verdict-head">
        <Stamp verdict={report.verdict} label={t.verdictLabel[report.verdict]} />
        <div>
          <h2 id="verdict-title" tabIndex={-1} className="verdict-title">
            {t.verdictWord[report.verdict]}
          </h2>
          <p className="verdict-meta">
            {report.scam_type !== "none" && <span>{report.scam_type_label[lang]}. </span>}
            {t.riskScore}: {report.risk_score}/100
          </p>
        </div>
      </div>

      <p className="summary">{report.summary[lang]}</p>
      {report.cached && <p className="muted small">{t.cachedNote}</p>}

      {flags.length > 0 && report.verdict !== "likely_safe" && (
        <div className="flags">
          <h3>{t.redFlags}</h3>
          <ul>
            {flags.map((f) => (
              <li key={f}>{f}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="todo">
        <h3>{t.whatToDo}</h3>
        {report.verdict !== "likely_safe" && (
          <fieldset className="lost-toggle">
            <legend>{t.lostQuestion}</legend>
            <div className="segmented" role="radiogroup">
              <button type="button" role="radio" aria-checked={!lost} className={!lost ? "on" : ""} onClick={() => setLost(false)}>
                {t.no}
              </button>
              <button type="button" role="radio" aria-checked={lost} className={lost ? "on danger" : ""} onClick={() => setLost(true)}>
                {t.yes}
              </button>
            </div>
          </fieldset>
        )}
        {lost && (
          <a className="call-1930" href="tel:1930">
            <span className="call-number">1930</span>
            <span>{lang === "hi" ? "अभी कॉल करें - साइबर क्राइम हेल्पलाइन" : "Call now - Cyber Crime Helpline"}</span>
          </a>
        )}
        <ol className="steps">
          {block.steps.map((s) => (
            <li key={s.en}>
              {s[lang]}{" "}
              {s.link && s.link.startsWith("http") && (
                <a href={s.link} target="_blank" rel="noopener noreferrer">
                  {s.link.replace(/^https?:\/\//, "")}
                </a>
              )}
            </li>
          ))}
        </ol>

        {report.verdict !== "likely_safe" && (
          <div className="report-box">
            <h4>{t.reportText}</h4>
            <p className="muted small">{t.reportHint}</p>
            <textarea readOnly value={reportText} rows={9} aria-label={t.reportText} />
            <div className="row-actions">
              <CopyButton text={reportText} />
              <a className="btn btn-secondary" href={block.report_url} target="_blank" rel="noopener noreferrer">
                {t.openSite}
              </a>
            </div>
          </div>
        )}
      </div>

      <details className="evidence">
        <summary>
          {t.evidence} ({evidence.length})
        </summary>
        <ul>
          {evidence.map((f, i) => (
            <li key={`${f.tool}-${i}`} className={`ev sig-${f.signal}`}>
              <p className="ev-title">{lang === "hi" ? f.title_hi : f.title_en}</p>
              <p className="ev-meta">
                {f.target !== "message" && <span className="ev-target">{f.target}</span>}
                {f.detail && <span> {f.detail}</span>}
              </p>
              <p className="ev-meta">
                {t.source}:{" "}
                {f.source_url ? (
                  <a href={f.source_url} target="_blank" rel="noopener noreferrer nofollow">
                    {f.source_name}
                  </a>
                ) : (
                  f.source_name
                )}
              </p>
            </li>
          ))}
        </ul>
        <p className="muted small">
          {t.aiNote[report.summary_by]} {report.decision_note}
        </p>
      </details>

      <aside className="disclaimer">
        <strong>{t.disclaimerTitle}: </strong>
        {report.disclaimer[lang]}
      </aside>
    </section>
  );
}
