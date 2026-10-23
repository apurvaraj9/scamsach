"use client";

import { useApp } from "@/lib/app-context";
import type { PlanEvent, Signal, StepEvent } from "@/lib/types";

export interface LogRow {
  key: string;
  step: StepEvent;
}

/** Merge a streamed step into the visible log. A "running" row is replaced
 * by its first "done" event; further results for the same check are added. */
export function mergeStep(rows: LogRow[], step: StepEvent): LogRow[] {
  if (step.status === "done") {
    let i = -1; // (manual loop: findLastIndex is missing on older phone browsers)
    for (let j = rows.length - 1; j >= 0; j--) {
      if (rows[j].step.id === step.id && rows[j].step.status === "running") {
        i = j;
        break;
      }
    }
    if (i !== -1) {
      const copy = rows.slice();
      copy[i] = { key: copy[i].key, step };
      return copy;
    }
  }
  return [...rows, { key: `${step.id}-${rows.length}`, step }];
}

const ICON: Record<Signal | "running" | "plain", string> = {
  danger: "!",
  warning: "?",
  ok: "✓",
  info: "i",
  skipped: "–",
  error: "×",
  running: "",
  plain: "✓",
};

export function CaseLog({ rows, plans }: { rows: LogRow[]; plans: PlanEvent[] }) {
  const { t, lang } = useApp();
  const firstPlan = plans.find((p) => p.round === 0);
  return (
    <section className="case-log" aria-labelledby="log-title">
      <h2 id="log-title">{t.logTitle}</h2>
      <ol className="log-list" aria-live="polite">
        {rows.map(({ key, step }) => {
          const signal = step.status === "running" ? "running" : (step.finding?.signal ?? "plain");
          const title = lang === "hi" ? step.title_hi : step.title_en;
          return (
            <li key={key} className={`log-row sig-${signal}`}>
              <span className="log-icon" aria-hidden="true">
                {signal === "running" ? <span className="spinner" /> : ICON[signal]}
              </span>
              <div className="log-text">
                <p className="log-title">{title}</p>
                {step.detail && <p className="log-detail">{step.detail}</p>}
                {step.finding?.source_name && (
                  <p className="log-source">
                    {t.source}:{" "}
                    {step.finding.source_url ? (
                      <a href={step.finding.source_url} target="_blank" rel="noopener noreferrer nofollow">
                        {step.finding.source_name}
                      </a>
                    ) : (
                      step.finding.source_name
                    )}
                  </p>
                )}
                {step.id === "plan" && step.status === "done" && firstPlan && firstPlan.calls.length > 0 && (
                  <ul className="plan-list">
                    {firstPlan.calls.map((c) => (
                      <li key={`${c.tool}-${c.target}`}>
                        <span className="plan-tool">{c.target_label}:</span> {c.reason}
                        {c.source === "safety floor" && <span className="plan-floor"> ({t.safetyFloor})</span>}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
