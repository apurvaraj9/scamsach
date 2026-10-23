"use client";

import { useState } from "react";
import { sendFeedback } from "@/lib/api";
import { useApp } from "@/lib/app-context";
import type { Report } from "@/lib/types";

type Rating = "correct" | "wrong" | "unsure";
type Actual = "scam" | "genuine" | "unsure";

/** "Was this result right?" Wrong-verdict reports become new evaluation cases. */
export function Feedback({ report, message }: { report: Report; message: string }) {
  const { t, token } = useApp();
  const [rating, setRating] = useState<Rating | null>(null);
  const [actual, setActual] = useState<Actual | null>(null);
  const [comment, setComment] = useState("");
  const [share, setShare] = useState(false);
  const [state, setState] = useState<"idle" | "sending" | "sent" | "error">("idle");

  async function submit(r: Rating) {
    setState("sending");
    try {
      await sendFeedback(token, {
        rating: r,
        verdict_shown: report.verdict,
        scam_type: report.scam_type,
        actual: r === "correct" ? null : actual,
        comment: comment.trim(),
        share_message: share,
        message: share ? message : null,
        trace_id: report.trace_id ?? null,
      });
      setState("sent");
    } catch {
      setState("error");
    }
  }

  if (state === "sent") {
    return (
      <p className="feedback-thanks" role="status">
        {t.fbThanks}
      </p>
    );
  }

  return (
    <section className="feedback" aria-labelledby="fb-title">
      <h3 id="fb-title">{t.fbQuestion}</h3>
      <div className="chips">
        <button type="button" className={`chip ${rating === "correct" ? "chip-on" : ""}`} disabled={state === "sending"}
          onClick={() => { setRating("correct"); void submit("correct"); }}>
          {t.fbYes}
        </button>
        <button type="button" className={`chip ${rating === "wrong" ? "chip-on" : ""}`} onClick={() => setRating("wrong")}>
          {t.fbNo}
        </button>
        <button type="button" className={`chip ${rating === "unsure" ? "chip-on" : ""}`} onClick={() => setRating("unsure")}>
          {t.fbUnsure}
        </button>
      </div>

      {(rating === "wrong" || rating === "unsure") && (
        <form
          className="feedback-form"
          onSubmit={(e) => {
            e.preventDefault();
            void submit(rating);
          }}
        >
          <fieldset>
            <legend>{t.fbActual}</legend>
            <div className="chips">
              {(
                [
                  ["scam", t.fbActualScam],
                  ["genuine", t.fbActualGenuine],
                  ["unsure", t.fbActualUnsure],
                ] as [Actual, string][]
              ).map(([value, label]) => (
                <label key={value} className={`chip ${actual === value ? "chip-on" : ""}`}>
                  <input type="radio" name="actual" value={value} checked={actual === value}
                    onChange={() => setActual(value)} className="sr-only" />
                  {label}
                </label>
              ))}
            </div>
          </fieldset>
          <label htmlFor="fb-comment" className="field-label small-label">
            {t.fbComment}
          </label>
          <textarea id="fb-comment" rows={2} maxLength={500} value={comment} onChange={(e) => setComment(e.target.value)} />
          <label className="check-row">
            <input type="checkbox" checked={share} onChange={(e) => setShare(e.target.checked)} />
            <span>{t.fbShare}</span>
          </label>
          <button type="submit" className="btn btn-secondary" disabled={state === "sending"}>
            {t.fbSend}
          </button>
        </form>
      )}
      {state === "error" && <p className="form-error">{t.errorGeneric}</p>}
    </section>
  );
}
