import type { CaseDetail, CaseSummary, Lang, PlanEvent, Report, StepEvent } from "./types";

export const API_URL = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

function authHeaders(token?: string | null): Record<string, string> {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/** Ping the backend. Free hosting sleeps, so this may take up to a minute. */
export async function pingBackend(timeoutMs = 6000): Promise<boolean> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${API_URL}/health`, { signal: ctrl.signal, cache: "no-store" });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

export interface StreamHandlers {
  onStep: (e: StepEvent) => void;
  onPlan: (e: PlanEvent) => void;
  onResult: (report: Report, caseId: string | null) => void;
}

/** POST the message and read the Server-Sent Events stream. EventSource
 * cannot send a POST body or an auth header, so we parse the stream ourselves. */
export async function investigate(message: string, token: string | null, handlers: StreamHandlers, signal?: AbortSignal) {
  const res = await fetch(`${API_URL}/api/investigate`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders(token) },
    body: JSON.stringify({ message }),
    signal,
  });
  if (!res.ok || !res.body) {
    let detail = "";
    try {
      detail = (await res.json()).detail ?? "";
    } catch {
      /* body was not JSON */
    }
    throw new ApiError(typeof detail === "string" ? detail : "", res.status);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx: number;
    while ((idx = buffer.indexOf("\n\n")) !== -1) {
      const block = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      const dataLine = block.split("\n").find((l) => l.startsWith("data: "));
      if (!dataLine) continue;
      const event = JSON.parse(dataLine.slice(6));
      if (event.type === "step") handlers.onStep(event);
      else if (event.type === "plan") handlers.onPlan(event);
      else if (event.type === "result") handlers.onResult(event.report, event.case_id ?? null);
      else if (event.type === "error") throw new ApiError(event.message, 500);
    }
  }
}

async function json<T>(path: string, token: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...authHeaders(token), ...(init.headers ?? {}) },
    cache: "no-store",
  });
  if (!res.ok) {
    let detail = "";
    try {
      detail = (await res.json()).detail ?? "";
    } catch {
      /* ignore */
    }
    throw new ApiError(typeof detail === "string" ? detail : "", res.status);
  }
  return res.json() as Promise<T>;
}

export const listCases = (token: string) => json<{ cases: CaseSummary[] }>("/api/cases", token);
export const getCase = (token: string, id: string) => json<CaseDetail>(`/api/cases/${encodeURIComponent(id)}`, token);
export const deleteCase = (token: string, id: string) =>
  json<{ deleted: boolean }>(`/api/cases/${encodeURIComponent(id)}`, token, { method: "DELETE" });
export const deleteAllCases = (token: string) => json<{ deleted: boolean }>("/api/cases", token, { method: "DELETE" });
export const askFollowup = (token: string, id: string, question: string, lang: Lang) =>
  json<{ answer: string; engine: string }>(`/api/cases/${encodeURIComponent(id)}/followup`, token, {
    method: "POST",
    body: JSON.stringify({ question, lang }),
  });
