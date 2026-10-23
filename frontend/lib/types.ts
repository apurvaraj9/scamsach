export type Lang = "en" | "hi";
export type Verdict = "scam" | "suspicious" | "likely_safe";
export type Signal = "danger" | "warning" | "ok" | "info" | "skipped" | "error";

export interface Finding {
  tool: string;
  target: string;
  signal: Signal;
  title_en: string;
  title_hi: string;
  detail: string;
  source_name: string;
  source_url: string;
  weight: number;
  hard: boolean;
}

export interface StepEvent {
  type: "step";
  id: string;
  status: "running" | "done";
  phase: string;
  title_en: string;
  title_hi: string;
  detail: string;
  finding: Finding | null;
}

export interface PlanCall {
  tool: string;
  target: string;
  target_label: string;
  reason: string;
  source: "planner" | "safety floor";
}

export interface PlanEvent {
  type: "plan";
  round: number;
  planner: { by?: string; provider?: string; model?: string; hypothesis?: string };
  calls: PlanCall[];
}

export interface Bilingual {
  en: string;
  hi: string;
}

export interface NextStep {
  en: string;
  hi: string;
  link: string | null;
}

export interface StepsBlock {
  steps: NextStep[];
  report_title: string;
  report_text: string;
  report_url: string;
}

export interface Report {
  verdict: Verdict;
  risk_score: number;
  scam_type: string;
  scam_type_label: Bilingual;
  confidence: number;
  summary: Bilingual;
  red_flags: { en: string[]; hi: string[] };
  summary_by: "ai" | "rules";
  decision_note: string;
  hard_evidence: string[];
  findings: Finding[];
  next_steps: { no_loss: StepsBlock; money_lost: StepsBlock };
  impersonates: string | null;
  links: string[];
  language_detected: string;
  masked_message: string;
  privacy: { masked_counts: Record<string, number> };
  engine: { planner: string; judge: string };
  disclaimer: Bilingual;
  cached?: boolean;
  created_at: string;
}

export interface CaseSummary {
  id: string;
  created_at: string;
  verdict: Verdict;
  risk_score: number;
  scam_type: string;
  snippet: string;
}

export interface Followup {
  id: string;
  created_at: string;
  question: string;
  answer: string;
}

export interface CaseDetail {
  id: string;
  created_at: string;
  verdict: Verdict;
  report: Report;
  followups: Followup[];
}
