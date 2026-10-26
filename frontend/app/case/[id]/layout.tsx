import type { Metadata } from "next";
import type { ReactNode } from "react";

// Personal page: keep it out of search results.
export const metadata: Metadata = { title: "Saved check", robots: { index: false, follow: false } };

export default function CaseLayout({ children }: { children: ReactNode }) {
  return children;
}
