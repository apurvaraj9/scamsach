import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = {
  title: "How to spot a fake SMS or WhatsApp message",
  description:
    "Simple checks to tell a real bank, electricity, parcel or challan message from a scam in India: sender names, web addresses, WhatsApp, and where to verify or report.",
  alternates: { canonical: "/guide" },
};

export default function GuideLayout({ children }: { children: ReactNode }) {
  return children;
}
