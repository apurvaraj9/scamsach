import "@fontsource/mukta/400.css";
import "@fontsource/mukta/600.css";
import "@fontsource/mukta/800.css";
import "./globals.css";
import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";
import { Footer, Header, WakeBanner } from "@/components/Chrome";
import { AppProvider } from "@/lib/app-context";
import { SITE_URL } from "@/lib/site";

const DESCRIPTION =
  "Free scam message checker for India. Paste an SMS, WhatsApp message, link or UPI request and an AI agent checks it step by step, shows the evidence, and tells you exactly what to do. Works in English and Hindi.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: "ScamSach: free scam message checker for India (SMS, WhatsApp, UPI)",
    template: "%s | ScamSach",
  },
  description: DESCRIPTION,
  applicationName: "ScamSach",
  keywords: [
    "ScamSach",
    "scam message checker",
    "is this message a scam",
    "fake SMS check India",
    "WhatsApp scam check",
    "UPI fraud check",
    "fake traffic challan message",
    "KYC update scam",
    "digital arrest scam",
  ],
  alternates: { canonical: "/" },
  openGraph: {
    type: "website",
    siteName: "ScamSach",
    url: "/",
    title: "ScamSach: is this message a scam? Check before you click, call or pay",
    description: DESCRIPTION,
    locale: "en_IN",
  },
  twitter: { card: "summary", title: "ScamSach: free scam message checker for India", description: DESCRIPTION },
  robots: { index: true, follow: true },
  // Google Search Console ownership tag. The value is public by design; set it in Vercel.
  verification: process.env.NEXT_PUBLIC_GOOGLE_SITE_VERIFICATION
    ? { google: process.env.NEXT_PUBLIC_GOOGLE_SITE_VERIFICATION }
    : undefined,
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#14284B",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AppProvider>
          <a className="skip-link" href="#main">
            Skip to content
          </a>
          <Header />
          <WakeBanner />
          <main id="main" className="wrap">
            {children}
          </main>
          <Footer />
        </AppProvider>
      </body>
    </html>
  );
}
