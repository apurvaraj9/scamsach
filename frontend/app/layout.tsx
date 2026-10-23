import "@fontsource/mukta/400.css";
import "@fontsource/mukta/600.css";
import "@fontsource/mukta/800.css";
import "./globals.css";
import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";
import { Footer, Header, WakeBanner } from "@/components/Chrome";
import { AppProvider } from "@/lib/app-context";

export const metadata: Metadata = {
  title: "ScamSach: check a message before you click, call or pay",
  description:
    "Free scam checker for India. Paste an SMS, WhatsApp message, link or UPI request and an AI agent investigates it, then tells you exactly what to do.",
  robots: { index: true, follow: true },
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
