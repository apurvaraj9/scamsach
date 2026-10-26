import { Checker } from "@/components/Checker";
import { HomeInfo } from "@/components/HomeInfo";
import { SITE_URL } from "@/lib/site";

// Tells search engines what ScamSach is (schema.org WebApplication).
const jsonLd = {
  "@context": "https://schema.org",
  "@type": "WebApplication",
  name: "ScamSach",
  alternateName: ["Scam Sach", "ScamSach scam checker"],
  url: SITE_URL,
  applicationCategory: "SecurityApplication",
  operatingSystem: "Any",
  inLanguage: ["en-IN", "hi-IN"],
  isAccessibleForFree: true,
  offers: { "@type": "Offer", price: "0", priceCurrency: "INR" },
  description:
    "Free scam message checker for India. Paste an SMS, WhatsApp message, link or UPI request and an AI agent checks it, shows the evidence and tells you what to do.",
};

export default function Home() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
      <Checker />
      <HomeInfo />
    </>
  );
}
