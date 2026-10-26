"use client";

import Link from "next/link";
import { useApp } from "@/lib/app-context";

// Keep this page in step with the code: backend/app/security/masking.py (what is
// hidden), services/store.py + supabase/schema.sql (what is kept) and main.py
// (rate limiting by IP in memory only). Plain words, no legal jargon.
const UPDATED = "25 October 2026";
const ISSUES = "https://github.com/apurvaraj9/scamsach/issues";

const CONTENT = {
  en: {
    title: "Privacy",
    intro:
      "ScamSach is a free, non-commercial personal project. It has no ads, does not sell data and uses no tracking or advertising cookies. This page explains in plain words what happens to what you paste.",
    sections: [
      {
        h: "When you check a message",
        items: [
          "Before any AI sees your message, we replace phone numbers, bank account, card, Aadhaar and PAN numbers, UPI IDs, email addresses, OTPs and vehicle numbers with labels like [PHONE_1].",
          "The masked message is read by an AI service: Google Gemini, or Groq as a backup. Free AI plans may use what they receive to improve their services, which is why we mask it first.",
          "Links in the message are looked up, not opened, at Google Safe Browsing, VirusTotal and URLhaus. We also look up when the website was registered in the public domain registry (RDAP).",
          "We never visit the links you paste. For short links such as bit.ly we only ask the link-shortening service where the link points.",
        ],
      },
      {
        h: "What we keep",
        items: [
          "Not logged in: your check is not saved to any account. A masked copy of the result is kept for up to 2 days so that the same message gets an instant answer. It is filed under a scrambled code, not under your name or IP address.",
          "Logged in with Google: we keep your Google email address and name (for login), and your checks (the masked message and the result) and follow-up questions, until you delete them. \"Delete all my data\" on My past checks removes them straight away.",
          "Feedback: we keep your rating and your comment (masked). We keep the masked message only if you tick \"share this message\".",
          "Your IP address is used only in the server's memory, to limit how many checks one connection can make. It is not saved in our database. The server's technical logs on Render record things like IP address and which page was requested, but not your message.",
          "To find and fix mistakes, the agent's steps are recorded in Langfuse using the masked text only.",
          "Your login session is kept in your own browser so that you stay logged in.",
        ],
      },
      {
        h: "Services ScamSach uses",
        items: [
          "Supabase (database and Google login), Render (server), Vercel (website).",
          "Google Gemini and Groq (AI). Google Safe Browsing, VirusTotal and URLhaus (link checks). Langfuse (recording the agent's steps).",
        ],
      },
      {
        h: "Please remember",
        items: [
          "ScamSach gives guidance, not a guarantee. When in doubt, contact the organisation through its official app, website or the number on your card.",
          "Do not paste passwords, full card numbers or PINs. ScamSach never needs them.",
        ],
      },
    ],
    contact: "Questions or a request to delete data? Open an issue on the project's GitHub page:",
    updated: "Last updated:",
    back: "Check a message",
  },
  hi: {
    title: "प्राइवेसी",
    intro:
      "ScamSach एक मुफ़्त, गैर-व्यावसायिक निजी प्रोजेक्ट है। इसमें कोई विज्ञापन नहीं है, यह डेटा नहीं बेचता और ट्रैकिंग या विज्ञापन वाली कुकीज़ का इस्तेमाल नहीं करता। यह पेज आसान शब्दों में बताता है कि आप जो पेस्ट करते हैं उसका क्या होता है।",
    sections: [
      {
        h: "जब आप कोई संदेश जांचते हैं",
        items: [
          "किसी भी AI के देखने से पहले हम फ़ोन नंबर, बैंक खाता, कार्ड, आधार और PAN नंबर, UPI ID, ईमेल पता, OTP और गाड़ी का नंबर हटाकर उनकी जगह [PHONE_1] जैसे लेबल लगा देते हैं।",
          "छुपाया हुआ संदेश एक AI सेवा पढ़ती है: Google Gemini, या बैकअप के तौर पर Groq। मुफ़्त AI सेवाएं मिली हुई जानकारी का इस्तेमाल अपनी सेवा सुधारने के लिए कर सकती हैं, इसीलिए हम पहले जानकारी छुपाते हैं।",
          "संदेश के लिंक खोले नहीं जाते, सिर्फ़ Google Safe Browsing, VirusTotal और URLhaus पर जांचे जाते हैं। हम सार्वजनिक डोमेन रजिस्ट्री (RDAP) से यह भी देखते हैं कि वेबसाइट कब बनी।",
          "आपके भेजे लिंक हम कभी नहीं खोलते। bit.ly जैसे छोटे लिंक के लिए हम सिर्फ़ लिंक छोटा करने वाली सेवा से पूछते हैं कि लिंक कहाँ जाता है।",
        ],
      },
      {
        h: "हम क्या रखते हैं",
        items: [
          "लॉग इन नहीं हैं: आपकी जांच किसी खाते में सेव नहीं होती। नतीजे की एक छुपाई हुई कॉपी ज़्यादा से ज़्यादा 2 दिन रखी जाती है, ताकि वही संदेश दोबारा आने पर तुरंत जवाब मिले। यह एक बदले हुए कोड के नाम से रखी जाती है, आपके नाम या IP पते से नहीं।",
          "Google से लॉग इन हैं: हम आपका Google ईमेल और नाम (लॉग इन के लिए), और आपकी जांचें (छुपाया हुआ संदेश और नतीजा) व आगे पूछे गए सवाल तब तक रखते हैं जब तक आप उन्हें मिटा न दें। \"मेरी पिछली जांचें\" पेज पर \"मेरा सारा डेटा मिटाएं\" से सब तुरंत मिट जाता है।",
          "फ़ीडबैक: हम आपकी रेटिंग और आपकी टिप्पणी (छुपाकर) रखते हैं। छुपाया हुआ संदेश तभी रखते हैं जब आप \"यह संदेश साझा करें\" पर टिक करें।",
          "आपका IP पता सिर्फ़ सर्वर की मेमोरी में इस्तेमाल होता है, ताकि एक कनेक्शन से गिनी-चुनी जांचें ही हों। यह हमारे डेटाबेस में सेव नहीं होता। Render पर सर्वर के तकनीकी लॉग में IP पता और कौन-सा पेज मांगा गया जैसी बातें दर्ज होती हैं, आपका संदेश नहीं।",
          "गलतियां ढूंढकर ठीक करने के लिए, एजेंट के कदम Langfuse में सिर्फ़ छुपाए हुए टेक्स्ट के साथ दर्ज होते हैं।",
          "आपका लॉग इन आपके अपने ब्राउज़र में रहता है, ताकि आप लॉग इन बने रहें।",
        ],
      },
      {
        h: "ScamSach कौन-सी सेवाएं इस्तेमाल करता है",
        items: [
          "Supabase (डेटाबेस और Google लॉग इन), Render (सर्वर), Vercel (वेबसाइट)।",
          "Google Gemini और Groq (AI)। Google Safe Browsing, VirusTotal और URLhaus (लिंक की जांच)। Langfuse (एजेंट के कदम दर्ज करना)।",
        ],
      },
      {
        h: "ध्यान रखें",
        items: [
          "ScamSach सलाह देता है, गारंटी नहीं। शक हो तो संस्था के आधिकारिक ऐप, वेबसाइट या कार्ड पर छपे नंबर से संपर्क करें।",
          "पासवर्ड, पूरा कार्ड नंबर या PIN पेस्ट न करें। ScamSach को इनकी कभी ज़रूरत नहीं होती।",
        ],
      },
    ],
    contact: "कोई सवाल है या डेटा मिटवाना है? प्रोजेक्ट के GitHub पेज पर issue खोलें:",
    updated: "आखिरी बदलाव:",
    back: "संदेश जांचें",
  },
};

export default function PrivacyPage() {
  const { lang } = useApp();
  const c = CONTENT[lang];
  return (
    <article className="page guide">
      <h1>{c.title}</h1>
      <p className="intro">{c.intro}</p>
      {c.sections.map((s) => (
        <section key={s.h}>
          <h2>{s.h}</h2>
          <ul>
            {s.items.map((i) => (
              <li key={i}>{i}</li>
            ))}
          </ul>
        </section>
      ))}
      <p>
        {c.contact}{" "}
        <a href={ISSUES} target="_blank" rel="noopener noreferrer">
          github.com/apurvaraj9/scamsach/issues
        </a>
      </p>
      <p className="muted">
        {c.updated} {UPDATED}
      </p>
      <Link href="/" className="btn btn-primary">
        {c.back}
      </Link>
    </article>
  );
}
