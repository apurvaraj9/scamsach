"use client";

import Link from "next/link";
import { useApp } from "@/lib/app-context";

// Short plain-language answers under the checker. They help first-time visitors
// and tell search engines what the page is for ("is this message a scam?").
const CONTENT = {
  en: {
    title: "Is this message a scam? How ScamSach helps",
    items: [
      {
        q: "What can I check?",
        a: "Any SMS, WhatsApp message, link or UPI payment request: bank KYC alerts, electricity disconnection notices, parcel or customs fees, traffic challans, job offers, lottery prizes, cashback requests and \"digital arrest\" calls.",
      },
      {
        q: "How does it decide?",
        a: "An AI agent reads the message and chooses its checks: link safety with Google Safe Browsing, VirusTotal and URLhaus, how new the website is, look-alike bank and government addresses, and known scam wording. You see every step and its source.",
      },
      {
        q: "Is it free and private?",
        a: "Yes, it is free and needs no sign-up. Phone numbers, account numbers and OTPs are hidden before any AI reads the message, and the links you paste are never opened.",
      },
      {
        q: "What if I already paid or shared an OTP?",
        a: "Call 1930 (National Cyber Crime Helpline) at once and report at cybercrime.gov.in. ScamSach gives you ready-to-paste report text.",
      },
    ],
    more: "Learn how to spot a fake message",
    privacy: "How we handle your data",
  },
  hi: {
    title: "क्या यह संदेश धोखा है? ScamSach कैसे मदद करता है",
    items: [
      {
        q: "मैं क्या जांच सकता हूँ?",
        a: "कोई भी SMS, WhatsApp संदेश, लिंक या UPI पेमेंट रिक्वेस्ट: बैंक KYC अलर्ट, बिजली कटने का नोटिस, पार्सल या कस्टम्स फ़ीस, ट्रैफिक चालान, नौकरी का ऑफ़र, लॉटरी इनाम, कैशबैक रिक्वेस्ट और \"डिजिटल अरेस्ट\" कॉल।",
      },
      {
        q: "यह कैसे तय करता है?",
        a: "एक AI एजेंट संदेश पढ़कर अपनी जांचें चुनता है: Google Safe Browsing, VirusTotal और URLhaus से लिंक की सुरक्षा, वेबसाइट कितनी नई है, बैंक और सरकारी पतों की नकल, और धोखे वाले जाने-पहचाने शब्द। आप हर कदम और उसका स्रोत देखते हैं।",
      },
      {
        q: "क्या यह मुफ़्त और सुरक्षित है?",
        a: "हाँ, यह मुफ़्त है और साइन-अप की ज़रूरत नहीं। किसी भी AI के पढ़ने से पहले फ़ोन नंबर, खाता नंबर और OTP छुपा दिए जाते हैं, और आपके भेजे लिंक कभी खोले नहीं जाते।",
      },
      {
        q: "अगर मैंने पैसे दे दिए या OTP बता दिया तो?",
        a: "तुरंत 1930 (राष्ट्रीय साइबर अपराध हेल्पलाइन) पर कॉल करें और cybercrime.gov.in पर शिकायत करें। ScamSach आपको पेस्ट करने के लिए तैयार रिपोर्ट टेक्स्ट देता है।",
      },
    ],
    more: "नकली संदेश पहचानना सीखें",
    privacy: "हम आपकी जानकारी कैसे संभालते हैं",
  },
};

export function HomeInfo() {
  const { lang } = useApp();
  const c = CONTENT[lang];
  return (
    <section className="home-info" aria-labelledby="home-info-title">
      <h2 id="home-info-title">{c.title}</h2>
      <dl>
        {c.items.map((i) => (
          <div key={i.q}>
            <dt>{i.q}</dt>
            <dd>{i.a}</dd>
          </div>
        ))}
      </dl>
      <p>
        <Link href="/guide">{c.more}</Link> · <Link href="/privacy">{c.privacy}</Link>
      </p>
    </section>
  );
}
