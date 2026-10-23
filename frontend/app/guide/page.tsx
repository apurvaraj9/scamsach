"use client";

import Link from "next/link";
import { useApp } from "@/lib/app-context";

// Facts here were checked against TRAI's 2025 SMS header rules, RBI's .bank.in
// rule and the official e-Challan site. Keep wording cautious: a genuine-looking
// sign is a good sign, never proof.
const CONTENT = {
  en: {
    title: "How to tell a real message from a fake one",
    intro: "Scammers copy logos, names and even your real vehicle or account details. These checks help, but when in doubt, check it yourself through the official app or website, never through the message.",
    sections: [
      {
        h: "Who sent the SMS?",
        items: [
          "Banks, companies and government offices send SMS from a sender name like VM-HDFCBK-T, not from a normal 10-digit mobile number.",
          "Since May 2025 the last letter shows the type of message: -T for transactions such as OTPs and bank alerts, -S for service updates, -P for offers and ads, -G for government.",
          "A bank \"alert\" from a 10-digit mobile number or a WhatsApp number is a strong warning sign.",
          "A correct-looking sender name is a good sign, but not proof. Never act on a link inside any message.",
        ],
      },
      {
        h: "Read the web address carefully",
        items: [
          "Indian bank websites are moving to addresses that end in .bank.in, as the RBI requires.",
          "Government websites end in .gov.in or .nic.in. A site that only looks old or official is not proof.",
          "Look at the end of the address, just before the first single slash: sbi.co.in.kyc-update.xyz/login ends with kyc-update.xyz, so that is the real owner, not SBI.",
          "Look for spelling tricks such as hdfcbnak, paytrn or amaz0n, and for short links like bit.ly that hide the address.",
        ],
      },
      {
        h: "On WhatsApp",
        items: [
          "Verified businesses show a verification tick next to their name. A company logo as the profile photo proves nothing.",
          "Police, courts and customs do not send notices or demand payments on WhatsApp.",
          "Some banks offer WhatsApp banking, but only from their verified account, and never ask for your OTP or PIN there.",
        ],
      },
    ],
    whereTitle: "Where to check things yourself",
    where: [
      ["Traffic challan", "echallan.parivahan.gov.in (type your vehicle number yourself)", "https://echallan.parivahan.gov.in"],
      ["Parcel or courier", "the courier's own app or website; India Post: indiapost.gov.in", "https://www.indiapost.gov.in"],
      ["Electricity bill", "your electricity company's official app or your printed bill", ""],
      ["Bank account or KYC", "your bank's app, your branch, or the number printed on your card", ""],
      ["Report a fraud SMS, call or WhatsApp", "Chakshu on Sanchar Saathi", "https://sancharsaathi.gov.in/sfc/"],
      ["Lost money", "call 1930 at once and file at cybercrime.gov.in", "https://cybercrime.gov.in"],
    ],
    rulesTitle: "Rules that are always true",
    rules: [
      "No bank, company or government office will ever ask for your OTP, UPI PIN, CVV or password.",
      "You never need to enter a PIN to receive money. A PIN always sends money.",
      "There is no \"digital arrest\". Police never arrest anyone on a video call.",
      "Real jobs never ask you to pay a fee.",
      "Hurry and fear (\"today\", \"tonight\", \"or else\") are the scammer's main tools. Slow down and ask someone you trust.",
    ],
    cta: "Check a message now",
  },
  hi: {
    title: "असली और नकली संदेश में फ़र्क कैसे करें",
    intro: "धोखेबाज़ लोगो, नाम और कभी-कभी आपकी असली गाड़ी या खाते की जानकारी भी कॉपी कर लेते हैं। ये जांचें मदद करती हैं, लेकिन शक हो तो संदेश से नहीं, आधिकारिक ऐप या वेबसाइट से खुद जांचें।",
    sections: [
      {
        h: "SMS किसने भेजा?",
        items: [
          "बैंक, कंपनियां और सरकारी दफ़्तर VM-HDFCBK-T जैसे भेजने वाले नाम से SMS भेजते हैं, किसी सामान्य 10 अंकों वाले मोबाइल नंबर से नहीं।",
          "मई 2025 से आखिरी अक्षर संदेश का प्रकार बताता है: -T लेन-देन (जैसे OTP और बैंक अलर्ट), -S सेवा से जुड़ी जानकारी, -P ऑफ़र और विज्ञापन, -G सरकार।",
          "10 अंकों वाले मोबाइल नंबर या WhatsApp नंबर से आया बैंक \"अलर्ट\" खतरे का बड़ा संकेत है।",
          "सही दिखने वाला भेजने वाला नाम अच्छा संकेत है, लेकिन सबूत नहीं। किसी भी संदेश के लिंक पर भरोसा न करें।",
        ],
      },
      {
        h: "वेब पता ध्यान से पढ़ें",
        items: [
          "RBI के नियम के अनुसार भारतीय बैंकों की वेबसाइट अब .bank.in पर खत्म होने वाले पतों पर जा रही हैं।",
          "सरकारी वेबसाइट .gov.in या .nic.in पर खत्म होती हैं। साइट का पुराना या सरकारी जैसा दिखना कोई सबूत नहीं है।",
          "पते का आखिरी हिस्सा देखें, पहले अकेले स्लैश (/) से ठीक पहले: sbi.co.in.kyc-update.xyz/login का आखिरी हिस्सा kyc-update.xyz है, यही असली मालिक है, SBI नहीं।",
          "hdfcbnak, paytrn या amaz0n जैसी स्पेलिंग की चालाकियों और bit.ly जैसे छोटे लिंक से सावधान रहें, जो असली पता छुपाते हैं।",
        ],
      },
      {
        h: "WhatsApp पर",
        items: [
          "वेरिफ़ाइड बिज़नेस के नाम के पास वेरिफ़िकेशन का निशान होता है। प्रोफ़ाइल फ़ोटो में कंपनी का लोगो कुछ साबित नहीं करता।",
          "पुलिस, कोर्ट और कस्टम्स WhatsApp पर नोटिस नहीं भेजते और भुगतान नहीं मांगते।",
          "कुछ बैंक WhatsApp बैंकिंग देते हैं, लेकिन सिर्फ़ अपने वेरिफ़ाइड अकाउंट से, और वहाँ भी कभी OTP या PIN नहीं मांगते।",
        ],
      },
    ],
    whereTitle: "खुद कहाँ जांचें",
    where: [
      ["ट्रैफिक चालान", "echallan.parivahan.gov.in (गाड़ी का नंबर खुद डालें)", "https://echallan.parivahan.gov.in"],
      ["पार्सल या कूरियर", "कूरियर का अपना ऐप या वेबसाइट; इंडिया पोस्ट: indiapost.gov.in", "https://www.indiapost.gov.in"],
      ["बिजली का बिल", "बिजली कंपनी का आधिकारिक ऐप या छपा हुआ बिल", ""],
      ["बैंक खाता या KYC", "बैंक का ऐप, आपकी ब्रांच, या कार्ड पर छपा नंबर", ""],
      ["धोखे वाला SMS, कॉल या WhatsApp रिपोर्ट करें", "संचार साथी पर चक्षु", "https://sancharsaathi.gov.in/sfc/"],
      ["पैसे चले गए", "तुरंत 1930 पर कॉल करें और cybercrime.gov.in पर शिकायत करें", "https://cybercrime.gov.in"],
    ],
    rulesTitle: "ये बातें हमेशा सच हैं",
    rules: [
      "कोई भी बैंक, कंपनी या सरकारी दफ़्तर कभी आपका OTP, UPI PIN, CVV या पासवर्ड नहीं मांगेगा।",
      "पैसे पाने के लिए कभी PIN नहीं डालना पड़ता। PIN डालने से हमेशा पैसे जाते हैं।",
      "\"डिजिटल अरेस्ट\" जैसा कुछ नहीं होता। पुलिस वीडियो कॉल पर किसी को गिरफ्तार नहीं करती।",
      "असली नौकरी कभी फ़ीस नहीं मांगती।",
      "जल्दबाज़ी और डर (\"आज ही\", \"आज रात\", \"वरना\") धोखेबाज़ के मुख्य हथियार हैं। रुकें और किसी भरोसेमंद व्यक्ति से पूछें।",
    ],
    cta: "अभी कोई संदेश जांचें",
  },
};

export default function GuidePage() {
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
      <section>
        <h2>{c.whereTitle}</h2>
        <dl className="where-list">
          {c.where.map(([what, where, href]) => (
            <div key={what}>
              <dt>{what}</dt>
              <dd>
                {href ? (
                  <a href={href} target="_blank" rel="noopener noreferrer">
                    {where}
                  </a>
                ) : (
                  where
                )}
              </dd>
            </div>
          ))}
        </dl>
      </section>
      <section className="rules">
        <h2>{c.rulesTitle}</h2>
        <ul>
          {c.rules.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      </section>
      <Link href="/" className="btn btn-primary">
        {c.cta}
      </Link>
    </article>
  );
}
