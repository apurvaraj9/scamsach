"""What the user should do next. Deliberately rule-based, not LLM-written:
reporting channels and helpline numbers must always be exactly right.

Reporting channels (India):
- No money lost  -> Chakshu on Sanchar Saathi: https://sancharsaathi.gov.in/sfc/
- Money lost     -> call 1930 immediately and file at https://cybercrime.gov.in
"""

from __future__ import annotations

CHAKSHU_URL = "https://sancharsaathi.gov.in/sfc/"
CYBERCRIME_URL = "https://cybercrime.gov.in"

CHAKSHU_CATEGORY = {
    "kyc": "KYC related (bank / electricity / gas / insurance)",
    "electricity": "KYC related (bank / electricity / gas / insurance)",
    "digital_arrest": "Impersonation as Government official",
    "courier": "Impersonation as Government official / company",
    "traffic_challan": "Impersonation as Government official",
    "job_task": "Online job / lottery / gifts / loan offer",
    "lottery": "Online job / lottery / gifts / loan offer",
    "loan": "Online job / lottery / gifts / loan offer",
    "investment": "Online job / lottery / gifts / loan offer",
    "impersonation": "Impersonation as relative / friend",
    "upi_collect": "Fake customer care / helpline / payment request",
    "refund": "Fake customer care / helpline / payment request",
}


# "Check it the real way": where to verify each kind of claim yourself,
# instead of using anything inside the message.
OFFICIAL_CHECK: dict[str, tuple[str, str, str | None]] = {
    "traffic_challan": (
        "To check for a real challan, open echallan.parivahan.gov.in yourself and type your vehicle number.",
        "असली चालान देखने के लिए खुद echallan.parivahan.gov.in खोलें और अपनी गाड़ी का नंबर डालें।",
        "https://echallan.parivahan.gov.in",
    ),
    "courier": (
        "To track a parcel, use the tracking number from the shop where you ordered, on the courier's own app or "
        "website (India Post: indiapost.gov.in). Customs never asks for fees by SMS or WhatsApp.",
        "पार्सल ट्रैक करने के लिए, जहाँ से ऑर्डर किया उसका ट्रैकिंग नंबर कूरियर के अपने ऐप या वेबसाइट पर डालें "
        "(इंडिया पोस्ट: indiapost.gov.in)। कस्टम्स कभी SMS या WhatsApp पर फ़ीस नहीं मांगता।",
        "https://www.indiapost.gov.in",
    ),
    "electricity": (
        "Check your bill only in your electricity company's official app or website, or on the printed bill. "
        "Power companies never ask you to call a mobile number.",
        "अपना बिल सिर्फ़ बिजली कंपनी के आधिकारिक ऐप/वेबसाइट या छपे हुए बिल पर देखें। बिजली कंपनी कभी मोबाइल नंबर पर कॉल करने को नहीं कहती।",
        None,
    ),
    "kyc": (
        "Real banks do KYC in the branch or inside their own app. Indian bank websites now end in .bank.in.",
        "असली बैंक KYC ब्रांच में या अपने ऐप में करते हैं। भारतीय बैंकों की वेबसाइट अब .bank.in पर खत्म होती है।",
        None,
    ),
    "refund": (
        "Real refunds come back to your account on their own. You never need to share an OTP or PIN to get one.",
        "असली रिफंड अपने-आप खाते में आता है। इसके लिए कभी OTP या PIN बताने की ज़रूरत नहीं होती।",
        None,
    ),
    "upi_collect": (
        "In a UPI app, entering your PIN always SENDS money. You never need a PIN to receive money.",
        "UPI ऐप में PIN डालने से पैसे हमेशा जाते हैं। पैसे पाने के लिए कभी PIN नहीं लगता।",
        None,
    ),
    "job_task": (
        "Real jobs never ask you to pay a fee or do paid 'tasks'. Search the company's official careers page yourself.",
        "असली नौकरी कभी फ़ीस या पैसे वाले 'टास्क' नहीं मांगती। कंपनी का आधिकारिक करियर पेज खुद खोजें।",
        None,
    ),
    "digital_arrest": (
        "There is no such thing as 'digital arrest' in Indian law. Hang up and call 1930 or your local police station.",
        "भारतीय कानून में 'डिजिटल अरेस्ट' जैसा कुछ नहीं होता। कॉल काटें और 1930 या नज़दीकी थाने पर कॉल करें।",
        "tel:1930",
    ),
}


def _step(en: str, hi: str, link: str | None = None) -> dict:
    return {"en": en, "hi": hi, "link": link}


def build_next_steps(verdict: str, scam_type: str, impersonates: str | None, links: list[str], impersonates_category: str | None = None) -> dict:
    """Return steps for both situations; the UI switches between them when the
    user answers 'Did you lose money or share your OTP/PIN?'."""
    who = impersonates or "a trusted organisation"
    link_line = ", ".join(links[:3]) if links else "(no link)"

    if verdict == "likely_safe":
        no_loss = [
            _step("This looks like a normal message, but stay careful.", "यह सामान्य संदेश लगता है, फिर भी सावधान रहें।"),
            _step(
                "Check anything important inside the official app or website, not through links in messages.",
                "कोई भी ज़रूरी बात संदेश के लिंक से नहीं, बल्कि आधिकारिक ऐप या वेबसाइट में जाकर जांचें।",
            ),
            _step(
                "Never share your OTP, UPI PIN or CVV. Real banks never ask for them.",
                "अपना OTP, UPI PIN या CVV कभी किसी को न बताएं। असली बैंक कभी नहीं मांगते।",
            ),
        ]
    else:
        no_loss = [
            _step("Do not click the link, call the number or reply.", "लिंक पर क्लिक न करें, नंबर पर कॉल न करें और जवाब न दें।"),
            _step(
                "Never share OTP, UPI PIN, CVV or passwords. You never need a PIN to RECEIVE money.",
                "OTP, UPI PIN, CVV या पासवर्ड कभी न बताएं। पैसे पाने के लिए कभी PIN नहीं लगता।",
            ),
            *([_step(*OFFICIAL_CHECK[scam_type])] if scam_type in OFFICIAL_CHECK else []),
            _step("Take a screenshot, then block the sender and delete the message.", "स्क्रीनशॉट ले लें, फिर भेजने वाले को ब्लॉक करें और संदेश हटा दें।"),
            _step(
                "Report it on Chakshu (Sanchar Saathi). Use the ready report text below.",
                "इसे चक्षु (संचार साथी) पर रिपोर्ट करें। नीचे दिया तैयार रिपोर्ट टेक्स्ट इस्तेमाल करें।",
                CHAKSHU_URL,
            ),
        ]
        if impersonates and impersonates_category in ("bank", "payments"):
            no_loss.append(
                _step(
                    f"If you are worried about your {impersonates} account, call the number printed on your card or on "
                    "the official website - never the number in this message.",
                    f"अगर आपको अपने {impersonates} खाते की चिंता है, तो कार्ड पर छपे या आधिकारिक वेबसाइट वाले नंबर पर कॉल करें - इस संदेश वाले नंबर पर कभी नहीं।",
                )
            )
        if scam_type == "digital_arrest":
            no_loss.append(
                _step(
                    "Police, CBI or customs never arrest anyone on a video call and never ask for money to 'clear' a case. "
                    "Hang up and tell a family member.",
                    "पुलिस, CBI या कस्टम्स कभी वीडियो कॉल पर गिरफ्तार नहीं करते और केस 'निपटाने' के लिए पैसे नहीं मांगते। कॉल काटें और परिवार को बताएं।",
                )
            )
        if scam_type in ("malicious_app", "remote_access"):
            no_loss.append(
                _step(
                    "If you already installed an app from this message, uninstall it, turn off mobile data and call your bank.",
                    "अगर आपने इस संदेश से कोई ऐप इंस्टॉल कर लिया है, तो उसे हटाएं, मोबाइल डेटा बंद करें और बैंक को कॉल करें।",
                )
            )

    money_lost = [
        _step(
            "Call 1930 right now (National Cyber Crime Helpline). The first few hours matter most to stop the money.",
            "अभी 1930 पर कॉल करें (राष्ट्रीय साइबर अपराध हेल्पलाइन)। पैसा रुकवाने के लिए शुरू के कुछ घंटे सबसे ज़रूरी हैं।",
            "tel:1930",
        ),
        _step(
            "File a complaint at cybercrime.gov.in (Report Cyber Crime > Financial Fraud). Keep the transaction ID "
            "(UTR), amount, date and screenshots ready.",
            "cybercrime.gov.in पर शिकायत दर्ज करें (Report Cyber Crime > Financial Fraud)। ट्रांज़ैक्शन ID (UTR), रकम, तारीख और स्क्रीनशॉट तैयार रखें।",
            CYBERCRIME_URL,
        ),
        _step(
            "Call your bank using the number on your card or official website: block your card/UPI and change your UPI PIN and passwords.",
            "कार्ड पर या आधिकारिक वेबसाइट पर दिए नंबर से बैंक को कॉल करें: कार्ड/UPI ब्लॉक करवाएं और UPI PIN व पासवर्ड बदलें।",
        ),
        _step(
            "If you installed any app or shared your screen, uninstall it and change passwords from another phone.",
            "अगर कोई ऐप इंस्टॉल किया या स्क्रीन शेयर की, तो उसे हटाएं और दूसरे फ़ोन से पासवर्ड बदलें।",
        ),
        _step(
            "Beware of 'recovery agents' who promise to get your money back for a fee - that is another scam.",
            "फ़ीस लेकर पैसा वापस दिलाने का वादा करने वाले 'रिकवरी एजेंट' से बचें - वह भी धोखा है।",
        ),
    ]

    chakshu_text = (
        "Report on Chakshu (Sanchar Saathi) - suspected fraud communication\n"
        "Medium: SMS / WhatsApp / Call  (choose one)\n"
        f"Category (pick the closest): {CHAKSHU_CATEGORY.get(scam_type, 'Others')}\n"
        "Date and time received: [fill in]\n"
        "Sender number / ID: [fill in]\n"
        "Message received:\n{MESSAGE}\n\n"
        f"Description: I received this message pretending to be {who}. It tried to make me click a link, call a "
        f"number, share details or pay money. I did not share any money or details. Suspicious link(s): {link_line}. "
        "Please take action against this sender."
    )
    cybercrime_text = (
        "Complaint for cybercrime.gov.in - Online Financial Fraud\n"
        "Date and time of fraud: [fill in]\n"
        "Amount lost: [fill in]   Payment method: UPI / card / net banking  (choose)\n"
        "Transaction ID / UTR number: [fill in]   Bank: [fill in]\n"
        "Scammer's number / UPI ID / account: [fill in]\n"
        "Message received:\n{MESSAGE}\n\n"
        f"Description: I received the above message pretending to be {who}. Believing it, I [describe what you did, "
        f"e.g. paid money / shared OTP / installed an app]. Suspicious link(s): {link_line}. I request help to freeze "
        "the money and act against the fraudster."
    )
    return {
        "no_loss": {"steps": no_loss, "report_title": "Chakshu report text", "report_text": chakshu_text, "report_url": CHAKSHU_URL},
        "money_lost": {
            "steps": money_lost,
            "report_title": "Cybercrime complaint text",
            "report_text": cybercrime_text,
            "report_url": CYBERCRIME_URL,
        },
    }
