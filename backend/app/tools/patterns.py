"""Rule-based recognition of common Indian scam patterns in English, Hindi
(Devanagari) and Hinglish. Deterministic, explainable and free to run, so
it always works even when every LLM quota is used up.

Each rule has a weight. Rules marked ``hard`` describe something no genuine
organisation ever asks for (e.g. "enter your UPI PIN to receive money"); a
hard hit alone is enough for a "scam" verdict.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    scam_type: str | None
    weight: int
    title_en: str
    title_hi: str
    patterns: tuple[str, ...]
    hard: bool = False


def _rx(*parts: str) -> tuple[str, ...]:
    return parts


RULES: tuple[Rule, ...] = (
    # ---------- Scam types ------------------------------------------------
    Rule(
        "kyc_expiry",
        "kyc",
        30,
        "KYC / PAN update threat",
        "KYC / PAN अपडेट की धमकी",
        _rx(
            r"\bkyc\b",
            r"\be-?kyc\b",
            r"\bpan\s*(card)?\s*(update|link|expired?|block)",
            r"(account|a/c|khata|yono|net\s?banking).{0,40}(block|suspend|deactivat|band|freeze|expire|close)",
            r"केवाईसी",
            r"खाता.{0,20}(बंद|ब्लॉक)",
            r"kyc\s*(update|pending|expired?)",
        ),
    ),
    Rule(
        "electricity",
        "electricity",
        30,
        "Electricity disconnection threat",
        "बिजली काटने की धमकी",
        _rx(
            r"electric(ity)?.{0,60}(disconnect|cut|off|band)",
            r"(power|light|bijli).{0,40}(disconnect|cut|kat|band)",
            r"बिजली.{0,40}(काट|कट|बंद)",
            r"electricity\s*(office|officer|department)",
            r"previous\s*month\s*bill\s*(was\s*)?not\s*(been\s*)?update",
            r"bijli\s*(ka\s*)?bill",
        ),
    ),
    Rule(
        "digital_arrest",
        "digital_arrest",
        45,
        "'Digital arrest' / fake police or agency threat",
        "'डिजिटल अरेस्ट' / नकली पुलिस या एजेंसी की धमकी",
        _rx(
            r"digital\s*arrest",
            r"डिजिटल\s*अरेस्ट",
            r"arrest\s*warrant",
            r"money\s*launder",
            r"\b(cbi|ncb|ed|narcotics|crime\s*branch|cyber\s*cell)\b.{0,80}(case|arrest|warrant|investigat|parcel|drug)",
            r"(parcel|package).{0,60}(drugs?|narcotics|mdma|illegal)",
            r"गिरफ्तार",
            r"skype.{0,30}(statement|verification|police)",
            r"video\s*call.{0,40}(police|officer|cbi|statement)",
            r"\b(trai|dot|telecom\s*department)\b.{0,80}(disconnect|block|suspend|illegal)",
            r"illegal\s*activit",
            r"मनी\s*लॉन्ड्रिंग",
        ),
        hard=True,
    ),
    Rule(
        "job_task",
        "job_task",
        40,
        "Part-time job / online task offer",
        "पार्ट-टाइम जॉब / ऑनलाइन टास्क का लालच",
        _rx(
            r"part[\s-]?time\s*(job|work)",
            r"work\s*from\s*home.{0,60}(earn|daily|salary|₹|rs)",
            r"(like|subscribe|rate|review).{0,40}(videos?|hotels?|products?).{0,60}(earn|₹|rs|paid|income)",
            r"(earn|kamao|kamaye|income).{0,30}(₹|rs\.?|inr)\s?\d[\d,]*.{0,20}(daily|per\s*day|roz|rozana|din)",
            r"ghar\s*baithe",
            r"घर\s*बैठे",
            r"prepaid\s*task",
            r"telegram.{0,40}(task|job|group)",
            r"(daily|per\s*day)\s*(income|earning)",
            r"simple\s*task",
        ),
    ),
    Rule(
        "courier",
        "courier",
        30,
        "Courier / parcel / customs hold",
        "कूरियर / पार्सल / कस्टम्स में रुका सामान",
        _rx(
            r"(parcel|package|courier|shipment|consignment).{0,60}(held|hold|stuck|ruka|return|undeliver|pending|customs|address)",
            r"customs\s*(duty|clearance|fee|charge)",
            r"(address|pata).{0,30}(incomplete|incorrect|galat|update)",
            r"पार्सल",
            r"कूरियर",
            r"india\s*post.{0,60}(address|delivery|fail|hold)",
        ),
    ),
    Rule(
        "traffic_challan",
        "traffic_challan",
        30,
        "Traffic challan payment demand",
        "ट्रैफिक चालान भुगतान की मांग",
        _rx(r"challan", r"चालान", r"traffic\s*(violation|fine|offen[cs]e)", r"\be-?challan\b", r"(vehicle|gaadi|vahan).{0,40}(fine|penalty|jurmana)"),
    ),
    Rule(
        "refund",
        "refund",
        25,
        "Refund / cashback bait",
        "रिफंड / कैशबैक का लालच",
        _rx(
            r"refund",
            r"cash\s*back",
            r"रिफंड",
            r"income\s*tax.{0,30}(refund|return)",
            r"(excess|extra)\s*(payment|amount).{0,30}(return|refund|wapas)",
        ),
    ),
    Rule(
        "upi_collect",
        "upi_collect",
        60,
        "Asks for UPI PIN to 'receive' money",
        "पैसे 'पाने' के लिए UPI PIN मांगना",
        _rx(
            r"(receive|get|credit|claim|accept|paane|milega|lene).{0,60}(upi\s*)?pin",
            r"(enter|daal|dalo|daalein|type).{0,25}(upi\s*)?pin.{0,60}(receive|get|credit|claim|refund|cashback|paise)",
            r"(approve|accept).{0,40}(collect|request).{0,60}(receive|get|credit|refund|cashback|prize)",
            r"पैसे.{0,30}(पाने|लेने).{0,40}पिन",
            r"collect\s*request",
        ),
        hard=True,
    ),
    Rule(
        "lottery",
        "lottery",
        35,
        "Lottery / prize / lucky draw",
        "लॉटरी / इनाम / लकी ड्रॉ",
        _rx(
            r"lottery",
            r"lucky\s*draw",
            r"(you\s*have\s*)?won.{0,40}(₹|rs|prize|car|lakh|crore|reward)",
            r"\bkbc\b",
            r"लॉटरी",
            r"इनाम",
            r"jackpot",
            r"prize\s*money",
            r"(win|jeet|jeeto).{0,30}(iphone|car|bike|prize|gift|scooty|cash)",
            r"spin\s*(the\s*)?wheel",
        ),
    ),
    Rule(
        "investment",
        "investment",
        40,
        "Guaranteed-profit investment / trading tips",
        "पक्का मुनाफ़ा / ट्रेडिंग टिप्स",
        _rx(
            r"guaranteed\s*(return|profit|income)",
            r"double\s*(your\s*)?money",
            r"paisa\s*double",
            r"(stock|share|ipo|crypto|trading).{0,40}(tips|group|profit|returns?)",
            r"\d{2,3}\s*%\s*(daily|weekly|monthly|return|profit)",
            r"(vip|premium).{0,20}(trading|stock).{0,10}group",
        ),
    ),
    Rule(
        "loan",
        "loan",
        30,
        "Instant loan offer with upfront fee",
        "पहले फीस लेकर तुरंत लोन का ऑफ़र",
        _rx(
            r"(instant|pre-?approved|easy)\s*loan",
            r"loan.{0,40}(approved|sanction).{0,40}(fee|charge|pay)",
            r"(fee|charge).{0,40}(receive|release|disburse).{0,20}(fund|loan|amount)",
            r"लोन\s*(मंजूर|अप्रूव)",
        ),
    ),
    Rule(
        "family_impersonation",
        "impersonation",
        30,
        "Claims to be family/friend on a new number",
        "नए नंबर से परिवार/दोस्त होने का दावा",
        _rx(
            r"(this\s*is\s*my\s*new\s*number|new\s*number\s*hai|naya\s*number)",
            r"(mom|mum|papa|dad|mummy|beta|uncle|aunty).{0,60}(urgent|emergency|hospital|send|bhej)",
            r"(phone|mobile)\s*(kho|lost|broke|toot)",
        ),
    ),
    # ---------- Generic manipulation signals ------------------------------
    Rule(
        "asks_credentials",
        None,
        40,
        "Asks you to share an OTP, PIN, CVV or password",
        "OTP, PIN, CVV या पासवर्ड बताने को कहना",
        _rx(
            r"(share|send|tell|forward|batao|bataye|bataiye|bhejo|bhejein|provide|give).{0,25}(otp|o\.t\.p|upi\s*pin|\bpin\b|cvv|password|mpin)",
            r"(otp|upi\s*pin|cvv|password|mpin).{0,25}(share|send|batao|bataye|bataiye|bhejo|bhejein|provide|de\s*do|dijiye)",
            r"(ओटीपी|पिन|पासवर्ड).{0,20}(बताएं|बताइए|भेजें|शेयर)",
            r"(update|enter|confirm|verify|submit|share).{0,20}(card|bank|banking|payment|account)\s*(details|info)",
        ),
    ),
    Rule(
        "urgency",
        None,
        10,
        "Creates urgency ('today', 'immediately')",
        "जल्दबाज़ी का दबाव ('आज ही', 'तुरंत')",
        _rx(
            r"\burgent(ly)?\b",
            r"immediately",
            r"within\s*\d+\s*(hours?|hrs|minutes?|mins)",
            r"\btoday\b",
            r"\btonight\b",
            r"last\s*(date|chance|warning|reminder)",
            r"\bturant\b",
            r"\bjaldi\b",
            r"\babhi\b",
            r"तुरंत",
            r"आज\s*(ही|रात)",
            r"जल्दी",
            r"\baaj\s*(hi|raat)\b",
            r"before\s*\d{1,2}\s*(:\d{2})?\s*(am|pm)",
        ),
    ),
    Rule(
        "threat",
        None,
        12,
        "Threatens blocking, legal action or a penalty",
        "ब्लॉक, कानूनी कार्रवाई या जुर्माने की धमकी",
        _rx(
            r"(will\s*be|has\s*been|get)\s*(blocked|suspended|disconnected|deactivated|cancelled|terminated)",
            r"legal\s*action",
            r"\bfir\b",
            r"penalty",
            r"band\s*ho\s*(jayega|jaega|jaayega)",
            r"बंद\s*(हो|कर)",
            r"कानूनी\s*कार्रवाई",
            r"jurmana",
            r"जुर्माना",
            r"\bwarna\b",
            r"वरना",
            r"to\s*avoid\s*(suspension|disconnection|penalty|court|legal|arrest|blocking)",
        ),
    ),
    Rule(
        "call_mobile_helpline",
        None,
        15,
        "Asks you to call a personal mobile number as 'customer care'",
        "'कस्टमर केयर' बताकर निजी मोबाइल नंबर पर कॉल करने को कहना",
        _rx(
            r"(call|contact|whatsapp|sampark|कॉल|संपर्क).{0,40}(officer|executive|helpline|customer\s*care|support|department|office|adhikari|अधिकारी|हेल्पलाइन)",
            r"(officer|executive|helpline|customer\s*care|support|adhikari|अधिकारी|हेल्पलाइन|कस्टमर\s*केयर).{0,40}(call|contact|whatsapp|sampark|कॉल|संपर्क|फ़ोन|फोन)",
        ),
    ),
    Rule(
        "click_link",
        None,
        10,
        "Pushes you to click a link to fix a problem",
        "समस्या ठीक करने के लिए लिंक पर क्लिक करवाना",
        _rx(
            r"(click|tap|visit|open|login|log\s*in).{0,30}(link|here|below|url|website)",
            r"(update|verify|complete|link).{0,30}(below|link|here)",
            r"लिंक\s*पर\s*क्लिक",
            r"link\s*(par|pe)\s*click",
        ),
    ),
    Rule(
        "pay_fee",
        None,
        15,
        "Asks for a small fee or payment to release money/goods",
        "पैसा/सामान छुड़ाने के लिए फीस मांगना",
        _rx(
            r"(processing|registration|clearance|delivery|verification|activation|security)\s*(fee|charge|amount)",
            r"\b\d{3,6}\s*(rs|rupees|rupaye|रुपये)?\s*(bhej|bhejo|send|transfer|de\s*do|chahiye)",
            r"(bhej|send|transfer)\s*(do|kar\s*do)?\s*\d{3,6}\b",
            r"(pay|transfer|send|bhejo|jama).{0,30}(₹|rs\.?|inr)\s?\d",
            r"(₹|rs\.?|inr)\s?\d[\d,]*.{0,30}(pay|transfer|bhejo|jama)",
            r"(₹|rs\.?|रु\.?)\s?\d[\d,]*.{0,40}(जमा|भुगतान|भेजें)",
            r"(send|transfer|bhej|pay).{0,40}(this|is|my|mere|ye)\s*(upi|account|a/c|gpay|phonepe|paytm|number)",
        ),
    ),
    Rule(
        "apk_install",
        "malicious_app",
        50,
        "Asks you to install an app file (APK) from a link",
        "लिंक से ऐप फ़ाइल (APK) इंस्टॉल करवाना",
        _rx(r"\.apk\b", r"\bapk\b.{0,40}(download|install|update)", r"(download|install).{0,40}\bapk\b", r"एपीके"),
        hard=True,
    ),
    Rule(
        "remote_access",
        "remote_access",
        45,
        "Asks you to install a screen-sharing app",
        "स्क्रीन-शेयरिंग ऐप इंस्टॉल करवाना",
        _rx(r"anydesk", r"teamviewer", r"quick\s*support", r"rustdesk", r"screen\s*shar"),
        hard=True,
    ),
    Rule(
        "moves_to_group",
        None,
        15,
        "Pulls you into a Telegram/WhatsApp group or private chat",
        "आपको टेलीग्राम/व्हाट्सऐप ग्रुप या निजी चैट में ले जाना",
        _rx(r"(join|add).{0,30}(telegram|whatsapp|group|channel)", r"t\.me/", r"chat\.whatsapp\.com", r"wa\.me/"),
    ),
    Rule(
        "wrong_number_opener",
        "impersonation",
        25,
        "'Wrong number' style opener used to start long scams",
        "'गलत नंबर' वाला शुरुआती संदेश, जिससे लंबे धोखे शुरू होते हैं",
        _rx(
            r"got\s*(your|ur)\s*number\s*from",
            r"(is\s*this|are\s*you)\s+[a-z]+\s*\?.{0,40}(friend|number|remember)",
            r"sorry,?\s*wrong\s*number.{0,40}(but|can\s*we|friends?)",
        ),
    ),
    Rule(
        "prompt_injection",
        None,
        25,
        "Contains hidden instructions aimed at AI checkers",
        "AI जांच को धोखा देने वाले छिपे निर्देश",
        _rx(
            r"ignore\s*(all\s*)?(previous|prior|above)\s*instructions",
            r"(classify|mark|label)\s*(this|it)\s*as\s*(safe|genuine|legit)",
            r"you\s*are\s*(an?\s*)?(ai|assistant|language\s*model)",
            r"system\s*prompt",
        ),
    ),
)

# Signals that point towards a genuine transactional message.
GENUINE_RULES: tuple[Rule, ...] = (
    Rule(
        "otp_delivery",
        None,
        -25,
        "Looks like a normal OTP message that warns you not to share it",
        "सामान्य OTP संदेश जैसा, जो इसे किसी को न बताने की चेतावनी देता है",
        _rx(
            r"(do\s*not|don'?t|never)\s*share",
            r"(kisi|kisi\s*ke)\s*(se|saath|sath)?\s*share\s*(na|mat)",
            r"किसी\s*(के\s*साथ|से)?\s*(भी)?\s*(साझा|शेयर)\s*(न|ना|मत)",
        ),
    ),
    Rule(
        "transaction_alert",
        None,
        -20,
        "Looks like a normal debit/credit alert",
        "सामान्य डेबिट/क्रेडिट अलर्ट जैसा",
        _rx(
            r"(debited|credited)\s*(from|to|by|with|in)\s*(your\s*)?(a/?c|account|acct)",
            r"(avl|available)\.?\s*bal",
            r"a/?c\s*(no\.?\s*)?x{2,}\d{3,4}",
            r"(not\s*you|if\s*not\s*done\s*by\s*you)",
        ),
    ),
    Rule(
        "delivery_update",
        None,
        -10,
        "Looks like a normal order/delivery update",
        "सामान्य ऑर्डर/डिलीवरी अपडेट जैसा",
        _rx(r"(your\s*)?order.{0,40}(shipped|delivered|out\s*for\s*delivery|dispatched)", r"arriving\s*(today|tomorrow)"),
    ),
)

SCAM_TYPE_LABELS: dict[str, tuple[str, str]] = {
    "kyc": ("KYC / account-block scam", "KYC / खाता बंद करने वाला धोखा"),
    "electricity": ("Electricity disconnection scam", "बिजली कटने वाला धोखा"),
    "digital_arrest": ("'Digital arrest' scam", "'डिजिटल अरेस्ट' धोखा"),
    "job_task": ("Part-time job / task scam", "पार्ट-टाइम जॉब / टास्क धोखा"),
    "courier": ("Courier / parcel scam", "कूरियर / पार्सल धोखा"),
    "traffic_challan": ("Fake traffic challan", "नकली ट्रैफिक चालान"),
    "refund": ("Refund / cashback scam", "रिफंड / कैशबैक धोखा"),
    "upi_collect": ("UPI collect-request scam", "UPI कलेक्ट-रिक्वेस्ट धोखा"),
    "lottery": ("Lottery / prize scam", "लॉटरी / इनाम धोखा"),
    "investment": ("Investment / trading scam", "निवेश / ट्रेडिंग धोखा"),
    "loan": ("Loan app scam", "लोन ऐप धोखा"),
    "impersonation": ("Impersonation (fake family/friend)", "पहचान बदलकर धोखा (नकली रिश्तेदार/दोस्त)"),
    "malicious_app": ("Malicious app (APK) scam", "खतरनाक ऐप (APK) धोखा"),
    "remote_access": ("Screen-sharing / remote-access scam", "स्क्रीन-शेयरिंग धोखा"),
    "phishing": ("Phishing link", "फ़िशिंग लिंक"),
    "other": ("Other suspicious message", "अन्य संदिग्ध संदेश"),
    "none": ("No scam pattern found", "कोई धोखे का पैटर्न नहीं मिला"),
}


@dataclass
class PatternHit:
    rule_id: str
    scam_type: str | None
    weight: int
    title_en: str
    title_hi: str
    hard: bool
    evidence: str  # the short matched phrase


_COMPILED = [(r, [re.compile(p, re.IGNORECASE) for p in r.patterns]) for r in RULES + GENUINE_RULES]


def scan_patterns(text: str) -> list[PatternHit]:
    """Return every rule that matches, with the phrase that triggered it."""
    hits: list[PatternHit] = []
    for rule, regexes in _COMPILED:
        for rx in regexes:
            m = rx.search(text)
            if m:
                phrase = m.group(0).strip()
                hits.append(PatternHit(rule.id, rule.scam_type, rule.weight, rule.title_en, rule.title_hi, rule.hard, phrase[:60]))
                break
    ids = {h.rule_id for h in hits}
    # "Do not share your OTP" also matches "share ... OTP": the warning wins.
    if "otp_delivery" in ids and "asks_credentials" in ids:
        hits = [h for h in hits if h.rule_id != "asks_credentials"]
    return hits


def primary_scam_type(hits: list[PatternHit]) -> str | None:
    typed = [h for h in hits if h.scam_type and h.weight > 0]
    if not typed:
        return None
    return max(typed, key=lambda h: (h.hard, h.weight)).scam_type
