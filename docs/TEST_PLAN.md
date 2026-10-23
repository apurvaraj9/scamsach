# Definition of done: live test plan

The project is **done** when every check below passes on the **live website** (not just locally).
Paste each message exactly as written. "Flagged" means the verdict is *SCAM* or *SUSPICIOUS*.

## A. Messages and expected verdicts

| # | Type | Message to paste | Expected verdict | Must also show |
|---|------|------------------|------------------|----------------|
| T1 | Bank KYC + lookalike link | `Dear Customer, your SBI YONO account will be blocked today. Update your PAN immediately: http://sbi-yono-kyc.xyz/update or call 9876543210` | SCAM | "Pretends to be State Bank of India"; "Hid 1 personal detail" step |
| T2 | Electricity (Hindi) | `प्रिय उपभोक्ता, आपका बिजली बिल अपडेट नहीं हुआ है। आज रात 9:30 बजे आपकी बिजली काट दी जाएगी। तुरंत बिजली अधिकारी 7890123456 से संपर्क करें।` | SCAM | Electricity disconnection threat |
| T3 | Digital arrest | `This is Inspector Sharma from Mumbai Crime Branch. A FedEx parcel booked on your Aadhaar contains MDMA. Join the video call for your statement or an arrest warrant will be issued.` | SCAM | Digital-arrest advice in "What to do now" |
| T4 | Part-time job (Hinglish) | `Hello ji, ghar baithe kamaye Rs 2000-5000 rozana. Bas YouTube videos like karne hai. Telegram join karo: https://t.me/earnfromhome_daily` | Flagged (SCAM expected) | Job / task offer |
| T5 | Parcel via short link | `India Post: Your parcel is held due to incomplete address. Pay Rs 25 redelivery fee within 12 hours: https://bit.ly/indiapost-redeliver` | Flagged | A "short link" step in the log |
| T6 | UPI collect | `Congratulations! You have received Rs 2,500 cashback from PhonePe. Approve the collect request and enter your UPI PIN to receive it.` | SCAM | "Asks for UPI PIN to 'receive' money" |
| T7 | Traffic challan | `Traffic violation detected for your vehicle. Pay e-challan of Rs 500 today to avoid court: http://echallan-parivahan-gov.online/pay` | SCAM | Pretends to be e-Challan (Parivahan) |
| T8 | Live threat-intel proof | `Your account is locked. Verify here: http://testsafebrowsing.appspot.com/s/phishing.html` | SCAM | "Google Safe Browsing lists this link as unsafe" (this is Google's official test page) |
| T9 | Genuine OTP | `Your OTP for login is 482913. Do not share it with anyone. -HDFC Bank` | LIKELY SAFE | The OTP is hidden in the saved case |
| T10 | Genuine debit alert | `Rs.1,250.00 debited from A/c XX4521 on 14-10-26 to VPA swiggy@icici. Not you? Call 18002586161 -SBI` | LIKELY SAFE | |
| T11 | Genuine delivery | `Your Amazon order for Prestige Pressure Cooker has been shipped and will arrive tomorrow. Track: https://amzn.in/d/abc123` | LIKELY SAFE | "Official website of Amazon" |
| T12 | Genuine family (Hindi) | `बेटा, मैं घर पहुँच गया हूँ। फ्री हो तो फ़ोन कर लेना। - पापा` | LIKELY SAFE | |

| T13 | Real-life challan case | `Traffic Police: Red light violation recorded for your vehicle MH12AB1234. Pay challan of Rs 1,000 today to avoid court case: https://echallan-bharat-traffic.in/pay` | SCAM | "Mentions a vehicle number" note; echallan.parivahan.gov.in step |

Pass rule: T1–T8 and T13 all flagged (at least 6 of them exactly SCAM) and T9–T12 all LIKELY SAFE.

## B. Feature checks (live site)

- [ ] **Phone:** open the site on a mobile phone; everything fits, buttons are easy to tap.
- [ ] **Live steps:** the "What we checked" list fills in step by step while checking.
- [ ] **Evidence:** "Evidence and sources" lists each finding with its source.
- [ ] **Money lost:** on a SCAM result, tap **Yes** under "Did you lose money…": the 1930 call button and cybercrime.gov.in steps appear; the report text changes.
- [ ] **Report text:** "Copy text" copies a report that contains your pasted message.
- [ ] **Hindi:** tap हिंदी; verdict, steps and buttons switch to Hindi.
- [ ] **Login:** "Log in with Google" works and returns to "My past checks".
- [ ] **History:** a check done while logged in appears in "My past checks".
- [ ] **Follow-up:** open a past case, ask "I already clicked the link, what should I do?" and get an answer.
- [ ] **Privacy:** in the saved case, phone numbers / OTPs are shown as `[PHONE_1]`, `[OTP_1]`.
- [ ] **Delete:** "Delete this check" removes it from history.
- [ ] **Cache:** checking T1 a second time shows "This exact message was checked recently".
- [ ] **Rate limit:** while logged out, a 6th check within an hour shows a friendly "too many checks" message.
- [ ] **Waking up:** if the backend was asleep, a "Waking up the checker…" banner appears instead of an error.
- [ ] **Feedback:** on any result, tap **No** under "Was this result right?", pick an answer, tick "Share this message", send; a thank-you appears (and a row appears in the Supabase `feedback` table).
- [ ] **Guide:** "How to spot a fake" opens from the header and from a result, in English and Hindi.
- [ ] **Vehicle number:** the real-life challan message (T13 above) is SCAM, the vehicle number shows as `[VEHICLE_1]` in the saved case, and "What to do now" links to echallan.parivahan.gov.in.
- [ ] **Disclaimer:** every result shows the "guidance, not a guarantee" note.
- [ ] **Observability:** the check appears as a trace in Langfuse, with masked text only.
- [ ] **CI:** the latest GitHub Actions run is green.
