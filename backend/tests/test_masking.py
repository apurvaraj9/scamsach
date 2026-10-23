from app.security.masking import mask_any, mask_for_display, mask_text


def test_masks_indian_mobile_account_pan_and_keeps_links():
    r = mask_text("SBI a/c 123456789012 blocked. Call 9876543210. PAN ABCDE1234F. Visit http://sbi-kyc.xyz/update")
    assert "9876543210" not in r.text
    assert "123456789012" not in r.text
    assert "ABCDE1234F" not in r.text
    assert "http://sbi-kyc.xyz/update" in r.text  # scammer's link stays visible to the LLM
    assert r.counts == {"PHONE": 1, "ACCOUNT": 1, "PAN": 1}


def test_masks_otp_card_aadhaar_upi_email():
    r = mask_text("OTP is 482913. Card 4111 1111 1111 1111. Aadhaar 2345 6789 0123. Pay x.y@ybl or mail a.b@gmail.com")
    for secret in ("482913", "4111 1111 1111 1111", "2345 6789 0123", "x.y@ybl", "a.b@gmail.com"):
        assert secret not in r.text
    assert {"OTP", "CARD", "AADHAAR", "UPI", "EMAIL"} <= set(r.counts)


def test_same_number_gets_same_placeholder():
    r = mask_text("Call 98765 43210 now. Again: 9876543210")
    assert r.text.count("[PHONE_1]") == 2
    assert r.counts["PHONE"] == 1


def test_toll_free_and_international_numbers():
    r = mask_text("Genuine: 1800-1234-567. Scammer: +92 300 1234567")
    assert "1800-1234-567" in r.text  # business toll-free numbers are not personal data
    assert "+92 300 1234567" not in r.text


def test_phone_inside_link_query_is_masked():
    r = mask_text("Track: https://trk.example.top/p?ph=9876543210&id=77 and wa.me/919812345678")
    assert "9876543210" not in r.text and "919812345678" not in r.text
    assert "trk.example.top" in r.text


def test_hindi_text_survives():
    r = mask_text("आपका खाता बंद होगा, 9876543210 पर कॉल करें")
    assert "आपका खाता बंद होगा" in r.text and "[PHONE_1]" in r.text


def test_mask_any_recurses():
    out = mask_any({"a": ["call 9876543210"], "b": {"c": "ok"}, "n": 5})
    assert out == {"a": ["call [PHONE_1]"], "b": {"c": "ok"}, "n": 5}


def test_mask_for_display():
    assert mask_for_display("9876543210") == "******3210"


def test_vehicle_numbers_masked_but_not_ordinary_words():
    r = mask_text("Challan for MH12AB1234 and DL 3C AB 1234. This is 12 at 2026.")
    assert "MH12AB1234" not in r.text and "DL 3C AB 1234" not in r.text
    assert "This is 12 at 2026" in r.text and r.counts["VEHICLE"] == 2
