"""Network tools, tested against mocked HTTP (respx): fast, free, offline."""

import socket

import httpx
import pytest
import respx

from app.tools import threat_intel
from app.tools.url_expand import UnsafeTarget, expand_shortlink

pytestmark = pytest.mark.asyncio


@pytest.fixture
def public_dns(monkeypatch):
    """Pretend every hostname resolves to a public IP."""

    async def fake_getaddrinfo(self, host, port, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr("asyncio.base_events.BaseEventLoop.getaddrinfo", fake_getaddrinfo)


@respx.mock
async def test_expand_follows_shortener_but_never_visits_destination(public_dns):
    respx.head("https://bit.ly/abc").mock(return_value=httpx.Response(301, headers={"location": "https://tinyurl.com/x"}))
    respx.head("https://tinyurl.com/x").mock(return_value=httpx.Response(302, headers={"location": "https://sbi-kyc.xyz/login?id=777"}))
    final = respx.route(host="sbi-kyc.xyz").mock(return_value=httpx.Response(200))
    res = await expand_shortlink("https://bit.ly/abc")
    assert res.final_url == "https://sbi-kyc.xyz/login?id=777"
    assert len(res.chain) == 3
    assert not final.called  # the scam site itself is never contacted


@respx.mock
async def test_expand_falls_back_to_get_without_reading_body(public_dns):
    respx.head("https://bit.ly/g").mock(return_value=httpx.Response(405))
    respx.get("https://bit.ly/g").mock(return_value=httpx.Response(301, headers={"location": "https://evil.top/"}))
    res = await expand_shortlink("https://bit.ly/g")
    assert res.final_url == "https://evil.top/"


async def test_expand_blocks_private_addresses(monkeypatch):
    async def private(self, host, port, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]

    monkeypatch.setattr("asyncio.base_events.BaseEventLoop.getaddrinfo", private)
    with pytest.raises(UnsafeTarget):
        await expand_shortlink("https://bit.ly/metadata")


async def test_expand_rejects_odd_ports(public_dns):
    with pytest.raises(UnsafeTarget):
        await expand_shortlink("https://bit.ly:8080/x")


@respx.mock
async def test_safe_browsing_match_is_hard_evidence(settings_env):
    settings_env(safe_browsing_api_key="k")
    route = respx.post("https://safebrowsing.googleapis.com/v4/threatMatches:find").mock(
        return_value=httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING", "cacheDuration": "300s"}]})
    )
    f = await threat_intel.safe_browsing("http://evil.example/")
    assert f.signal == "danger" and f.hard
    assert route.calls[0].request.headers["X-Goog-Api-Key"] == "k"
    assert "key=" not in str(route.calls[0].request.url)  # key never in URL (logs)
    await threat_intel.safe_browsing("http://evil.example/")
    assert route.call_count == 1  # second call served from cache


async def test_missing_key_means_skipped():
    f = await threat_intel.safe_browsing("http://x.example/")
    assert f.signal == "skipped"


@respx.mock
async def test_urlhaus_listed(settings_env):
    settings_env(urlhaus_auth_key="k")
    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
        return_value=httpx.Response(200, json={"query_status": "ok", "url_status": "online", "threat": "malware_download"})
    )
    f = await threat_intel.urlhaus("http://bad.example/a.apk", "bad.example")
    assert f.signal == "danger" and f.hard


@respx.mock
async def test_virustotal_respects_quota(settings_env):
    settings_env(virustotal_api_key="k", virustotal_per_minute=1)
    respx.get(url__regex=r"https://www.virustotal.com/api/v3/urls/.*").mock(
        return_value=httpx.Response(
            200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 10}}}}
        )
    )
    first = await threat_intel.virustotal("http://a.example/", "a.example")
    second = await threat_intel.virustotal("http://b.example/", "b.example")
    assert first.signal == "danger"
    assert second.signal == "skipped"  # 1 per minute budget used


@respx.mock
async def test_domain_age_new_domain():
    respx.get("https://rdap.org/domain/new-scam.xyz").mock(
        return_value=httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": "2099-01-01T00:00:00Z"}]})
    )
    f = await threat_intel.domain_age("new-scam.xyz")
    assert f.signal == "danger" and f.weight >= 30


@respx.mock
async def test_domain_age_not_found():
    respx.get("https://rdap.org/domain/ghost.top").mock(return_value=httpx.Response(404))
    f = await threat_intel.domain_age("ghost.top")
    assert f.signal == "warning"
