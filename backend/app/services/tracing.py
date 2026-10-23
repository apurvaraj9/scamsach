"""Langfuse tracing, optional. If the keys are not set, every helper here
is a no-op, so the app runs identically without an observability account.

Defence in depth: Langfuse's ``mask`` hook runs our PII masker over every
payload, so even if a raw string slipped into a span it would be masked
before leaving the server."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Iterator

from ..config import get_settings
from ..security.masking import mask_any

log = logging.getLogger("scamsach.tracing")
_client: Any = None
_init_done = False


def _get_client() -> Any:
    global _client, _init_done
    if _init_done:
        return _client
    _init_done = True
    s = get_settings()
    if not s.langfuse_enabled:
        return None
    try:
        from langfuse import Langfuse

        _client = Langfuse(
            public_key=s.langfuse_public_key,
            secret_key=s.langfuse_secret_key,
            base_url=s.langfuse_base_url,
            environment=s.environment,
            mask=lambda *, data, **_: mask_any(data),
        )
    except Exception as exc:  # tracing must never break the app
        log.warning("Langfuse disabled: %s", type(exc).__name__)
        _client = None
    return _client


class _NoopSpan:
    def update(self, **_: Any) -> None:
        return None


@contextmanager
def observe(name: str, as_type: str = "span", **kwargs: Any) -> Iterator[Any]:
    client = _get_client()
    if client is None:
        yield _NoopSpan()
        return
    try:
        cm = client.start_as_current_observation(name=name, as_type=as_type, **kwargs)
        span = cm.__enter__()
    except Exception:
        yield _NoopSpan()
        return
    try:
        yield span
    finally:
        try:
            cm.__exit__(None, None, None)
        except Exception:  # noqa: S110 - tracing must never break a request
            pass


def current_trace_id() -> str | None:
    client = _get_client()
    if client is None:
        return None
    try:
        return client.get_current_trace_id()
    except Exception:
        return None


def score_trace(trace_id: str, name: str, value: float, comment: str | None = None) -> bool:
    """Attach a user-feedback score to an agent trace in Langfuse."""
    client = _get_client()
    if client is None or not trace_id:
        return False
    try:
        client.create_score(trace_id=trace_id, name=name, value=value, data_type="NUMERIC", comment=comment)
        return True
    except Exception:
        return False


def flush() -> None:
    client = _get_client()
    if client is not None:
        try:
            client.flush()
        except Exception:  # noqa: S110 - tracing must never break a request
            pass
