"""
http_client.py
Thin wrapper around `requests` for POSTing events to the Spring Boot API.

Improvements over a bare requests.post() call:
- A pooled Session with automatic retry/backoff on transient failures
  (connection errors, 502/503/504) so a flaky local server doesn't kill
  a long simulation run.
- Dry-run mode that skips the network call entirely but still returns a
  result object, so simulator.py doesn't need scenario-specific branches.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class SendResult:
    ok: bool
    status_code: Optional[int]
    error: Optional[str]
    dry_run: bool = False


class EventClient:
    def __init__(self, base_url: str, timeout: float = 5.0, max_retries: int = 3, dry_run: bool = False):
        self.timeout = timeout
        self.dry_run = dry_run
        self.session = requests.Session()

        retry = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[502, 503, 504],
            allowed_methods=["POST"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def send_event(self, url: str, event: Dict) -> SendResult:
        if self.dry_run:
            return SendResult(ok=True, status_code=None, error=None, dry_run=True)

        try:
            resp = self.session.post(url, json=event, timeout=self.timeout)
            if 200 <= resp.status_code < 300:
                return SendResult(ok=True, status_code=resp.status_code, error=None)
            return SendResult(
                ok=False,
                status_code=resp.status_code,
                error=f"HTTP {resp.status_code}: {resp.text[:200]}",
            )
        except requests.exceptions.RequestException as exc:
            return SendResult(ok=False, status_code=None, error=str(exc))

    def close(self) -> None:
        self.session.close()
