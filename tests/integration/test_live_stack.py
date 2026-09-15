from __future__ import annotations

import os

import pytest

from test_client import run


@pytest.mark.integration
async def test_live_streamable_http_security_flow():
    base_url = os.getenv("GATEWAY_TEST_BASE_URL")
    if not base_url:
        pytest.skip("Set GATEWAY_TEST_BASE_URL to run the Docker-backed live-stack test")
    await run(base_url.rstrip("/"))
