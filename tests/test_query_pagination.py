# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Verify bounded negative-result pagination and request timeout behavior."""

import json
from collections import deque
from importlib import import_module
from unittest.mock import Mock

import httpx
import pytest
from soar_sdk.auth import StaticTokenAuth

from src import helper
from src.app import Asset

TEST_API_KEY = "test-key"  # pragma: allowlist secret


@pytest.mark.parametrize("controller", ["events", "attributes"])
def test_negative_query_keeps_last_rows_with_bounded_storage(monkeypatch, controller):
    module = import_module("src.actions.run_query")
    requests = []
    buffers = []

    class TrackedDeque(deque):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.peak_size = 0
            buffers.append(self)

        def extend(self, rows):
            super().extend(rows)
            self.peak_size = max(self.peak_size, len(self))

    def handle(request):
        requests.append(request)
        assert request.headers["Authorization"] == "test-key"
        assert request.url.path == f"/{controller}/restSearch"
        payload = json.loads(request.content)
        assert payload["limit"] == 1000
        page = payload["page"]
        assert page in {1, 2, 3}
        start, stop = (page - 1) * 1000, min(page * 1000, 2003)
        rows = [{"id": str(index)} for index in range(start, stop)]
        response = (
            [{"Event": row} for row in rows]
            if controller == "events"
            else {"Attribute": rows}
        )
        return httpx.Response(200, json={"response": response})

    asset = Asset(
        base_url="https://misp.example.test",
        api_key=TEST_API_KEY,
        verify_server_cert=True,
    )
    monkeypatch.setattr(module, "deque", TrackedDeque)
    monkeypatch.setattr(
        helper,
        "misp_client",
        lambda _asset: httpx.Client(
            transport=httpx.MockTransport(handle),
            auth=StaticTokenAuth(_asset.api_key, token_type=""),
            timeout=60,
        ),
    )
    soar = Mock()

    result = module.run_query.__wrapped__(
        module.RunQueryParams(controller=controller, max_results=-5), soar, asset
    )

    data = [row.model_dump() for row in result]
    rows = (
        [row["Event"] for row in data]
        if controller == "events"
        else data[0]["Attribute"]
    )
    assert [row["id"] for row in rows] == [str(index) for index in range(1998, 2003)]
    assert soar.set_summary.call_args.args[0].returned_rows == 5
    assert len(requests) == 3
    for request in requests:
        assert request.extensions["timeout"] == {
            "connect": None,
            "read": None,
            "write": None,
            "pool": None,
        }
    assert len(buffers) == 1
    assert buffers[0].maxlen == 5
    assert buffers[0].peak_size == 5


@pytest.mark.parametrize("negative", [False, True])
def test_query_timeout_reaches_http_client(monkeypatch, negative):
    module = import_module("src.actions.run_query")
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json={"response": []})

    monkeypatch.setattr(
        helper,
        "misp_client",
        lambda _asset: httpx.Client(transport=httpx.MockTransport(handle), timeout=60),
    )
    module.run_query.__wrapped__(
        module.RunQueryParams(controller="events", max_results=-5 if negative else 5),
        Mock(),
        Asset(base_url="https://misp.example.test", api_key=TEST_API_KEY),
    )

    assert len(requests) == 1
    expected = None if negative else 60
    assert set(requests[0].extensions["timeout"].values()) == {expected}


def test_other_requests_keep_existing_timeout(monkeypatch):
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json={"version": "2.4.140"})

    monkeypatch.setattr(
        helper,
        "misp_client",
        lambda _asset: httpx.Client(transport=httpx.MockTransport(handle), timeout=60),
    )
    helper.request(
        Asset(base_url="https://misp.example.test", api_key=TEST_API_KEY),
        "GET",
        "/servers/getPyMISPVersion.json",
    )

    assert set(requests[0].extensions["timeout"].values()) == {60}


@pytest.mark.parametrize("last_page_short", [False, True])
def test_negative_query_retains_100_page_limit(monkeypatch, last_page_short):
    module = import_module("src.actions.run_query")
    batch = [{"id": str(index)} for index in range(1000)]

    def request(_asset, _method, _endpoint, *, payload, timeout):
        assert timeout is None
        return batch[:3] if last_page_short and payload["page"] == 100 else batch

    mocked = Mock(side_effect=request)
    monkeypatch.setattr(module, "request", mocked)
    params = module.RunQueryParams(controller="attributes", max_results=-5)

    if last_page_short:
        result = module.run_query.__wrapped__(params, Mock(), Mock())
        assert [row["id"] for row in result[0].model_dump()["Attribute"]] == [
            "998",
            "999",
            "0",
            "1",
            "2",
        ]
    else:
        with pytest.raises(RuntimeError, match="maximum of 100 pages"):
            module.run_query.__wrapped__(params, Mock(), Mock())

    assert mocked.call_count == 100
    assert [call.kwargs["payload"]["page"] for call in mocked.call_args_list] == list(
        range(1, 101)
    )
