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
"""Tests for MISP's SDK make request action."""

from contextlib import nullcontext
from importlib import import_module

import httpx

from src.app import Asset


def test_make_request_preserves_endpoint_and_input_query_params(monkeypatch):
    """Keep repeated keys and values from both query-parameter sources."""
    action_module = import_module("src.actions.make_request")

    class FakeResponse:
        status_code = 200
        text = '{"version":"test"}'

        @staticmethod
        def json():
            return {"version": "test"}

    class CapturingClient:
        request_url = None

        def request(self, method, url, **kwargs):
            self.request_url = httpx.URL(url)
            self.request_kwargs = {"method": method, **kwargs}
            return FakeResponse()

    client = CapturingClient()
    monkeypatch.setattr(action_module, "misp_client", lambda _asset: nullcontext(client))

    params = action_module.MakeRequestParams(
        endpoint="/servers/getPyMISPVersion.json?shared=url-a&shared=url-b&url_only=1",
        method="GET",
        query_params='{"shared":"input","input_only":"2"}',
    )
    asset = Asset(
        base_url="https://misp.example.test",
        api_key="test-api-key",
        verify_server_cert=True,
    )

    result = action_module.make_request(params, None, asset)

    assert result.status_code == 200
    assert client.request_url.params.multi_items() == [
        ("shared", "url-a"),
        ("shared", "url-b"),
        ("url_only", "1"),
        ("shared", "input"),
        ("input_only", "2"),
    ]
    assert "params" not in client.request_kwargs
