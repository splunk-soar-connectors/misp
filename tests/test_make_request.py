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

import json
from contextlib import nullcontext
from importlib import import_module
from unittest.mock import Mock

import httpx
import pytest
from soar_sdk.app import App

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
    monkeypatch.setattr(
        action_module, "misp_client", lambda _asset: nullcontext(client)
    )

    params = action_module.MakeRequestParams(
        endpoint="/servers/getPyMISPVersion.json?shared=url-a&shared=url-b&url_only=1",
        method="GET",
        query_params='{"shared":"input","input_only":"2"}',
    )
    asset = Asset(
        base_url="https://misp.example.test",
        api_key="test-api-key",  # pragma: allowlist secret
        verify_server_cert=True,
    )

    result = action_module.make_request.__wrapped__(params, None, asset)

    assert result.status_code == 200
    assert {
        key: client.request_url.params.get_list(key)
        for key in client.request_url.params
    } == {
        "shared": ["url-a", "url-b", "input"],
        "url_only": ["1"],
        "input_only": ["2"],
    }
    assert "params" not in client.request_kwargs


@pytest.mark.parametrize(
    "inputs",
    [{}, {"payload": "null"}, {"query_params": "null"}],
    ids=["omitted", "null-body", "null-query-parameters"],
)
def test_make_request_treats_json_null_as_omitted(monkeypatch, inputs):
    action_module = import_module("src.actions.make_request")
    handle = Mock(return_value=httpx.Response(200, json={}))
    transport = httpx.MockTransport(handle)
    monkeypatch.setattr(
        action_module, "misp_client", lambda _asset: httpx.Client(transport=transport)
    )
    params = action_module.MakeRequestParams(
        endpoint="/events/restSearch?existing=1", method="POST", **inputs
    )
    asset = Asset(base_url="https://misp.example.test", api_key="fixture-key")

    result = action_module.make_request.__wrapped__(params, None, asset)

    assert result.status_code == 200
    handle.assert_called_once()
    request = handle.call_args.args[0]
    assert request.content == b""
    assert "Content-Type" not in request.headers
    assert request.url.params.multi_items() == [("existing", "1")]


def test_make_request_returns_http_403_as_successful_soar_output(monkeypatch):
    action_module = import_module("src.actions.make_request")
    body = {"message": "Forbidden"}
    client = Mock()
    client.request.return_value = httpx.Response(403, json=body)
    monkeypatch.setattr(
        action_module, "misp_client", lambda _asset: nullcontext(client)
    )
    params = action_module.MakeRequestParams(
        endpoint="/servers/getPyMISPVersion.json", method="GET"
    )
    asset = Asset(
        base_url="https://misp.example.test",
        api_key="test-api-key",  # pragma: allowlist secret
        verify_server_cert=True,
    )

    output = action_module.make_request.__wrapped__(params, None, asset)
    manager = Mock()

    assert App._adapt_action_result(output, manager, params) is True
    manager.add_result.assert_called_once()
    result = manager.add_result.call_args.args[0]
    assert result.get_status() is True
    (row,) = result.get_data()
    assert row["status_code"] == 403
    assert json.loads(row["response"]) == body
