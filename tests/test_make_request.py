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

import httpx2
import pytest
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams

from src.app import app
from src.asset import Asset


@pytest.mark.parametrize(
    "query_parameters",
    [
        '{"shared":["input-a","input-b"],"input_only":"2"}',
        "?shared=input-a&shared=input-b&input_only=2",
    ],
    ids=["json-object", "query-string"],
)
def test_make_request_preserves_endpoint_and_input_query_params(
    monkeypatch, query_parameters
):
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
            self.request_url = httpx2.URL(url)
            self.request_kwargs = {"method": method, **kwargs}
            return FakeResponse()

    client = CapturingClient()
    monkeypatch.setattr(
        action_module, "misp_client", lambda _asset, **_kwargs: nullcontext(client)
    )

    params = MakeRequestParams(
        endpoint="/servers/getPyMISPVersion.json?shared=url-a&shared=url-b&url_only=1",
        http_method="GET",
        query_parameters=query_parameters,
    )
    asset = Asset(
        base_url="https://misp.example.test",
        api_key="test-api-key",  # pragma: allowlist secret
        verify_server_cert=True,
    )

    result = action_module.make_request(params, asset)

    assert result.status_code == 200
    assert {
        key: client.request_url.params.get_list(key)
        for key in client.request_url.params
    } == {
        "shared": ["url-a", "url-b", "input-a", "input-b"],
        "url_only": ["1"],
        "input_only": ["2"],
    }
    assert "params" not in client.request_kwargs


@pytest.mark.parametrize(
    "inputs",
    [{}, {"body": "null"}, {"query_parameters": "null"}],
    ids=["omitted", "null-body", "null-query-parameters"],
)
def test_make_request_treats_json_null_as_omitted(monkeypatch, inputs):
    action_module = import_module("src.actions.make_request")
    handle = Mock(return_value=httpx2.Response(200, json={}))
    transport = httpx2.MockTransport(handle)
    monkeypatch.setattr(
        action_module,
        "misp_client",
        lambda _asset, **_kwargs: httpx2.Client(transport=transport),
    )
    params = MakeRequestParams(
        endpoint="/events/restSearch?existing=1", http_method="POST", **inputs
    )
    asset = Asset(base_url="https://misp.example.test", api_key="fixture-key")

    result = action_module.make_request(params, asset)

    assert result.status_code == 200
    handle.assert_called_once()
    request = handle.call_args.args[0]
    assert request.content == b""
    assert "Content-Type" not in request.headers
    assert request.url.params.multi_items() == [("existing", "1")]


@pytest.mark.parametrize(
    ("http_status", "response_kwargs", "expected_body"),
    [
        (403, {"json": {"message": "Forbidden"}}, '{"message": "Forbidden"}'),
        (404, {"text": "Not found"}, "Not found"),
    ],
)
def test_make_request_returns_http_errors_as_successful_soar_output(
    monkeypatch, http_status, response_kwargs, expected_body
):
    action_module = import_module("src.actions.make_request")
    client = Mock()
    client.request.return_value = httpx2.Response(http_status, **response_kwargs)
    monkeypatch.setattr(
        action_module, "misp_client", lambda _asset, **_kwargs: nullcontext(client)
    )
    add_result = Mock()
    monkeypatch.setattr(app.actions_manager, "add_result", add_result)
    params = {"endpoint": "/servers/getPyMISPVersion.json", "http_method": "GET"}
    asset = Asset(
        base_url="https://misp.example.test",
        api_key="test-api-key",  # pragma: allowlist secret
        verify_server_cert=True,
    )

    action = app.get_actions()["make_request"]
    assert action.params_class is MakeRequestParams
    assert action(params, asset=asset) is True
    add_result.assert_called_once()
    result = add_result.call_args.args[0]
    assert result.get_status() is True
    (row,) = result.get_data()
    assert row == {"status_code": http_status, "response": expected_body}


@pytest.mark.parametrize(
    "verify_ssl", [{}, {"verify_ssl": False}, {"verify_ssl": True}]
)
def test_make_request_applies_native_request_options(monkeypatch, verify_ssl):
    action_module = import_module("src.actions.make_request")
    real_client = httpx2.Client
    handle = Mock(return_value=httpx2.Response(204))
    client = Mock(
        side_effect=lambda **kwargs: real_client(
            transport=httpx2.MockTransport(handle), **kwargs
        )
    )
    monkeypatch.setattr(httpx2, "Client", client)
    params = MakeRequestParams(
        http_method="POST",
        endpoint="/events/restSearch",
        body='{"limit":1}',
        headers='{"X-MISP-Test":"sdk"}',
        timeout=7,
        **verify_ssl,
    )
    asset = Asset(
        base_url="https://misp.example.test",
        api_key="fixture-key",  # pragma: allowlist secret
        verify_server_cert=False,
    )

    result = action_module.make_request(params, asset)

    assert result.status_code == 204
    assert result.response == ""
    assert client.call_args.kwargs["verify"] is verify_ssl.get("verify_ssl", False)
    request = handle.call_args.args[0]
    assert json.loads(request.content) == {"limit": 1}
    assert request.headers["X-MISP-Test"] == "sdk"
    assert request.headers["Authorization"] == asset.api_key
    assert request.extensions["timeout"]["read"] == 7


def test_make_request_transport_failure_raises_action_failure(monkeypatch):
    action_module = import_module("src.actions.make_request")
    client = Mock()
    client.request.side_effect = httpx2.ConnectError("Connection failed")
    monkeypatch.setattr(
        action_module, "misp_client", lambda _asset, **_kwargs: nullcontext(client)
    )
    params = MakeRequestParams(
        http_method="GET", endpoint="/servers/getPyMISPVersion.json"
    )
    asset = Asset(base_url="https://misp.example.test", api_key="fixture-key")

    with pytest.raises(ActionFailure, match="Unable to connect to MISP"):
        action_module.make_request(params, asset)
