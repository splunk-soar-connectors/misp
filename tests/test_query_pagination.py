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
"""Verify bounded query pagination and request timeout behavior."""

import json
from collections import deque
from importlib import import_module
from threading import Event, get_ident
from unittest.mock import Mock

import httpx2
import pytest
from soar_sdk.app import App
from soar_sdk.auth import StaticTokenAuth
from soar_sdk.exceptions import ActionFailure

from src import helper
from src.app import app
from src.asset import Asset

TEST_API_KEY = "test-key"  # pragma: allowlist secret


def _query_rows(result, controller):
    manager = Mock()
    assert App._adapt_action_result(result, manager)
    data = manager.add_result.call_args.args[0].get_data()
    assert len(data) == 1
    return (
        [row["Event"] for row in data[0]]
        if controller == "events"
        else data[0]["Attribute"]
    )


@pytest.mark.parametrize(
    "error",
    [
        None,
        RuntimeError("MISP returned HTTP 403"),
        httpx2.ReadTimeout("Read timed out"),
    ],
    ids=["success", "vendor-error", "http-timeout"],
)
def test_waiting_query_reports_progress_on_action_thread(monkeypatch, error):
    module = import_module("src.actions.run_query")
    action_thread = get_ident()
    started = Event()
    release = Event()
    progress_threads = []
    response = {"response": []}

    def request(_asset, _method, _endpoint, *, payload, timeout):
        assert get_ident() != action_thread
        assert timeout == 60
        started.set()
        assert release.wait(timeout=2), "Request was not released by progress updates"
        if error is not None:
            raise error
        return response

    def progress(*_args):
        assert started.wait(timeout=1)
        progress_threads.append(get_ident())
        if len(progress_threads) == 3:
            release.set()

    monkeypatch.setattr(module, "request", request)
    monkeypatch.setattr(module, "_QUERY_PROGRESS_INTERVAL", 0.01)
    monkeypatch.setattr(module.logger, "progress", progress)

    try:
        if error is None:
            assert module._request_query_page(Mock(), "events", {"page": 1}) is response
        else:
            with pytest.raises(type(error), match=str(error)) as caught:
                module._request_query_page(Mock(), "events", {"page": 1})
            assert caught.value is error
    finally:
        release.set()

    assert progress_threads == [action_thread] * 3


@pytest.mark.parametrize("controller", ["events", "attributes"])
def test_negative_query_keeps_last_rows_with_bounded_storage(monkeypatch, controller):
    module = import_module("src.actions.run_query")
    requests = []
    page_size = 1000
    buffers = []
    progress_at_requests = []
    monkeypatch.setattr(
        module.logger,
        "progress",
        Mock(side_effect=lambda *_args: progress_at_requests.append(len(requests))),
    )

    class TrackedDeque(deque):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.peak_size = 0
            buffers.append(self)

        def extend(self, rows):
            super().extend(rows)
            self.peak_size = max(self.peak_size, len(self))

    def handle(request):
        assert len(requests) in progress_at_requests
        requests.append(request)
        assert request.headers["Authorization"] == "test-key"
        assert request.url.path == f"/{controller}/restSearch"
        payload = json.loads(request.content)
        assert payload["limit"] == page_size
        page = payload["page"]
        assert 1 <= page <= 2003 // page_size + 2
        start, stop = (page - 1) * page_size, min(page * page_size, 2003)
        rows = [{"id": str(index)} for index in range(start, stop)]
        response = (
            [{"Event": row} for row in rows]
            if controller == "events"
            else {"Attribute": rows}
        )
        return httpx2.Response(200, json={"response": response})

    asset = Asset(
        base_url="https://misp.example.test",
        api_key=TEST_API_KEY,
        verify_server_cert=True,
    )
    monkeypatch.setattr(module, "deque", TrackedDeque)
    monkeypatch.setattr(
        helper,
        "misp_client",
        lambda _asset: httpx2.Client(
            transport=httpx2.MockTransport(handle),
            auth=StaticTokenAuth(_asset.api_key, token_type=""),
            timeout=60,
        ),
    )
    soar = Mock()

    result = module.run_query(
        module.RunQueryParams(controller=controller, max_results=-5), soar, asset
    )

    rows = _query_rows(result, controller)
    assert [row["id"] for row in rows] == [str(index) for index in range(1998, 2003)]
    assert soar.set_summary.call_args.args[0].returned_rows == 5
    assert len(requests) == 2003 // page_size + 2
    assert len(requests) in progress_at_requests
    for request in requests:
        assert request.extensions["timeout"] == {
            "connect": 60,
            "read": 60,
            "write": 60,
            "pool": 60,
        }
    assert len(buffers) == 1
    assert buffers[0].maxlen == 5
    assert buffers[0].peak_size == 5


@pytest.mark.parametrize("max_results", [5, -5, 0])
@pytest.mark.parametrize("controller", ["events", "attributes"])
def test_query_timeout_reaches_http_client(monkeypatch, max_results, controller):
    module = import_module("src.actions.run_query")
    requests = []

    def handle(request):
        requests.append(request)
        return httpx2.Response(200, json={"response": []})

    monkeypatch.setattr(
        helper,
        "misp_client",
        lambda _asset: httpx2.Client(
            transport=httpx2.MockTransport(handle), timeout=60
        ),
    )
    module.run_query(
        module.RunQueryParams(controller=controller, max_results=max_results),
        Mock(),
        Asset(base_url="https://misp.example.test", api_key=TEST_API_KEY),
    )

    assert len(requests) == 1
    assert requests[0].extensions["timeout"] == {
        "connect": 60,
        "read": 60,
        "write": 60,
        "pool": 60,
    }


def test_other_requests_keep_existing_timeout(monkeypatch):
    requests = []

    def handle(request):
        requests.append(request)
        return httpx2.Response(200, json={"version": "2.4.140"})

    monkeypatch.setattr(
        helper,
        "misp_client",
        lambda _asset: httpx2.Client(
            transport=httpx2.MockTransport(handle), timeout=60
        ),
    )
    helper.request(
        Asset(base_url="https://misp.example.test", api_key=TEST_API_KEY),
        "GET",
        "/servers/getPyMISPVersion.json",
    )

    assert set(requests[0].extensions["timeout"].values()) == {60}


@pytest.mark.parametrize(
    ("controller", "max_results", "last_page_size"),
    [
        ("attributes", -5, 1000),
        ("attributes", -5, 0),
        ("attributes", 0, 3),
        ("events", -5, 3),
        ("events", -5, 0),
    ],
)
def test_uncapped_queries_retain_100_page_limit(
    monkeypatch, controller, max_results, last_page_size
):
    module = import_module("src.actions.run_query")
    page_size = 1000
    max_pages = 100
    batch = [{"id": str(index)} for index in range(page_size)]

    def request(_asset, _method, _endpoint, *, payload, timeout):
        assert timeout == 60
        assert payload["limit"] == page_size
        return batch[:last_page_size] if payload["page"] == max_pages else batch

    mocked = Mock(side_effect=request)
    monkeypatch.setattr(module, "request", mocked)
    params = module.RunQueryParams(controller=controller, max_results=max_results)

    if last_page_size == 0:
        result = module.run_query(params, Mock(), Mock())
        rows = _query_rows(result, controller)
        assert [row["id"] for row in rows] == [
            str(index) for index in range(page_size - 5, page_size)
        ]
    else:
        with pytest.raises(RuntimeError, match=f"maximum of {max_pages} pages"):
            module.run_query(params, Mock(), Mock())

    assert mocked.call_count == max_pages
    assert [call.kwargs["payload"]["page"] for call in mocked.call_args_list] == list(
        range(1, max_pages + 1)
    )


@pytest.mark.parametrize("controller", ["events", "attributes"])
@pytest.mark.parametrize("first_page_size", [2, 1000])
def test_zero_query_limit_collects_all_pages(monkeypatch, controller, first_page_size):
    module = import_module("src.actions.run_query")

    def request(_asset, _method, endpoint, *, payload, timeout):
        assert endpoint == f"/{controller}/restSearch"
        assert payload["limit"] == 1000
        assert timeout == 60
        page = payload["page"]
        assert page in (1, 2, 3)
        page_sizes = (first_page_size, 2, 0)
        start = sum(page_sizes[: page - 1])
        rows = [
            {"id": str(index)} for index in range(start, start + page_sizes[page - 1])
        ]
        if controller == "events":
            return {"response": [{"Event": row} for row in rows]}
        return {"response": {"Attribute": rows}}

    mocked = Mock(side_effect=request)
    monkeypatch.setattr(module, "request", mocked)
    soar = Mock()

    output = module.run_query(
        module.RunQueryParams(controller=controller, max_results=0), soar, Mock()
    )

    rows = _query_rows(output, controller)
    assert [row["id"] for row in rows] == [
        str(index) for index in range(first_page_size + 2)
    ]
    assert soar.set_summary.call_args.args[0].returned_rows == len(rows)
    assert mocked.call_count == 3


@pytest.mark.parametrize(
    ("other_overrides", "expected_controller"),
    [
        ({}, "events"),
        ({"controller": "attributes"}, "attributes"),
        ({"returnFormat": "json"}, "events"),
    ],
    ids=["events-csv", "attributes-override", "return-format-precedence"],
)
def test_query_csv_preserves_legacy_rows_and_pagination(
    monkeypatch, other_overrides, expected_controller
):
    module = import_module("src.actions.run_query")
    pages = [
        'id,value\r\n1,"example,one"\r\n',
        'id,value\r\n2,"line one\r\nline two"\r\n',
        "id,value\r\n",
    ]
    handle = Mock(
        side_effect=[
            httpx2.Response(200, headers={"Content-Type": "text/csv"}, text=page)
            for page in pages
        ]
    )
    transport = httpx2.MockTransport(handle)
    monkeypatch.setattr(
        module,
        "misp_client",
        lambda asset: httpx2.Client(
            transport=transport, auth=StaticTokenAuth(asset.api_key, token_type="")
        ),
    )
    add_result = Mock()
    monkeypatch.setattr(app.actions_manager, "add_result", add_result)
    params = module.RunQueryParams(
        controller="events",
        max_results=0,
        other=json.dumps(
            {
                "return_format": "csv",
                "pythonify": True,
                "type_attribute": "domain",
                **other_overrides,
            }
        ),
    )
    asset = Asset(base_url="https://misp.example.test", api_key=TEST_API_KEY)
    soar = Mock()

    assert app.get_actions()["run_query"](params, soar=soar, asset=asset) is True

    assert add_result.call_args.args[0].get_data() == [
        [
            {"id": "1", "value": "example,one"},
            {"id": "2", "value": "line one\r\nline two"},
        ]
    ]
    assert soar.set_summary.call_args.args[0].returned_rows == 2
    assert handle.call_count == 3
    for page, call in enumerate(handle.call_args_list, 1):
        request = call.args[0]
        assert request.method == "POST"
        assert request.url.path == f"/{expected_controller}/restSearch"
        assert request.headers["Accept"] == "application/json"
        assert request.headers["Authorization"] == TEST_API_KEY
        assert request.extensions["timeout"]["read"] == 60
        assert json.loads(request.content) == {
            "type": "domain",
            "headerless": 0,
            "returnFormat": "csv",
            "limit": 1000,
            "page": page,
        }


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx2.Response(403, json={"errors": "Forbidden"}), "MISP returned HTTP 403"),
        (
            httpx2.Response(200, json={"errors": "Invalid search"}),
            "invalid CSV response for page 2",
        ),
        (
            httpx2.Response(200, text="id,value\n2,extra,column\n"),
            "invalid CSV response for page 2",
        ),
    ],
    ids=["http-error", "json-error", "malformed-row"],
)
def test_query_csv_rejects_invalid_later_pages(monkeypatch, response, message):
    module = import_module("src.actions.run_query")
    handle = Mock(
        side_effect=[httpx2.Response(200, text="id,value\n1,example.test\n"), response]
    )
    transport = httpx2.MockTransport(handle)
    monkeypatch.setattr(
        module, "misp_client", lambda _asset: httpx2.Client(transport=transport)
    )
    add_result = Mock()
    monkeypatch.setattr(app.actions_manager, "add_result", add_result)
    params = module.RunQueryParams(
        controller="events",
        max_results=0,
        other='{"return_format":"csv","pythonify":true}',
    )
    asset = Asset(base_url="https://misp.example.test", api_key=TEST_API_KEY)

    assert app.get_actions()["run_query"](params, soar=Mock(), asset=asset) is False

    result = add_result.call_args.args[0]
    assert message in result.get_message()
    assert result.get_data() == []


@pytest.mark.parametrize(
    ("other", "message"),
    [
        ({"headerless": True}, "Run Query requires CSV headers"),
        ({"controller": "objects"}, "Object searches require JSON"),
    ],
    ids=["headerless", "objects"],
)
def test_query_rejects_unsupported_csv_options(monkeypatch, other, message):
    module = import_module("src.actions.run_query")
    request_page = Mock()
    monkeypatch.setattr(module, "_request_query_page", request_page)
    params = module.RunQueryParams(
        controller="events",
        other=json.dumps({"return_format": "csv", "pythonify": True, **other}),
    )

    with pytest.raises(ActionFailure, match=message):
        module.run_query(params, Mock(), Mock())

    request_page.assert_not_called()


@pytest.mark.parametrize(
    ("controller", "first_page"),
    [
        ("events", [{"Event": {"id": "42"}}]),
        ("attributes", {"Attribute": [{"id": "123"}]}),
    ],
    ids=["events", "attributes"],
)
@pytest.mark.parametrize(
    "bad_page",
    [{"message": "unexpected page"}, [42]],
    ids=["missing-collection", "invalid-row"],
)
def test_query_fails_on_malformed_second_page(
    monkeypatch, controller, first_page, bad_page
):
    module = import_module("src.actions.run_query")
    request_page = Mock(side_effect=[{"response": first_page}, {"response": bad_page}])
    monkeypatch.setattr(module, "_request_query_page", request_page)
    add_result = Mock()
    monkeypatch.setattr(app.actions_manager, "add_result", add_result)
    soar = Mock()

    success = app.get_actions()["run_query"](
        module.RunQueryParams(controller=controller, max_results=0),
        soar=soar,
        asset=Mock(),
    )

    assert success is False
    result = add_result.call_args.args[0]
    assert result.get_status() is False
    assert (
        f"unexpected search response shape for {controller} page 2"
        in result.get_message()
    )
    assert result.get_data() == []
    soar.set_summary.assert_not_called()
    soar.set_message.assert_not_called()
