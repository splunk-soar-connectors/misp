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
"""Record legacy PyMISP routes and guard the SDK read-action endpoints."""

import json
from importlib import import_module
from io import BytesIO
from unittest.mock import Mock
from urllib.parse import urlparse

import httpx2
import pytest
from pymisp import MISPEvent, PyMISP
from soar_sdk.exceptions import ActionFailure

from src.app import app


def test_pinned_legacy_pymisp_endpoints():
    # Skip transport initialization; record the actual API methods used by legacy.
    client = object.__new__(PyMISP)
    client.root_url = "https://misp.example.test/"
    client.global_pythonify = False
    client._prepare_request = Mock(return_value=[])
    client._check_json_response = lambda response: response
    event = MISPEvent()
    event.from_dict(
        id="42", info="Example", uuid="11111111-1111-4111-8111-111111111111"
    )

    client.add_event(event)
    client.update_event(event)
    client.get_event(42)
    client.search(controller="events", eventid=42)
    client.search(controller="attributes", eventid=42)
    client.tag(event, "example")
    client.untag(event, "example")

    actual = [
        (call.args[0], "/" + urlparse(call.args[1]).path.lstrip("/"))
        for call in client._prepare_request.call_args_list
    ]
    assert actual == [
        ("POST", "/events/add"),
        ("POST", f"/events/edit/{event.uuid}"),
        ("GET", "/events/view/42"),
        ("POST", "/events/restSearch"),
        ("POST", "/attributes/restSearch"),
        ("POST", "/tags/attachTagToObject"),
        ("POST", "/tags/removeTagFromObject"),
    ]


def test_sdk_read_actions_preserve_legacy_endpoints(monkeypatch):
    calls = []

    def request(_asset, method, endpoint, **_kwargs):
        calls.append((method, endpoint))
        if endpoint == "/events/view/42":
            return {"Event": {"id": "42", "info": "Example"}}
        if endpoint == "/attributes/restSearch":
            return {"response": {"Attribute": []}}
        if endpoint == "/events/restSearch":
            return {"response": []}
        assert endpoint == "/servers/getPyMISPVersion.json"
        return {"version": "2.4.140"}

    module = import_module("src.app")
    monkeypatch.setattr(module, "request", request)
    soar = Mock()
    module.test_connectivity.__wrapped__(soar, Mock())
    soar.set_message.assert_called_once_with("Test connectivity passed")
    module = import_module("src.actions.get_attributes")
    monkeypatch.setattr(module, "request", request)
    module.get_event(module.GetAttributesParams(event_id=42), Mock(), Mock())
    module = import_module("src.actions.run_query")
    monkeypatch.setattr(module, "request", request)
    for controller in ("events", "attributes"):
        module.run_query(
            module.RunQueryParams(controller=controller, max_results=1), Mock(), Mock()
        )

    assert calls == [
        ("GET", "/servers/getPyMISPVersion.json"),
        ("GET", "/events/view/42"),
        ("POST", "/attributes/restSearch"),
        ("POST", "/events/restSearch"),
        ("POST", "/attributes/restSearch"),
    ]


@pytest.mark.parametrize("wrapped", [True, False], ids=["wrapped", "unwrapped"])
def test_get_attributes_preserves_metadata_for_empty_results(monkeypatch, wrapped):
    module = import_module("src.actions.get_attributes")
    body = {"Attribute": [], "metadata": {"total": 0}}
    response = {"response": body, "outer_metadata": True} if wrapped else body
    request = Mock(side_effect=[{"Event": {"id": "42"}}, response])
    monkeypatch.setattr(module, "request", request)
    soar = Mock()

    result = module.get_event(module.GetAttributesParams(event_id=42), soar, Mock())

    assert result.model_dump() == body
    assert soar.set_summary.call_args.args[0].returned_attributes == 0


def test_get_attributes_reports_failure_when_second_sample_attachment_fails(
    monkeypatch,
):
    module = import_module("src.actions.get_attributes")
    event = {
        "Event": {
            "id": "42",
            "Object": [
                {
                    "Attribute": [
                        {
                            "type": "malware-sample",
                            "value": "samples/first.bin|first-hash",
                            "contents": b"first sample",
                        },
                        {
                            "type": "malware-sample",
                            "value": "samples/second.bin|second-hash",
                            "contents": b"second sample",
                        },
                    ]
                }
            ],
        }
    }
    monkeypatch.setattr(
        module,
        "request",
        Mock(side_effect=[event, {"response": {"Attribute": []}}]),
    )

    class FakeMISPAttribute:
        def from_dict(self, **attribute_data):
            self.malware_filename = attribute_data["value"].split("|", 1)[0]
            self.malware_binary = BytesIO(attribute_data["contents"])

    import pymisp

    monkeypatch.setattr(pymisp, "MISPAttribute", FakeMISPAttribute)
    saved_attachments = []
    soar = Mock()
    soar.get_executing_container_id.return_value = 42

    def create_attachment(**attachment):
        if attachment["file_name"] == "second.bin":
            raise RuntimeError("second attachment failed")
        saved_attachments.append(attachment)

    soar.vault.create_attachment.side_effect = create_attachment

    with pytest.raises(RuntimeError, match="second attachment failed"):
        module.get_event(
            module.GetAttributesParams(event_id=42, download_samples=True),
            soar,
            Mock(),
        )

    assert [item["file_name"] for item in saved_attachments] == ["first.bin"]
    assert [
        call.kwargs["file_name"] for call in soar.vault.create_attachment.call_args_list
    ] == ["first.bin", "second.bin"]
    soar.set_summary.assert_not_called()
    soar.set_message.assert_not_called()


@pytest.mark.parametrize(
    "response",
    [
        {"response": {"message": "unexpected"}},
        {"response": {"Attribute": [42]}},
        {"Attribute": {"id": "123"}},
        {"response": []},
    ],
    ids=["missing-list", "invalid-row", "invalid-list", "invalid-envelope"],
)
def test_get_attributes_rejects_malformed_search_response(monkeypatch, response):
    module = import_module("src.actions.get_attributes")
    request = Mock(side_effect=[{"Event": {"id": "42"}}, response])
    monkeypatch.setattr(module, "request", request)
    soar = Mock()

    with pytest.raises(RuntimeError, match="unexpected attribute response shape"):
        module.get_event(module.GetAttributesParams(event_id=42), soar, Mock())

    soar.set_message.assert_not_called()


@pytest.mark.parametrize(
    ("status", "body", "error_type", "message"),
    [
        (302, {"version": "2.4.140"}, RuntimeError, "MISP returned HTTP 302"),
        (200, {}, ActionFailure, "MISP did not return a usable PyMISP version"),
        (
            200,
            {"version": " "},
            ActionFailure,
            "MISP did not return a usable PyMISP version",
        ),
    ],
)
def test_connectivity_rejects_invalid_responses(
    monkeypatch, status, body, error_type, message
):
    module = import_module("src.app")
    helper = import_module("src.helper")
    transport = httpx2.MockTransport(
        lambda _request: httpx2.Response(status, json=body)
    )
    monkeypatch.setattr(
        helper, "misp_client", lambda _asset: httpx2.Client(transport=transport)
    )
    asset = module.Asset(base_url="https://misp.example.test", api_key="test-key")
    soar = Mock()

    with pytest.raises(error_type, match=message):
        module.test_connectivity.__wrapped__(soar, asset)

    soar.set_message.assert_not_called()


@pytest.mark.parametrize(
    ("other", "expected_filters"),
    [
        (
            {
                "type_attribute": ["domain", "hostname"],
                "quick_filter": "sample",
                "date_from": "2024-01-01",
                "date_to": 1706745600,
                "with_attachments": False,
                "last": "7d",
                "enforce_warninglist": "0",
                "include_event_uuid": True,
                "include_event_tags": 1,
                "sg_reference_only": "1",
                "include_context": 0,
                "include_sightings": True,
                "include_decay_score": False,
                "include_correlations": True,
                "exclude_decayed": "0",
                "metadata": False,
                "headerless": True,
                "to_ids": 0,
            },
            {
                "type": ["domain", "hostname"],
                "quickFilter": "sample",
                "from": "2024-01-01",
                "to": 1706745600,
                "withAttachments": 0,
                "publish_timestamp": "7d",
                "enforceWarninglist": 0,
                "includeEventUuid": 1,
                "includeEventTags": 1,
                "sgReferenceOnly": 1,
                "includeContext": 0,
                "includeSightings": 1,
                "includeDecayScore": 0,
                "includeCorrelations": 1,
                "excludeDecayed": 0,
                "metadata": 0,
                "headerless": 1,
                "to_ids": 0,
            },
        ),
        (
            {
                "type_attribute": "hostname",
                "type": "domain",
                "date_from": "2024-01-01",
                "from": "2d",
                "last": "7d",
                "publish_timestamp": "2d",
                "include_event_tags": True,
                "includeEventTags": 0,
                "include_event_uuid": True,
                "includeEventUuid": None,
                "eventid": 42,
                "tags": ["example"],
                "order": "Event.id ASC",
                "controller": "attributes",
                "pythonify": False,
                "return_format": "json",
                "returnFormat": "csv",
                "page": 9,
                "limit": 99,
            },
            {
                "type": "hostname",
                "from": "2024-01-01",
                "publish_timestamp": "7d",
                "includeEventTags": 0,
                "includeEventUuid": 1,
                "eventid": 42,
                "tags": ["example"],
                "order": "Event.id ASC",
            },
        ),
        (
            {
                "type": "domain",
                "from": "2d",
                "includeEventTags": False,
                "pythonify": None,
            },
            {"type": "domain", "from": "2d", "includeEventTags": 0},
        ),
    ],
    ids=["pymisp-aliases", "conflicting-keys-and-pagination", "native-keys"],
)
def test_run_query_translates_legacy_pymisp_filters(
    monkeypatch, other, expected_filters
):
    module = import_module("src.actions.run_query")
    request = Mock(return_value={"response": {"Attribute": []}})
    monkeypatch.setattr(module, "request", request)
    asset = Mock()

    module.run_query(
        module.RunQueryParams(
            controller="attributes", max_results=2, other=json.dumps(other)
        ),
        Mock(),
        asset,
    )

    request.assert_called_once_with(
        asset,
        "POST",
        "/attributes/restSearch",
        payload={**expected_filters, "returnFormat": "json", "page": 1, "limit": 2},
        timeout=60,
    )
    flag_fields = {"includeEventTags", "includeEventUuid"} & expected_filters.keys()
    assert all(
        type(request.call_args.kwargs["payload"][key]) is int for key in flag_fields
    )


@pytest.mark.parametrize(
    ("controller", "override", "response", "expected_data"),
    [
        (
            "events",
            "attributes",
            {"Attribute": [{"id": "23", "value": "example.test"}]},
            [
                {
                    "Attribute": [{"id": "23", "value": "example.test"}],
                    "attribute_count": "1",
                }
            ],
        ),
        (
            "attributes",
            "events",
            [{"Event": {"id": "42"}}],
            [[{"Event": {"id": "42"}}]],
        ),
        (
            "events",
            "objects",
            [{"Object": {"id": "12", "name": "file", "Attribute": [{"id": "23"}]}}],
            [[{"Object": {"id": "12", "name": "file", "Attribute": [{"id": "23"}]}}]],
        ),
    ],
    ids=["events-to-attributes", "attributes-to-events", "objects-override"],
)
def test_run_query_uses_controller_override_for_request_and_output(
    monkeypatch, controller, override, response, expected_data
):
    module = import_module("src.actions.run_query")
    request = Mock(return_value={"response": response})
    monkeypatch.setattr(module, "request", request)
    add_result = Mock()
    monkeypatch.setattr(app.actions_manager, "add_result", add_result)
    asset = Mock()
    params = module.RunQueryParams(
        controller=controller, max_results=1, other=json.dumps({"controller": override})
    )

    assert app.get_actions()["run_query"](params, soar=Mock(), asset=asset) is True

    request.assert_called_once_with(
        asset,
        "POST",
        f"/{override}/restSearch",
        payload={"returnFormat": "json", "page": 1, "limit": 1},
        timeout=60,
    )
    assert add_result.call_args.args[0].get_data() == expected_data


@pytest.mark.parametrize(
    ("other", "error_message"),
    [
        (
            {"controller": "sightings"},
            r"other\.controller must be events, attributes, or objects",
        ),
        (
            {"return_format": "csv"},
            r"other\.return_format must be 'json'.*Make Request",
        ),
        (
            {"return_format": "csv", "pythonify": True},
            r"other\.return_format must be 'json'.*Make Request",
        ),
        ({"returnFormat": "xml"}, r"other\.returnFormat must be 'json'.*Make Request"),
        ({"pythonify": True}, r"other\.pythonify must be false or null"),
    ],
    ids=[
        "unsupported-controller",
        "pymisp-return-format",
        "attributes-csv",
        "rest-return-format",
        "pythonify",
    ],
)
def test_run_query_rejects_unsupported_overrides(monkeypatch, other, error_message):
    module = import_module("src.actions.run_query")
    request_page = Mock()
    monkeypatch.setattr(module, "_request_query_page", request_page)
    params = module.RunQueryParams(controller="attributes", other=json.dumps(other))

    with pytest.raises(ActionFailure, match=error_message):
        module.run_query(params, Mock(), Mock())

    request_page.assert_not_called()
