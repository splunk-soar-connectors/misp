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
"""Exercise legacy event-edit writes through SDK-authenticated HTTP requests."""

import copy
import json
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from pymisp import MISPAttribute
from soar_sdk.action_results import ActionResult
from soar_sdk.auth import StaticTokenAuth

from src import helper
from src.actions.add_attributes import UpdateEventParams
from src.app import Asset

EVENT_UUID = "11111111-1111-4111-8111-111111111111"


@pytest.fixture
def misp_server(monkeypatch):
    """Model 2.4.140: an event edit can succeed without saving a new duplicate."""
    event = {"id": "42", "uuid": EVENT_UUID, "info": "Example", "Attribute": []}
    requests = []

    def handle(request):
        requests.append(request)
        assert request.headers["Authorization"] == "test-key"
        if request.method == "GET":
            assert request.url.path == "/events/view/42"
            return httpx.Response(200, json={"Event": event})
        assert request.method == "POST"
        assert "breakOnDuplicate" not in str(request.url)
        if request.url.path == "/events/add":
            return httpx.Response(200, json={"Event": event})
        if request.url.path.startswith("/tags/"):
            return httpx.Response(200, json={"saved": True})
        assert request.url.path == f"/events/edit/{EVENT_UUID}"
        submitted_event = json.loads(request.content)
        assert submitted_event["id"] == "42"
        assert submitted_event["info"] == "Example"
        assert submitted_event["uuid"] == EVENT_UUID
        assert "created_event_id" not in submitted_event
        for row in submitted_event.get("Attribute", []):
            if row["value"] in {"forbidden", "invalid"}:
                return httpx.Response(403, json={"errors": "Rejected event update"})
            existing = next(
                (
                    attribute
                    for attribute in event["Attribute"]
                    if attribute["uuid"] == row["uuid"]
                ),
                None,
            )
            if existing:
                continue
            duplicate = any(
                all(attribute[key] == row[key] for key in ("type", "category", "value"))
                for attribute in event["Attribute"]
            )
            if duplicate:
                continue
            event["Attribute"].append(
                {**row, "id": str(len(event["Attribute"]) + 1), "event_id": "42"}
            )
        return httpx.Response(200, json={"Event": event})

    transport = httpx.MockTransport(handle)
    monkeypatch.setattr(
        helper,
        "misp_client",
        lambda _asset: httpx.Client(
            transport=transport, auth=StaticTokenAuth(_asset.api_key, token_type="")
        ),
    )
    return event, requests


@pytest.fixture
def asset():
    return Asset(
        base_url="https://misp.example.test",
        api_key="test-key",  # pragma: allowlist secret
        verify_server_cert=True,
    )


@pytest.mark.parametrize(
    ("field", "attribute_type", "value"),
    [
        ("source_ips", "ip-src", "192.0.2.1"),
        ("dest_ips", "ip-dst", "192.0.2.1"),
        ("domains", "domain", "example.com"),
        ("urls", "url", "https://example.com"),
        ("source_emails", "email-src", "user@example.com"),
        ("dest_emails", "email-dst", "user@example.com"),
        ("json_mapping", "comment", "existing"),
        ("json_list", "comment", "existing"),
    ],
)
def test_event_edit_returns_existing_duplicate_without_forcing_changes(
    misp_server, asset, field, attribute_type, value
):
    event, requests = misp_server
    existing = MISPAttribute()
    existing.from_dict(
        type=attribute_type, value=value, to_ids=True, id="123", event_id="42"
    )
    stored = json.loads(existing.to_json())
    event["Attribute"].append(stored)
    if field == "json_mapping":
        inputs = {"json": json.dumps({attribute_type: value})}
    elif field == "json_list":
        inputs = {
            "json": json.dumps(
                [{"type": attribute_type, "value": value, "to_ids": False}]
            )
        }
    else:
        inputs = {field: value}
    original = copy.deepcopy(event)

    rows = helper.add_iocs(
        asset, 42, SimpleNamespace(to_ids=False, **inputs), event=event
    )

    assert rows == [stored]
    assert rows[0]["to_ids"] is True
    assert event == original
    assert [request.url.path for request in requests] == [f"/events/edit/{EVENT_UUID}"]
    submitted = json.loads(requests[0].content)["Attribute"]
    assert submitted[0] == stored
    assert submitted[1]["to_ids"] is False
    assert submitted[1]["uuid"] != stored["uuid"]


def test_repeated_inputs_return_complete_server_event(misp_server, asset):
    event, requests = misp_server
    module = import_module("src.actions.add_attributes")
    params = UpdateEventParams(
        event_id=42, source_ips="192.0.2.1,192.0.2.1", to_ids=False
    )

    first_soar = Mock()
    second_soar = Mock()
    first = module.add_attributes.__wrapped__(params, first_soar, asset)
    second = module.add_attributes.__wrapped__(params, second_soar, asset)

    assert len(event["Attribute"]) == 1
    assert [row.id for row in first] == ["1"]
    assert [row.id for row in second] == ["1"]
    assert first_soar.set_summary.call_args.args[0].attributes_added == 1
    assert second_soar.set_summary.call_args.args[0].attributes_added == 0
    assert len([request for request in requests if request.method == "POST"]) == 4


@pytest.mark.parametrize("value", ["forbidden", "invalid"])
def test_event_edit_preserves_genuine_failures(misp_server, asset, value):
    module = import_module("src.actions.add_attributes")
    params = UpdateEventParams(event_id=42, json=json.dumps({"comment": value}))

    with pytest.raises(helper.PartialIOCError, match="HTTP 403"):
        module.add_attributes.__wrapped__(params, Mock(), asset)


def test_later_failure_retains_last_saved_event_attributes(misp_server, asset):
    module = import_module("src.actions.add_attributes")
    params = UpdateEventParams(
        event_id=42, json=json.dumps({"comment": ["saved", "forbidden"]})
    )

    result = module.add_attributes.__wrapped__(params, Mock(), asset)

    assert isinstance(result, ActionResult)
    assert result.get_status() is False
    assert "HTTP 403" in result.get_message()
    assert len(result.get_data()) == 1
    assert result.get_data()[0]["id"] == "1"
    assert result.get_data()[0]["value"] == "saved"


@pytest.mark.parametrize("value", ["forbidden", "invalid"])
def test_vendor_rejection_uses_sdk_error_result(monkeypatch, misp_server, asset, value):
    module = import_module("src.actions.add_attributes")
    add_result = Mock()
    monkeypatch.setattr(module.app.actions_manager, "add_result", add_result)

    success = module.add_attributes(
        UpdateEventParams(event_id=42, json=json.dumps({"comment": value})),
        soar=Mock(),
        asset=asset,
    )

    assert success is False
    result = add_result.call_args.args[0]
    assert "HTTP 403" in result.get_message()
    assert "Traceback" not in result.get_message()


def test_update_replaces_tags_using_legacy_endpoints(misp_server, asset):
    event, requests = misp_server
    event["Tag"] = [{"name": "old"}]
    module = import_module("src.actions.add_attributes")

    module.add_attributes.__wrapped__(
        UpdateEventParams(event_id=42, tags="new", replace_tags=True),
        Mock(),
        asset,
    )

    posts = [request for request in requests if request.method == "POST"]
    assert [request.url.path for request in posts] == [
        "/tags/removeTagFromObject",
        "/tags/attachTagToObject",
    ]
    assert json.loads(posts[0].content) == {"uuid": EVENT_UUID, "tag": "old"}
    assert json.loads(posts[1].content) == {
        "uuid": EVENT_UUID,
        "tag": "new",
        "local": False,
    }


def test_create_uses_legacy_event_and_tag_endpoints(misp_server, asset):
    _event, requests = misp_server
    module = import_module("src.actions.create_event")

    rows = module.create_event.__wrapped__(
        module.CreateEventParams(
            info="Example", add_attributes=True, domains="example.com", tags="new"
        ),
        Mock(),
        asset,
    )

    assert [request.url.path for request in requests] == [
        "/events/add",
        "/tags/attachTagToObject",
        f"/events/edit/{EVENT_UUID}",
    ]
    assert rows[0].id == "42"
    assert rows[0].created_event_id == "42"
    assert rows[1].value == "example.com"
    assert json.loads(requests[1].content) == {
        "uuid": EVENT_UUID,
        "tag": "new",
        "local": False,
    }
