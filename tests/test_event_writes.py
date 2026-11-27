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

import httpx2
import pytest
from pymisp import MISPAttribute
from soar_sdk.action_results import ActionResult
from soar_sdk.auth import StaticTokenAuth
from soar_sdk.exceptions import ActionFailure

from src import helper
from src.actions.add_attributes import UpdateEventParams
from src.app import app
from src.asset import Asset

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
            return httpx2.Response(200, json={"Event": event})
        assert request.method == "POST"
        assert "breakOnDuplicate" not in str(request.url)
        if request.url.path == "/events/add":
            return httpx2.Response(200, json={"Event": event})
        if request.url.path.startswith("/tags/"):
            payload = json.loads(request.content)
            tags = event.setdefault("Tag", [])
            matching = [
                tag
                for tag in tags
                if payload["tag"] in {tag.get("name"), str(tag.get("id"))}
            ]
            if request.url.path == "/tags/removeTagFromObject":
                event["Tag"] = [tag for tag in tags if tag not in matching]
            elif payload["tag"] == "forbidden":
                return httpx2.Response(403, json={"errors": "Insufficient privileges"})
            elif any(tag.get("local", 0) in (False, 0, "0") for tag in matching):
                return httpx2.Response(
                    403,
                    json={"errors": "Event already has the requested tag attached"},
                )
            else:
                tags.append({"name": payload["tag"], "local": 0})
            return httpx2.Response(200, json={"saved": True})
        assert request.url.path == f"/events/edit/{EVENT_UUID}"
        submitted_event = json.loads(request.content)
        assert submitted_event["id"] == "42"
        assert submitted_event["info"] == "Example"
        assert submitted_event["uuid"] == EVENT_UUID
        assert "created_event_id" not in submitted_event
        for row in submitted_event.get("Attribute", []):
            if row["value"].startswith("reject-"):
                return httpx2.Response(422, json={"errors": row["value"]})
            if row["value"] in {"forbidden", "invalid"}:
                return httpx2.Response(403, json={"errors": "Rejected event update"})
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
        return httpx2.Response(200, json={"Event": event})

    transport = httpx2.MockTransport(handle)
    monkeypatch.setattr(
        helper,
        "misp_client",
        lambda _asset: httpx2.Client(
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
    first = module.add_attributes(params, first_soar, asset)
    second = module.add_attributes(params, second_soar, asset)

    assert len(event["Attribute"]) == 1
    assert [row.id for row in first] == ["1"]
    assert [row.id for row in second] == ["1"]
    assert first_soar.set_summary.call_args.args[0].attributes_added == 1
    assert second_soar.set_summary.call_args.args[0].attributes_added == 0
    assert (
        first_soar.set_summary.call_args.args[0].message
        == "Attributes added to event: 42"
    )
    first_soar.set_message.assert_called_once_with("Attributes added to event: 42")
    assert len([request for request in requests if request.method == "POST"]) == 4


@pytest.mark.parametrize("value", ["forbidden", "invalid"])
def test_event_edit_preserves_genuine_failures(misp_server, asset, value):
    module = import_module("src.actions.add_attributes")
    params = UpdateEventParams(event_id=42, json=json.dumps({"comment": value}))

    with pytest.raises(ActionFailure, match=r"MISP event 42:.*HTTP 403") as error:
        module.add_attributes(params, Mock(), asset)
    assert "earlier attribute update" not in error.value.message


def test_later_write_failure_reports_earlier_save(monkeypatch, misp_server, asset):
    event, _requests = misp_server
    add_result = Mock()
    monkeypatch.setattr(app.actions_manager, "add_result", add_result)
    params = UpdateEventParams(
        event_id=42, json=json.dumps({"comment": ["saved", "forbidden"]})
    )

    success = app.get_actions()["add_attributes"](params, soar=Mock(), asset=asset)

    assert success is False
    result = add_result.call_args.args[0]
    assert "MISP event 42" in result.get_message()
    assert "HTTP 403" in result.get_message()
    assert "MISP accepted an earlier attribute update" in result.get_message()
    assert result.get_data() == []
    assert [attribute["value"] for attribute in event["Attribute"]] == ["saved"]


def test_update_reports_all_json_row_rejections(monkeypatch, misp_server, asset):
    event, _requests = misp_server
    add_result = Mock()
    monkeypatch.setattr(app.actions_manager, "add_result", add_result)
    params = UpdateEventParams(
        event_id=42, json=json.dumps({"comment": ["reject-first", "reject-second"]})
    )

    assert (
        app.get_actions()["add_attributes"](params, soar=Mock(), asset=asset) is False
    )

    message = add_result.call_args.args[0].get_message()
    assert "Failed to add attributes to MISP event 42:" in message
    assert "HTTP 422" in message
    assert "reject-first" in message
    assert "reject-second" in message
    assert event["Attribute"] == []


def test_update_keeps_valid_json_rows_and_summarizes_rejections(misp_server, asset):
    module = import_module("src.actions.add_attributes")
    params = UpdateEventParams(
        event_id=42, json=json.dumps({"comment": ["reject-first", "saved"]})
    )
    soar = Mock()

    rows = module.add_attributes(params, soar, asset)

    assert [row.value for row in rows] == ["saved"]
    summary = soar.set_summary.call_args.args[0]
    assert summary.attributes_added == 1
    assert "reject-first" in summary.errors


@pytest.mark.parametrize("value", ["forbidden", "invalid"])
def test_vendor_rejection_uses_sdk_error_result(monkeypatch, misp_server, asset, value):
    add_result = Mock()
    monkeypatch.setattr(app.actions_manager, "add_result", add_result)

    success = app.get_actions()["add_attributes"](
        UpdateEventParams(event_id=42, json=json.dumps({"comment": value})),
        soar=Mock(),
        asset=asset,
    )

    assert success is False
    result = add_result.call_args.args[0]
    assert "HTTP 403" in result.get_message()
    assert "Traceback" not in result.get_message()


def test_update_rejects_empty_replacement_before_writing(misp_server, asset):
    event, requests = misp_server
    event["Tag"] = [{"name": "old"}]
    module = import_module("src.actions.add_attributes")
    params = UpdateEventParams(
        event_id=42, tags=",,,", replace_tags=True, domains="example.com"
    )

    with pytest.raises(
        ActionFailure, match="Please provide at least one replacement tag"
    ):
        module.add_attributes(params, Mock(), asset)

    assert event["Tag"] == [{"name": "old"}]
    assert requests == []


def test_update_replaces_tags_using_legacy_endpoints(misp_server, asset):
    event, requests = misp_server
    event["Tag"] = [{"name": "old"}]
    module = import_module("src.actions.add_attributes")

    module.add_attributes(
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


@pytest.mark.parametrize("tag_input", ["old", "7", "old,7,old"])
@pytest.mark.parametrize("local", [False, 0, "0"])
def test_update_skips_existing_global_tags(misp_server, asset, tag_input, local):
    event, requests = misp_server
    event["Tag"] = [{"id": "7", "name": "old", "local": local}]
    module = import_module("src.actions.add_attributes")
    soar = Mock()

    rows = module.add_attributes(
        UpdateEventParams(event_id=42, tags=tag_input), soar, asset
    )

    assert [request.method for request in requests] == ["GET"]
    assert rows[0].event_id == "42"
    assert soar.set_summary.call_args.args[0].attributes_added == 0


def test_update_appends_new_tags_once_without_removing_existing(misp_server, asset):
    event, requests = misp_server
    event["Tag"] = [{"id": "7", "name": "old"}]
    module = import_module("src.actions.add_attributes")

    module.add_attributes(
        UpdateEventParams(event_id=42, tags="old,new,new,7,another,another"),
        Mock(),
        asset,
    )

    posts = [request for request in requests if request.method == "POST"]
    assert [request.url.path for request in posts] == ["/tags/attachTagToObject"] * 2
    assert [json.loads(request.content)["tag"] for request in posts] == [
        "new",
        "another",
    ]
    assert [tag["name"] for tag in event["Tag"]] == ["old", "new", "another"]


@pytest.mark.parametrize("local", [True, 1, "1"])
def test_update_adds_global_tag_when_only_local_tag_exists(misp_server, asset, local):
    event, requests = misp_server
    event["Tag"] = [{"id": "7", "name": "old", "local": local}]
    module = import_module("src.actions.add_attributes")

    module.add_attributes(UpdateEventParams(event_id=42, tags="old"), Mock(), asset)

    posts = [request for request in requests if request.method == "POST"]
    assert len(posts) == 1
    assert json.loads(posts[0].content) == {
        "uuid": EVENT_UUID,
        "tag": "old",
        "local": False,
    }


def test_update_replacement_reattaches_requested_existing_tag(misp_server, asset):
    event, requests = misp_server
    event["Tag"] = [{"id": "7", "name": "old", "local": 0}]
    module = import_module("src.actions.add_attributes")

    module.add_attributes(
        UpdateEventParams(event_id=42, tags="old,old", replace_tags=True),
        Mock(),
        asset,
    )

    posts = [request for request in requests if request.method == "POST"]
    assert [request.url.path for request in posts] == [
        "/tags/removeTagFromObject",
        "/tags/attachTagToObject",
    ]
    assert [tag["name"] for tag in event["Tag"]] == ["old"]


@pytest.mark.parametrize("with_attributes", [False, True])
def test_update_does_not_suppress_tag_permission_errors(
    misp_server, asset, with_attributes
):
    event, _requests = misp_server
    event["Tag"] = [{"id": "7", "name": "old"}]
    module = import_module("src.actions.add_attributes")
    params = UpdateEventParams(
        event_id=42,
        tags="old,forbidden",
        json='{"comment":"saved"}' if with_attributes else None,
    )

    if with_attributes:
        result = module.add_attributes(params, Mock(), asset)
        assert isinstance(result, ActionResult)
        assert result.get_status() is False
        assert "Insufficient privileges" in result.get_message()
        assert result.get_data()[0]["value"] == "saved"
    else:
        with pytest.raises(RuntimeError, match="HTTP 403.*Insufficient privileges"):
            module.add_attributes(params, Mock(), asset)


def test_create_uses_legacy_event_and_tag_endpoints(misp_server, asset):
    _event, requests = misp_server
    module = import_module("src.actions.create_event")
    soar = Mock()

    rows = module.create_event(
        module.CreateEventParams(
            info="Example", add_attributes=True, domains="example.com", tags="new"
        ),
        soar,
        asset,
    )

    assert soar.set_summary.call_args.args[0].message == "Event created with id: 42"
    soar.set_message.assert_called_once_with("Event created with id: 42")
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


@pytest.mark.parametrize(
    ("values", "succeeded"),
    [(["saved"], True), (["saved", "forbidden"], False)],
    ids=["success", "partial-failure"],
)
@pytest.mark.parametrize(
    "response_type", [str, int], ids=["string-fields", "int-fields"]
)
def test_create_keeps_event_snapshot_serializable(
    monkeypatch, misp_server, asset, values, succeeded, response_type
):
    """Keep a JSON event snapshot with the same field types on either outcome."""
    event, _requests = misp_server
    string_fields = {
        "id": 42,
        "analysis": 0,
        "attribute_count": 0,
        "distribution": 0,
        "org_id": 1,
        "orgc_id": 1,
        "publish_timestamp": 0,
        "sharing_group_id": 0,
        "threat_level_id": 1,
        "timestamp": 1700000000,
    }
    event.update({key: response_type(value) for key, value in string_fields.items()})
    event["published"] = False
    module = import_module("src.actions.create_event")
    add_result = Mock()
    soar = Mock()
    monkeypatch.setattr(app.actions_manager, "add_result", add_result)

    success = app.get_actions()["create_event"](
        module.CreateEventParams(
            info="Example", add_attributes=True, json=json.dumps({"comment": values})
        ),
        soar=soar,
        asset=asset,
    )

    assert success is succeeded
    result = add_result.call_args.args[0]
    data = json.loads(json.dumps(result.get_data()))
    assert {key: data[0][key] for key in string_fields} == {
        key: str(value) for key, value in string_fields.items()
    }
    assert data[0]["published"] is False
    assert data[0]["created_event_id"] == "42"
    assert data[0]["Attribute"] == []
    assert event["Attribute"][0]["value"] == "saved"
    if succeeded:
        assert data[1]["value"] == "saved"
        assert soar.set_summary.call_args.args[0].created_event_id == 42
    else:
        assert result.get_summary()["created_event_id"] == 42
        assert "HTTP 403" in result.get_message()
        assert "MISP accepted an earlier attribute update" in result.get_message()
