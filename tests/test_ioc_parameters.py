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
"""Cover IOC list metadata, IPv6 support, and validation inside SDK actions."""

from importlib import import_module
from unittest.mock import Mock

import pytest
from soar_sdk.exceptions import ActionFailure

from src import helper
from src.actions.add_attributes import UpdateEventParams
from src.actions.create_event import CreateEventParams
from src.app import app

IOC_FIELDS = (
    "source_ips",
    "dest_ips",
    "domains",
    "urls",
    "source_emails",
    "dest_emails",
)


@pytest.mark.parametrize("params_class", [CreateEventParams, UpdateEventParams])
def test_manifest_declares_ioc_lists_and_both_ip_versions(params_class):
    fields = params_class._to_json_schema()
    for field in IOC_FIELDS:
        assert fields[field]["allow_list"] is True
        assert fields[field]["data_type"] == "string"
    for field in ("source_ips", "dest_ips"):
        assert fields[field]["contains"] == ["ip", "ipv6"]


@pytest.fixture
def attribute_requests(monkeypatch):
    submitted = []
    event_uuid = "11111111-1111-4111-8111-111111111111"

    def request(_asset, method, endpoint, *, payload=None, params=None):
        if method == "GET":
            return {"Event": {"id": "42", "info": "Example", "uuid": event_uuid}}
        if endpoint == "/events/add":
            return {"Event": {"id": "42", "info": "Example", "uuid": event_uuid}}
        assert endpoint == f"/events/edit/{event_uuid}"
        row = payload["Attribute"][-1]
        submitted.append(row.copy())
        row.update(id=str(len(submitted)), event_id="42")
        return {"Event": payload}

    monkeypatch.setattr(helper, "request", request)
    for module_name in ("add_attributes", "create_event"):
        monkeypatch.setattr(
            import_module(f"src.actions.{module_name}"), "request", request
        )
    return submitted


IP_CASES = [
    ("2001:db8::1", ["2001:db8::1"]),
    ("2001:db8::1,192.0.2.1,192.0.2.2", ["2001:db8::1", "192.0.2.1", "192.0.2.2"]),
    ("192.0.2.1,192.0.2.1", ["192.0.2.1", "192.0.2.1"]),
    (",,,,,192.0.2.1", ["192.0.2.1"]),
    ("192.0.2.1,,,,,", ["192.0.2.1"]),
    ("192.0.2.1,,,,,192.0.2.2", ["192.0.2.1", "192.0.2.2"]),
]
EMAILS = [
    '"xyz.test.@.test.com"@domain.com',
    "example-abc@abc-domain.com",
    "example@s.solutions",
    "id-with-dash@domain.com",
    "#!$%&'*+-/=?^_{}|~@domain.org",
]
VALID_CASES = [
    (field, value, expected)
    for field in ("source_ips", "dest_ips")
    for value, expected in IP_CASES
] + [
    ("urls", ",,,,,https://example.com", ["https://example.com"]),
    (
        "urls",
        ",,,,,https://example.com,,,,https://example.org",
        ["https://example.com", "https://example.org"],
    ),
    ("source_emails", ",\t".join(EMAILS), EMAILS),
    ("dest_emails", ",\t".join(EMAILS), EMAILS),
]


@pytest.mark.parametrize("module_name", ["add_attributes", "create_event"])
@pytest.mark.parametrize(("field", "value", "expected"), VALID_CASES)
def test_ioc_lists_reach_misp_as_individual_attributes(
    attribute_requests, module_name, field, value, expected
):
    module = import_module(f"src.actions.{module_name}")
    if module_name == "add_attributes":
        params = UpdateEventParams(event_id=42, to_ids=False, **{field: value})
        action = module.add_attributes
    else:
        params = CreateEventParams(add_attributes=True, to_ids=False, **{field: value})
        action = module.create_event

    action(params, Mock(), Mock())

    assert [row["value"] for row in attribute_requests] == expected
    assert all(row["to_ids"] is False for row in attribute_requests)


@pytest.mark.parametrize("field", IOC_FIELDS)
def test_separator_only_update_has_no_attributes(attribute_requests, field):
    module = import_module("src.actions.add_attributes")
    params = UpdateEventParams(event_id=42, **{field: ",,,,,"})

    with pytest.raises(ActionFailure, match="Please provide at least one attribute"):
        module.add_attributes(params, Mock(), Mock())

    assert attribute_requests == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_ips", "192.0.2.1,999.1.1.1"),
        ("dest_ips", "2001:db8::1,2001:invalid"),
        ("urls", "https://example.com,invalid"),
        ("source_emails", "user@example.com,invalid"),
        ("dest_emails", "user@example.com,invalid"),
        ("domains", "example.com,bad@domain"),
    ],
)
def test_invalid_ioc_still_fails_before_writing(attribute_requests, field, value):
    module = import_module("src.actions.add_attributes")
    params = UpdateEventParams(event_id=42, **{field: value})

    with pytest.raises(ActionFailure, match=field):
        module.add_attributes(params, Mock(), Mock())

    assert attribute_requests == []


@pytest.mark.parametrize(
    ("inputs", "expected"),
    [
        ({"urls": ",,,,,"}, "Please provide at least one attribute"),
        ({"source_ips": "999.1.1.1"}, "'source_ips'"),
    ],
)
def test_expected_validation_failure_uses_sdk_error_result(
    monkeypatch, attribute_requests, inputs, expected
):
    add_result = Mock()
    monkeypatch.setattr(app.actions_manager, "add_result", add_result)

    success = app.get_actions()["add_attributes"](
        UpdateEventParams(event_id=42, **inputs), soar=Mock(), asset=Mock()
    )

    assert success is False
    result = add_result.call_args.args[0]
    assert expected in result.get_message()
    assert "Traceback" not in result.get_message()
    assert attribute_requests == []
