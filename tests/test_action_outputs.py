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
"""Regression coverage for SDK serialization of MISP action results."""

import json
from importlib import import_module
from unittest.mock import Mock

import pytest
from soar_sdk.app import App

from src.actions.add_attributes import UpdateEventOutput
from src.actions.create_event import CreateAttributeRow, CreateEventRow
from src.actions.run_query import RunQueryOutput
from src.helper import output


@pytest.mark.parametrize(
    ("output_model", "payload"),
    [
        (
            RunQueryOutput,
            {
                "Attribute": [{"id": "123", "value": "192.0.2.1"}],
                "attribute_count": "1",
            },
        ),
        (RunQueryOutput, {"Attribute": [], "attribute_count": "0"}),
        (CreateEventRow, {"id": "2020", "info": "test", "Tag": [{"name": "test"}]}),
        (CreateAttributeRow, {"id": "123", "event_id": "2020", "value": "192.0.2.1"}),
    ],
    ids=[
        "query-attributes",
        "empty-attributes",
        "created-event",
        "created-attribute",
    ],
)
def test_vendor_outputs_serialize_through_sdk(output_model, payload):
    """The SDK must serialize raw vendor rows without recursion or data changes."""
    expected = json.loads(json.dumps(payload))
    manager = Mock()

    success = App._adapt_action_result([output(output_model, payload)], manager)

    assert success is True
    result = manager.add_result.call_args.args[0]
    assert json.loads(json.dumps(result.get_data())) == [expected]


@pytest.mark.parametrize(
    "event_rows",
    [
        [{"Event": {"id": "2020", "Object": [{"custom": {"value": "test"}}]}}],
        [],
    ],
    ids=["events", "empty"],
)
def test_query_event_list_preserves_legacy_nesting(monkeypatch, event_rows):
    module = import_module("src.actions.run_query")
    monkeypatch.setattr(
        module, "_request_query_page", Mock(side_effect=[{"response": event_rows}, []])
    )
    manager = Mock()
    result = module.run_query.__wrapped__(
        module.RunQueryParams(controller="events"), Mock(), Mock()
    )

    assert App._adapt_action_result(result, manager)
    data = manager.add_result.call_args.args[0].get_data()
    assert json.loads(json.dumps(data)) == [event_rows]


def test_query_manifest_preserves_legacy_event_datapaths():
    paths = {field["data_path"] for field in RunQueryOutput._to_json_schema()}
    event_prefix = "action_result.data.*.*.Event."
    assert sum(path.startswith(event_prefix) for path in paths) == 103
    assert {
        f"{event_prefix}{path}"
        for path in (
            "id",
            "Attribute.*.value",
            "Object.*.Attribute.*.value",
            "Object.*.meta-category",
            "Org.local",
            "RelatedEvent.*.Event.Orgc.uuid",
            "Tag.*.name",
        )
    } <= paths
    assert "action_result.data.*.Attribute.*.id" in paths


def test_fixed_output_preserves_vendor_field_types():
    """Keep existing fixed-schema construction and vendor scalar types intact."""
    row = {"id": "123", "event_id": "2020", "to_ids": False, "deleted": 0}

    result = output(UpdateEventOutput, row).model_dump(exclude_unset=True)

    assert result == row
