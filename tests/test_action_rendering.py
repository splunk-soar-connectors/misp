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
"""Cover SDK table metadata and distinct event/attribute IDs in create results."""

from importlib import import_module
from unittest.mock import Mock

import pytest
from soar_sdk.app import App
from soar_sdk.cli.manifests.processors import ManifestProcessor


def test_manifest_restores_legacy_table_columns_and_query_json():
    manifest = ManifestProcessor("", ".").build().to_json_manifest()
    actions = {action["action"]: action for action in manifest["actions"]}
    expected = {
        "create event": [
            ("MISP Event ID", "created_event_id"),
            ("MISP Attribute ID", "id"),
            ("Event Info / Description", "info"),
            ("Threat Level ID", "threat_level_id"),
            ("Distribution", "distribution"),
            ("Attribute Count", "attribute_count"),
        ],
        "update event": [
            ("MISP Attribute ID", "id"),
            ("Attribute Value", "value"),
            ("MISP Event ID", "event_id"),
            ("Attribute Category", "category"),
            ("Distribution", "distribution"),
        ],
        "get attributes": [
            ("Category", "Attribute.*.category"),
            ("Type", "Attribute.*.type"),
            ("Value", "Attribute.*.value"),
            ("Comment", "Attribute.*.comment"),
        ],
    }
    for name, columns in expected.items():
        action = actions[name]
        assert action["render"]["type"] == "table"
        actual = sorted(
            (field["column_order"], field["column_name"], field["data_path"])
            for field in action["output"]
            if field.get("column_name")
        )
        assert actual == [
            (order, title, f"action_result.data.*.{field}")
            for order, (title, field) in enumerate(columns)
        ]
    assert actions["run query"]["render"]["type"] == "json"
    for name in ("run query", "get attributes"):
        assert actions[name]["read_only"] is True
    for name in ("create event", "update event"):
        assert any(
            field["data_path"] == "action_result.summary.message"
            for field in actions[name]["output"]
        )


@pytest.mark.parametrize("add_attributes", [False, True])
def test_create_event_column_preserves_ids_and_vendor_rows(monkeypatch, add_attributes):
    module = import_module("src.actions.create_event")
    event = {
        "id": "42",
        "info": "Example",
        "Org": {"id": "7", "name": "Test", "local": True},
        "Tag": [{"name": "test"}],
        "Attribute": [],
    }
    attributes = [
        {
            "id": "101",
            "event_id": "42",
            "value": "192.0.2.1",
            "deleted": 0,
            "comment": None,
        },
        {"id": "102", "event_id": "42", "value": "192.0.2.2"},
    ]
    monkeypatch.setattr(module, "request", Mock(return_value={"Event": event}))
    monkeypatch.setattr(module, "add_tags", Mock())
    monkeypatch.setattr(module, "add_iocs", Mock(return_value=attributes))

    rows = module.create_event(
        module.CreateEventParams(add_attributes=add_attributes), Mock(), Mock()
    )
    assert isinstance(rows[0], module.CreateEventRow)
    assert all(isinstance(row, module.CreateAttributeRow) for row in rows[1:])
    manager = Mock()
    assert App._adapt_action_result(rows, manager) is True
    data = manager.add_result.call_args.args[0].get_data()

    assert data == [dict(event, created_event_id="42")] + (
        attributes if add_attributes else []
    )
    assert "created_event_id" not in event
    assert all("created_event_id" not in row for row in attributes)


@pytest.mark.parametrize("failure_stage", ["add_tags", "add_iocs"])
def test_partial_create_retains_event_id_column(monkeypatch, failure_stage):
    module = import_module("src.actions.create_event")
    event = {"id": "42", "info": "Example"}
    monkeypatch.setattr(module, "request", Mock(return_value={"Event": event}))
    monkeypatch.setattr(module, "add_tags", Mock())
    monkeypatch.setattr(module, "add_iocs", Mock())
    monkeypatch.setattr(module, failure_stage, Mock(side_effect=RuntimeError("denied")))

    result = module.create_event(
        module.CreateEventParams(add_attributes=True), Mock(), Mock()
    )

    assert result.get_status() is False
    assert result.get_data() == [dict(event, created_event_id="42")]
    assert result.get_summary()["created_event_id"] == 42
    assert result.get_summary()["message"] == "Event created with id: 42"
    assert "denied" in result.get_message()
