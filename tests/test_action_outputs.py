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
from unittest.mock import Mock

import pytest
from soar_sdk.app import App

from src.actions.add_attributes import UpdateEventOutput
from src.actions.create_event import CreateEventOutput
from src.actions.run_query import RunQueryOutput
from src.helper import output


@pytest.mark.parametrize(
    ("output_model", "payload"),
    [
        (
            RunQueryOutput,
            {"Event": {"id": "2020", "Object": [{"custom": {"value": "test"}}]}},
        ),
        (
            RunQueryOutput,
            {
                "Attribute": [{"id": "123", "value": "192.0.2.1"}],
                "attribute_count": "1",
            },
        ),
        (RunQueryOutput, {"Attribute": [], "attribute_count": "0"}),
        (CreateEventOutput, {"id": "2020", "info": "test", "Tag": [{"name": "test"}]}),
        (CreateEventOutput, {"id": "123", "event_id": "2020", "value": "192.0.2.1"}),
    ],
    ids=[
        "query-events",
        "query-attributes",
        "empty-attributes",
        "created-event",
        "created-attribute",
    ],
)
def test_permissive_outputs_serialize_through_sdk(output_model, payload):
    """The SDK must serialize raw vendor rows without recursion or data changes."""
    expected = json.loads(json.dumps(payload))
    manager = Mock()

    success = App._adapt_action_result([output(output_model, payload)], manager)

    assert success is True
    result = manager.add_result.call_args.args[0]
    assert json.loads(json.dumps(result.get_data())) == [expected]


def test_fixed_output_preserves_vendor_field_types():
    """Keep existing fixed-schema construction and vendor scalar types intact."""
    row = {"id": "123", "event_id": "2020", "to_ids": False, "deleted": 0}

    result = output(UpdateEventOutput, row).model_dump(exclude_unset=True)

    assert result == row
