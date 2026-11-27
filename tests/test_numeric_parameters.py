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
"""Check numeric action parameters and documented MISP output types."""

from importlib import import_module
from unittest.mock import Mock

import pytest

from src.actions.add_attributes import UpdateEventParams
from src.actions.get_attributes import GetAttributesParams
from src.actions.run_query import RunQueryOutput, RunQueryParams
from src.helper import positive_int


@pytest.mark.parametrize("params_class", [GetAttributesParams, UpdateEventParams])
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (42, 42),
        (42.0, 42),
        ("42", 42),
        (9007199254740993, 9007199254740993),
        ("9007199254740993", 9007199254740993),
        (10**61 + 1, 10**61 + 1),
        (str(10**61 + 1), 10**61 + 1),
    ],
)
def test_numeric_event_ids_preserve_integer_precision(params_class, value, expected):
    assert params_class.model_validate({"event_id": value}).event_id == expected


@pytest.mark.parametrize("params_class", [GetAttributesParams, UpdateEventParams])
@pytest.mark.parametrize(
    "value",
    [
        "4.2e1",
        "1.234567890987654e+45",
        42.5,
        0,
        -1,
        None,
        float("inf"),
        float("nan"),
    ],
)
def test_invalid_event_ids_fail_before_request(monkeypatch, params_class, value):
    module_name, handler_name = (
        ("get_attributes", "get_event")
        if params_class is GetAttributesParams
        else ("add_attributes", "add_attributes")
    )
    module = import_module(f"src.actions.{module_name}")
    request = Mock()
    monkeypatch.setattr(module, "request", request)
    with pytest.raises(ValueError, match="event_id"):
        getattr(module, handler_name)(
            params_class.model_validate({"event_id": value}), Mock(), Mock()
        )
    request.assert_not_called()


@pytest.mark.parametrize("value", ["42.0", "4.2e1", "1.234567890987654e+45"])
def test_query_rejects_invalid_id_before_misp_request(monkeypatch, value):
    module = import_module("src.actions.run_query")
    request = Mock()
    monkeypatch.setattr(module, "request", request)

    with pytest.raises(ValueError, match="event_id must be"):
        module.run_query(
            RunQueryParams(controller="events", event_id=value), Mock(), Mock()
        )

    request.assert_not_called()


def test_id_helper_does_not_round_large_digit_strings():
    assert positive_int("9007199254740993", "event_id") == 9007199254740993


@pytest.mark.parametrize("limit_input", [{}, {"max_results": None}])
def test_missing_query_limit_sends_default_integer(monkeypatch, limit_input):
    module = import_module("src.actions.run_query")
    request = Mock(return_value=[])
    monkeypatch.setattr(module, "request", request)
    params = RunQueryParams.model_validate({"controller": "events", **limit_input})

    module.run_query(params, Mock(), Mock())

    assert request.call_args.kwargs["payload"]["limit"] == 10
    assert type(request.call_args.kwargs["payload"]["limit"]) is int


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (7, 7),
        (7.0, 7),
        ("7", 7),
        (0, 0),
        (0.0, 0),
        ("0", 0),
        (-5, -5),
        ("-5", -5),
        (9007199254740993, 9007199254740993),
        (10**43 + 1, 10**43 + 1),
        (str(10**43 + 1), 10**43 + 1),
    ],
)
def test_query_limit_preserves_signed_integers(value, expected):
    assert (
        RunQueryParams.model_validate(
            {"controller": "events", "max_results": value}
        ).max_results
        == expected
    )


@pytest.mark.parametrize("value", [7.5, "7e1", float("inf"), float("nan")])
def test_query_limit_rejects_invalid_counts_before_request(monkeypatch, value):
    module = import_module("src.actions.run_query")
    request = Mock()
    monkeypatch.setattr(module, "request", request)

    with pytest.raises(ValueError, match="max_results"):
        module.run_query(
            RunQueryParams.model_validate(
                {"controller": "events", "max_results": value}
            ),
            Mock(),
            Mock(),
        )

    request.assert_not_called()


def test_integer_parameter_manifest_stays_numeric():
    for params_class, field in (
        (GetAttributesParams, "event_id"),
        (UpdateEventParams, "event_id"),
        (RunQueryParams, "max_results"),
    ):
        assert params_class._to_json_schema()[field]["data_type"] == "numeric"


def test_output_manifest_types_match_misp_api():
    module = import_module("src.actions.create_event")
    query_fields = {
        field["data_path"]: field["data_type"]
        for field in RunQueryOutput._to_json_schema()
    }
    create_fields = {
        field["data_path"]: field["data_type"]
        for field in module.CreateEventOutput._to_json_schema()
    }

    assert query_fields["action_result.data.*.Attribute.*.deleted"] == "boolean"
    assert (
        query_fields["action_result.data.*.Attribute.*.disable_correlation"]
        == "boolean"
    )
    assert create_fields["action_result.data.*.publish_timestamp"] == "string"
