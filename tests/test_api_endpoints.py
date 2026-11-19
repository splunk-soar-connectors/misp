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

from importlib import import_module
from unittest.mock import Mock
from urllib.parse import urlparse

from pymisp import MISPEvent, PyMISP


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
    module.test_connectivity.__wrapped__(Mock(), Mock())
    module = import_module("src.actions.get_attributes")
    monkeypatch.setattr(module, "request", request)
    module.get_event.__wrapped__(
        module.GetAttributesParams(event_id=42), Mock(), Mock()
    )
    module = import_module("src.actions.run_query")
    monkeypatch.setattr(module, "request", request)
    for controller in ("events", "attributes"):
        module.run_query.__wrapped__(
            module.RunQueryParams(controller=controller, max_results=1), Mock(), Mock()
        )

    assert calls == [
        ("GET", "/servers/getPyMISPVersion.json"),
        ("GET", "/events/view/42"),
        ("POST", "/attributes/restSearch"),
        ("POST", "/events/restSearch"),
        ("POST", "/attributes/restSearch"),
    ]
