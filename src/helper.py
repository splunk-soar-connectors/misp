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
"""Shared MISP REST helpers."""

from __future__ import annotations

import ipaddress
import json
import re
from copy import deepcopy

from soar_sdk.action_results import PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure


def misp_client(asset):
    """Build an HTTP client using the SDK's static-token auth handler."""
    import httpx2
    from soar_sdk.auth import StaticTokenAuth

    return httpx2.Client(
        auth=StaticTokenAuth(asset.api_key, token_type=""),
        verify=asset.verify_server_cert,
        timeout=60,
    )


def request(
    asset,
    method: str,
    endpoint: str,
    *,
    payload=None,
    params=None,
    timeout: float | None = 60,
    require_success: bool = False,
):
    """Call the MISP REST API and return decoded JSON."""
    base_url = asset.base_url.rstrip("/")
    with misp_client(asset) as client:
        response = client.request(
            method,
            f"{base_url}{endpoint}",
            headers={"Accept": "application/json"},
            json=payload,
            params=params,
            timeout=timeout,
        )
    try:
        body = response.json()
    except ValueError as exc:
        raise RuntimeError(
            f"MISP returned HTTP {response.status_code}: {response.text[:1000]}"
        ) from exc
    if response.status_code >= 400 or (
        require_success and not 200 <= response.status_code < 300
    ):
        raise RuntimeError(f"MISP returned HTTP {response.status_code}: {body}")
    response_body = body.get("response") if isinstance(body, dict) else None
    response_body = response_body if isinstance(response_body, dict) else body
    errors = body.get("errors") if isinstance(body, dict) else None
    errors = errors or (
        response_body.get("errors") if isinstance(response_body, dict) else None
    )
    if errors:
        raise RuntimeError(f"MISP error: {errors}")
    saved_false = (isinstance(body, dict) and body.get("saved") is False) or (
        isinstance(response_body, dict) and response_body.get("saved") is False
    )
    if saved_false:
        message = (
            response_body.get("message") if isinstance(response_body, dict) else None
        )
        raise RuntimeError(f"MISP did not save the requested change: {message or body}")
    return body


def output(model, payload):
    """Build an SDK output while retaining the source connector's JSON shape."""
    if isinstance(payload, dict) and isinstance(payload.get("response"), dict):
        payload = payload["response"]
    if not isinstance(payload, dict):
        payload = {"result": payload}
    if issubclass(model, PermissiveActionOutput):
        # The constructor initializes the raw payload used by SDK serialization.
        return model(**payload)
    return model.model_construct(**payload)


def split_values(value):
    """Split IOC inputs using the connector's comma/semicolon conventions."""
    if not value:
        return []
    return [item for raw_item in re.split(r"[,;]", value) if (item := raw_item.strip())]


def integer_value(value, field_name):
    """Parse the original value without float rounding or fractional truncation."""
    try:
        if not isinstance(value, int | float | str):
            raise ValueError("Unsupported integer value")
        if isinstance(value, float) and not value.is_integer():
            raise ValueError("Fractional or non-finite value")
        return int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc


def positive_int(value, field_name):
    """Parse a positive integer without converting through float."""
    numeric = integer_value(value, field_name)
    if numeric <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return numeric


def add_iocs(asset, event_id, params, *, event, confirmed_rows=None, errors=None):
    """Append attributes, collecting definite JSON row rejections when requested."""
    from soar_sdk.shims.phantom import utils as phantom_utils

    mapping = (
        ("source_ips", "ip-src", "ip"),
        ("dest_ips", "ip-dst", "ip"),
        ("domains", "domain", "domain"),
        ("urls", "url", "url"),
        ("dest_emails", "email-dst", "email"),
        ("source_emails", "email-src", "email"),
    )
    to_ids = bool(getattr(params, "to_ids", False))
    saved_rows = None
    current_event = None

    def attribute_failure(message):
        if saved_rows is not None:
            message += " MISP accepted an earlier attribute update."
        return ActionFailure(message)

    def submit_row(row, *, collect_rejection=False):
        from pymisp import MISPEvent

        nonlocal current_event, saved_rows
        try:
            candidate = MISPEvent()
            if current_event is None:
                # PyMISP can reuse empty lists; keep SDK output free of model objects.
                candidate.load(deepcopy(event))
            else:
                candidate.load(json.loads(current_event.to_json()))
            try:
                candidate.add_attribute(**row)
            except Exception as exc:
                if collect_rejection and errors is not None:
                    errors.append(str(exc))
                    return
                raise attribute_failure(str(exc)) from exc
            try:
                response = request(
                    asset,
                    "POST",
                    f"/events/edit/{candidate.uuid}",
                    payload=json.loads(candidate.to_json()),
                )
            except RuntimeError as exc:
                message = str(exc)
                rejected = message.startswith(
                    (
                        "MISP error:",
                        "MISP did not save the requested change:",
                        "MISP returned HTTP 400:",
                        "MISP returned HTTP 422:",
                    )
                )
                if collect_rejection and errors is not None and rejected:
                    errors.append(message)
                    return
                raise
            updated_event = MISPEvent()
            updated_event.load(response)
            if str(updated_event.id) != str(event_id):
                raise ValueError(
                    "MISP returned an unexpected event ID after updating attributes"
                )
            current_event = updated_event
            # Event edits return the complete saved event. Retain exactly those
            # attributes; do not infer that a submitted duplicate was changed.
            saved_rows = json.loads(current_event.to_json()).get("Attribute", [])
            if confirmed_rows is not None:
                confirmed_rows[:] = saved_rows
        except Exception as exc:
            if isinstance(exc, ActionFailure):
                raise
            raise attribute_failure(str(exc)) from exc

    def submit(attribute_type, value):
        submit_row({"type": attribute_type, "value": value, "to_ids": to_ids})

    validators = {
        "ip": _valid_ip,
        "domain": phantom_utils.is_domain,
        "email": phantom_utils.is_email,
        "url": phantom_utils.is_url,
    }
    for key, attribute_type, validation_type in mapping:
        values = split_values(getattr(params, key, None))
        if values and not all(validators[validation_type](value) for value in values):
            raise attribute_failure(f"'{key}'")
        for value in values:
            submit(attribute_type, value)

    extra = getattr(params, "json", None)
    if extra:
        try:
            parsed = json.loads(extra)
        except (TypeError, ValueError) as exc:
            raise attribute_failure(f"Invalid JSON parameter: {exc}") from exc
        if isinstance(parsed, list):
            for row in parsed:
                submit_row(row, collect_rejection=True)
        elif isinstance(parsed, dict):
            for attribute_type, raw_values in parsed.items():
                values = (
                    raw_values
                    if isinstance(raw_values, list)
                    else split_values(str(raw_values))
                )
                for value in values:
                    submit_row(
                        {
                            "type": attribute_type,
                            "value": value,
                            "to_ids": to_ids,
                        },
                        collect_rejection=True,
                    )
        else:
            raise attribute_failure("Invalid JSON parameter")
    return saved_rows or []


def _valid_ip(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def add_tags(asset, event_identifier, value, *, existing_tags=(), event_id=None):
    """Attach each requested global tag once, preserving existing associations."""
    attached = set()
    for tag in existing_tags:
        # A local association does not satisfy this connector's global-tag request.
        if tag.get("local", 0) in (True, 1, "1"):
            continue
        attached.update(
            str(tag[key]) for key in ("id", "name") if tag.get(key) is not None
        )
    requested_tags = split_values(value)
    if not requested_tags:
        return
    local_conflicts = [
        requested_tag
        for requested_tag in requested_tags
        if any(
            tag.get("local", 0) in (True, 1, "1")
            and (
                str(tag.get("id", "")) == requested_tag
                if requested_tag.isdecimal()
                else str(tag.get("name", "")).casefold() == requested_tag.casefold()
            )
            for tag in existing_tags
        )
    ]
    for tag in requested_tags:
        if tag in attached:
            continue
        request(
            asset,
            "POST",
            "/tags/attachTagToObject",
            payload={"uuid": str(event_identifier), "tag": tag, "local": False},
        )
        attached.add(tag)

    if local_conflicts:
        event_response = request(
            asset, "GET", f"/events/view/{event_id or event_identifier}"
        )
        event_data = event_response.get("Event", event_response)
        current_tags = event_data.get("Tag", []) if isinstance(event_data, dict) else []
        failures = []
        for requested_tag in local_conflicts:
            if requested_tag.isdecimal():
                matches = [
                    tag
                    for tag in current_tags
                    if str(tag.get("id", "")) == requested_tag
                ]
            else:
                matches = [
                    tag
                    for tag in current_tags
                    if str(tag.get("name", "")).casefold() == requested_tag.casefold()
                ]
            if any(tag.get("local") in (False, 0, "0") for tag in matches):
                continue
            if any(tag.get("local") in (True, 1, "1") for tag in matches):
                failures.append(f"{requested_tag} remains local")
            elif matches:
                failures.append(f"{requested_tag} scope could not be verified")
            else:
                failures.append(f"{requested_tag} is not attached")
        if failures:
            raise RuntimeError(
                "Global tag request made no change: " + "; ".join(failures)
            )
