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


class PartialIOCError(RuntimeError):
    """An IOC write failed after zero or more earlier writes succeeded."""

    def __init__(self, message: str, completed_rows: list[dict]):
        super().__init__(message)
        self.completed_rows = completed_rows


def misp_client(asset):
    """Build an HTTP client using the SDK's static-token auth handler."""
    import httpx  # noqa: PLC0415
    from soar_sdk.auth import StaticTokenAuth  # noqa: PLC0415

    return httpx.Client(
        auth=StaticTokenAuth(asset.api_key, token_type=""),
        verify=asset.verify_server_cert,
        timeout=60,
    )


def request(asset, method: str, endpoint: str, *, payload=None, params=None):
    """Call the MISP REST API and return decoded JSON."""
    base_url = asset.base_url.rstrip("/")
    with misp_client(asset) as client:
        response = client.request(
            method,
            f"{base_url}{endpoint}",
            headers={"Accept": "application/json"},
            json=payload,
            params=params,
        )
    try:
        body = response.json()
    except ValueError as exc:
        raise RuntimeError(f"MISP returned HTTP {response.status_code}: {response.text[:1000]}") from exc
    # Match requests.Response.ok semantics used by the legacy connector while
    # avoiding that requests-only property on an httpx.Response.
    if response.status_code >= 400:
        raise RuntimeError(f"MISP returned HTTP {response.status_code}: {body}")
    response_body = body.get("response") if isinstance(body, dict) else None
    response_body = response_body if isinstance(response_body, dict) else body
    errors = body.get("errors") if isinstance(body, dict) else None
    errors = errors or (
        response_body.get("errors") if isinstance(response_body, dict) else None
    )
    if errors:
        raise RuntimeError(f"MISP error: {errors}")
    saved_false = (
        isinstance(body, dict)
        and body.get("saved") is False
        or isinstance(response_body, dict)
        and response_body.get("saved") is False
    )
    if saved_false:
        message = (
            response_body.get("message")
            if isinstance(response_body, dict)
            else None
        )
        raise RuntimeError(
            "MISP did not save the requested change: "
            f"{message or body}"
        )
    return body


def output(model, payload):
    """Build an SDK output while retaining the source connector's JSON shape."""
    if isinstance(payload, dict) and isinstance(payload.get("response"), dict):
        payload = payload["response"]
    if not isinstance(payload, dict):
        payload = {"result": payload}
    return model.model_construct(**payload)


def split_values(value):
    """Split IOC inputs using the connector's comma/semicolon conventions."""
    if not value:
        return []
    separator = ";" if ";" in value else ","
    return [item.strip() for item in value.split(separator) if item.strip()]


def positive_int(value, field_name):
    """Parse a legacy-compatible positive integer parameter without truncation."""
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a positive integer") from exc
    if not numeric.is_integer() or numeric <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return int(numeric)


def add_iocs(asset, event_id, params):
    """Add the supplied IOC parameters to an event."""
    from soar_sdk.shims.phantom import utils as phantom_utils  # noqa: PLC0415

    mapping = (
        ("source_ips", "ip-src", "ip"),
        ("dest_ips", "ip-dst", "ip"),
        ("domains", "domain", "domain"),
        ("urls", "url", "url"),
        ("dest_emails", "email-dst", "email"),
        ("source_emails", "email-src", "email"),
    )
    to_ids = bool(getattr(params, "to_ids", False))
    completed_rows = []

    def submit_row(row):
        try:
            response = request(
                asset,
                "POST",
                f"/attributes/add/{event_id}",
                payload=row,
            )
        except Exception as exc:
            raise PartialIOCError(str(exc), completed_rows.copy()) from exc

        response_data = response.get("response", response) if isinstance(response, dict) else None
        returned_attribute = (
            response_data.get("Attribute", response_data)
            if isinstance(response_data, dict)
            else None
        )
        if isinstance(row, dict) and isinstance(returned_attribute, dict):
            attribute_fields = {
                "category",
                "comment",
                "deleted",
                "disable_correlation",
                "distribution",
                "event_id",
                "first_seen",
                "id",
                "last_seen",
                "object_id",
                "object_relation",
                "sharing_group_id",
                "timestamp",
                "to_ids",
                "type",
                "uuid",
                "value",
            }
            row.update(
                {
                    key: value
                    for key, value in returned_attribute.items()
                    if key in attribute_fields
                }
            )
        completed_rows.append(row)

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
            raise PartialIOCError(f"'{key}'", completed_rows.copy())
        for value in values:
            submit(attribute_type, value)

    extra = getattr(params, "json", None)
    if extra:
        try:
            parsed = json.loads(extra)
        except (TypeError, ValueError) as exc:
            raise PartialIOCError(
                f"Invalid JSON parameter: {exc}", completed_rows.copy()
            ) from exc
        if isinstance(parsed, list):
            for row in parsed:
                submit_row(row)
        elif isinstance(parsed, dict):
            for attribute_type, raw_values in parsed.items():
                values = (
                    raw_values
                    if isinstance(raw_values, list)
                    else split_values(str(raw_values))
                )
                for value in values:
                    submit(attribute_type, value)
        else:
            raise PartialIOCError("Invalid JSON parameter", completed_rows.copy())
    return completed_rows


def _valid_ip(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def add_tags(asset, event_id, value):
    for tag in split_values(value):
        request(asset, "POST", f"/events/addTag/{event_id}", payload={"tag": tag})
