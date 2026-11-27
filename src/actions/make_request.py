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
"""Send a custom REST request to the configured MISP server."""

import json
from urllib.parse import urlsplit

from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams

from ..asset import Asset
from ..helper import misp_client


class MakeRequestOutput(ActionOutput):
    status_code: int = OutputField()
    response: str = OutputField()


def make_request(params: MakeRequestParams, asset: Asset) -> MakeRequestOutput:
    """Send a custom REST request to the configured MISP server."""
    import httpx2

    endpoint = params.endpoint.strip()
    if not endpoint.startswith("/") or endpoint.startswith("//"):
        raise ActionFailure("endpoint must be a relative MISP path starting with '/'")
    if ".." in urlsplit(endpoint).path.split("/"):
        raise ActionFailure("endpoint cannot contain parent-directory path segments")

    method = params.http_method.upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise ActionFailure("Unsupported HTTP method")
    if params.timeout is not None and params.timeout <= 0:
        raise ActionFailure("timeout must be positive")

    try:
        payload = json.loads(params.body) if params.body else None
        headers = json.loads(params.headers) if params.headers else {}
    except ValueError as exc:
        raise ActionFailure("headers and body must contain valid JSON") from exc
    if not isinstance(headers, dict) or any(
        not isinstance(value, str) for value in headers.values()
    ):
        raise ActionFailure("headers must be a JSON object with string values")
    if any(name.lower() in {"authorization", "host"} for name in headers):
        raise ActionFailure("Authorization and Host are set by the MISP asset")

    query_params = _parse_query_parameters(params.query_parameters)
    url = httpx2.URL(f"{asset.base_url.rstrip('/')}{endpoint}")
    query_pairs = list(url.params.multi_items())
    query_pairs.extend(httpx2.QueryParams(query_params).multi_items())
    url = url.copy_with(params=httpx2.QueryParams(query_pairs))

    request_headers = httpx2.Headers({"Accept": "application/json"})
    request_headers.update(headers)
    verify_ssl = params.verify_ssl if "verify_ssl" in params.model_fields_set else None
    try:
        with misp_client(
            asset, verify_ssl=verify_ssl, timeout=params.timeout
        ) as client:
            response = client.request(
                method, url, headers=request_headers, json=payload
            )
    except httpx2.RequestError as exc:
        raise ActionFailure(f"Unable to connect to MISP: {exc}") from exc
    try:
        body = json.dumps(response.json())
    except ValueError:
        body = response.text
    return MakeRequestOutput(status_code=response.status_code, response=body)


def _parse_query_parameters(value: str | None) -> dict | str | None:
    if not value:
        return None
    value = value.strip()
    if value.startswith("?") or (
        "=" in value and not value.startswith(("{", "[", '"'))
    ):
        return value.removeprefix("?")
    error = "query_parameters must be a JSON object or a query string"
    try:
        query = json.loads(value)
    except ValueError as exc:
        raise ActionFailure(error) from exc
    if query is not None and not isinstance(query, dict):
        raise ActionFailure(error)
    return query
