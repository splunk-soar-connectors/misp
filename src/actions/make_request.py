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

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import misp_client


class MakeRequestParams(Params):
    endpoint: str = Param(
        description="Relative MISP API endpoint, for example /servers/getPyMISPVersion.json",
        required=True,
    )
    method: str = Param(
        description="HTTP method",
        default="GET",
        value_list=["GET", "POST", "PUT", "PATCH", "DELETE"],
    )
    payload: str | None = Param(
        description="Optional JSON request body",
    )
    query_params: str | None = Param(
        description="Optional JSON object of URL query parameters",
    )


class MakeRequestOutput(ActionOutput):
    status_code: int = OutputField()
    response: str = OutputField()


@app.action(
    name="make request",
    description="Send a custom REST request to the configured MISP server",
    action_type="generic",
    read_only=False,
    params_class=MakeRequestParams,
    output_class=MakeRequestOutput,
)
def make_request(
    params: MakeRequestParams, soar: SOARClient, asset: Asset
) -> MakeRequestOutput:
    """Make an authenticated request to a relative MISP API endpoint."""
    import httpx
    from urllib.parse import urlsplit

    endpoint = params.endpoint.strip()
    parsed_endpoint = urlsplit(endpoint)
    if not endpoint.startswith("/") or parsed_endpoint.scheme or parsed_endpoint.netloc:
        raise ValueError("endpoint must be a relative MISP path starting with '/'")
    if ".." in parsed_endpoint.path.split("/"):
        raise ValueError("endpoint cannot contain parent-directory path segments")

    method = params.method.upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("Unsupported HTTP method")

    payload = json.loads(params.payload) if params.payload else None
    query_params = json.loads(params.query_params) if params.query_params else None
    if query_params is not None and not isinstance(query_params, dict):
        raise ValueError("query_params must be a JSON object")

    url = httpx.URL(f"{asset.base_url.rstrip('/')}{endpoint}")
    query_pairs = list(url.params.multi_items())
    if query_params:
        query_pairs.extend(httpx.QueryParams(query_params).multi_items())
    url = url.copy_with(params=httpx.QueryParams(query_pairs))

    with misp_client(asset) as client:
        response = client.request(
            method,
            url,
            headers={"Accept": "application/json"},
            json=payload,
        )
    try:
        body = json.dumps(response.json())
    except ValueError:
        body = response.text
    return MakeRequestOutput(status_code=response.status_code, response=body)
