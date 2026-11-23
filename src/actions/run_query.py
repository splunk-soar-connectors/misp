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
import json
from collections import deque
from concurrent.futures import ThreadPoolExecutor, wait

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params
from ..app import Asset, app, logger
from ..helper import integer_value, output, positive_int, request

_QUERY_PROGRESS_INTERVAL = 30


def _request_query_page(asset, controller, payload):
    """Keep IPC progress on the action thread while the HTTP request runs."""
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(
            request,
            asset,
            "POST",
            f"/{controller}/restSearch",
            payload=payload,
            timeout=60,
        )
        while not wait((pending,), timeout=_QUERY_PROGRESS_INTERVAL).done:
            logger.progress("Waiting for MISP %s page %s", controller, payload["page"])
        return pending.result()


class RunQueryParams(Params):
    controller: str = Param(
        description="Search for events or attributes",
        value_list=["events", "attributes"],
    )
    max_results: int | None = Param(description="Max results to return", default=10)
    event_id: str | None = Param(
        description="Comma seperated list of Event IDs",
        primary=True,
        cef_types=["misp event id"],
    )
    tags: str | None = Param(description="Comma seperated list of tags")
    other: str | None = Param(description="Other search parameters, as a JSON object")


class EventOutput(ActionOutput):
    distribution: str = OutputField(example_values=["1"])
    id: str = OutputField(example_values=["2020"])
    info: str = OutputField(example_values=["Event created by test"])
    org_id: str = OutputField(example_values=["1"])
    orgc_id: str = OutputField(example_values=["1"])
    uuid: str = OutputField(example_values=["342c12ab-32ad-41d0-aea2-1c3dccc6ce09"])


class ObjectOutput(ActionOutput):
    distribution: str = OutputField(example_values=["5"])
    id: str = OutputField(example_values=["10"])
    sharing_group_id: str = OutputField(example_values=["0"])


class AttributeOutput(ActionOutput):
    Event: EventOutput
    Object: ObjectOutput
    category: str = OutputField(example_values=["Other", "Payload delivery"])
    comment: str
    deleted: bool
    disable_correlation: bool = OutputField(example_values=[False, True])
    distribution: str = OutputField(example_values=["5"])
    event_id: str = OutputField(cef_types=["misp event id"], example_values=["1"])
    first_seen: str
    id: str = OutputField(cef_types=["misp attribute id"], example_values=["164201"])
    last_seen: str
    object_id: str = OutputField(example_values=["0", "10"])
    object_relation: str = OutputField(example_values=["filename"])
    sharing_group_id: str = OutputField(example_values=["0"])
    timestamp: str = OutputField(example_values=["1498505296"])
    to_ids: bool
    type: str = OutputField(example_values=["comment", "filename"])
    uuid: str = OutputField(example_values=["56e96919-ad18-4f68-8aa1-539002de0b81"])
    value: str = OutputField(
        cef_types=["url", "domain", "ip", "email", "hash", "md5", "sha256", "md1"],
        example_values=["email1@gmail.com"],
    )


class QueryEventDetails(PermissiveActionOutput):
    """MISP event search rows can include variable nested event data."""

    distribution: str = OutputField(example_values=["1"])
    id: str = OutputField(example_values=["2020"])
    info: str = OutputField(example_values=["Event created by test"])
    org_id: str = OutputField(example_values=["1"])
    orgc_id: str = OutputField(example_values=["1"])
    uuid: str = OutputField(example_values=["342c12ab-32ad-41d0-aea2-1c3dccc6ce09"])


class RunQueryOutput(PermissiveActionOutput):
    """Search output varies with the selected MISP controller."""

    Event: QueryEventDetails | None = None
    Attribute: list[AttributeOutput] | None = None
    attribute_count: str | None = OutputField(example_values=["103"])


class RunQuerySummary(ActionOutput):
    returned_rows: int


@app.action(
    description="Run a query to find events or attributes",
    action_type="investigate",
    render_as="json",
    summary_type=RunQuerySummary,
    verbose=(
        "By default, returns the first 10 matches. Set <b>max_results</b> to 0 for no requested cap "
        "or to -N for the last N matches. The connector requests up to 1,000 results per page, "
        "subject to MISP limits, and fails if the search is incomplete after 100 pages. "
        "Pass additional MISP filters as JSON in <b>other</b>."
    ),
)
def run_query(
    params: RunQueryParams, soar: SOARClient, asset: Asset
) -> list[RunQueryOutput]:
    limit = params.max_results
    if limit is None or limit == "":
        limit = 10
    max_results = integer_value(limit, "max_results")
    filters = {}
    if params.event_id:
        ids = [item.strip() for item in params.event_id.split(",") if item.strip()]
        ids = [positive_int(event_id, "event_id") for event_id in ids]
        if ids:
            filters["eventid"] = ids if len(ids) > 1 else ids[0]
    if params.tags:
        filters["tags"] = [
            item.strip() for item in params.tags.split(",") if item.strip()
        ]
    if params.other:
        other = json.loads(params.other)
        if not isinstance(other, dict):
            raise ValueError("other must be a JSON object")
        filters.update(other)
    controller = params.controller.lower()
    if controller not in {"events", "attributes"}:
        raise ValueError("controller must be events or attributes")
    # The legacy connector let `other` override event IDs and tags, but it
    # always reset limit and page for its own bounded pagination loop.
    filters["returnFormat"] = "json"
    filters["limit"] = min(max_results, 1000) if max_results > 0 else 1000
    rows = deque(maxlen=abs(max_results)) if max_results < 0 else []
    for page in range(1, 101):
        logger.progress("Fetching MISP %s page %s", controller, page)
        result = _request_query_page(
            asset,
            controller,
            {**filters, "page": page},
        )
        batch = result.get("response", result) if isinstance(result, dict) else result
        if isinstance(batch, dict):
            batch = batch.get(
                "Attribute" if controller == "attributes" else "Event", []
            )
        if isinstance(batch, dict):
            batch = [batch]
        if not isinstance(batch, list):
            raise RuntimeError("MISP returned an unexpected search response shape")
        logger.progress("Received %s results from MISP page %s", len(batch), page)
        if not batch:
            break
        rows.extend(batch)
        if max_results > 0 and len(rows) >= max_results:
            rows = rows[:max_results]
            break
    else:
        raise RuntimeError("MISP query exceeded the maximum of 100 pages")
    if max_results < 0:
        rows = list(rows)
    result_key = "Event" if controller == "events" else "Attribute"
    soar.set_summary(RunQuerySummary(returned_rows=len(rows)))
    soar.set_message("Successfully ran query")
    if controller == "events":
        event_rows = [
            row if isinstance(row, dict) and "Event" in row else {"Event": row}
            for row in rows
        ]
        return [output(RunQueryOutput, row) for row in event_rows]
    return [
        output(
            RunQueryOutput,
            {result_key: rows, "attribute_count": str(len(rows))},
        )
    ]
