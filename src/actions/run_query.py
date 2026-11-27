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
from csv import DictReader, Error as CSVError
from io import StringIO

from pydantic import model_serializer
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params
from ..asset import Asset
from ..helper import integer_value, misp_client, output, positive_int, request

logger = getLogger()

_QUERY_PROGRESS_INTERVAL = 30

_PYMISP_SEARCH_ALIASES = {
    "type_attribute": "type",
    "quick_filter": "quickFilter",
    "date_from": "from",
    "date_to": "to",
    "with_attachments": "withAttachments",
    "last": "publish_timestamp",
    "enforce_warninglist": "enforceWarninglist",
    "include_event_uuid": "includeEventUuid",
    "include_event_tags": "includeEventTags",
    "sg_reference_only": "sgReferenceOnly",
    "include_context": "includeContext",
    "include_sightings": "includeSightings",
    "include_decay_score": "includeDecayScore",
    "include_correlations": "includeCorrelations",
    "exclude_decayed": "excludeDecayed",
}
_PYMISP_DEPRECATED_REST_KEYS = {
    "quickFilter",
    "withAttachments",
    "enforceWarninglist",
    "includeEventUuid",
    "includeEventTags",
    "includeContext",
    "includeSightings",
    "includeDecayScore",
    "includeCorrelations",
}
_PYMISP_INTEGER_FLAGS = (
    "withAttachments",
    "metadata",
    "enforceWarninglist",
    "includeEventUuid",
    "includeEventTags",
    "sgReferenceOnly",
    "includeContext",
    "headerless",
    "includeSightings",
    "includeDecayScore",
    "includeCorrelations",
    "excludeDecayed",
)


def _normalize_search_filters(filters, *, allow_csv: bool):
    """Translate legacy PyMISP search options to the REST payload."""
    explicit_return_format = "return_format" in filters
    return_format = filters.pop("return_format", "json")
    pythonify = filters.pop("pythonify", None)
    if return_format != "json" and not (
        return_format == "csv" and allow_csv and pythonify is True
    ):
        raise ActionFailure(
            "other.return_format must be 'json' unless CSV is requested with pythonify "
            "set to true and events selected in controller or other.controller. "
            "Object searches require JSON. Use Make Request for other formats."
        )
    # PyMISP gives the explicit return_format argument precedence over the REST key.
    rest_format = filters.pop("returnFormat", "json")
    if not explicit_return_format and rest_format != "json":
        raise ActionFailure(
            "other.returnFormat must be 'json'. Use Make Request for other formats."
        )
    if return_format == "json" and pythonify is not None and pythonify is not False:
        raise ActionFailure(
            "other.pythonify must be false or null. Run Query returns JSON data."
        )

    for alias, key in _PYMISP_SEARCH_ALIASES.items():
        value = filters.pop(alias, None)
        # PyMISP lets its deprecated REST-spelled arguments override newer ones.
        if value is not None and (
            key not in _PYMISP_DEPRECATED_REST_KEYS or filters.get(key) is None
        ):
            filters[key] = value

    for key in _PYMISP_INTEGER_FLAGS:
        value = filters.get(key)
        if value is not None:
            try:
                flag = int(value)
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError(f"Invalid MISP search flag: {key}") from exc
            filters[key] = 1 if flag else 0

    if return_format == "csv":
        if filters.get("headerless"):
            raise ActionFailure(
                "Run Query requires CSV headers. Set other.headerless to false."
            )
        filters["headerless"] = 0
    filters["returnFormat"] = return_format
    return filters


def _request_csv_page(asset, method, endpoint, *, payload, timeout):
    with misp_client(asset) as client:
        response = client.request(
            method,
            f"{asset.base_url.rstrip('/')}{endpoint}",
            # MISP uses returnFormat to select the export, as in the PyMISP request.
            headers={"Accept": "application/json"},
            json=payload,
            timeout=timeout,
        )
    if not response.is_success:
        raise ActionFailure(
            f"MISP returned HTTP {response.status_code}: {response.text[:1000]}"
        )

    body = response.text.removeprefix("\ufeff")
    error = f"MISP returned an invalid CSV response for page {payload['page']}"
    if body.lstrip().startswith(("<", "{", "[")):
        raise ActionFailure(error)
    reader = DictReader(StringIO(body, newline=""), strict=True)
    try:
        rows = list(reader)
    except CSVError as exc:
        raise ActionFailure(error) from exc
    if not reader.fieldnames or any(not field.strip() for field in reader.fieldnames):
        raise ActionFailure(error)
    if any(None in row or None in row.values() for row in rows):
        raise ActionFailure(error)
    return rows


def _request_query_page(asset, controller, payload):
    """Keep IPC progress on the action thread while the HTTP request runs."""
    request_page = (
        _request_csv_page if payload.get("returnFormat") == "csv" else request
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(
            request_page,
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


class QueryAttributeDetails(ActionOutput):
    category: str = OutputField(example_values=["Payload delivery"])
    comment: str
    deleted: int = OutputField(example_values=[True, False])
    disable_correlation: int = OutputField(example_values=[True, False])
    distribution: str = OutputField(example_values=["5"])
    event_id: str = OutputField(example_values=["2020"])
    first_seen: str
    id: str = OutputField(example_values=["4953"])
    last_seen: str
    object_id: str = OutputField(example_values=["10"])
    object_relation: str = OutputField(example_values=["filename"])
    sharing_group_id: str = OutputField(example_values=["0"])
    timestamp: str = OutputField(example_values=["1623078296"])
    to_ids: int = OutputField(example_values=[True, False])
    type: str = OutputField(example_values=["filename"])
    uuid: str = OutputField(example_values=["2fd53a9b-44fd-4ebc-af93-0e1605cf3b64"])
    value: str = OutputField(
        cef_types=["url", "domain", "ip", "email", "hash", "md5", "sha256", "md1"],
        example_values=["6.43.3.2"],
    )


class QueryEventAttributeOutput(QueryAttributeDetails):
    type: str = OutputField(cef_types=["url"], example_values=["email-dst"])


class QueryEventObjectOutput(ObjectOutput):
    Attribute: list[QueryAttributeDetails]
    comment: str
    deleted: int = OutputField(example_values=[True, False])
    description: str = OutputField(
        example_values=["File object describing a file with meta-information"]
    )
    event_id: str = OutputField(example_values=["2020"])
    first_seen: str
    last_seen: str
    meta_category: str = OutputField(alias="meta-category", example_values=["file"])
    name: str = OutputField(example_values=["file"])
    template_uuid: str = OutputField(
        example_values=["688c46fb-5edb-40a3-8273-1af7923e2215"]
    )
    template_version: str = OutputField(example_values=["24"])
    timestamp: str = OutputField(example_values=["1623078296"])
    uuid: str = OutputField(example_values=["4b5cb238-9e55-40eb-b60e-b30f71cab6f6"])


class RelatedEventOrgOutput(ActionOutput):
    id: str = OutputField(example_values=["1"])
    name: str = OutputField(example_values=["ORGNAME"])
    uuid: str = OutputField(example_values=["2af87aa3-a713-4ca5-83f7-03ae949c8459"])


class QueryEventOrgOutput(RelatedEventOrgOutput):
    local: int = OutputField(example_values=[True, False])


class RelatedEventDetails(EventOutput):
    Org: RelatedEventOrgOutput
    Orgc: RelatedEventOrgOutput
    analysis: str = OutputField(example_values=["0"])
    date: str = OutputField(example_values=["2021-06-14"])
    published: int = OutputField(example_values=[True, False])
    threat_level_id: str = OutputField(example_values=["4"])
    timestamp: str = OutputField(example_values=["1623645286"])


class RelatedEventOutput(ActionOutput):
    Event: RelatedEventDetails


class QueryEventTagOutput(ActionOutput):
    colour: str = OutputField(example_values=["#7ab870"])
    exportable: int = OutputField(example_values=[True, False])
    hide_tag: int = OutputField(example_values=[True, False])
    id: str = OutputField(example_values=["8"])
    is_custom_galaxy: int = OutputField(example_values=[True, False])
    is_galaxy: int = OutputField(example_values=[True, False])
    local: int = OutputField(example_values=[1])
    name: str = OutputField(example_values=["test_1"])
    numerical_value: str
    user_id: str = OutputField(example_values=["1"])


class QueryEventDetails(RelatedEventDetails):
    """Declare the legacy event datapaths and types for the SOAR manifest."""

    Attribute: list[QueryEventAttributeOutput]
    Object: list[QueryEventObjectOutput]
    Org: QueryEventOrgOutput
    Orgc: QueryEventOrgOutput
    RelatedEvent: list[RelatedEventOutput]
    Tag: list[QueryEventTagOutput]
    attribute_count: str = OutputField(example_values=["7"])
    disable_correlation: int = OutputField(example_values=[True, False])
    event_creator_email: str = OutputField(
        cef_types=["email"], example_values=["test@test.com"]
    )
    extends_uuid: str
    locked: int = OutputField(example_values=[True, False])
    proposal_email_lock: int = OutputField(example_values=[True, False])
    publish_timestamp: str = OutputField(example_values=["0"])
    sharing_group_id: str = OutputField(example_values=["0"])


class QueryEventRow(ActionOutput):
    Event: QueryEventDetails


class QueryEventRows(ActionOutput):
    rows: list[dict]

    @model_serializer
    def serialize_rows(self) -> list[dict]:
        """Emit the complete list as one SOAR data item, matching legacy output."""
        return self.rows


class RunQueryOutput(PermissiveActionOutput):
    """Search output varies with the selected MISP controller."""

    # The event-mode data item is a list, so its first datapath segment is an index.
    event_row: QueryEventRow | None = OutputField(alias="*")
    Attribute: list[AttributeOutput] | None = None
    attribute_count: str | None = OutputField(example_values=["103"])


class RunQuerySummary(ActionOutput):
    returned_rows: int


def run_query(params: RunQueryParams, soar: SOARClient, asset: Asset):
    limit = params.max_results
    if limit is None or limit == "":
        limit = 10
    max_results = integer_value(limit, "max_results")
    filters = {"returnFormat": "json"}
    if params.event_id:
        ids = [item.strip() for item in params.event_id.split(",") if item.strip()]
        ids = [positive_int(event_id, "event_id") for event_id in ids]
        if ids:
            filters["eventid"] = ids if len(ids) > 1 else ids[0]
    if params.tags:
        filters["tags"] = [
            item.strip() for item in params.tags.split(",") if item.strip()
        ]
    requested_controller = params.controller.lower()
    controller = requested_controller
    if controller not in {"events", "attributes"}:
        raise ValueError("controller must be events or attributes")
    if params.other:
        other = json.loads(params.other)
        if not isinstance(other, dict):
            raise ValueError("other must be a JSON object")
        controller = other.pop("controller", controller)
        if controller not in ("events", "attributes", "objects"):
            raise ActionFailure(
                "other.controller must be events, attributes, or objects"
            )
        filters.update(
            _normalize_search_filters(
                other,
                allow_csv=controller != "objects"
                and "events" in (requested_controller, controller),
            )
        )
    # The legacy connector let `other` override event IDs and tags, but it
    # always reset limit and page for its own bounded pagination loop.
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
        if isinstance(batch, dict) and controller != "objects":
            batch = batch.get("Attribute" if controller == "attributes" else "Event")
            if isinstance(batch, dict):
                batch = [batch]
        if not isinstance(batch, list) or any(
            not isinstance(row, dict) for row in batch
        ):
            raise RuntimeError(
                f"MISP returned an unexpected search response shape for {controller} page {page}"
            )
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
    soar.set_summary(RunQuerySummary(returned_rows=len(rows)))
    soar.set_message("Successfully ran query")
    if controller == "objects" or filters["returnFormat"] == "csv":
        return QueryEventRows(rows=rows)
    if controller == "events":
        event_rows = [
            row if isinstance(row, dict) and "Event" in row else {"Event": row}
            for row in rows
        ]
        return QueryEventRows(rows=event_rows)
    return [
        output(
            RunQueryOutput,
            {"Attribute": rows, "attribute_count": str(len(rows))},
        )
    ]
