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
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params
from ..app import Asset, app
from ..helper import (
    PartialIOCError,
    add_iocs,
    add_tags,
    output,
    positive_int,
    request,
    split_values,
)


class UpdateEventParams(Params):
    event_id: int = Param(
        description="MISP event ID for adding attributes",
        primary=True,
        cef_types=["misp event id"],
    )
    to_ids: bool | None = Param(
        description="Set 'to_IDS' flag=True in MISP", default=True
    )
    source_ips: str | None = Param(
        description="Source IPs to be added as attributes",
        primary=True,
        cef_types=["ip", "ipv6"],
        allow_list=True,
    )
    dest_ips: str | None = Param(
        description="Destination IPs to be added as attributes",
        primary=True,
        cef_types=["ip", "ipv6"],
        allow_list=True,
    )
    domains: str | None = Param(
        description="Domains to be added as attributes",
        primary=True,
        cef_types=["domain"],
        allow_list=True,
    )
    source_emails: str | None = Param(
        description="Source email addresses to be added as attributes",
        primary=True,
        cef_types=["email"],
        allow_list=True,
    )
    dest_emails: str | None = Param(
        description="Destination email addresses to be added as attributes",
        primary=True,
        cef_types=["email"],
        allow_list=True,
    )
    urls: str | None = Param(
        description="URLs to be added as attributes",
        primary=True,
        cef_types=["url"],
        allow_list=True,
    )
    tags: str | None = Param(
        description="Comma separated list of tags (append to existing tags default)"
    )
    replace_tags: bool | None = Param(
        description="Replace tags with new provided tags", default=False
    )
    json: str | None = Param(description="JSON key value list of attributes")


class UpdateEventOutput(ActionOutput):
    id: str = OutputField(
        column_name="MISP Attribute ID",
        cef_types=["misp attribute id"],
        example_values=["5360"],
    )
    value: str = OutputField(
        column_name="Attribute Value",
        cef_types=["url", "domain", "ip", "email", "hash", "md5", "sha256", "md1"],
        example_values=["email1@email.com"],
    )
    event_id: str = OutputField(
        column_name="MISP Event ID",
        cef_types=["misp event id"],
        example_values=["2121"],
    )
    category: str = OutputField(
        column_name="Attribute Category", example_values=["Other"]
    )
    distribution: str = OutputField(column_name="Distribution", example_values=["5"])
    comment: str
    deleted: bool
    disable_correlation: bool
    object_id: str = OutputField(example_values=["0"])
    sharing_group_id: str = OutputField(example_values=["0"])
    timestamp: str = OutputField(example_values=["1623038555"])
    to_ids: bool
    type: str = OutputField(example_values=["port"])
    uuid: str = OutputField(example_values=["68e219ee-5727-4cb2-a32f-8dc27aa4231f"])


class UpdateEventSummary(ActionOutput):
    updated_event_id: int
    attributes_added: int
    message: str | None = None


@app.action(
    name="update event",
    description="Add attributes / IOCs to an event in MISP",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=UpdateEventSummary,
    verbose="Parameters urls, domains, source_ips, dest_ips, source_emails, dest_emails accept comma-separated values.",
)
def add_attributes(
    params: UpdateEventParams, soar: SOARClient, asset: Asset
) -> list[UpdateEventOutput]:
    event_id = positive_int(params.event_id, "event_id")
    has_tags = bool(split_values(params.tags))
    if params.replace_tags and params.tags and not has_tags:
        raise ActionFailure("Please provide at least one replacement tag")

    event = request(asset, "GET", f"/events/view/{event_id}")
    event_data = event.get("Event", event)
    event_identifier = event_data.get("uuid") or event_id
    existing_ids = {
        str(attribute["id"])
        for attribute in event_data.get("Attribute", [])
        if attribute.get("id") is not None
    }
    attributes = []
    try:
        attributes = add_iocs(asset, event_id, params, event=event)
    except PartialIOCError as exc:
        attributes = exc.completed_rows
        error = exc
    else:
        error = None

    attributes_added = sum(
        attribute.get("id") is not None and str(attribute["id"]) not in existing_ids
        for attribute in attributes
    )
    if error is None and not attributes and not has_tags:
        raise ActionFailure("Please provide at least one attribute")

    if error is not None:
        if not attributes:
            raise error
        return _partial_failure(params, event_id, attributes, attributes_added, error)

    try:
        if has_tags and params.replace_tags:
            current = event_data.get("Tag", [])
            for tag in current:
                name = tag.get("name") if isinstance(tag, dict) else tag
                if name:
                    request(
                        asset,
                        "POST",
                        "/tags/removeTagFromObject",
                        payload={"uuid": str(event_identifier), "tag": name},
                    )
        add_tags(
            asset,
            event_identifier,
            params.tags,
            existing_tags=() if params.replace_tags else event_data.get("Tag", []),
        )
    except Exception as exc:
        if not attributes:
            raise
        return _partial_failure(params, event_id, attributes, attributes_added, exc)

    message = (
        f"Attributes added to event: {event_id}"
        if attributes
        else f"Tags added to event: {event_id}"
    )
    summary = UpdateEventSummary(
        updated_event_id=event_id,
        attributes_added=attributes_added,
        message=message,
    )
    soar.set_summary(summary)
    soar.set_message(message)
    if attributes:
        return [output(UpdateEventOutput, row) for row in attributes]
    return [output(UpdateEventOutput, {"event_id": str(event_id)})]


def _partial_failure(params, event_id, attributes, attributes_added, error):
    failed_result = ActionResult(
        status=False,
        message=error.message if isinstance(error, ActionFailure) else str(error),
        param=params.model_dump(),
    )
    for attribute in attributes:
        failed_result.add_data(attribute)
    failed_result.set_summary(
        UpdateEventSummary(
            updated_event_id=event_id,
            attributes_added=attributes_added,
        ).model_dump(exclude_none=True)
    )
    return failed_result
