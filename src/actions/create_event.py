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
from soar_sdk.action_results import (
    ActionOutput,
    ActionResult,
    OutputField,
    PermissiveActionOutput,
)
from soar_sdk.params import Param, Params
from ..app import Asset, app
from ..helper import add_iocs, add_tags, output, request


class CreateEventParams(Params):
    distribution: str = Param(
        description="Distribution level for sharing",
        default="This Community Only",
        value_list=[
            "Your Org Only",
            "This Community Only",
            "Connected Communities",
            "All Communities",
        ],
    )
    threat_level_id: str = Param(
        description="Threat level id",
        default="Undefined",
        value_list=["High", "Medium", "Low", "Undefined"],
    )
    analysis: str = Param(
        description="Current stage of analysis for event",
        default="Initial",
        value_list=["Initial", "Ongoing", "Completed"],
    )
    info: str = Param(
        description="Information / Description for Event",
        default="Event created by test",
    )
    add_attributes: bool | None = Param(
        description="Add attributes upon event creation", default=True
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
    tags: str | None = Param(description="Comma separated list of tags")
    json: str | None = Param(description="JSON key value list of attributes")


class OrgOutput(ActionOutput):
    id: str = OutputField(example_values=["1"])
    local: bool
    name: str = OutputField(example_values=["ORGNAME"])
    uuid: str = OutputField(example_values=["2af87aa3-a713-4ca5-83f7-03ae949c8459"])


class OrgcOutput(ActionOutput):
    id: str = OutputField(example_values=["1"])
    local: bool
    name: str = OutputField(example_values=["ORGNAME"])
    uuid: str = OutputField(example_values=["2af87aa3-a713-4ca5-83f7-03ae949c8459"])


class CreateEventOutput(PermissiveActionOutput):
    """A create action emits both an event row and attribute rows."""

    created_event_id: str | None = OutputField(
        column_name="MISP Event ID", cef_types=["misp event id"]
    )
    id: str = OutputField(column_name="MISP Attribute ID")
    info: str = OutputField(column_name="Event Info / Description")
    threat_level_id: str = OutputField(column_name="Threat Level ID")
    distribution: str = OutputField(column_name="Distribution")
    attribute_count: str = OutputField(column_name="Attribute Count")
    Org: OrgOutput
    Orgc: OrgcOutput
    analysis: str = OutputField(example_values=["0"])
    category: str = OutputField(example_values=["Network activity"])
    comment: str
    date: str = OutputField(example_values=["2021-06-09"])
    deleted: bool
    disable_correlation: bool
    event_creator_email: str = OutputField(example_values=["test@test.com"])
    event_id: str = OutputField(cef_types=["misp event id"], example_values=["2052"])
    extends_uuid: str
    locked: bool
    object_id: str = OutputField(example_values=["0"])
    org_id: str = OutputField(example_values=["1"])
    orgc_id: str = OutputField(example_values=["1"])
    proposal_email_lock: bool
    publish_timestamp: str = OutputField(example_values=["0"])
    published: bool
    sharing_group_id: str = OutputField(example_values=["0"])
    timestamp: str = OutputField(example_values=["1623206691"])
    to_ids: bool
    type: str = OutputField(example_values=["url"])
    uuid: str = OutputField(example_values=["82c82204-4ebd-42cb-a913-4df726b5d7fe"])
    value: str = OutputField(
        cef_types=["url", "domain", "ip", "email", "hash", "md5", "sha256", "md1"],
        example_values=["8.8.8.8"],
    )


class CreateEventSummary(ActionOutput):
    created_event_id: int
    attributes_added: int
    message: str


@app.action(
    description="Create a new event in MISP",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=CreateEventSummary,
    verbose="This action first creates an event, then adds attributes to that event. Parameters urls, domains, source_ips, dest_ips, source_emails, dest_emails accept comma-separated values.",
)
def create_event(
    params: CreateEventParams, soar: SOARClient, asset: Asset
) -> list[CreateEventOutput]:
    distributions = {
        "your org only": 0,
        "this community only": 1,
        "connected communities": 2,
        "all communities": 3,
    }
    threat_levels = {"high": 1, "medium": 2, "low": 3, "undefined": 4}
    analyses = {"initial": 0, "ongoing": 1, "completed": 2}
    event = request(
        asset,
        "POST",
        "/events/add",
        payload={
            "Event": {
                "distribution": distributions.get(
                    params.distribution.lower(), params.distribution
                ),
                "threat_level_id": threat_levels.get(
                    params.threat_level_id.lower(), params.threat_level_id
                ),
                "analysis": analyses.get(params.analysis.lower(), params.analysis),
                "info": params.info,
            }
        },
    )
    if isinstance(event, dict) and "Event" in event:
        event = event["Event"]
    event_id = event.get("id") if isinstance(event, dict) else None
    if not event_id:
        raise RuntimeError("MISP created the event but returned no event ID")
    event = dict(event)
    # The legacy table selects data.0.id for the event and data.*.id for attributes.
    # Keep id unchanged and expose the first row's event ID as an SDK-native column.
    event_output = {**event, "created_event_id": str(event_id)}
    try:
        add_tags(asset, event.get("uuid") or event_id, params.tags)
    except Exception as exc:
        return _partial_create_failure(
            params, event_output, event_id, f"Failed to add tags to MISP event: {exc}"
        )
    try:
        attributes = (
            add_iocs(asset, event_id, params, event=event)
            if params.add_attributes
            else []
        )
    except Exception as exc:
        return _partial_create_failure(
            params,
            event_output,
            event_id,
            f"Failed to add attributes to MISP event: {exc}",
        )

    message = f"Event created with id: {event_id}"
    soar.set_summary(
        CreateEventSummary(
            created_event_id=int(event_id),
            attributes_added=len(attributes),
            message=message,
        )
    )
    soar.set_message(message)
    return [output(CreateEventOutput, event_output)] + [
        output(CreateEventOutput, attribute) for attribute in attributes
    ]


def _partial_create_failure(params, event, event_id, message):
    failed_result = ActionResult(
        status=False,
        message=message,
        param=params.model_dump(),
    )
    failed_result.add_data(event)
    failed_result.set_summary(
        CreateEventSummary(
            created_event_id=int(event_id),
            attributes_added=0,
            message=f"Event created with id: {event_id}",
        ).model_dump()
    )
    return failed_result
