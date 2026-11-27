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
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params
from ..asset import Asset
from ..helper import positive_int, request


class GetAttributesParams(Params):
    event_id: int = Param(
        description="An Event ID", primary=True, cef_types=["misp event id"]
    )
    download_samples: bool | None = Param(
        description="Download malware samples to vault", default=False
    )


class EventOutput(ActionOutput):
    distribution: str = OutputField(example_values=["1"])
    id: str = OutputField(cef_types=["misp event id"], example_values=["2028"])
    info: str = OutputField(example_values=["Event created by test"])
    org_id: str = OutputField(example_values=["1"])
    orgc_id: str = OutputField(example_values=["1"])
    uuid: str = OutputField(
        example_values=[
            "552d93e4-fa0d-48cb-810e-a5f56c0af5ea",
            "342c12ab-32ad-41d0-aea2-1c3dccc6ce09",
        ]
    )


class ObjectOutput(ActionOutput):
    distribution: str = OutputField(example_values=["5"])
    id: str = OutputField(example_values=["10"])
    sharing_group_id: str = OutputField(example_values=["0"])


class AttributeOutput(ActionOutput):
    Event: EventOutput
    Object: ObjectOutput
    category: str = OutputField(
        column_name="Category", example_values=["Network activity"]
    )
    type: str = OutputField(column_name="Type", example_values=["ip-src"])
    value: str = OutputField(
        column_name="Value",
        cef_types=["url", "domain", "ip", "email", "hash", "md5", "sha256", "md1"],
        example_values=["192.162.8.1"],
    )
    comment: str = OutputField(column_name="Comment")
    deleted: bool = OutputField(example_values=[False, True])
    disable_correlation: bool = OutputField(example_values=[False, True])
    distribution: str = OutputField(example_values=["5"])
    event_id: str = OutputField(cef_types=["misp event id"], example_values=["686"])
    first_seen: str
    id: str = OutputField(cef_types=["misp attribute id"], example_values=["164191"])
    last_seen: str
    object_id: str = OutputField(example_values=["0", "10"])
    object_relation: str = OutputField(example_values=["filename"])
    sharing_group_id: str = OutputField(example_values=["0"])
    timestamp: str = OutputField(example_values=["1498002097"])
    to_ids: bool
    uuid: str = OutputField(example_values=["5949b2b1-35b4-4152-a633-7e530a10000d"])


class GetAttributesOutput(ActionOutput, extra="allow"):
    Attribute: list[AttributeOutput]


class GetAttributesSummary(ActionOutput):
    returned_attributes: int


def get_event(
    params: GetAttributesParams, soar: SOARClient, asset: Asset
) -> GetAttributesOutput:
    event_id = positive_int(params.event_id, "event_id")
    event = request(asset, "GET", f"/events/view/{event_id}")
    event_data = event.get("Event", event) if isinstance(event, dict) else None
    if not isinstance(event_data, dict) or not event_data.get("id"):
        raise RuntimeError(f"Failed to get event {event_id}")
    result = request(
        asset,
        "POST",
        "/attributes/restSearch",
        payload={"eventid": event_id, "returnFormat": "json"},
    )
    body = result.get("response", result) if isinstance(result, dict) else result
    attributes = body.get("Attribute") if isinstance(body, dict) else None
    if not isinstance(attributes, list) or any(
        not isinstance(row, dict) for row in attributes
    ):
        raise RuntimeError("MISP returned an unexpected attribute response shape")
    if params.download_samples:
        _download_malware_samples(soar, event)
    soar.set_summary(GetAttributesSummary(returned_attributes=len(attributes)))
    soar.set_message("Successfully retrieved attributes")
    return GetAttributesOutput.model_construct(**body)


def _download_malware_samples(soar, event):
    from pathlib import Path

    from pymisp import MISPAttribute

    event_data = event.get("Event", event) if isinstance(event, dict) else {}
    objects = event_data.get("Object", []) or []
    if isinstance(objects, dict):
        objects = [objects]
    for misp_object in objects:
        object_attributes = misp_object.get("Attribute", []) or []
        if isinstance(object_attributes, dict):
            object_attributes = [object_attributes]
        for attribute_data in object_attributes:
            if not isinstance(attribute_data, dict):
                continue
            if attribute_data.get("type") != "malware-sample":
                continue
            attribute = MISPAttribute()
            attribute.from_dict(**attribute_data)
            malware_binary = attribute.malware_binary
            if malware_binary is None:
                continue
            file_name = Path(attribute.malware_filename or "").name or "malware_sample"
            soar.vault.create_attachment(
                container_id=soar.get_executing_container_id(),
                file_content=malware_binary.read(),
                file_name=file_name,
            )
