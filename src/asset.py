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
from soar_sdk.asset import BaseAsset, AssetField, FieldCategory


class Asset(BaseAsset):
    base_url: str = AssetField(
        required=True,
        category=FieldCategory.CONNECTIVITY,
        description="MISP instance URL (http://misp_instance.company.com/)",
    )
    verify_server_cert: bool | None = AssetField(
        category=FieldCategory.CONNECTIVITY,
        description="Verify server certificate",
        default=True,
    )
    api_key: str = AssetField(
        required=True,
        category=FieldCategory.CONNECTIVITY,
        sensitive=True,
        description="API Key found under Event Actions: Automation",
    )
