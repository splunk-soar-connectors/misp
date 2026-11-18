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
from soar_sdk.app import App
from soar_sdk.asset import BaseAsset, AssetField, FieldCategory
from soar_sdk.logging import getLogger
from .helper import request

logger = getLogger()

class Asset(BaseAsset):
    base_url: str = AssetField(
        required=True,
        category=FieldCategory.CONNECTIVITY,
        description="MISP instance URL (http://misp_instance.company.com/)"
    )
    verify_server_cert: bool | None = AssetField(
        category=FieldCategory.CONNECTIVITY,
        description="Verify server certificate", default=True
    )
    api_key: str = AssetField(
        required=True,
        category=FieldCategory.CONNECTIVITY,
        sensitive=True,
        description="API Key found under Event Actions: Automation",
    )

app = App(
    name="misp",
    app_type="threat intel",
    logo="logo_misp.svg",
    logo_dark="logo_misp_dark.svg",
    product_vendor="MISP",
    product_name="MISP",
    publisher="Splunk",
    appid="54c18439-fd16-49bf-a73f-873e162083e7",
    fips_compliant=True,
    encrypt_cache_state=True,
    encrypt_ingest_state=True,
    asset_cls=Asset,
)

@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    request(asset, "GET", "/servers/getPyMISPVersion.json")
    soar.set_message("Test connectivity passed")

# Importing action modules registers their handlers with the SDK app.
from .actions import add_attributes, create_event, get_attributes, make_request, run_query  # noqa: F401

if __name__ == "__main__":
    app.cli()
