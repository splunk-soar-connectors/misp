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
from soar_sdk.exceptions import ActionFailure

from .actions import register_actions
from .asset import Asset
from .helper import request


app = App(
    name="MISP",
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
    body = request(asset, "GET", "/servers/getPyMISPVersion.json", require_success=True)
    version = body.get("version") if isinstance(body, dict) else None
    if not isinstance(version, str) or not version.strip():
        raise ActionFailure("MISP did not return a usable PyMISP version")
    soar.set_message("Test connectivity passed")


register_actions(app)

if __name__ == "__main__":
    app.cli()
