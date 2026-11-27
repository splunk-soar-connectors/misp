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
"""MISP SDK action registrations."""

from soar_sdk.app import App

from . import add_attributes, create_event, get_attributes, make_request, run_query


def register_actions(app: App) -> None:
    """Register the MISP actions with the SDK app."""
    app.register_action(
        add_attributes.add_attributes,
        name="update event",
        description="Add attributes / IOCs to an event in MISP",
        action_type="generic",
        read_only=False,
        render_as="table",
        summary_type=add_attributes.UpdateEventSummary,
        verbose="Parameters urls, domains, source_ips, dest_ips, source_emails, dest_emails accept comma-separated values.",
    )
    app.register_action(
        create_event.create_event,
        description="Create a new event in MISP",
        action_type="generic",
        read_only=False,
        render_as="table",
        output_class=create_event.CreateEventOutput,
        summary_type=create_event.CreateEventSummary,
        verbose="This action first creates an event, then adds attributes to that event. Parameters urls, domains, source_ips, dest_ips, source_emails, dest_emails accept comma-separated values.",
    )
    app.register_action(
        get_attributes.get_event,
        name="get attributes",
        description="Get attributes for a specific event",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=get_attributes.GetAttributesSummary,
        verbose="<b>download_samples</b> will only download files which are marked as a 'malware-sample'.",
    )
    app.make_request()(make_request.make_request)
    app.register_action(
        run_query.run_query,
        description="Run a query to find events or attributes",
        action_type="investigate",
        read_only=True,
        render_as="json",
        output_class=run_query.RunQueryOutput,
        summary_type=run_query.RunQuerySummary,
        verbose=(
            "By default, returns the first 10 matches. Set <b>max_results</b> to 0 for no requested cap "
            "or to -N for the last N matches. The connector requests up to 1,000 results per page, "
            "subject to MISP limits, and fails if the search is incomplete after 100 pages. "
            "Pass additional MISP filters as JSON in <b>other</b>."
        ),
    )
