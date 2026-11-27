# MISP

Publisher: Splunk <br>
Connector Version: 3.0.0 <br>
Product Vendor: MISP <br>
Product Name: MISP <br>
Minimum Product Version: 7.0.0

Take action with Malware Information Sharing Platform

## Port Information

The app communicates with the MISP server over HTTP or HTTPS. The default ports are:

| Service | Transport | Port |
|---------|-----------|------|
| HTTP | TCP | 80 |
| HTTPS | TCP | 443 |

## Additional Usage Notes

### MISP Enumerated Values

MISP uses the following integer values for event fields:

| Field | Value | Meaning |
|-------|-------|---------|
| Distribution | 0 | Your organization only |
| Distribution | 1 | This community only |
| Distribution | 2 | Connected communities |
| Distribution | 3 | All communities |
| Distribution | 4 | Sharing group |
| Distribution | 5 | Inherit |
| Threat level | 1 | High |
| Threat level | 2 | Medium |
| Threat level | 3 | Low |
| Threat level | 4 | Undefined |
| Analysis | 0 | Initial |
| Analysis | 1 | Ongoing |
| Analysis | 2 | Completed |

### Attribute Input

For **create event** and **update event**, the `json` parameter accepts either a mapping of MISP
attribute types to values or a list of attribute objects containing `type` and `value`. Values may
be strings or lists. A comma-separated string is split into multiple values; pass a JSON list when
a value itself contains a comma. MISP API errors, including an explicit `saved: false` response,
fail the action. If some attributes were added before a later failure, the action returns those
successful rows with the failure.

In **create event**, the event may already have been created when adding its attributes or tags
fails. In that case, the action fails while retaining the created event in its output.

In **run query**, use a list in the `other` JSON object to keep a comma-containing tag as one value:

```json
{"tags": ["tag1, tag11", "tag_2"]}
```

### Custom Requests

For custom MISP API requests, `query_parameters` accepts a JSON object or a query string.
Repeated keys and values are retained when combined with the endpoint query.

Any received HTTP response yields a successful SOAR action result. Use
`action_result.data.*.status_code` to check the HTTP status and `response` to read the body.

### Malware Sample Downloads

When **get attributes** is run with `download_samples` enabled, malware-sample attributes are
decrypted and the sample files are added to the SOAR Vault.

### Configuration variables

This table lists the configuration variables required to operate MISP. These variables are specified when configuring a MISP asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** | required | string | MISP instance URL (http://misp_instance.company.com/) |
**verify_server_cert** | optional | boolean | Verify server certificate |
**api_key** | required | password | API Key found under Event Actions: Automation |

### Supported Actions

[test connectivity](#action-test-connectivity) - test connectivity <br>
[update event](#action-update-event) - Add attributes / IOCs to an event in MISP <br>
[create event](#action-create-event) - Create a new event in MISP <br>
[get attributes](#action-get-attributes) - Get attributes for a specific event <br>
[make request](#action-make-request) - Send a custom REST request to the configured MISP server. <br>
[run query](#action-run-query) - Run a query to find events or attributes

## action: 'test connectivity'

test connectivity

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update event'

Add attributes / IOCs to an event in MISP

Type: **generic** <br>
Read only: **False**

Parameters urls, domains, source_ips, dest_ips, source_emails, dest_emails accept comma-separated values.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event_id** | required | MISP event ID for adding attributes | numeric | `misp event id` |
**to_ids** | optional | Set 'to_IDS' flag=True in MISP | boolean | |
**source_ips** | optional | Source IPs to be added as attributes | string | `ip` `ipv6` |
**dest_ips** | optional | Destination IPs to be added as attributes | string | `ip` `ipv6` |
**domains** | optional | Domains to be added as attributes | string | `domain` |
**source_emails** | optional | Source email addresses to be added as attributes | string | `email` |
**dest_emails** | optional | Destination email addresses to be added as attributes | string | `email` |
**urls** | optional | URLs to be added as attributes | string | `url` |
**tags** | optional | Comma separated list of tags (append to existing tags default) | string | |
**replace_tags** | optional | Replace tags with new provided tags | boolean | |
**json** | optional | JSON key value list of attributes | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.event_id | numeric | `misp event id` | |
action_result.parameter.to_ids | boolean | | |
action_result.parameter.source_ips | string | `ip` `ipv6` | |
action_result.parameter.dest_ips | string | `ip` `ipv6` | |
action_result.parameter.domains | string | `domain` | |
action_result.parameter.source_emails | string | `email` | |
action_result.parameter.dest_emails | string | `email` | |
action_result.parameter.urls | string | `url` | |
action_result.parameter.tags | string | | |
action_result.parameter.replace_tags | boolean | | |
action_result.parameter.json | string | | |
action_result.data.\*.id | string | `misp attribute id` | 5360 |
action_result.data.\*.value | string | `url` `domain` `ip` `email` `hash` `md5` `sha256` `md1` | email1@email.com |
action_result.data.\*.event_id | string | `misp event id` | 2121 |
action_result.data.\*.category | string | | Other |
action_result.data.\*.distribution | string | | 5 |
action_result.data.\*.comment | string | | |
action_result.data.\*.deleted | boolean | | True False |
action_result.data.\*.disable_correlation | boolean | | True False |
action_result.data.\*.object_id | string | | 0 |
action_result.data.\*.sharing_group_id | string | | 0 |
action_result.data.\*.timestamp | string | | 1623038555 |
action_result.data.\*.to_ids | boolean | | True False |
action_result.data.\*.type | string | | port |
action_result.data.\*.uuid | string | | 68e219ee-5727-4cb2-a32f-8dc27aa4231f |
action_result.summary.updated_event_id | numeric | | |
action_result.summary.attributes_added | numeric | | |
action_result.summary.message | string | | |
action_result.summary.errors | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create event'

Create a new event in MISP

Type: **generic** <br>
Read only: **False**

This action first creates an event, then adds attributes to that event. Parameters urls, domains, source_ips, dest_ips, source_emails, dest_emails accept comma-separated values.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**distribution** | required | Distribution level for sharing | string | |
**threat_level_id** | required | Threat level id | string | |
**analysis** | required | Current stage of analysis for event | string | |
**info** | required | Information / Description for Event | string | |
**add_attributes** | optional | Add attributes upon event creation | boolean | |
**to_ids** | optional | Set 'to_IDS' flag=True in MISP | boolean | |
**source_ips** | optional | Source IPs to be added as attributes | string | `ip` `ipv6` |
**dest_ips** | optional | Destination IPs to be added as attributes | string | `ip` `ipv6` |
**domains** | optional | Domains to be added as attributes | string | `domain` |
**source_emails** | optional | Source email addresses to be added as attributes | string | `email` |
**dest_emails** | optional | Destination email addresses to be added as attributes | string | `email` |
**urls** | optional | URLs to be added as attributes | string | `url` |
**tags** | optional | Comma separated list of tags | string | |
**json** | optional | JSON key value list of attributes | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.distribution | string | | |
action_result.parameter.threat_level_id | string | | |
action_result.parameter.analysis | string | | |
action_result.parameter.info | string | | |
action_result.parameter.add_attributes | boolean | | |
action_result.parameter.to_ids | boolean | | |
action_result.parameter.source_ips | string | `ip` `ipv6` | |
action_result.parameter.dest_ips | string | `ip` `ipv6` | |
action_result.parameter.domains | string | `domain` | |
action_result.parameter.source_emails | string | `email` | |
action_result.parameter.dest_emails | string | `email` | |
action_result.parameter.urls | string | `url` | |
action_result.parameter.tags | string | | |
action_result.parameter.json | string | | |
action_result.data.\*.created_event_id | string | `misp event id` | |
action_result.data.\*.id | string | | |
action_result.data.\*.info | string | | |
action_result.data.\*.threat_level_id | string | | |
action_result.data.\*.distribution | string | | |
action_result.data.\*.attribute_count | string | | |
action_result.data.\*.Org.id | string | | 1 |
action_result.data.\*.Org.local | boolean | | True False |
action_result.data.\*.Org.name | string | | ORGNAME |
action_result.data.\*.Org.uuid | string | | 2af87aa3-a713-4ca5-83f7-03ae949c8459 |
action_result.data.\*.Orgc.id | string | | 1 |
action_result.data.\*.Orgc.local | boolean | | True False |
action_result.data.\*.Orgc.name | string | | ORGNAME |
action_result.data.\*.Orgc.uuid | string | | 2af87aa3-a713-4ca5-83f7-03ae949c8459 |
action_result.data.\*.analysis | string | | 0 |
action_result.data.\*.category | string | | Network activity |
action_result.data.\*.comment | string | | |
action_result.data.\*.date | string | | 2021-06-09 |
action_result.data.\*.deleted | boolean | | True False |
action_result.data.\*.disable_correlation | boolean | | True False |
action_result.data.\*.event_creator_email | string | | test@test.com |
action_result.data.\*.event_id | string | `misp event id` | 2052 |
action_result.data.\*.extends_uuid | string | | |
action_result.data.\*.locked | boolean | | True False |
action_result.data.\*.object_id | string | | 0 |
action_result.data.\*.org_id | string | | 1 |
action_result.data.\*.orgc_id | string | | 1 |
action_result.data.\*.proposal_email_lock | boolean | | True False |
action_result.data.\*.publish_timestamp | string | | 0 |
action_result.data.\*.published | boolean | | True False |
action_result.data.\*.sharing_group_id | string | | 0 |
action_result.data.\*.timestamp | string | | 1623206691 |
action_result.data.\*.to_ids | boolean | | True False |
action_result.data.\*.type | string | | url |
action_result.data.\*.uuid | string | | 82c82204-4ebd-42cb-a913-4df726b5d7fe |
action_result.data.\*.value | string | `url` `domain` `ip` `email` `hash` `md5` `sha256` `md1` | 8.8.8.8 |
action_result.summary.created_event_id | numeric | | |
action_result.summary.attributes_added | numeric | | |
action_result.summary.message | string | | |
action_result.summary.errors | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get attributes'

Get attributes for a specific event

Type: **investigate** <br>
Read only: **True**

<b>download_samples</b> will only download files which are marked as a 'malware-sample'.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event_id** | required | An Event ID | numeric | `misp event id` |
**download_samples** | optional | Download malware samples to vault | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.event_id | numeric | `misp event id` | |
action_result.parameter.download_samples | boolean | | |
action_result.data.\*.Attribute.\*.Event.distribution | string | | 1 |
action_result.data.\*.Attribute.\*.Event.id | string | `misp event id` | 2028 |
action_result.data.\*.Attribute.\*.Event.info | string | | Event created by test |
action_result.data.\*.Attribute.\*.Event.org_id | string | | 1 |
action_result.data.\*.Attribute.\*.Event.orgc_id | string | | 1 |
action_result.data.\*.Attribute.\*.Event.uuid | string | | 552d93e4-fa0d-48cb-810e-a5f56c0af5ea 342c12ab-32ad-41d0-aea2-1c3dccc6ce09 |
action_result.data.\*.Attribute.\*.Object.distribution | string | | 5 |
action_result.data.\*.Attribute.\*.Object.id | string | | 10 |
action_result.data.\*.Attribute.\*.Object.sharing_group_id | string | | 0 |
action_result.data.\*.Attribute.\*.category | string | | Network activity |
action_result.data.\*.Attribute.\*.type | string | | ip-src |
action_result.data.\*.Attribute.\*.value | string | `url` `domain` `ip` `email` `hash` `md5` `sha256` `md1` | 192.162.8.1 |
action_result.data.\*.Attribute.\*.comment | string | | |
action_result.data.\*.Attribute.\*.deleted | boolean | | True False |
action_result.data.\*.Attribute.\*.disable_correlation | boolean | | True False |
action_result.data.\*.Attribute.\*.distribution | string | | 5 |
action_result.data.\*.Attribute.\*.event_id | string | `misp event id` | 686 |
action_result.data.\*.Attribute.\*.first_seen | string | | |
action_result.data.\*.Attribute.\*.id | string | `misp attribute id` | 164191 |
action_result.data.\*.Attribute.\*.last_seen | string | | |
action_result.data.\*.Attribute.\*.object_id | string | | 0 10 |
action_result.data.\*.Attribute.\*.object_relation | string | | filename |
action_result.data.\*.Attribute.\*.sharing_group_id | string | | 0 |
action_result.data.\*.Attribute.\*.timestamp | string | | 1498002097 |
action_result.data.\*.Attribute.\*.to_ids | boolean | | True False |
action_result.data.\*.Attribute.\*.uuid | string | | 5949b2b1-35b4-4152-a633-7e530a10000d |
action_result.summary.returned_attributes | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'make request'

Send a custom REST request to the configured MISP server.

Type: **generic** <br>
Read only: **False**

'make request' action for the app. Used to handle arbitrary HTTP requests with the app's asset

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_method** | required | The HTTP method to use for the request. | string | |
**endpoint** | required | The endpoint to send the request to. | string | |
**headers** | optional | The headers to send with the request (JSON object). An example is {'Content-Type': 'application/json'} | string | |
**query_parameters** | optional | Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2 | string | |
**body** | optional | The body to send with the request (JSON object). An example is {'key': 'value', 'key2': 'value2'} | string | |
**timeout** | optional | The timeout for the request in seconds. | numeric | |
**verify_ssl** | optional | Whether to verify the SSL certificate. Default is True. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_method | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.headers | string | | |
action_result.parameter.query_parameters | string | | |
action_result.parameter.body | string | | |
action_result.parameter.timeout | numeric | | |
action_result.parameter.verify_ssl | boolean | | |
action_result.data.\*.status_code | numeric | | |
action_result.data.\*.response | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'run query'

Run a query to find events or attributes

Type: **investigate** <br>
Read only: **True**

By default, returns the first 10 matches. Set <b>max_results</b> to 0 for no requested cap or to -N for the last N matches. The connector requests up to 1,000 results per page, subject to MISP limits, and fails if the search is incomplete after 100 pages. Pass additional MISP filters as JSON in <b>other</b>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**controller** | required | Search for events or attributes | string | |
**max_results** | optional | Max results to return | numeric | |
**event_id** | optional | Comma seperated list of Event IDs | string | `misp event id` |
**tags** | optional | Comma seperated list of tags | string | |
**other** | optional | Other search parameters, as a JSON object | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.controller | string | | |
action_result.parameter.max_results | numeric | | |
action_result.parameter.event_id | string | `misp event id` | |
action_result.parameter.tags | string | | |
action_result.parameter.other | string | | |
action_result.data.\*.\*.Event.distribution | string | | 1 |
action_result.data.\*.\*.Event.id | string | | 2020 |
action_result.data.\*.\*.Event.info | string | | Event created by test |
action_result.data.\*.\*.Event.org_id | string | | 1 |
action_result.data.\*.\*.Event.orgc_id | string | | 1 |
action_result.data.\*.\*.Event.uuid | string | | 342c12ab-32ad-41d0-aea2-1c3dccc6ce09 |
action_result.data.\*.\*.Event.Org.id | string | | 1 |
action_result.data.\*.\*.Event.Org.name | string | | ORGNAME |
action_result.data.\*.\*.Event.Org.uuid | string | | 2af87aa3-a713-4ca5-83f7-03ae949c8459 |
action_result.data.\*.\*.Event.Org.local | numeric | | True False |
action_result.data.\*.\*.Event.Orgc.id | string | | 1 |
action_result.data.\*.\*.Event.Orgc.name | string | | ORGNAME |
action_result.data.\*.\*.Event.Orgc.uuid | string | | 2af87aa3-a713-4ca5-83f7-03ae949c8459 |
action_result.data.\*.\*.Event.Orgc.local | numeric | | True False |
action_result.data.\*.\*.Event.analysis | string | | 0 |
action_result.data.\*.\*.Event.date | string | | 2021-06-14 |
action_result.data.\*.\*.Event.published | numeric | | True False |
action_result.data.\*.\*.Event.threat_level_id | string | | 4 |
action_result.data.\*.\*.Event.timestamp | string | | 1623645286 |
action_result.data.\*.\*.Event.Attribute.\*.category | string | | Payload delivery |
action_result.data.\*.\*.Event.Attribute.\*.comment | string | | |
action_result.data.\*.\*.Event.Attribute.\*.deleted | numeric | | True False |
action_result.data.\*.\*.Event.Attribute.\*.disable_correlation | numeric | | True False |
action_result.data.\*.\*.Event.Attribute.\*.distribution | string | | 5 |
action_result.data.\*.\*.Event.Attribute.\*.event_id | string | | 2020 |
action_result.data.\*.\*.Event.Attribute.\*.first_seen | string | | |
action_result.data.\*.\*.Event.Attribute.\*.id | string | | 4953 |
action_result.data.\*.\*.Event.Attribute.\*.last_seen | string | | |
action_result.data.\*.\*.Event.Attribute.\*.object_id | string | | 10 |
action_result.data.\*.\*.Event.Attribute.\*.object_relation | string | | filename |
action_result.data.\*.\*.Event.Attribute.\*.sharing_group_id | string | | 0 |
action_result.data.\*.\*.Event.Attribute.\*.timestamp | string | | 1623078296 |
action_result.data.\*.\*.Event.Attribute.\*.to_ids | numeric | | True False |
action_result.data.\*.\*.Event.Attribute.\*.type | string | `url` | email-dst |
action_result.data.\*.\*.Event.Attribute.\*.uuid | string | | 2fd53a9b-44fd-4ebc-af93-0e1605cf3b64 |
action_result.data.\*.\*.Event.Attribute.\*.value | string | `url` `domain` `ip` `email` `hash` `md5` `sha256` `md1` | 6.43.3.2 |
action_result.data.\*.\*.Event.Object.\*.distribution | string | | 5 |
action_result.data.\*.\*.Event.Object.\*.id | string | | 10 |
action_result.data.\*.\*.Event.Object.\*.sharing_group_id | string | | 0 |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.category | string | | Payload delivery |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.comment | string | | |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.deleted | numeric | | True False |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.disable_correlation | numeric | | True False |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.distribution | string | | 5 |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.event_id | string | | 2020 |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.first_seen | string | | |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.id | string | | 4953 |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.last_seen | string | | |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.object_id | string | | 10 |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.object_relation | string | | filename |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.sharing_group_id | string | | 0 |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.timestamp | string | | 1623078296 |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.to_ids | numeric | | True False |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.type | string | | filename |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.uuid | string | | 2fd53a9b-44fd-4ebc-af93-0e1605cf3b64 |
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.value | string | `url` `domain` `ip` `email` `hash` `md5` `sha256` `md1` | 6.43.3.2 |
action_result.data.\*.\*.Event.Object.\*.comment | string | | |
action_result.data.\*.\*.Event.Object.\*.deleted | numeric | | True False |
action_result.data.\*.\*.Event.Object.\*.description | string | | File object describing a file with meta-information |
action_result.data.\*.\*.Event.Object.\*.event_id | string | | 2020 |
action_result.data.\*.\*.Event.Object.\*.first_seen | string | | |
action_result.data.\*.\*.Event.Object.\*.last_seen | string | | |
action_result.data.\*.\*.Event.Object.\*.meta-category | string | | file |
action_result.data.\*.\*.Event.Object.\*.name | string | | file |
action_result.data.\*.\*.Event.Object.\*.template_uuid | string | | 688c46fb-5edb-40a3-8273-1af7923e2215 |
action_result.data.\*.\*.Event.Object.\*.template_version | string | | 24 |
action_result.data.\*.\*.Event.Object.\*.timestamp | string | | 1623078296 |
action_result.data.\*.\*.Event.Object.\*.uuid | string | | 4b5cb238-9e55-40eb-b60e-b30f71cab6f6 |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.distribution | string | | 1 |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.id | string | | 2020 |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.info | string | | Event created by test |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.org_id | string | | 1 |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.orgc_id | string | | 1 |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.uuid | string | | 342c12ab-32ad-41d0-aea2-1c3dccc6ce09 |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.Org.id | string | | 1 |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.Org.name | string | | ORGNAME |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.Org.uuid | string | | 2af87aa3-a713-4ca5-83f7-03ae949c8459 |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.Orgc.id | string | | 1 |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.Orgc.name | string | | ORGNAME |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.Orgc.uuid | string | | 2af87aa3-a713-4ca5-83f7-03ae949c8459 |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.analysis | string | | 0 |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.date | string | | 2021-06-14 |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.published | numeric | | True False |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.threat_level_id | string | | 4 |
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.timestamp | string | | 1623645286 |
action_result.data.\*.\*.Event.Tag.\*.colour | string | | #7ab870 |
action_result.data.\*.\*.Event.Tag.\*.exportable | numeric | | True False |
action_result.data.\*.\*.Event.Tag.\*.hide_tag | numeric | | True False |
action_result.data.\*.\*.Event.Tag.\*.id | string | | 8 |
action_result.data.\*.\*.Event.Tag.\*.is_custom_galaxy | numeric | | True False |
action_result.data.\*.\*.Event.Tag.\*.is_galaxy | numeric | | True False |
action_result.data.\*.\*.Event.Tag.\*.local | numeric | | 1 |
action_result.data.\*.\*.Event.Tag.\*.name | string | | test_1 |
action_result.data.\*.\*.Event.Tag.\*.numerical_value | string | | |
action_result.data.\*.\*.Event.Tag.\*.user_id | string | | 1 |
action_result.data.\*.\*.Event.attribute_count | string | | 7 |
action_result.data.\*.\*.Event.disable_correlation | numeric | | True False |
action_result.data.\*.\*.Event.event_creator_email | string | `email` | test@test.com |
action_result.data.\*.\*.Event.extends_uuid | string | | |
action_result.data.\*.\*.Event.locked | numeric | | True False |
action_result.data.\*.\*.Event.proposal_email_lock | numeric | | True False |
action_result.data.\*.\*.Event.publish_timestamp | string | | 0 |
action_result.data.\*.\*.Event.sharing_group_id | string | | 0 |
action_result.data.\*.Attribute.\*.Event.distribution | string | | 1 |
action_result.data.\*.Attribute.\*.Event.id | string | | 2020 |
action_result.data.\*.Attribute.\*.Event.info | string | | Event created by test |
action_result.data.\*.Attribute.\*.Event.org_id | string | | 1 |
action_result.data.\*.Attribute.\*.Event.orgc_id | string | | 1 |
action_result.data.\*.Attribute.\*.Event.uuid | string | | 342c12ab-32ad-41d0-aea2-1c3dccc6ce09 |
action_result.data.\*.Attribute.\*.Object.distribution | string | | 5 |
action_result.data.\*.Attribute.\*.Object.id | string | | 10 |
action_result.data.\*.Attribute.\*.Object.sharing_group_id | string | | 0 |
action_result.data.\*.Attribute.\*.category | string | | Other Payload delivery |
action_result.data.\*.Attribute.\*.comment | string | | |
action_result.data.\*.Attribute.\*.deleted | boolean | | True False |
action_result.data.\*.Attribute.\*.disable_correlation | boolean | | True False |
action_result.data.\*.Attribute.\*.distribution | string | | 5 |
action_result.data.\*.Attribute.\*.event_id | string | `misp event id` | 1 |
action_result.data.\*.Attribute.\*.first_seen | string | | |
action_result.data.\*.Attribute.\*.id | string | `misp attribute id` | 164201 |
action_result.data.\*.Attribute.\*.last_seen | string | | |
action_result.data.\*.Attribute.\*.object_id | string | | 0 10 |
action_result.data.\*.Attribute.\*.object_relation | string | | filename |
action_result.data.\*.Attribute.\*.sharing_group_id | string | | 0 |
action_result.data.\*.Attribute.\*.timestamp | string | | 1498505296 |
action_result.data.\*.Attribute.\*.to_ids | boolean | | True False |
action_result.data.\*.Attribute.\*.type | string | | comment filename |
action_result.data.\*.Attribute.\*.uuid | string | | 56e96919-ad18-4f68-8aa1-539002de0b81 |
action_result.data.\*.Attribute.\*.value | string | `url` `domain` `ip` `email` `hash` `md5` `sha256` `md1` | email1@gmail.com |
action_result.data.\*.attribute_count | string | | 103 |
action_result.summary.returned_rows | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
