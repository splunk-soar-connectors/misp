[comment]: # "Auto-generated SOAR connector documentation"
# MISP

Publisher: Splunk  
Connector Version: 2.2.2  
Product Vendor: MISP  
Product Name: MISP  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.2.1  

Take action with Malware Information Sharing Platform

[comment]: # "File: README.md"
[comment]: # "Copyright (c) 2017-2024 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## pymisp-2.4.138

This app uses the pymisp module, which is licensed under an open source license. A simplified 2-BSD
License, Copyright (c) 2017 Raphaël Vinot.

## jsonschema-3.2.0

This app uses the jsonschema module, which is licensed under the MIT License, Copyright (c) 2013
Julian Berman.

## Deprecated-1.2.12

This app uses the Deprecated module, which is licensed under the MIT License, Copyright (c) 2017
Laurent LAPORTE.

## cachetools-4.2.2

This app uses the cachetools module, which is licensed under the MIT License, Copyright (c)
2014-2021 Thomas Kemmer.  

Misp will return integers which correspond to various values. Here is the complete list:  
  
For **distribution** :  

-   0: Your Org Only
-   1: This Community Only
-   2: Connected Communities
-   3: All Communities
-   4: Sharing Group
-   5: Inherit

  
For **threat level id** :  

-   1: High
-   2: Medium
-   3: Low
-   4: Undefined

  
For **analysis** :  

-   0: Initial
-   1: Ongoing
-   2: Completed

  
**Note:**

-   There is no validation provided in case of an incorrect value in the 'json' action parameter of
    the **'create event'** and **'update event'** actions. Hence, the action will pass even if an
    incorrect attribute value is passed in the 'json' action parameter and no attributes will be
    added.

-   The value of the attribute passed in the 'json' action parameter of **'create event'** and
    **'update event'** will be treated as a list if a list is specified. If a string is specified
    then a list will be created by splitting the string by comma (,). For example:

    -   json: {"email_body": \["body 1", "body 2"\], "ip-dst": "8.8.8.8, 12.4.6.34"}

    The value of the 'email_body' will be considered a list and the value of the 'ip-dst' will be
    converted to a list having two elements(\["8.8.8.8", "12.4.6.34"\]).

-   In the **'run query'** action, tags containing a comma (,) in its value can be passed through
    the 'other' action parameter. For example:

    -   other: {"tags": \["tag1, tag11", "tag_2"\]}

    "tag1, tag11" will be considered a single tag.

## Port Information

The app uses HTTP/HTTPS protocol for communicating with the Misp Server. Below are the default ports
used by Splunk SOAR.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |


### Configuration variables
This table lists the configuration variables required to operate MISP. These variables are specified when configuring a MISP asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** |  required  | string | MISP instance URL (http://misp_instance.company.com/)
**verify_server_cert** |  optional  | boolean | Verify server certificate
**api_key** |  required  | password | API Key found under Event Actions: Automation

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[create event](#action-create-event) - Create a new event in MISP  
[update event](#action-update-event) - Add attributes / IOCs to an event in MISP  
[run query](#action-run-query) - Run a query to find events or attributes  
[get attributes](#action-get-attributes) - Get attributes for a specific event  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'create event'
Create a new event in MISP

Type: **generic**  
Read only: **False**

This action first creates an event, then adds attributes to that event. Parameters urls, domains, source_ips, dest_ips, source_emails, dest_emails accept comma-separated values.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**distribution** |  required  | Distribution level for sharing | string | 
**threat_level_id** |  required  | Threat level id | string | 
**analysis** |  required  | Current stage of analysis for event | string | 
**info** |  required  | Information / Description for Event | string | 
**add_attributes** |  optional  | Add attributes upon event creation | boolean | 
**to_ids** |  optional  | Set 'to_IDS' flag=True in MISP | boolean | 
**source_ips** |  optional  | Source IPs to be added as attributes | string |  `ip` 
**dest_ips** |  optional  | Destination IPs to be added as attributes | string |  `ip` 
**domains** |  optional  | Domains to be added as attributes | string |  `domain` 
**source_emails** |  optional  | Source email addresses to be added as attributes | string |  `email` 
**dest_emails** |  optional  | Destination email addresses to be added as attributes | string |  `email` 
**urls** |  optional  | URLs to be added as attributes | string |  `url` 
**tags** |  optional  | Comma separated list of tags | string | 
**json** |  optional  | JSON key value list of attributes | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.add_attributes | boolean |  |   True  False 
action_result.parameter.analysis | string |  |   Initial 
action_result.parameter.dest_emails | string |  `email`  |   test@test.com 
action_result.parameter.dest_ips | string |  `ip`  |   122.122.122.122 
action_result.parameter.distribution | string |  |   This Community Only 
action_result.parameter.domains | string |  `domain`  |   www.test.com 
action_result.parameter.info | string |  |   Event Info Goes Here 
action_result.parameter.json | string |  |   {"ip-src|port":"1.1.1.1:888"} 
action_result.parameter.source_emails | string |  `email`  |   test@test.com 
action_result.parameter.source_ips | string |  `ip`  |   122.122.122.122 
action_result.parameter.threat_level_id | string |  |   undefined 
action_result.parameter.to_ids | boolean |  |   True  False 
action_result.parameter.urls | string |  `url`  |   https://test.com 
action_result.parameter.tags | string |  |   test_1,test_2 
action_result.data.\*.Org.id | string |  |   1 
action_result.data.\*.Org.local | boolean |  |   True  False 
action_result.data.\*.Org.name | string |  |   ORGNAME 
action_result.data.\*.Org.uuid | string |  |   2af87aa3-a713-4ca5-83f7-03ae949c8459 
action_result.data.\*.Orgc.id | string |  |   1 
action_result.data.\*.Orgc.local | boolean |  |   True  False 
action_result.data.\*.Orgc.name | string |  |   ORGNAME 
action_result.data.\*.Orgc.uuid | string |  |   2af87aa3-a713-4ca5-83f7-03ae949c8459 
action_result.data.\*.analysis | string |  |   0 
action_result.data.\*.attribute_count | string |  |  
action_result.data.\*.category | string |  |   Network activity 
action_result.data.\*.comment | string |  |  
action_result.data.\*.date | string |  |   2021-06-09 
action_result.data.\*.deleted | boolean |  |   True  False 
action_result.data.\*.disable_correlation | boolean |  |   True  False 
action_result.data.\*.distribution | string |  |  
action_result.data.\*.event_creator_email | string |  |   test@test.com 
action_result.data.\*.event_id | string |  `misp event id`  |   2052 
action_result.data.\*.extends_uuid | string |  |  
action_result.data.\*.id | string |  |  
action_result.data.\*.info | string |  |  
action_result.data.\*.locked | boolean |  |   True  False 
action_result.data.\*.object_id | string |  |   0 
action_result.data.\*.org_id | string |  |   1 
action_result.data.\*.orgc_id | string |  |   1 
action_result.data.\*.proposal_email_lock | boolean |  |   True  False 
action_result.data.\*.publish_timestamp | numeric |  |   0 
action_result.data.\*.published | boolean |  |   True  False 
action_result.data.\*.sharing_group_id | string |  |   0 
action_result.data.\*.threat_level_id | string |  |  
action_result.data.\*.timestamp | string |  |   1623206691 
action_result.data.\*.to_ids | boolean |  |   True  False 
action_result.data.\*.type | string |  |   url 
action_result.data.\*.uuid | string |  |   82c82204-4ebd-42cb-a913-4df726b5d7fe 
action_result.data.\*.value | string |  `url`  `domain`  `ip`  `email`  `hash`  `md5`  `sha256`  `md1`  |   8.8.8.8 
action_result.data.0.id | string |  `misp event id`  |  
action_result.summary.errors | string |  |    'test' is/are invalid attribute name/names in 'json' action parameter 
action_result.summary.message | string |  |   Event created with id: 2139 
action_result.message | string |  |   Message: Event created with id: 2139, Errors: 'test' is/are invalid attribute name/names in 'json' action parameter 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'update event'
Add attributes / IOCs to an event in MISP

Type: **generic**  
Read only: **False**

Parameters urls, domains, source_ips, dest_ips, source_emails, dest_emails accept comma-separated values.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event_id** |  required  | MISP event ID for adding attributes | numeric |  `misp event id` 
**to_ids** |  optional  | Set 'to_IDS' flag=True in MISP | boolean | 
**source_ips** |  optional  | Source IPs to be added as attributes | string |  `ip` 
**dest_ips** |  optional  | Destination IPs to be added as attributes | string |  `ip` 
**domains** |  optional  | Domains to be added as attributes | string |  `domain` 
**source_emails** |  optional  | Source email addresses to be added as attributes | string |  `email` 
**dest_emails** |  optional  | Destination email addresses to be added as attributes | string |  `email` 
**urls** |  optional  | URLs to be added as attributes | string |  `url` 
**tags** |  optional  | Comma separated list of tags (append to existing tags default) | string | 
**replace_tags** |  optional  | Replace tags with new provided tags | boolean | 
**json** |  optional  | JSON key value list of attributes | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.dest_emails | string |  `email`  |   test@test.com 
action_result.parameter.dest_ips | string |  `ip`  |   122.122.122.122 
action_result.parameter.domains | string |  `domain`  |   www.test.com 
action_result.parameter.event_id | numeric |  `misp event id`  |   686 
action_result.parameter.tags | string |  |   test_1,test2 
action_result.parameter.replace_tags | boolean |  |   True  False 
action_result.parameter.json | string |  |   {"comment":["email_1,email11","email_2"], "soufds":"jflkl"} 
action_result.parameter.source_emails | string |  `email`  |   test@test.com 
action_result.parameter.source_ips | string |  `ip`  |   122.122.122.122 
action_result.parameter.to_ids | boolean |  |   True  False 
action_result.parameter.urls | string |  `url`  |   http://test.com 
action_result.data.\*.category | string |  |   Other 
action_result.data.\*.comment | string |  |  
action_result.data.\*.deleted | boolean |  |   True  False 
action_result.data.\*.disable_correlation | boolean |  |   True  False 
action_result.data.\*.distribution | string |  |   5 
action_result.data.\*.event_id | string |  `misp event id`  |   2121 
action_result.data.\*.id | string |  `misp attribute id`  |   5360 
action_result.data.\*.object_id | string |  |   0 
action_result.data.\*.sharing_group_id | string |  |   0 
action_result.data.\*.timestamp | string |  |   1623038555 
action_result.data.\*.to_ids | boolean |  |   True  False 
action_result.data.\*.type | string |  |   port 
action_result.data.\*.uuid | string |  |   68e219ee-5727-4cb2-a32f-8dc27aa4231f 
action_result.data.\*.value | string |  `url`  `domain`  `ip`  `email`  `hash`  `md5`  `sha256`  `md1`  |   email1@email.com 
action_result.summary | string |  |  
action_result.summary.errors | string |  |    'soufds' is/are invalid attribute name/names in 'json' action parameter 
action_result.summary.message | string |  |   Attributes added to event: 2121 
action_result.message | string |  |   Message: Attributes added to event: 2121, Errors:  'soufds' is/are invalid attribute name/names in 'json' action parameter 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'run query'
Run a query to find events or attributes

Type: **investigate**  
Read only: **True**

By setting max_results to 0, you can get every result. It is recommended you do not do this, as MISP can return <b>a lot</b> of data. The default is 10, and this will be the oldest 10 results.<br><br>The other field expects a json string, which can have the key value pairs of any field which the search API supports.<br><br>By giving max results as a negative number, <i>n</i>, it will take the last <i>n</i> results from the query. From there, you can take the timestamp from the first object in the resulting list, then pass it in the <b>other</b> field like so: {"timestamp": &lt;timestamp + 1&gt;}. All the results will now be after that specified timestamp.<br><br>Also note that when searching for events, events with no attributes will not be returned.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**controller** |  required  | Search for events or attributes | string | 
**max_results** |  optional  | Max results to return | numeric | 
**event_id** |  optional  | Comma seperated list of Event IDs | string |  `misp event id` 
**tags** |  optional  | Comma seperated list of tags | string | 
**other** |  optional  | Other search parameters, as a JSON object | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.controller | string |  |   events  attributes 
action_result.parameter.event_id | string |  `misp event id`  |   1 
action_result.parameter.max_results | numeric |  |   1000 
action_result.parameter.other | string |  |  
action_result.parameter.tags | string |  |   test_1 
action_result.data.\*.\*.Event.Attribute.\*.category | string |  |   Network activity 
action_result.data.\*.\*.Event.Attribute.\*.comment | string |  |  
action_result.data.\*.\*.Event.Attribute.\*.deleted | numeric |  |   True  False 
action_result.data.\*.\*.Event.Attribute.\*.disable_correlation | numeric |  |   True  False 
action_result.data.\*.\*.Event.Attribute.\*.distribution | string |  |   5 
action_result.data.\*.\*.Event.Attribute.\*.event_id | string |  |   1 
action_result.data.\*.\*.Event.Attribute.\*.first_seen | string |  |  
action_result.data.\*.\*.Event.Attribute.\*.id | string |  |   4265 
action_result.data.\*.\*.Event.Attribute.\*.last_seen | string |  |  
action_result.data.\*.\*.Event.Attribute.\*.object_id | string |  |   0 
action_result.data.\*.\*.Event.Attribute.\*.object_relation | string |  |  
action_result.data.\*.\*.Event.Attribute.\*.sharing_group_id | string |  |   0 
action_result.data.\*.\*.Event.Attribute.\*.timestamp | string |  |   1622191169 
action_result.data.\*.\*.Event.Attribute.\*.to_ids | numeric |  |   True  False 
action_result.data.\*.\*.Event.Attribute.\*.type | string |  `url`  |   email-dst 
action_result.data.\*.\*.Event.Attribute.\*.uuid | string |  |   03fa856e-b6f9-4e34-82ac-1e50dd058f37 
action_result.data.\*.\*.Event.Attribute.\*.value | string |  `url`  `domain`  `ip`  `email`  `hash`  `md5`  `sha256`  `md1`  |   abc@abc.com 
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.category | string |  |   Payload delivery 
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.comment | string |  |  
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.deleted | numeric |  |   True  False 
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.disable_correlation | numeric |  |   True  False 
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.distribution | string |  |   5 
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.event_id | string |  |   2020 
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.first_seen | string |  |  
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.id | string |  |   4953 
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.last_seen | string |  |  
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.object_id | string |  |   10 
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.object_relation | string |  |   filename 
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.sharing_group_id | string |  |   0 
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.timestamp | string |  |   1623078296 
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.to_ids | numeric |  |   True  False 
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.type | string |  |   filename 
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.uuid | string |  |   2fd53a9b-44fd-4ebc-af93-0e1605cf3b64 
action_result.data.\*.\*.Event.Object.\*.Attribute.\*.value | string |  `url`  `domain`  `ip`  `email`  `hash`  `md5`  `sha256`  `md1`  |   6.43.3.2 
action_result.data.\*.\*.Event.Object.\*.comment | string |  |  
action_result.data.\*.\*.Event.Object.\*.deleted | numeric |  |   True  False 
action_result.data.\*.\*.Event.Object.\*.description | string |  |   File object describing a file with meta-information 
action_result.data.\*.\*.Event.Object.\*.distribution | string |  |   5 
action_result.data.\*.\*.Event.Object.\*.event_id | string |  |   2020 
action_result.data.\*.\*.Event.Object.\*.first_seen | string |  |  
action_result.data.\*.\*.Event.Object.\*.id | string |  |   10 
action_result.data.\*.\*.Event.Object.\*.last_seen | string |  |  
action_result.data.\*.\*.Event.Object.\*.meta-category | string |  |   file 
action_result.data.\*.\*.Event.Object.\*.name | string |  |   file 
action_result.data.\*.\*.Event.Object.\*.sharing_group_id | string |  |   0 
action_result.data.\*.\*.Event.Object.\*.template_uuid | string |  |   688c46fb-5edb-40a3-8273-1af7923e2215 
action_result.data.\*.\*.Event.Object.\*.template_version | string |  |   24 
action_result.data.\*.\*.Event.Object.\*.timestamp | string |  |   1623078296 
action_result.data.\*.\*.Event.Object.\*.uuid | string |  |   4b5cb238-9e55-40eb-b60e-b30f71cab6f6 
action_result.data.\*.\*.Event.Org.id | string |  |   1 
action_result.data.\*.\*.Event.Org.local | numeric |  |   True  False 
action_result.data.\*.\*.Event.Org.name | string |  |   ORGNAME 
action_result.data.\*.\*.Event.Org.uuid | string |  |   2af87aa3-a713-4ca5-83f7-03ae949c8459 
action_result.data.\*.\*.Event.Orgc.id | string |  |   1 
action_result.data.\*.\*.Event.Orgc.local | numeric |  |   True  False 
action_result.data.\*.\*.Event.Orgc.name | string |  |   ORGNAME 
action_result.data.\*.\*.Event.Orgc.uuid | string |  |   2af87aa3-a713-4ca5-83f7-03ae949c8459 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.Org.id | string |  |   1 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.Org.name | string |  |   ORGNAME 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.Org.uuid | string |  |   2af87aa3-a713-4ca5-83f7-03ae949c8459 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.Orgc.id | string |  |   1 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.Orgc.name | string |  |   ORGNAME 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.Orgc.uuid | string |  |   2af87aa3-a713-4ca5-83f7-03ae949c8459 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.analysis | string |  |   0 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.date | string |  |   2021-06-14 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.distribution | string |  |   1 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.id | string |  |   2161 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.info | string |  |   Event created by test 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.org_id | string |  |   1 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.orgc_id | string |  |   1 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.published | numeric |  |   True  False 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.threat_level_id | string |  |   4 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.timestamp | string |  |   1623645286 
action_result.data.\*.\*.Event.RelatedEvent.\*.Event.uuid | string |  |   f346cd43-ef47-4401-b725-a5f4f45a4ed3 
action_result.data.\*.\*.Event.Tag.\*.colour | string |  |   #7ab870 
action_result.data.\*.\*.Event.Tag.\*.exportable | numeric |  |   True  False 
action_result.data.\*.\*.Event.Tag.\*.hide_tag | numeric |  |   True  False 
action_result.data.\*.\*.Event.Tag.\*.id | string |  |   8 
action_result.data.\*.\*.Event.Tag.\*.is_custom_galaxy | numeric |  |   True  False 
action_result.data.\*.\*.Event.Tag.\*.is_galaxy | numeric |  |   True  False 
action_result.data.\*.\*.Event.Tag.\*.local | numeric |  |   1 
action_result.data.\*.\*.Event.Tag.\*.name | string |  |   test_1 
action_result.data.\*.\*.Event.Tag.\*.numerical_value | string |  |  
action_result.data.\*.\*.Event.Tag.\*.user_id | string |  |   1 
action_result.data.\*.\*.Event.analysis | string |  |   0 
action_result.data.\*.\*.Event.attribute_count | string |  |   7 
action_result.data.\*.\*.Event.date | string |  |   2021-03-17 
action_result.data.\*.\*.Event.disable_correlation | numeric |  |   True  False 
action_result.data.\*.\*.Event.distribution | string |  |   1 
action_result.data.\*.\*.Event.event_creator_email | string |  `email`  |   test@test.com 
action_result.data.\*.\*.Event.extends_uuid | string |  |  
action_result.data.\*.\*.Event.id | string |  |   1 
action_result.data.\*.\*.Event.info | string |  |   Event created by test 
action_result.data.\*.\*.Event.locked | numeric |  |   True  False 
action_result.data.\*.\*.Event.org_id | string |  |   1 
action_result.data.\*.\*.Event.orgc_id | string |  |   1 
action_result.data.\*.\*.Event.proposal_email_lock | numeric |  |   True  False 
action_result.data.\*.\*.Event.publish_timestamp | string |  |   0 
action_result.data.\*.\*.Event.published | numeric |  |   True  False 
action_result.data.\*.\*.Event.sharing_group_id | string |  |   0 
action_result.data.\*.\*.Event.threat_level_id | string |  |   4 
action_result.data.\*.\*.Event.timestamp | string |  |   1623657727 
action_result.data.\*.\*.Event.uuid | string |  |   15483d56-fc32-4e54-a8b4-e9f56e7818bd 
action_result.data.\*.Attribute.\*.Event.distribution | string |  |   1 
action_result.data.\*.Attribute.\*.Event.id | string |  |   2020 
action_result.data.\*.Attribute.\*.Event.info | string |  |   Event created by test 
action_result.data.\*.Attribute.\*.Event.org_id | string |  |   1 
action_result.data.\*.Attribute.\*.Event.orgc_id | string |  |   1 
action_result.data.\*.Attribute.\*.Event.uuid | string |  |   342c12ab-32ad-41d0-aea2-1c3dccc6ce09 
action_result.data.\*.Attribute.\*.Object.distribution | string |  |   5 
action_result.data.\*.Attribute.\*.Object.id | string |  |   10 
action_result.data.\*.Attribute.\*.Object.sharing_group_id | string |  |   0 
action_result.data.\*.Attribute.\*.category | string |  |   Other  Payload delivery 
action_result.data.\*.Attribute.\*.comment | string |  |  
action_result.data.\*.Attribute.\*.deleted | numeric |  |   True  False 
action_result.data.\*.Attribute.\*.disable_correlation | numeric |  |   False  True 
action_result.data.\*.Attribute.\*.distribution | string |  |   5 
action_result.data.\*.Attribute.\*.event_id | string |  `misp event id`  |   1 
action_result.data.\*.Attribute.\*.first_seen | string |  |  
action_result.data.\*.Attribute.\*.id | string |  `misp attribute id`  |   164201 
action_result.data.\*.Attribute.\*.last_seen | string |  |  
action_result.data.\*.Attribute.\*.object_id | string |  |   0  10 
action_result.data.\*.Attribute.\*.object_relation | string |  |   filename 
action_result.data.\*.Attribute.\*.sharing_group_id | string |  |   0 
action_result.data.\*.Attribute.\*.timestamp | string |  |   1498505296 
action_result.data.\*.Attribute.\*.to_ids | boolean |  |   True  False 
action_result.data.\*.Attribute.\*.type | string |  |   comment  filename 
action_result.data.\*.Attribute.\*.uuid | string |  |   56e96919-ad18-4f68-8aa1-539002de0b81 
action_result.data.\*.Attribute.\*.value | string |  `url`  `domain`  `ip`  `email`  `hash`  `md5`  `sha256`  `md1`  |   email1@gmail.com 
action_result.data.\*.attribute_count | string |  |   103 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully ran query 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get attributes'
Get attributes for a specific event

Type: **investigate**  
Read only: **True**

<b>download_samples</b> will only download files which are marked as a 'malware-sample'.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event_id** |  required  | An Event ID | numeric |  `misp event id` 
**download_samples** |  optional  | Download malware samples to vault | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.download_samples | boolean |  |   True  False 
action_result.parameter.event_id | numeric |  `misp event id`  |   686 
action_result.data.\*.Attribute.\*.Event.distribution | string |  |   1 
action_result.data.\*.Attribute.\*.Event.id | string |  `misp event id`  |   2028 
action_result.data.\*.Attribute.\*.Event.info | string |  |   Event created by test 
action_result.data.\*.Attribute.\*.Event.org_id | string |  |   1 
action_result.data.\*.Attribute.\*.Event.orgc_id | string |  |   1 
action_result.data.\*.Attribute.\*.Event.uuid | string |  |   552d93e4-fa0d-48cb-810e-a5f56c0af5ea  342c12ab-32ad-41d0-aea2-1c3dccc6ce09 
action_result.data.\*.Attribute.\*.Object.distribution | string |  |   5 
action_result.data.\*.Attribute.\*.Object.id | string |  |   10 
action_result.data.\*.Attribute.\*.Object.sharing_group_id | string |  |   0 
action_result.data.\*.Attribute.\*.category | string |  |   Network activity 
action_result.data.\*.Attribute.\*.comment | string |  |  
action_result.data.\*.Attribute.\*.deleted | boolean |  |   False  True 
action_result.data.\*.Attribute.\*.disable_correlation | boolean |  |   False  True 
action_result.data.\*.Attribute.\*.distribution | string |  |   5 
action_result.data.\*.Attribute.\*.event_id | string |  `misp event id`  |   686 
action_result.data.\*.Attribute.\*.first_seen | string |  |  
action_result.data.\*.Attribute.\*.id | string |  `misp attribute id`  |   164191 
action_result.data.\*.Attribute.\*.last_seen | string |  |  
action_result.data.\*.Attribute.\*.object_id | string |  |   0  10 
action_result.data.\*.Attribute.\*.object_relation | string |  |   filename 
action_result.data.\*.Attribute.\*.sharing_group_id | string |  |   0 
action_result.data.\*.Attribute.\*.timestamp | string |  |   1498002097 
action_result.data.\*.Attribute.\*.to_ids | boolean |  |   True  False 
action_result.data.\*.Attribute.\*.type | string |  |   ip-src 
action_result.data.\*.Attribute.\*.uuid | string |  |   5949b2b1-35b4-4152-a633-7e530a10000d 
action_result.data.\*.Attribute.\*.value | string |  `url`  `domain`  `ip`  `email`  `hash`  `md5`  `sha256`  `md1`  |   192.162.8.1 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully retrieved attributes 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 