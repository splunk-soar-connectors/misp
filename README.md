[comment]: # "Auto-generated SOAR connector documentation"
# MISP

Publisher: Splunk  
Connector Version: 2\.1\.6  
Product Vendor: MISP  
Product Name: MISP  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

Take action with Malware Information Sharing Platform

[comment]: # "File: README.md"
[comment]: # "Copyright (c) 2017-2022 Splunk Inc."
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


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a MISP asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | MISP instance URL \(http\://misp\_instance\.company\.com/\)
**verify\_server\_cert** |  required  | boolean | Verify server certificate
**api\_key** |  required  | password | API Key found under Event Actions\: Automation

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

This action first creates an event, then adds attributes to that event\. Parameters urls, domains, source\_ips, dest\_ips, source\_emails, dest\_emails accept comma\-separated values\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**distribution** |  required  | Distribution level for sharing | string | 
**threat\_level\_id** |  required  | Threat level id | string | 
**analysis** |  required  | Current stage of analysis for event | string | 
**info** |  required  | Information / Description for Event | string | 
**add\_attributes** |  optional  | Add attributes upon event creation | boolean | 
**to\_ids** |  optional  | Set 'to\_IDS' flag=True in MISP | boolean | 
**source\_ips** |  optional  | Source IPs to be added as attributes | string |  `ip` 
**dest\_ips** |  optional  | Destination IPs to be added as attributes | string |  `ip` 
**domains** |  optional  | Domains to be added as attributes | string |  `domain` 
**source\_emails** |  optional  | Source email addresses to be added as attributes | string |  `email` 
**dest\_emails** |  optional  | Destination email addresses to be added as attributes | string |  `email` 
**urls** |  optional  | URLs to be added as attributes | string |  `url` 
**json** |  optional  | JSON key value list of attributes | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.add\_attributes | boolean | 
action\_result\.parameter\.analysis | string | 
action\_result\.parameter\.dest\_emails | string |  `email` 
action\_result\.parameter\.dest\_ips | string |  `ip` 
action\_result\.parameter\.distribution | string | 
action\_result\.parameter\.domains | string |  `domain` 
action\_result\.parameter\.info | string | 
action\_result\.parameter\.json | string | 
action\_result\.parameter\.source\_emails | string |  `email` 
action\_result\.parameter\.source\_ips | string |  `ip` 
action\_result\.parameter\.threat\_level\_id | string | 
action\_result\.parameter\.to\_ids | boolean | 
action\_result\.parameter\.urls | string |  `url` 
action\_result\.data\.\*\.Org\.id | string | 
action\_result\.data\.\*\.Org\.local | boolean | 
action\_result\.data\.\*\.Org\.name | string | 
action\_result\.data\.\*\.Org\.uuid | string | 
action\_result\.data\.\*\.Orgc\.id | string | 
action\_result\.data\.\*\.Orgc\.local | boolean | 
action\_result\.data\.\*\.Orgc\.name | string | 
action\_result\.data\.\*\.Orgc\.uuid | string | 
action\_result\.data\.\*\.analysis | string | 
action\_result\.data\.\*\.attribute\_count | string | 
action\_result\.data\.\*\.category | string | 
action\_result\.data\.\*\.comment | string | 
action\_result\.data\.\*\.date | string | 
action\_result\.data\.\*\.deleted | boolean | 
action\_result\.data\.\*\.disable\_correlation | boolean | 
action\_result\.data\.\*\.distribution | string | 
action\_result\.data\.\*\.event\_creator\_email | string | 
action\_result\.data\.\*\.event\_id | string |  `misp event id` 
action\_result\.data\.\*\.extends\_uuid | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.info | string | 
action\_result\.data\.\*\.locked | boolean | 
action\_result\.data\.\*\.object\_id | string | 
action\_result\.data\.\*\.org\_id | string | 
action\_result\.data\.\*\.orgc\_id | string | 
action\_result\.data\.\*\.proposal\_email\_lock | boolean | 
action\_result\.data\.\*\.publish\_timestamp | numeric | 
action\_result\.data\.\*\.published | boolean | 
action\_result\.data\.\*\.sharing\_group\_id | string | 
action\_result\.data\.\*\.threat\_level\_id | string | 
action\_result\.data\.\*\.timestamp | string | 
action\_result\.data\.\*\.to\_ids | boolean | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.value | string |  `url`  `domain`  `ip`  `email`  `hash`  `md5`  `sha256`  `md1` 
action\_result\.data\.0\.id | string |  `misp event id` 
action\_result\.summary\.errors | string | 
action\_result\.summary\.message | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update event'
Add attributes / IOCs to an event in MISP

Type: **generic**  
Read only: **False**

Parameters urls, domains, source\_ips, dest\_ips, source\_emails, dest\_emails accept comma\-separated values\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event\_id** |  required  | MISP event ID for adding attributes | numeric |  `misp event id` 
**to\_ids** |  optional  | Set 'to\_IDS' flag=True in MISP | boolean | 
**source\_ips** |  optional  | Source IPs to be added as attributes | string |  `ip` 
**dest\_ips** |  optional  | Destination IPs to be added as attributes | string |  `ip` 
**domains** |  optional  | Domains to be added as attributes | string |  `domain` 
**source\_emails** |  optional  | Source email addresses to be added as attributes | string |  `email` 
**dest\_emails** |  optional  | Destination email addresses to be added as attributes | string |  `email` 
**urls** |  optional  | URLs to be added as attributes | string |  `url` 
**json** |  optional  | JSON key value list of attributes | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.dest\_emails | string |  `email` 
action\_result\.parameter\.dest\_ips | string |  `ip` 
action\_result\.parameter\.domains | string |  `domain` 
action\_result\.parameter\.event\_id | numeric |  `misp event id` 
action\_result\.parameter\.json | string | 
action\_result\.parameter\.source\_emails | string |  `email` 
action\_result\.parameter\.source\_ips | string |  `ip` 
action\_result\.parameter\.to\_ids | boolean | 
action\_result\.parameter\.urls | string |  `url` 
action\_result\.data\.\*\.category | string | 
action\_result\.data\.\*\.comment | string | 
action\_result\.data\.\*\.deleted | boolean | 
action\_result\.data\.\*\.disable\_correlation | boolean | 
action\_result\.data\.\*\.distribution | string | 
action\_result\.data\.\*\.event\_id | string |  `misp event id` 
action\_result\.data\.\*\.id | string |  `misp attribute id` 
action\_result\.data\.\*\.object\_id | string | 
action\_result\.data\.\*\.sharing\_group\_id | string | 
action\_result\.data\.\*\.timestamp | string | 
action\_result\.data\.\*\.to\_ids | boolean | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.value | string |  `url`  `domain`  `ip`  `email`  `hash`  `md5`  `sha256`  `md1` 
action\_result\.summary | string | 
action\_result\.summary\.errors | string | 
action\_result\.summary\.message | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'run query'
Run a query to find events or attributes

Type: **investigate**  
Read only: **True**

By setting max\_results to 0, you can get every result\. It is recommended you do not do this, as MISP can return <b>a lot</b> of data\. The default is 10, and this will be the oldest 10 results\.<br><br>The other field expects a json string, which can have the key value pairs of any field which the search API supports\.<br><br>The MISP API doesn't support paging, but it is possible to work around this\. By giving max results as a negative number, <i>n</i>, it will take the last <i>n</i> results from the query\. From there, you can take the timestamp from the first object in the resulting list, then pass it in the <b>other</b> field like so\: \{"timestamp"\: &lt;timestamp \+ 1&gt;\}\. All the results will now be after that specified timestamp\.<br><br>Also note that when searching for events, events with no attributes will not be returned\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**controller** |  required  | Search for events or attributes | string | 
**max\_results** |  optional  | Max results to return | numeric | 
**event\_id** |  optional  | Comma seperated list of Event IDs | string |  `misp event id` 
**tags** |  optional  | Comma seperated list of tags | string | 
**other** |  optional  | Other search parameters, as a JSON object | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.controller | string | 
action\_result\.parameter\.event\_id | string |  `misp event id` 
action\_result\.parameter\.max\_results | numeric | 
action\_result\.parameter\.other | string | 
action\_result\.parameter\.tags | string | 
action\_result\.data\.\*\.Attribute\.\*\.Event\.distribution | string | 
action\_result\.data\.\*\.Attribute\.\*\.Event\.id | string | 
action\_result\.data\.\*\.Attribute\.\*\.Event\.info | string | 
action\_result\.data\.\*\.Attribute\.\*\.Event\.org\_id | string | 
action\_result\.data\.\*\.Attribute\.\*\.Event\.orgc\_id | string | 
action\_result\.data\.\*\.Attribute\.\*\.Event\.uuid | string | 
action\_result\.data\.\*\.Attribute\.\*\.Object\.distribution | string | 
action\_result\.data\.\*\.Attribute\.\*\.Object\.id | string | 
action\_result\.data\.\*\.Attribute\.\*\.Object\.sharing\_group\_id | string | 
action\_result\.data\.\*\.Attribute\.\*\.category | string | 
action\_result\.data\.\*\.Attribute\.\*\.comment | string | 
action\_result\.data\.\*\.Attribute\.\*\.deleted | numeric | 
action\_result\.data\.\*\.Attribute\.\*\.disable\_correlation | numeric | 
action\_result\.data\.\*\.Attribute\.\*\.distribution | string | 
action\_result\.data\.\*\.Attribute\.\*\.event\_id | string |  `misp event id` 
action\_result\.data\.\*\.Attribute\.\*\.first\_seen | string | 
action\_result\.data\.\*\.Attribute\.\*\.id | string |  `misp attribute id` 
action\_result\.data\.\*\.Attribute\.\*\.last\_seen | string | 
action\_result\.data\.\*\.Attribute\.\*\.object\_id | string | 
action\_result\.data\.\*\.Attribute\.\*\.object\_relation | string | 
action\_result\.data\.\*\.Attribute\.\*\.sharing\_group\_id | string | 
action\_result\.data\.\*\.Attribute\.\*\.timestamp | string | 
action\_result\.data\.\*\.Attribute\.\*\.to\_ids | boolean | 
action\_result\.data\.\*\.Attribute\.\*\.type | string | 
action\_result\.data\.\*\.Attribute\.\*\.uuid | string | 
action\_result\.data\.\*\.Attribute\.\*\.value | string |  `url`  `domain`  `ip`  `email`  `hash`  `md5`  `sha256`  `md1` 
action\_result\.data\.\*\.\*\.Event\.id | string | 
action\_result\.data\.\*\.\*\.Event\.Org\.id | string | 
action\_result\.data\.\*\.\*\.Event\.Org\.name | string | 
action\_result\.data\.\*\.\*\.Event\.Org\.uuid | string | 
action\_result\.data\.\*\.\*\.Event\.Org\.local | numeric | 
action\_result\.data\.\*\.\*\.Event\.Orgc\.id | string | 
action\_result\.data\.\*\.\*\.Event\.Orgc\.name | string | 
action\_result\.data\.\*\.\*\.Event\.Orgc\.uuid | string | 
action\_result\.data\.\*\.\*\.Event\.Orgc\.local | numeric | 
action\_result\.data\.\*\.\*\.Event\.date | string | 
action\_result\.data\.\*\.\*\.Event\.info | string | 
action\_result\.data\.\*\.\*\.Event\.uuid | string | 
action\_result\.data\.\*\.\*\.Event\.locked | numeric | 
action\_result\.data\.\*\.\*\.Event\.org\_id | string | 
action\_result\.data\.\*\.\*\.Event\.orgc\_id | string | 
action\_result\.data\.\*\.\*\.Event\.analysis | string | 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.id | string | 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.type | string |  `url` 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.uuid | string | 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.value | string |  `url`  `domain`  `ip`  `email`  `hash`  `md5`  `sha256`  `md1` 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.to\_ids | numeric | 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.comment | string | 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.deleted | numeric | 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.category | string | 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.event\_id | string | 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.last\_seen | string | 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.object\_id | string | 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.timestamp | string | 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.first\_seen | string | 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.distribution | string | 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.object\_relation | string | 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.sharing\_group\_id | string | 
action\_result\.data\.\*\.\*\.Event\.Attribute\.\*\.disable\_correlation | numeric | 
action\_result\.data\.\*\.\*\.Event\.published | numeric | 
action\_result\.data\.\*\.\*\.Event\.timestamp | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.id | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.Org\.id | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.Org\.name | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.Org\.uuid | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.Orgc\.id | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.Orgc\.name | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.Orgc\.uuid | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.date | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.info | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.uuid | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.org\_id | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.orgc\_id | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.analysis | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.published | numeric | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.timestamp | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.distribution | string | 
action\_result\.data\.\*\.\*\.Event\.RelatedEvent\.\*\.Event\.threat\_level\_id | string | 
action\_result\.data\.\*\.\*\.Event\.distribution | string | 
action\_result\.data\.\*\.\*\.Event\.extends\_uuid | string | 
action\_result\.data\.\*\.\*\.Event\.attribute\_count | string | 
action\_result\.data\.\*\.\*\.Event\.threat\_level\_id | string | 
action\_result\.data\.\*\.\*\.Event\.sharing\_group\_id | string | 
action\_result\.data\.\*\.\*\.Event\.publish\_timestamp | string | 
action\_result\.data\.\*\.\*\.Event\.disable\_correlation | numeric | 
action\_result\.data\.\*\.\*\.Event\.event\_creator\_email | string |  `email` 
action\_result\.data\.\*\.\*\.Event\.proposal\_email\_lock | numeric | 
action\_result\.data\.\*\.\*\.Event\.Tag\.\*\.id | string | 
action\_result\.data\.\*\.\*\.Event\.Tag\.\*\.name | string | 
action\_result\.data\.\*\.\*\.Event\.Tag\.\*\.local | numeric | 
action\_result\.data\.\*\.\*\.Event\.Tag\.\*\.colour | string | 
action\_result\.data\.\*\.\*\.Event\.Tag\.\*\.user\_id | string | 
action\_result\.data\.\*\.\*\.Event\.Tag\.\*\.hide\_tag | numeric | 
action\_result\.data\.\*\.\*\.Event\.Tag\.\*\.is\_galaxy | numeric | 
action\_result\.data\.\*\.\*\.Event\.Tag\.\*\.exportable | numeric | 
action\_result\.data\.\*\.\*\.Event\.Tag\.\*\.numerical\_value | string | 
action\_result\.data\.\*\.\*\.Event\.Tag\.\*\.is\_custom\_galaxy | numeric | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.id | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.name | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.uuid | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.comment | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.deleted | numeric | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.event\_id | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.id | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.type | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.uuid | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.value | string |  `url`  `domain`  `ip`  `email`  `hash`  `md5`  `sha256`  `md1` 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.to\_ids | numeric | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.comment | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.deleted | numeric | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.category | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.event\_id | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.last\_seen | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.object\_id | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.timestamp | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.first\_seen | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.distribution | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.object\_relation | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.sharing\_group\_id | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.Attribute\.\*\.disable\_correlation | numeric | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.last\_seen | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.timestamp | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.first\_seen | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.description | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.distribution | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.meta\-category | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.template\_uuid | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.sharing\_group\_id | string | 
action\_result\.data\.\*\.\*\.Event\.Object\.\*\.template\_version | string | 
action\_result\.data\.\*\.attribute\_count | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get attributes'
Get attributes for a specific event

Type: **investigate**  
Read only: **True**

<b>download\_samples</b> will only download files which are marked as a 'malware\-sample'\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event\_id** |  required  | An Event ID | numeric |  `misp event id` 
**download\_samples** |  optional  | Download malware samples to vault | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.download\_samples | boolean | 
action\_result\.parameter\.event\_id | numeric |  `misp event id` 
action\_result\.data\.\*\.Attribute\.\*\.Event\.distribution | string | 
action\_result\.data\.\*\.Attribute\.\*\.Event\.id | string |  `misp event id` 
action\_result\.data\.\*\.Attribute\.\*\.Event\.info | string | 
action\_result\.data\.\*\.Attribute\.\*\.Event\.org\_id | string | 
action\_result\.data\.\*\.Attribute\.\*\.Event\.orgc\_id | string | 
action\_result\.data\.\*\.Attribute\.\*\.Event\.uuid | string | 
action\_result\.data\.\*\.Attribute\.\*\.Object\.distribution | string | 
action\_result\.data\.\*\.Attribute\.\*\.Object\.id | string | 
action\_result\.data\.\*\.Attribute\.\*\.Object\.sharing\_group\_id | string | 
action\_result\.data\.\*\.Attribute\.\*\.category | string | 
action\_result\.data\.\*\.Attribute\.\*\.comment | string | 
action\_result\.data\.\*\.Attribute\.\*\.deleted | boolean | 
action\_result\.data\.\*\.Attribute\.\*\.disable\_correlation | boolean | 
action\_result\.data\.\*\.Attribute\.\*\.distribution | string | 
action\_result\.data\.\*\.Attribute\.\*\.event\_id | string |  `misp event id` 
action\_result\.data\.\*\.Attribute\.\*\.first\_seen | string | 
action\_result\.data\.\*\.Attribute\.\*\.id | string |  `misp attribute id` 
action\_result\.data\.\*\.Attribute\.\*\.last\_seen | string | 
action\_result\.data\.\*\.Attribute\.\*\.object\_id | string | 
action\_result\.data\.\*\.Attribute\.\*\.object\_relation | string | 
action\_result\.data\.\*\.Attribute\.\*\.sharing\_group\_id | string | 
action\_result\.data\.\*\.Attribute\.\*\.timestamp | string | 
action\_result\.data\.\*\.Attribute\.\*\.to\_ids | boolean | 
action\_result\.data\.\*\.Attribute\.\*\.type | string | 
action\_result\.data\.\*\.Attribute\.\*\.uuid | string | 
action\_result\.data\.\*\.Attribute\.\*\.value | string |  `url`  `domain`  `ip`  `email`  `hash`  `md5`  `sha256`  `md1` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 