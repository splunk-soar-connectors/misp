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

## Playbook Backward Compatibility

-   "**create event**" action has been updated
    -   The following parameters have been removed from the create event action:
        -   to_ids
        -   source ips
        -   dest ips
        -   domains
        -   source emails
        -   dest emails
        -   urls
    -   The input for the `json` parameter has changed. Please refer the notes below to see the new format.

-   The "**update event**" action has been renamed to "**add attribute**" and has the following changes:
    -   The following new parameters are added :
        -   attribute category
        -   attribute type
        -   attribute value
        -   attribute comment

    -   The following parameters are removed and moved to `attribute type`:
        -   source_ips
        -   dest_ips
        -   domains
        -   source_emails
        -   dest_emails
        -   urls

    -   The input for the `json` parameter has changed. Please refer the notes below to see the new format.


-   The below-mentioned actions have been added
    -   bulk add attributes

-   Hence, it is requested to the end-user to please
    update their existing playbooks by inserting the corresponding action blocks for this action on
    the earlier versions of the app.


Note: The asset configuration parameter 'timezone', will be used for the 'occur_date' parameter in
the 'add ttp' action.


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

-   Create new events with the `create event` action.
-   `create event` action supports add attributes while creating the event.
-   To add a single attribute to an existing event use the `add attribute` action.
    -   To add a single attribute using `json` paramter, pass json data as show below:
        ```
        {
            "category": "Network activity",
            "type": "comment",
            "value": "Example value for and event",
            "to_ids": true
        }
        ```
    - All the properties that can be added using the `json` parameter can be checked in the [misp documentation](https://www.misp-project.org/openapi/#tag/Attributes/operation/addAttribute)  
-   To add multiple attributes to an event, use the `bulk add attributes` action.
-   The `json` parameter of `create event` and `bulk add attribute` takes similar input. The user needs to pass a list of dictionaries in the format given below:
    ```
       [
             {
                "category": "Network activity",
                "type": "comment",
                "value": "Example value for and event 1",
                "to_ids": true
            },
            {
                "type": "comment",
                "value": "Example value for and event 2",
                "to_ids": false
            }
        ]
    ```
-   In the "**run query**" action, tags containing a comma (,) in its value can be passed through
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
