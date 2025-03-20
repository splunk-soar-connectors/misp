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

- 0: Your Org Only
- 1: This Community Only
- 2: Connected Communities
- 3: All Communities
- 4: Sharing Group
- 5: Inherit

For **threat level id** :

- 1: High
- 2: Medium
- 3: Low
- 4: Undefined

For **analysis** :

- 0: Initial
- 1: Ongoing
- 2: Completed

**Note:**

- There is no validation provided in case of an incorrect value in the 'json' action parameter of
  the **'create event'** and **'update event'** actions. Hence, the action will pass even if an
  incorrect attribute value is passed in the 'json' action parameter and no attributes will be
  added.

- The value of the attribute passed in the 'json' action parameter of **'create event'** and
  **'update event'** will be treated as a list if a list is specified. If a string is specified
  then a list will be created by splitting the string by comma (,). For example:

  - json: {"email_body": ["body 1", "body 2"], "ip-dst": "8.8.8.8, 12.4.6.34"}

  The value of the 'email_body' will be considered a list and the value of the 'ip-dst' will be
  converted to a list having two elements(["8.8.8.8", "12.4.6.34"]).

- In the **'run query'** action, tags containing a comma (,) in its value can be passed through
  the 'other' action parameter. For example:

  - other: {"tags": ["tag1, tag11", "tag_2"]}

  "tag1, tag11" will be considered a single tag.

## Port Information

The app uses HTTP/HTTPS protocol for communicating with the Misp Server. Below are the default ports
used by Splunk SOAR.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http | tcp | 80 |
| https | tcp | 443 |
