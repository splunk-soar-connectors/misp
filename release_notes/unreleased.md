**Unreleased**
* Following changes have been made to misp app for [PAPP-33460]: 
    * "**create event**" action has been updated
        * The following parameters have been removed from the create event action:
            * to_ids, source ips, dest ips, domains, source emails, dest emails, urls
        * The input for the `json` parameter has changed. Please refer the notes below to see the new format.

    * The "**update event**" action has been renamed to "**add attribute**" and has the following changes:
        * The following new parameters are added :
            * attribute category, attribute type, attribute value, attribute comment

        * The following parameters are removed and moved to `attribute type`:
            * source_ips, dest_ips, domains, source_emails, dest_emails, urls
        * The input for the `json` parameter has changed. Please refer the notes below to see the new format.

    * Added "**bulk add attributes**" actions
