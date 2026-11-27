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
