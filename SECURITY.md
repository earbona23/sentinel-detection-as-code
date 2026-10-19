# Security policy

## Reporting a vulnerability

Open a [private security advisory](https://github.com/earbona23/sentinel-detection-as-code/security/advisories/new)
on this repository. Please do not open a public issue for a vulnerability.

If you cannot use the advisory form, email **earbona@arrankago.com** instead.

You will get an acknowledgement within 72 hours and an assessment within seven days. There
is no bounty programme — this is a single-maintainer project — but every report is credited
in the advisory unless you ask me not to.

## What counts as a vulnerability here

`sentinel-detection-as-code` holds KQL detections for Microsoft Sentinel, validated with
Microsoft's own parser and mapped to ATT&CK against the official catalogue.

A detection repository has two distinct security surfaces: the tooling, and the detections
themselves.

| Class | Why it matters |
|---|---|
| **A detection that silently never fires** | A query that parses, deploys, and matches nothing because of a logic error. It occupies the slot of a control that does not exist, which is worse than an empty slot — the gap is now invisible. |
| **A trivially evadable detection presented as coverage** | If a one-character change in the attacker's command defeats it, the rule needs that limitation documented, not a coverage claim. |
| **A validation step that passes without validating** | The parser check and the ATT&CK mapping check are the guarantees here. A path where either reports success without running is in scope. |
| **An invented or revoked technique ID accepted** | Mapping to an ID that does not exist inflates a coverage map with nothing. |
| **Anything executed at validation time** | KQL is data. Validating it must never run it. |

## Out of scope

- A detection producing false positives in your environment. Tune the thresholds; every
  rule documents the ones it has. Open a normal issue.
- Requests for coverage of a technique not yet included — a feature request.
