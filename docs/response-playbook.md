# Endpoint triage and response playbook

Disposition for the supplied lab: **authorised simulation; no demonstrated compromise**. The actions below are recommendations for unexpected enterprise activity, not actions performed in this project.

| Stage | Questions / action | Evidence to retain |
|---|---|---|
| Validate | Is this the right host, interval and log channel? Is sensor collection healthy? | Host, event record IDs, collection bounds, active config |
| Investigate process | What ran, under which user, with which immediate parent and command line? | Full Event ID 1 XML, ProcessGuid, ParentProcessGuid, image hash |
| Correlate | What files, DNS requests and connections share the process instance? | Event IDs 11, 22, 3 with time and ProcessGuid |
| Assess intent | Does approved administration explain it? Is there additional suspicious evidence? | User/owner context, change record, full related telemetry |
| Preserve | Export relevant records before changing the host when compromise is plausible | EVTX, file metadata/hashes and collection notes |
| Contain | Apply approved controls when evidence and response policy justify them | Authorised action and verification results |
| Remediate/recover | Address the established cause, restore intended operation, monitor recurrence | Actual remediation and recovery checks |
| Improve | Refine detections using reviewed outcomes | Rule revision, tests, tuning rationale and owner |

Do not block a destination or isolate a host solely because PowerShell, Temp or port 443 appears. Missing results may reflect query scope or collection gaps.

## Case-note template

```text
Host / user / review interval (with timezone):
Sensor and collection scope:
Observed events and record IDs:
ProcessGuid / ParentProcessGuid correlation:
Hypotheses and benign explanations:
Missing or conflicting evidence:
Disposition / confidence / rationale:
Actions performed and actual verification:
Next action / accountable owner:
```
