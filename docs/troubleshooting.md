# Troubleshooting

| Symptom | Check |
|---|---|
| UEFI shell instead of Windows setup | Correct ARM64 Windows ISO and UTM virtualization configuration |
| Sysmon service not found | Confirm architecture and actual service name; this lab uses Sysmon64a |
| PowerShell cmdlets fail at C:\ prompt | Exit CMD and return to PowerShell |
| Event ID 3 missing | Inspect active configuration; network collection is disabled in the original initial setup |
| File exists but query returns nothing | Check time range, channel, sensor settings and event retention; latest-N searches may omit relevant records |
| XML file cannot be opened | Check actual path and accidental .xml.txt extension |
| Schema mismatch | Inspect `Sysmon64a.exe -s` and validate against the installed binary |
| Discovery rule misses ipconfig | Inspect immediate parent; CMD-parent execution is outside Rule 1 |
| Text file does not match Rule 2 | .txt is intentionally excluded |
| Test-NetConnection DNS failure | Separate resolution failure from connection evidence; do not attribute an older returned event to the failed test |
| DNS event names a different process/domain | Preserve it as background context; scope by time, QueryName and ProcessGuid |
| Exported table omits fields | Export objects before Format-Table; display truncation is not loss in the underlying event |
| Timeline appears reversed | Explicitly sort by event time and record ID; screenshot order is not event order |
| YAML test passes but no SIEM alert appears | YAML and offline fixtures do not prove backend translation, ingestion or engine execution |

The timeline companion is read-only against the event log. Save its object output as CSV/JSON for review; retain EVTX separately when original records are needed. No automatic cleanup, host isolation or sensor removal is included.
