# PowerShell investigation companion

`Get-SysmonTimeline.ps1` is an added read-only query companion, not a verbatim transcript. It parses named XML fields instead of matching rendered message strings; adds Event ID 3 to process/file/DNS review; retains process identities and network fields; and sorts ascending.

Run on the Windows VM with permission to read its Sysmon log. The examples use explicit UTC bounds; replace them with the actual review period.

```powershell
$events = .\scripts\Get-SysmonTimeline.ps1 `
    -StartTime '2026-09-28T03:00:00Z' `
    -EndTime '2026-09-28T07:00:00Z'

$events | Format-Table EventTimeUtc, EventId, Image, TargetFilename, QueryName
New-Item -ItemType Directory -Path .\exports -Force | Out-Null
$events | Export-Csv .\exports\timeline.csv -NoTypeInformation
$events | ConvertTo-Json -Depth 4 | Set-Content .\exports\timeline.json
```

No matching events causes Get-WinEvent to report an error. Investigate the interval and collection state rather than assuming the activity did not occur. Export objects before formatting them. CSV/JSON are analysis views, not replacements for original EVTX.

Use `-ProcessGuid '{GUID-FROM-YOUR-EVENT}'` to select events for one process instance. To find the parent, search Event ID 1 for a ProcessGuid equal to the child's ParentProcessGuid. The parameter does not recursively traverse ancestors or automatically include child events.

**Validation boundary:** reviewed statically; not executed in Windows or parsed by a PowerShell runtime in the repository preparation environment. Keep the original PDF's manual queries available when reproducing the lab.
