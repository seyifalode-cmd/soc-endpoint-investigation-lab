# Evidence review and source qualifications

## Source and preservation

The original 32-page build-along PDF is retained unchanged. [source-manifest.json](../evidence/source-manifest.json) records its SHA256 and the 15 figures extracted from its embedded image objects. Raw EVTX logs, original standalone screenshots and a Windows VM were not supplied. Image pixels were not edited or recreated.

## What the images independently show

| Source page | Visible evidence | Qualification |
|---|---|---|
| 5 | UTM ARM64 setup with 4 GB RAM | The setup image shows default cores and 7.45 GB storage; it does not independently verify the prose recommendation of four cores/64 GB or the final VM state |
| 8 | Sysmon64a service Running | Does not alone establish all required event categories are collected |
| 11 | Notepad process with cmd.exe parent | Supports CMD-to-Notepad; the entire PowerShell-to-CMD-to-Notepad chain requires the parent event too |
| 13 | ipconfig.exe Event ID 1 | Its lower parent fields are cropped; earlier parent fields at the top belong to another visible record fragment |
| 14 | File creation, query with no output; preceding cmd.exe parent fields | Shows a failed retrieval; does not alone establish no event existed in all retained logs |
| 15 | Network collection disabled, no rules installed | Confirms a configuration gap for network visibility |
| 16 | Configuration validated and updated | Accepted input schema 4.90, binary reports 4.91; published XML uses 4.91 |
| 17 | Event ID 11 for project2-file-evidence-2.txt with PowerShell Image | Strong process-to-file evidence; a .txt file is outside Rule 2's extension list |
| 18 | Failed example.com resolution and an older svchost.exe UDP event | The returned network event is not evidence of the failed test command connecting |
| 19 | nslookup output and DNS events from Sysmon64a.exe/svchost.exe | Shows DNS visibility; the displayed Event ID 22 records are not visibly the requested nslookup-to-microsoft.com event |
| 20–21 | Process/file/DNS table with newest rows first | Does not show the ascending sorted timeline described in surrounding prose; network Event ID 3 is absent from the displayed query |
| 26, first image | Fresh whoami.exe process-create fields | ParentImage is below the crop; prose reports its confirmation, but the image alone is incomplete |
| 26, second image | Script creation and query commands | The returned Event ID 11 and TargetFilename are not visible in this crop |
| 27 | PowerShell network event, ProcessGuid, PID, TCP | Initiated and destination fields are below the crop. The visible UtcTime predates the later validation sequence |

## Source narrative versus independently visible evidence

The PDF reports that all three rules' required fields were manually confirmed and that YAML syntax was checked. This repository preserves that report while identifying where embedded crops prevent an independent reader from verifying every field. It does not silently upgrade source-reported confirmation into fully visible event evidence.

The source's final scenario is authorised simulation. No screenshot establishes malware, persistence, credential theft, exfiltration, enterprise isolation, or Sigma-engine alert generation.

## Publication additions

- Three YAML files and the XML config are transcribed from the published appendix.
- A read-only PowerShell timeline script uses named XML fields, includes Event ID 3, sorts by event time, and exposes process and network fields.
- Offline tests use explicitly synthetic fixtures to exercise the rules' limited selection logic, including negative cases and known coverage gaps.
- Static checks cover YAML structure, UUIDs, XML shape, hashes and local document links.

These additions are distinct from original Windows execution. The PowerShell script has not been run against a live Windows event log in this publication environment. No Sigma backend translation or engine execution is claimed.

## Evidence needed for stronger validation

Export raw EVTX with collection time, host context and retention boundaries. Preserve event record IDs and full XML for each positive and negative case. Capture fresh process, file and network tests in separate explicit time windows. For network evidence, include Image, ProcessGuid, Initiated, DestinationIp and DestinationPort in one record. Translate rules with the selected backend and data pipeline, then replay retained events and verify actual alerts.
