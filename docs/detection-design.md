# Detection design and coverage

All three rules are experimental. They describe review-worthy behaviour, not a maliciousness verdict. Files reproduce Appendix C, including original titles and identifiers.

## Rule 1 — PowerShell launching discovery utilities

[Rule file](../detections/powershell-discovery.yml) · Event ID 1 · process_creation

Requires ParentImage ending in `\powershell.exe` or `\pwsh.exe` AND Image ending in `\whoami.exe` or `\ipconfig.exe`.

The parent check is immediate: `PowerShell -> CMD -> ipconfig` does not match because ipconfig's ParentImage is CMD. A direct `PowerShell -> ipconfig` can match. The lab deliberately includes both patterns; do not describe this rule as arbitrary ancestry correlation.

Legitimate administration and troubleshooting can match. The child names map to discovery techniques; PowerShell use provides execution context. No malicious command line is required.

## Rule 2 — PowerShell script/executable creation in Temp

[Rule file](../detections/powershell-temp-file.yml) · Event ID 11 · file_event

Requires PowerShell Image, a TargetFilename containing `\Temp\` or `\AppData\Local\Temp\`, and a selected extension: .exe, .dll, .ps1, .bat or .vbs.

**Title versus actual scope:** the source title says “User Temp”, but `\Temp\` also matches `C:\Windows\Temp\`. The longer user path is redundant under that OR selection. The file is preserved as supplied and this broad scope is tested explicitly. Narrow it before deployment if only per-user Temp is intended.

The earlier .txt example does not match. A .ps1 file created by Notepad does not match the PowerShell Image selector. File creation does not establish script execution, persistence or delivery from a remote source. Approved software/script staging can match.

## Rule 3 — PowerShell outbound connection

[Rule file](../detections/powershell-network.yml) · Event ID 3 · network_connection

Requires PowerShell Image and Initiated equal to the string 'true'. It contains no destination IP, port or protocol restriction. The lab's 1.1.1.1:443 is a test context, not a detection condition or indicator of compromise.

A network event from svchost.exe does not match. An event with Initiated='false' does not match. Backend field/type mappings must be confirmed; the offline harness expects the same text representation as a named Sysmon XML field. It intentionally rejects a JSON boolean instead of silently assuming backend conversion.

## Shared assumptions

Windows paths are compared case-insensitively in the offline fixtures. Missing required fields fail to match. The category-to-EventID mapping is an explicit harness assumption; a real backend/pipeline must implement the correct logsource mapping. The rules themselves use Sigma categories rather than an explicit EventID selector.

The harness supports only the selectors used here: exact string values, endswith/contains, OR within value lists, AND within selections, and AND between named selections. It rejects unsupported conditions/modifiers. It is not a general Sigma implementation and does not measure production alert quality.

## Promotion criteria

1. Confirm full source records and collection coverage.
2. Validate with Sigma tooling and the target backend/pipeline.
3. Verify field names, path case handling and Initiated type mapping.
4. Execute positive and negative replays and retain engine outputs.
5. Baseline approved activity, add justified contextual exclusions and measure alert volume.
6. Review ownership, triage guidance, deployment controls and rollback before promotion.
