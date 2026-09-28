#requires -Version 5.1
<#
.SYNOPSIS
Read a bounded Sysmon timeline as objects, preserving correlation fields.
.DESCRIPTION
Repository companion to the original lab. No endpoint state is changed.
StartTime and EndTime are converted to UTC for querying and export.
Windows runtime validation is still required; this script was not executed
against a live Windows event log during publication.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [datetimeoffset] $StartTime,
    [Parameter(Mandatory = $true)] [datetimeoffset] $EndTime,
    [int[]] $EventId = @(1, 3, 11, 22),
    [string] $ProcessGuid
)

if ($EndTime -le $StartTime) { throw 'EndTime must be after StartTime.' }
$filter = @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    StartTime = $StartTime.UtcDateTime
    EndTime = $EndTime.UtcDateTime
    Id = $EventId
}
# No latest-N limit: keep the selected interval and narrow it when too large.
$events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
$events | ForEach-Object {
    $record = $_
    $xml = [xml]$record.ToXml()
    $fields = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        $fields[$node.GetAttribute('Name')] = $node.InnerText
    }
    if ((-not $ProcessGuid) -or ($fields['ProcessGuid'] -eq $ProcessGuid)) {
        [PSCustomObject]@{
            EventTimeUtc = $record.TimeCreated.ToUniversalTime().ToString('o')
            SysmonUtcTime = $fields['UtcTime']
            EventRecordId = $record.RecordId
            EventId = $record.Id
            Computer = $record.MachineName
            ProcessGuid = $fields['ProcessGuid']
            ProcessId = $fields['ProcessId']
            Image = $fields['Image']
            CommandLine = $fields['CommandLine']
            User = $fields['User']
            ParentProcessGuid = $fields['ParentProcessGuid']
            ParentProcessId = $fields['ParentProcessId']
            ParentImage = $fields['ParentImage']
            ParentCommandLine = $fields['ParentCommandLine']
            TargetFilename = $fields['TargetFilename']
            QueryName = $fields['QueryName']
            QueryStatus = $fields['QueryStatus']
            QueryResults = $fields['QueryResults']
            Protocol = $fields['Protocol']
            Initiated = $fields['Initiated']
            SourceIp = $fields['SourceIp']
            SourcePort = $fields['SourcePort']
            DestinationIp = $fields['DestinationIp']
            DestinationPort = $fields['DestinationPort']
        }
    }
} | Sort-Object EventTimeUtc, EventRecordId
