# Sysmon collection configuration

[sysmon-lab-config.xml](sysmon-lab-config.xml) is transcribed from Appendix C of the source PDF. It requests SHA256 hashing and broad collection for ProcessCreate, NetworkConnect, FileCreate and DnsQuery using empty exclusion lists.

The original screenshot on PDF page 16 shows a schema 4.90 file accepted by Sysmon 15.22, which reports schema 4.91. The PDF's published appendix and this XML use 4.91. Parsing XML locally verifies its structure; it does not prove the published XML was applied to a Windows machine during repository preparation.

In your isolated Windows VM, from the Sysmon extraction directory:

```powershell
.\Sysmon64a.exe -s
.\Sysmon64a.exe -c C:\path\to\soc-endpoint-investigation-lab\config\sysmon-lab-config.xml
.\Sysmon64a.exe -c
Get-Service Sysmon64a
```

Inspect the installed binary's schema and configuration output before continuing. These commands update collection when you run them; none was run on a live endpoint during repository publication. Broad collection is appropriate for this exercise but requires environment-specific filtering and capacity planning before production use.
