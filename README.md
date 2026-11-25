# Microsoft Azure Sentinel Honeypot Lab

This walkthrough follows a Windows RDP honeypot from Azure provisioning through failed sign-in collection, IP geolocation, and a Microsoft Sentinel workbook map. The figures and observations document the classroom walkthrough.

## 1. Create the Windows VM

The walkthrough uses `honeypot-vm` in the `honeypot-vm_group` resource group in East US. The Azure portal screenshot shows a Windows 10 Pro image selected during setup.

<!-- Figure pending upload: ![Windows VM configuration in Azure](./createvm.png) -->

## 2. Review network exposure and reachability

The historical walkthrough shows a permissive Azure network security group and a change to Windows Defender Firewall, followed by an ICMP reachability check. Use an isolated VM for reproduction, keep the firewall enabled, and restrict access to an approved lab client or private management path. Ping verifies ICMP reachability. An authorized failed RDP sign-in can provide a test Windows Security event.

<!-- Figure pending upload: ![Historical Azure inbound rule screen](./NICSecurityGroup.png) -->
<!-- Figure pending upload: ![Windows Defender Firewall properties in the historical walkthrough](./wfmsc.png) -->
<!-- Figure pending upload: ![ICMP reachability test with the destination redacted](./ping.png) -->

## 3. Set up Log Analytics and Microsoft Defender for Cloud

The walkthrough creates the `law-honeypot` Log Analytics workspace in the same resource group and region as the VM. It then opens Defender for Cloud environment settings and reviews the workspace plans. The screenshots show Foundational CSPM and Servers enabled and SQL servers on machines disabled.

<!-- Figure pending upload: ![Log Analytics workspace configuration](./law.png) -->
<!-- Figure pending upload: ![Defender for Cloud environment settings](./clouddefender.png) -->
<!-- Figure pending upload: ![Defender plans shown for the lab workspace](./turnonclouddefender.png) -->

## 4. Connect the VM and add Microsoft Sentinel

The VM connection screenshot shows the older workspace connection page before onboarding. The Sentinel screenshot shows `law-honeypot` selected as the workspace. For a new deployment, use Azure Monitor Agent and an associated data collection rule (DCR).

<!-- Figure pending upload: ![Historical workspace VM connection screen before onboarding](./connectlawvm.png) -->
<!-- Figure pending upload: ![Log Analytics workspace selected for Microsoft Sentinel](./sentineladd.png) -->

## 5. Export failed logons and enrich source IPs

The PowerShell exporter reads failed Windows Security logon events, extracts fields such as the destination host and source IP, looks up approximate IP geolocation, and writes enriched records to `C:\ProgramData\failed_rdp.log`. Event ID 4625 identifies a failed logon. Use the event's logon type and context when evaluating whether it was an RDP failure.

The historical exporter uses an external geolocation API. Store any credential outside source control and use it only when sending eligible source IPs to the provider is authorized.

<!-- Figure pending upload: ![PowerShell exporter field extraction and enrichment](./logexporterscript.png) -->
<!-- Figure pending upload: ![Example geolocation response from the IP lookup provider](./geolocation.png) -->
<!-- Figure pending upload: ![Exporter configuration with the credential redacted](./apikey.png) -->

## 6. Ingest the custom log

The walkthrough opens **Tables** in the workspace and shows the DCR-based custom log option. The final configuration screenshot shows a historical custom text-log wizard and identifies the file, newline delimiter, and destination table `FAILED_RDP_WITH_GEO_CD_CL`. For a new implementation, configure Azure Monitor Agent custom text-log collection for the equivalent file and associate the DCR with the VM. Use a destination schema that includes a string column named `RawData` for the queries below.

<!-- Figure pending upload: ![DCR-based custom log option in Log Analytics](./customlogdcr.png) -->
<!-- Figure pending upload: ![Historical custom log file, delimiter, path, and table name](./failedrdpwithgeo.png) -->

## 7. Verify the ingested rows

```kusto
FAILED_RDP_WITH_GEO_CD_CL
| take 15
```

Confirm that the returned rows have timestamps and that `RawData` contains the expected enriched fields. The classroom screenshot shows 1,135 results for its selected time range.

<!-- Figure pending upload: ![Log Analytics custom table results with Azure identifiers redacted](./queryresults.png) -->

## 8. Build the failed RDP map

Add a query to a Sentinel workbook for the lab workspace. Use the workbook time picker, choose a map visualization, and bind the latitude and longitude fields. Use `Attempts` to size markers and `Country` to label them.

```kusto
FAILED_RDP_WITH_GEO_CD_CL
| extend Latitude = todouble(extract(@"(?:^|,)latitude:([^,]+)", 1, RawData)),
         Longitude = todouble(extract(@"(?:^|,)longitude:([^,]+)", 1, RawData)),
         Country = extract(@"(?:^|,)country:([^,]+)", 1, RawData),
         Destination = extract(@"(?:^|,)destinationhost:([^,]+)", 1, RawData),
         SourceIP = extract(@"(?:^|,)sourcehost:([^,]+)", 1, RawData)
| where isnotempty(SourceIP) and Destination !~ "samplehost"
| where Latitude between (-90.0 .. 90.0) and Longitude between (-180.0 .. 180.0)
| summarize Attempts = count() by Latitude, Longitude, Country
| order by Attempts desc
```

The supplied workbook view shows its largest displayed count in the Philippines, followed by Germany. Those counts describe the captured classroom view. IP geolocation estimates the location associated with the source IP, which may belong to a proxy, VPN, or hosting provider.

<!-- Figure pending upload: ![Classroom workbook map of geolocated failed sign-in events](./map.png) -->

## 9. Clean up Azure resources

After collecting the required evidence, remove dedicated resources that are no longer needed and review workspace retention and service costs.

## Reference

[Microsoft Azure Sentinel Honeypot Lab](https://github.com/nuttercd/microsoft-azure-sentinel-honeypot-lab) documents the reference workflow. The results described here are from the supplied classroom walkthrough.
