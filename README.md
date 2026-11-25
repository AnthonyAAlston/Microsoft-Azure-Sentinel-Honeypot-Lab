# Microsoft Azure Sentinel Honeypot Lab

This walkthrough follows a Windows RDP honeypot from Azure provisioning through failed sign-in collection, IP geolocation, and a Microsoft Sentinel workbook map. The figures and observations document the classroom walkthrough.

## 1. Create the Windows VM

The walkthrough uses `honeypot-vm` in the `honeypot-vm_group` resource group in East US. The Azure portal screenshot shows a Windows 10 Pro image selected during setup.

![Windows VM configuration in Azure](https://github.com/user-attachments/assets/b2b3aa38-d9ba-4265-92f2-6e9935aeb244)


## 2. Review network exposure and reachability

The historical walkthrough shows a permissive Azure network security group and a change to Windows Defender Firewall, followed by an ICMP reachability check. Use an isolated VM for reproduction, keep the firewall enabled, and restrict access to an approved lab client or private management path. Ping verifies ICMP reachability. An authorized failed RDP sign-in can provide a test Windows Security event.

![Historical Azure inbound rule screen](https://github.com/user-attachments/assets/110427db-47d3-4e99-9388-049423c599df)

![Windows Defender Firewall properties in the historical walkthrough](https://github.com/user-attachments/assets/4e4660fe-896f-4308-bfe0-545f73173020)

![ICMP reachability test with the destination redacted](https://github.com/user-attachments/assets/d6b0e1ba-34fc-462b-a968-8b63db32168d)


## 3. Set up Log Analytics and Microsoft Defender for Cloud

The walkthrough creates the `law-honeypot` Log Analytics workspace in the same resource group and region as the VM. It then opens Defender for Cloud environment settings and reviews the workspace plans. The screenshots show Foundational CSPM and Servers enabled and SQL servers on machines disabled.

![Log Analytics workspace configuration](https://github.com/user-attachments/assets/0bec4bab-f51c-46b7-87d6-3803fc694e24)

![Defender for Cloud environment settings](https://github.com/user-attachments/assets/8fab16f7-1f44-47c3-920e-cbd9fdb0b40c)

![Defender plans shown for the lab workspace](https://github.com/user-attachments/assets/d95a6ec3-b446-4ad0-97b3-7cee5e3e6da1)


## 4. Connect the VM and add Microsoft Sentinel

The VM connection screenshot shows the older workspace connection page before onboarding. The Sentinel screenshot shows `law-honeypot` selected as the workspace. For a new deployment, use Azure Monitor Agent and an associated data collection rule (DCR).

![Historical workspace VM connection screen before onboarding](https://github.com/user-attachments/assets/e025cb91-99f5-4497-948c-c6a771efbdc6)

![Log Analytics workspace selected for Microsoft Sentinel](https://github.com/user-attachments/assets/6c26518d-c908-4585-86d5-9b62948ecd73)


## 5. Export failed logons and enrich source IPs

The PowerShell exporter reads failed Windows Security logon events, extracts fields such as the destination host and source IP, looks up approximate IP geolocation, and writes enriched records to `C:\ProgramData\failed_rdp.log`. Event ID 4625 identifies a failed logon. Use the event's logon type and context when evaluating whether it was an RDP failure.

The historical exporter uses an external geolocation API. Store any credential outside source control and use it only when sending eligible source IPs to the provider is authorized.

![PowerShell exporter field extraction and enrichment](https://github.com/user-attachments/assets/c5fc41d0-7119-4868-93bc-b413bfc0a3c2)

![Example geolocation response from the IP lookup provider](https://github.com/user-attachments/assets/2e77fd57-df3e-4922-b2a4-317bd432d17f)

![Exporter configuration with the credential redacted](https://github.com/user-attachments/assets/e66612d6-3846-4161-ab79-c5f2c88425e1)


## 6. Ingest the custom log

The walkthrough opens **Tables** in the workspace and shows the DCR-based custom log option. The final configuration screenshot shows a historical custom text-log wizard and identifies the file, newline delimiter, and destination table `FAILED_RDP_WITH_GEO_CD_CL`. For a new implementation, configure Azure Monitor Agent custom text-log collection for the equivalent file and associate the DCR with the VM. Use a destination schema that includes a string column named `RawData` for the queries below.

![DCR-based custom log option in Log Analytics](https://github.com/user-attachments/assets/1a623297-2b01-436b-9d5f-04489b1873bb)

![Historical custom log file, delimiter, path, and table name](https://github.com/user-attachments/assets/ec6f20da-a438-481e-afd5-f19b5f1917f5)


## 7. Verify the ingested rows

```kusto
FAILED_RDP_WITH_GEO_CD_CL
| take 15
```

Confirm that the returned rows have timestamps and that `RawData` contains the expected enriched fields. The classroom screenshot shows 1,135 results for its selected time range.

![Log Analytics custom table results with Azure identifiers redacted](https://github.com/user-attachments/assets/61295ee3-faf2-4a2c-841c-e97c93d7d244)


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

![Classroom workbook map of geolocated failed sign-in events](https://github.com/user-attachments/assets/2b61c431-9a0b-43dd-bb7b-cbe59cd8985b)


## 9. Clean up Azure resources

After collecting the required evidence, remove dedicated resources that are no longer needed and review workspace retention and service costs.

## Reference

[Microsoft Azure Sentinel Honeypot Lab](https://github.com/nuttercd/microsoft-azure-sentinel-honeypot-lab) documents the reference workflow. The results described here are from the supplied classroom walkthrough.
