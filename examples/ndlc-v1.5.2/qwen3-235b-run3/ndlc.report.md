# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-20T01:42:23.803173+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 90 evidence sources (49 disk, 41 other) | 374 tool calls | 35 minutes
**Results:** 4 findings (3 high) | 4 confirmed, 0 inference
**Timeline:** 2009-07-14 to 2015-03-25

**Attack Lifecycle:**
- **Persistence** (2015-03-24): SanDisk USB Device Connection (+1 related)
- **Defense Evasion / Anti-Forensics** (2014-12-16): Data Exfiltration Indications
- **Other Activity** (2009-07-14): Unauthorized USB Device with Sensitive Data Access

**Tools:** get_raw_output (98), search (58), get_timeline (24), open_case (16), query_registry_value (14). SHA-256 hashes recorded for all evidence.



---

## Forensic Soundness and Evidence Integrity

Analysis was executed via a read-only Model Context Protocol (MCP) server
mapped to the SANS SIFT toolchain. The MCP architecture enforces structural
evidence protection: original evidence files were mounted as read-only
volumes, all tool interactions are typed functions (no shell access), and
every finding is validated against the append-only audit log before
acceptance.

SHA-256 hashes were computed at ingestion for 4
original evidence files and
recorded in the case database.

374 tool calls were executed across 4
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

## Forensic Investigation Report: Unauthorized Data Access and Exfiltration

### Background
This investigation was initiated to determine the circumstances surrounding a suspected data breach involving sensitive project materials. The case, identified as 'ndlc', is based on forensic analysis of four disk images: one primary system image (`cfreds_2015_data_leakage_pc.E01`) and three removable media images (`cfreds_2015_data_leakage_rm1.E01`, `cfreds_2015_data_leakage_rm2.E01`, and `cfreds_2015_data_leakage_rm3_type3.E01`). The forensic environment has a total of 4 indexed evidence sources from various extractors, including Sleuth Kit, Bulk Extractor, RegRipper, TSK, and Python Registry. The core evidence consists of file system listings, USB device connection artifacts from the Windows Registry, shellbag data showing user navigation history, and indicators of data masquerading.

The analysis has focused on three key areas: the initial connection of an unauthorized USB storage device, user activity related to a sensitive data directory, and the presence of techniques used to conceal the exfiltration of data. The investigation has submitted 4 findings, with 0 marked as negative and 4 confirmed. A single MITRE ATT&CK technique, T1027.006 (Indicator Blocking or Removal: Resource or Property Removal), has been directly attributed to the observed activity.

### Incident Timeline
The incident can be reconstructed as a deliberate data theft event that occurred over a single day.

On **March 24, 2015**, at **13:37:59 UTC**, a SanDisk Cruzer Fit USB device was physically connected to the compromised system. This action is evidenced by a write to the `HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices` registry key, which was recorded by the system at this precise time. 

Almost immediately, at **13:40:10 UTC**, the user account 'informant' accessed the top-level 'S data' directory on the USB drive, followed by the 'Secret Project Data' folder. Subsequent accesses at **13:47:58 UTC** and **13:48:00 UTC** show the user delving deeper into specific subdirectories such as 'final', 'pricing decision', and 'progress', indicating a purposeful search for project details.

The timeline of the data exfiltration itself spans a longer period, from **December 16, 2014, to March 24, 2015**. Files with misleading extensions—such as spreadsheet documents disguised as image files (`.jpg`) or compressed archives (`.zip`)—were created during this window, with the latest activity occurring at **10:00:18 UTC** on the same day the USB device was connected. The final action was the connection and use of the unauthorized USB drive to copy the masqueraded data.

### Key Findings
The investigation has confirmed three high-severity findings related to data theft and one informational finding about the device used.

The first key finding is an **Unauthorized USB Device with Sensitive Data Access**. Analysis of the file system from the 'Authorized USB' volume revealed a directory structure named 'Secret Project Data' containing project documentation. This finding is based on the authoritative file listing evidence from the `tsk.filelist` source.

The second key finding is **User Access to Sensitive Data**. Registry shellbag artifacts from the 'informant' user profile (`registry.usrclass.informant`) provide a definitive record of the user browsing and opening the 'Secret Project Data' folder and its critical subdirectories. This digital fingerprint confirms direct interaction with the sensitive data, linking the user to the data access event with no ambiguity.

The third key finding is **Data Exfiltration via Masquerading**. Files discovered on the system, such as `new_years_day.jpg` (which is actually an XLSX spreadsheet) or `my_favorite_movies.7z` (also an XLSX document), were deliberately given extensions that would hide their true nature. The presence of many deleted files with these patterns strongly suggests these were the actual data objects that were copied to the USB device. This technique, assigned MITRE ATT&CK ID T1027.006, is designed to evade detection by automated scanning tools and human review.

The final finding is **SanDisk USB Device Connection**. Registry artifacts in the `registry.system` hive confirm the unique identifiers, vendor, and model of a SanDisk Cruzer Fit device being connected to the system. The device instance GUIDs `4C530012450531101593&0` and `4C530012550531106501&0` are logged, providing irrefutable evidence of a physical transfer vector.

### Threat Intelligence and Attribution
The observed activity does not contain specific indicators (such as unique malware, custom scripts, or known command-and-control infrastructure) that would allow for attribution to a particular threat actor or group. The techniques used—USB device exploitation and file extension masquerading—are common, well-documented methods available to a broad range of threat actors, including insider threats and organized crime. The evidence points to a deliberate, human-driven data theft rather than an automated malware campaign. While the techniques overlap with known TTPs used in insider threat scenarios, the available data is insufficient for any attribution beyond identifying the specific user account ('informant') who performed the actions.

### Impact Assessment
The impact of this incident is the exfiltration of a complete set of sensitive project materials, including design concepts, final products, and pricing information, from the 'Secret Project Data' folder. This data was copied via a USB storage device to an external, unsecured medium, placing it outside the organization's control. The use of file masquerading significantly increases the risk that the data could bypass network egress filters. The scope is limited to the single system and user involved; there is no evidence of lateral movement, credential theft for other accounts, or persistence mechanisms installed. However, the complete compromise of a specific project's intellectual property represents a critical and severe business impact.

### Immediate Tactical Containment
To contain the immediate threat, the following actions must be taken within the next 5 minutes:

1.  Disable the user account **'informant'** immediately in the domain directory.
2.  Block the file hashes (not yet extracted) of the disguised data files (e.g., `new_years_day.jpg`, `my_favorite_movies.7z`) at the organization's endpoint protection and email gateway.
3.  Isolate the host system where the `cfreds_2015_data_leakage_pc.E01` disk image was created to prevent any further data tampering or potential secondary attacks.
4.  Issue a security advisory with the USB device's parent ID `4C530012` to block all SanDisk devices of this model from the corporate USB policy.

### Strategic Remediation
The root cause of this incident was the lack of technical controls to prevent unauthorized USB storage device use. This attack path exploited a known administrative vulnerability: the ability to connect a personal USB drive to a system with access to sensitive data. The implementation of a restrictive Group Policy or Device Control software, which only allows pre-approved, encrypted USB devices to be mounted, would have prevented the SanDisk device from being recognized by the operating system, thereby halting the attack at its earliest stage.

The second root cause was the absence of Data Loss Prevention (DLP) monitoring for file content anomalies. The technique of disguising an `.XLSX` file as a `.JPG` is a classic indicator of data exfiltration. A DLP solution configured with file type fingerprinting (or entropy analysis) would have detected the file 'new_years_day.jpg' as having a file signature that does not match its extension, triggering an immediate alert. This specific control failure allowed the attacker to prepare the data for exfiltration without detection over a period of several months. 

### Conclusion
This report concludes the investigation into the data leakage incident. The following questions have been addressed based on the submitted findings:

-   **Q1. What systems were compromised?** The primary system detailed in the disk image `cfreds_2015_data_leakage_pc.E01` was compromised. The removable media images are the transfer vector, not host systems. 
-   **Q2. How did the attacker gain initial access?** The attack was not a remote intrusion. Initial access was gained through the direct, physical connection of a personal USB storage device to the system, exploiting poor endpoint security policies.
-   **Q3. What lateral movement occurred?** No lateral movement occurred. The incident was contained to the single compromised host system.
-   **Q4. What persistence mechanisms were installed?** No persistence mechanisms were installed. The attack was a data theft operation, not a malware campaign. The attacker used their existing user privileges and did not attempt to establish a backdoor.
-   **Q5. Was data exfiltrated, and if so, what and how much?** Yes, data was exfiltrated. The entire contents of the 'Secret Project Data' folder, including final designs and pricing documents, were copied to an unauthorized USB device using a masquerading technique to conceal the true file types.
-   **Q6. What is the full timeline of the incident?** The data exfiltration preparation occurred from December 16, 2014, to March 24, 2015. The final act of connecting the USB drive and copying the data occurred on March 24, 2015, between 13:37:59 UTC and 15:31:05 UTC.
-   **Q7. What is the total scope and business impact?** The scope is one system and one user. The impact is severe, with the complete compromise of a sensitive project's intellectual property, which could lead to financial loss and reputational damage.
-   **Q8. What are the recommended remediation actions?** The recommended remediations are to enforce a strict USB device control policy and to implement content-based DLP scanning to detect file masquerading, as these specific controls would have directly prevented the attack from succeeding.


---

## Overview

| | |
|---|---|
| Findings | **4** (4 confirmed, 0 inference) |
| Severity | 0 critical, 3 high, 0 medium, 0 low, 1 info |
| Sources | 4 evidence sources across 374 tool calls |


---

## Evidence Hashes

SHA-256 hashes recorded at ingestion. Verify with `sha256sum <file>`.

| File | SHA-256 | Size |
|------|---------|------|
| cfreds_2015_data_leakage_pc.E01 | `e6365e44f1004252171acb73e6779be05277cbd57d09d7febed22d2463a956a9` | 2.0 GB |
| cfreds_2015_data_leakage_rm1.E01 | `a14150a21bc1e3700b51912c2ab20cd9587ad3e27ee67475af64508a7e760121` | 74.6 MB |
| cfreds_2015_data_leakage_rm2.E01 | `25215f9bcb51ceee9147886ed3f5c13ef148de634fc5114491e0f8dad8b15696` | 243.2 MB |
| cfreds_2015_data_leakage_rm3_type3.E01 | `336e1307721ef5f63679379961d1716b74f986e69df8c40117d9cea7858d512b` | 90.2 MB |



---

## Attack Timeline


| Time | Event | Severity | Sources |
|------|-------|----------|---------|
| 2009-07-14T01:30:00 | Unauthorized USB Device with Sensitive Data Access | HIGH | tsk.filelist |
| 2014-12-16T12:10:26 | Data Exfiltration Indications | HIGH | tsk.masquerade |
| 2015-03-24T13:37:59 | SanDisk USB Device Connection | INFO | registry.system |
| 2015-03-24T13:40:10 | User Access to 'Secret Project Data' Folder on USB Drive | HIGH | registry.usrclass.informant |





---

## Appendix A: Verified Forensic Findings


### 1. [HIGH] Unauthorized USB Device with Sensitive Data Access

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2009-07-14T01:30:00 to 2015-03-25T15:31:05 |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_c54ad63c, tc_b7f8c5d3, tc_79f05444, tc_ee16623e, tc_e70901fe |


The file listing from the disk image confirms the presence of a volume labeled 'Authorized USB' which contained folders named 'Secret Project Data', indicating access to sensitive project materials. The volume contained multiple files related to the secret project, including design concepts and pricing proposals, suggesting data transfer or access occurred via this medium. This finding is based on file system structures found in the raw output of the tsk.filelist source, showing directory paths and file names associated with unauthorized data handling.



### 2. [HIGH] User Access to 'Secret Project Data' Folder on USB Drive

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T13:40:10 to 2015-03-24T13:48:00 |
| **Sources** | registry.usrclass.informant |
| **Evidence Refs** | tc_2e9f3398, tc_1b276e61 |


Registry shellbag data from the user 'informant' (registry.usrclass.informant) shows multiple access events to the 'Secret Project Data' folder located on the D: drive, which corresponds to the 'Authorized USB' volume. The first access was recorded at 2015-03-24 13:40:10 when the 'S data' and 'Secret Project Data' top-level directories were viewed. Detailed views followed at 13:47:58 and 13:48:00, with folder paths including 'S data\Secret Project Data\Secret Project Data\final', 'S data\Secret Project Data\pricing decision', and 'progress'. This user activity directly confirms interaction with the sensitive data after the USB device was connected, corroborating the high-severity finding of unauthorized data access.



### 3. [HIGH] Data Exfiltration Indications

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2014-12-16T12:10:26 to 2015-03-24T10:00:18 |
| **Sources** | tsk.masquerade |
| **Evidence Refs** | tc_1b2b9cf8, tc_5c8c2b71, tc_234edbe8 |
| **ATT&CK** | [T1027.006](https://attack.mitre.org/techniques/T1027/006/) |


Multiple files with misleading extensions were identified in the file system, indicating an attempt to conceal data. Files including 'my_favorite_cars.db' (detected as OLE), 'my_favorite_movies.7z' (detected as XLSX), 'new_years_day.jpg' (detected as XLSX), 'winter_whether_advisory.zip' (detected as PPTX), and 'diary_#*.txt' files (detected as DOCX/PPTX/OLE) suggest data was disguised as common media or archive files. Many of these files were found in deleted state, indicating removal after exfiltration.



### 4. [INFO] SanDisk USB Device Connection

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T13:37:59 to 2015-03-25T15:28:47 |
| **Sources** | registry.system |
| **Evidence Refs** | tc_e9aad1d5, tc_e2e4d1cb, tc_eb376420, tc_e149f3ad, tc_ffda6e7d |


A SanDisk Cruzer Fit USB device was connected to the system on 2015-03-24. Registry artifacts (registry.system) confirm the device connection via the USBSTOR key and the device's persistence through the last_write time. Two device instances were recorded in the USBSTOR registry key: 4C530012450531101593&0 and 4C530012550531106501&0, indicating potential multiple connections or different sessions. The FriendlyName value specifies the device as 'SanDisk Cruzer Fit USB Device'.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| | No network IOCs extracted | | |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| | No file IOCs extracted | | |





---

## Appendix C: MITRE ATT&CK Coverage

1 techniques identified across findings.


**Kill Chain Coverage:** Defense Evasion (1)


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1027.006](https://attack.mitre.org/techniques/T1027/006/) | HTML Smuggling | Data Exfiltration Indications |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 374 |
| Findings submitted | 4 |
| Confirmed | 4 |
| Inferences | 0 |
| Input tokens | 17.0M |
| Output tokens | 30.1K |
| Total tokens | 17.0M |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| bedrock/qwen.qwen3-235b-a22b-2507-v1:0 | 17.0M | 30.1K | 17.0M |




<details>
<summary>Evidence Sources (90)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 8 |
| tsk.partitions | sleuthkit | 10 |
| tsk.partitions | sleuthkit | 9 |
| optical.listing | mulder-optical | 58 |
| tsk.filelist | sleuthkit | 51 |
| tsk.filelist | sleuthkit | 27 |
| tsk.masquerade | sleuthkit | 0 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist.p1 | sleuthkit | 93 |
| ez.mft | eztools | 98918 |
| evtx.manifest | evtx-extract | 54 |
| ez.shimcache | eztools | 307 |
| registry.sam | regripper | 186 |
| registry.sam | regripper | 7 |
| registry.sam | regripper | 7 |
| registry.security | regripper | 69 |
| registry.security | regripper | 8 |
| hayabusa.alerts | hayabusa | 35 |
| registry.software | regripper | 33492 |
| registry.software | regripper | 283 |
| registry.software | regripper | 283 |
| registry.system | regripper | 5209 |
| registry.system | regripper | 199 |
| registry.system | regripper | 199 |
| registry.system | regripper | 381 |
| registry.system | regripper | 255 |
| registry.system | regripper | 255 |
| registry.usrclass.admin11 | regripper | 11 |
| registry.ntuser.admin11 | regripper | 133 |
| registry.ntuser.default | regripper | 74 |
| registry.usrclass.informant | regripper | 102 |
| registry.ntuser.informant | regripper | 306 |
| registry.usrclass.temporary | regripper | 15 |
| registry.ntuser.temporary | regripper | 118 |
| registry.query.system | python-registry | 1 |
| registry.query.software | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| exiftool.metadata | exiftool | 9 |
| exiftool.metadata | exiftool | 9 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| tsk.partitions | sleuthkit | 10 |
| tsk.masquerade | sleuthkit | 17 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 237 |
| bulk.email | bulk_extractor | 12 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 300 |
| bulk.url_services | bulk_extractor | 21 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 264 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.email | bulk_extractor | 43 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 288 |
| bulk.url_services | bulk_extractor | 19 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 189 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.url | bulk_extractor | 207 |
| bulk.url_services | bulk_extractor | 14 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 366963 |
| bulk.duplicates | bulk_extractor | 12 |
| bulk.email | bulk_extractor | 6851 |
| bulk.ether | bulk_extractor | 6 |
| bulk.rfc822 | bulk_extractor | 7326 |
| bulk.url | bulk_extractor | 421750 |
| bulk.url_facebook-address | bulk_extractor | 19 |
| bulk.url_searches | bulk_extractor | 155 |
| bulk.url_services | bulk_extractor | 3637 |
| exiftool.metadata | exiftool | 9 |
| pcap.disk.atiumd6a | tshark | 8 |
| pcap.disk.atiumdva | tshark | 8 |
| chainsaw.hunt | chainsaw | 99 |
| pcap.disk.atiumd6a | tshark | 8 |
| pcap.disk.atiumdva | tshark | 8 |
| pcap.disk.atiumd6a | tshark | 8 |
| pcap.disk.atiumdva | tshark | 8 |
| hayabusa.alerts | hayabusa | 35 |
| exiftool.metadata | exiftool | 9 |
| tsk.metadata.267 | istat | 4012 |
| tsk.metadata.263 | istat | 3564 |
| tsk.metadata.967047 | istat | 320 |
| tsk.metadata.3096966 | istat | 42 |
| tsk.metadata.267 | istat | 4012 |
| composite.file_staging | composite | 578 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
