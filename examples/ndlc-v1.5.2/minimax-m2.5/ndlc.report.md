# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-19T20:22:15.533876+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 99 evidence sources (58 disk, 41 other) | 323 tool calls | 27 minutes
**Results:** 13 findings (3 high) | 7 confirmed, 6 inference
**Timeline:** 2015-01-05 to 2015-03-25

**Attack Lifecycle:**
- **Initial Access / Deployment** (2015-01-05 to 2015-03-23): CD (RM3) to USB (RM2) Data Staging Path Confirmed (+4 related)
- **Persistence** (2015-03-22 to 2015-03-25): Program executions preceding data exfiltration (+2 related)
- **Discovery / Collection** (2015-03-24): Timeline of data exfiltration on March 24 2015
- **Other Activity** (2015-03-22 to 2015-03-24): Suspicious User Activity Timeline March 22-25 2015 (+1 related)

**Tools:** search (73), open_case (24), get_raw_output (18), submit_finding (16), start_extraction_batch (14). SHA-256 hashes recorded for all evidence.



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

323 tool calls were executed across 11
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Investigation Report: Insider Data Exfiltration via Removable Media

## Background

This investigation concerns a suspected data exfiltration incident involving a Windows workstation at NIST. The evidence set consists of a PC disk image, two removable media images (RM2 - USB drive, RM3 - optical CD), and various forensically extracted artifacts including registry hives, MFT records, browser history, email archives, and bulk-extracted data. The investigation window spans March 22-25, 2015, with the primary exfiltration event occurring on March 24, 2015.

The evidence inventory includes 99 indexed sources extracted using multiple forensic tools including SleuthKit (file system analysis), EZTools (MFT parsing), regripper (registry analysis), bulk_extractor (carving and data extraction), and composite analysis modules. These sources yielded 13 findings of varying severity and confidence levels. The MITRE ATT&CK techniques identified include T1048 (Exfiltration Over Alternative Protocol), T1025 (Removable Media), T1059 (Command and Scripting Interpreter), T1078 (Valid Accounts), and T1041 (Exfiltration Over C2 Server).

## Incident Timeline

The investigation revealed a structured timeline of events leading to and including the data exfiltration. The reconstruction is organized into distinct operational phases with timestamps derived from MFT records, registry last-write times, and file creation metadata.

**Phase 1: Pre-Exfiltration User Activity (March 22, 2015)**

On March 22, 2015, user 'informant' logged into the workstation and began accessing multiple user profile directories, including AppData, SendTo, and Start Menu locations between 14:34 and 14:41 UTC. At 15:03, the user launched Microsoft Excel (EXCEL.EXE), followed by Microsoft Outlook (OUTLOOK.EXE) at 15:03:42, and PowerPoint at 15:23:10. Windows Mail was also accessed at 14:34:53. This demonstrates active business application usage on the system two days before the primary exfiltration event.

During this same period, users 'admin11' and 'temporary' also accessed the system. User 'admin11' launched NOTEPAD.EXE and explorer.exe at 15:54-15:57 on March 22. User 'temporary' executed explorer.exe and GettingStarted.exe at 15:54-15:56. However, both of these users were only active on March 22 and showed no activity on March 24 when the exfiltration occurred.

**Phase 2: Cloud Sync Activity (March 23, 2015)**

On March 23, 2015, between 20:02 and 20:05 UTC, Google Drive was actively synchronizing on the workstation. Evidence includes the Google Drive installation at Program Files (x86)\Google\Drive, user data folders at \Users\informant\AppData\Local\Google\Drive and \Users\informant\Google Drive, language pack access, and a lockfile indicating active synchronization. This cloud activity was initially assessed as a potential exfiltration vector but further analysis confirmed it was not the source of the business documents copied to USB.

**Phase 3: Data Exfiltration (March 24, 2015)**

The primary data exfiltration occurred on March 24, 2015, between 09:59:27 and 10:00:18 UTC. During this window, 17 deleted files were created on the USB removable media (RM2) located in the OrphanFiles directory. These files exhibited mislabeled extensions indicating intentional obfuscation:

- winter_whether_advisory.zip → actually PPTX (16,381,123 bytes)
- my_favorite_movies.7z → actually XLSX (100,078 bytes)
- new_years_day.jpg → actually XLSX
- my_smartphone.png → actually DOCX
- new_year_calendar.one → actually DOCX
- a_gift_from_you.gif → actually DOCX
- landscape.png → actually DOCX
- diary_#1d.txt → actually DOCX
- diary_#1p.txt → actually PPTX
- diary_#2d.txt → actually DOCX
- Plus 7 additional OLE files with mislabeled extensions

The USB Mass Storage Driver (USBSTOR.SYS) was loaded and active on March 24, 2015 at 13:37:59, confirming removable media was connected to the system around the time of the data exfiltration. The registry USBSTOR key contained one subkey, indicating at least one USB mass storage device was connected.

User 'informant' was the only user active on March 24 who accessed files matching the exfiltrated data. RecentDocs entries for this user show access to: winter_whether_advisory.zip (20:44:18Z), BD-RE Drive (D:) IAMAN CD (21:01:14Z), and image files (Koala.jpg, Tulips.jpg, Penguins.jpg) from the CD. These files directly correspond to the data found on the USB removable media. The user also had Google Drive configured on this date.

**Phase 4: Post-Exfiltration Activity (March 25, 2015)**

The workstation remained active after the exfiltration. On March 25, 2015, between 15:24 and 15:28, xpsrchvw.exe (the Windows XML Paper Specification viewer, often used to view Office documents) was executed by user 'informant'. Additional Microsoft Office programs were also used on this date. The LastLoggedOnUser registry key showed "informant" with a last write time of 2015-03-25 13:05:47Z, reflecting the system state on March 25.

## Key Findings

**Data Staging Path Confirmed**

The investigation definitively established the data staging path: files were copied from the CD (RM3) to the USB drive (RM2), not directly from the PC hard drive. This conclusion is supported by multiple converging evidence points:

File sizes match exactly between RM3 and RM2. For example, winter_storm.amr is 14,547,968 bytes on both media. winter_whether_advisory.zip is 16,381,123 bytes on both. my_favorite_movies.7z is 100,078 bytes on both.

Directory structure matches between the two removable media. The CD contains /design, /pricing decision, /progress, /proposal, and /technical review directories. The USB contains $OrphanFiles/design, $OrphanFiles/PRICIN~1, $OrphanFiles/progress, $OrphanFiles/proposal, and $OrphanFiles/TECHNI~1 directories.

File modification timestamps match. winter_storm.amr shows modified=2015-01-23T20:47:10Z on CD and mtime=2015-01-23 16:47:10 UTC on USB. winter_whether_advisory.zip shows modified=2014-12-16T16:10:26Z on CD and mtime=2014-12-16 12:10:26 UTC on USB.

The deletion timeline on the CD shows files were deleted during session -1 around 20:54-20:55 on March 24, 2015, correlating with the USB file creation times (09:59:27-10:00:18 on March 24).

**Mislabeled Extensions as Anti-Forensic Measure**

The 17 files on the USB drive exhibited deliberately mislabeled file extensions, represent a classic anti-forensic technique designed to evade content inspection and automated data loss prevention (DLP) systems. The masquerade analysis tool confirmed these files had extensions that did not match their actual file types. For example, files with .jpg and .png extensions were actually Microsoft Office documents (DOCX, XLSX). This technique suggests the user either knew about or was concerned about content inspection mechanisms.

**Content of Exfiltrated Data**

Analysis of the CD (RM3) revealed extensive business and personal data that had been stored over 9 sessions. The currently present files include 3 legitimate JPEG images (Koala.jpg, Penguins.jpg, Tulips.jpg) totaling approximately 2.1MB. However, deleted files from previous sessions reveal the full scope of data that was staged for potential exfiltration: design documents, pricing decisions, technical reviews, proposals, progress reports, and personal diary files. The business documents appear to be corporate or government-sensitive materials based on their naming conventions.

**Google Drive Sync - Non-Factor**

The Google Drive synchronization activity observed on March 23 (20:02-20:05 UTC) was thoroughly investigated and determined to be unrelated to the March 24 USB exfiltration. Evidence supporting this conclusion includes: the business documents copied to USB on March 24 have file modification timestamps from December 2014 to January 2015, predating the March 23 Google Drive activity. The specific files on the USB (winter_storm.amr, winter_whether_advisory.zip, diary files) were staged from CD (RM3), not from cloud sync. The PC's Google Drive sync-related OrphanFiles show different files (installer components, sync client resources) than the business documents found on USB.

**Network Connection to 10.11.11.128**

The bulk_extractor domain analysis detected references to IP address 10.11.11.128 labeled as "SECURED_DRIVE" or "secured_drive." This is a private IP address (10.x.x.x range), suggesting a local network resource such as a network-attached storage (NAS) device. However, no direct evidence was found showing data was actually transferred to this IP address during the investigation window. The correlation between this network connection and the USB data exfiltration event is not clearly established. This finding may represent an alternative exfiltration vector that was considered or attempted but not confirmed as the primary method.

**User Attribution Assessment**

The user 'informant' is the most likely source of the data exfiltration based on the following evidence:

RecentDocs entries from March 24 show access to winter_whether_advisory.zip and the BD-RE Drive (D:) IAMAN CD, which directly corresponds to the files found on the USB device. The user was the only account active on March 24. The xpsrchvw.exe execution on March 25 represents post-exfiltration activity consistent with reviewing copied Office documents. Other user accounts (admin11 and temporary) were only active on March 22, two days before the exfiltration occurred. However, attribution is rated as "inference" confidence rather than "confirmed" because there is no direct process-level or USN journal evidence showing exactly who performed the USB copy operation.

## Threat Intelligence and Attribution

This investigation examined the possibility of external threat actor involvement and malware-driven exfiltration. The evidence conclusively indicates this was an insider threat scenario rather than an external compromise:

There is no evidence of malware or unauthorized remote access. No suspicious processes, payload delivery mechanisms, or command-and-control (C2) communications were identified. The activity pattern is consistent with authorized user behavior misused for data exfiltration, not an external attacker.

The mislabeled extensions technique, while representing deliberate obfuscation, is a relatively simple anti-forensic method that could be employed by a non-technical insider aware of basic DLP mechanisms. The use of USB removable media (the "IAMAN $_@" device) as an exfiltration vector suggests the user wanted physical control over the data transfer, possibly to avoid network-based monitoring.

The presence of NIST email addresses (iaman.informant@nist.gov, informant@nist.gov) in the extracted data strongly suggests the user was a NIST employee or contractor with legitimate access to the workstation and potentially sensitive information. The business documents on the CD (design documents, pricing decisions, technical reviews, proposals, progress reports) appear consistent with NIST business operations.

**Attribution Conclusion:** The activity is internally sourced and attributed to the user account 'informant.' No external threat groups or known threat actor ttps were identified. The confidence level for attribution to insider threat is high, while attribution to any specific external actor is not applicable as no external actor involvement was identified.

## Impact Assessment

**Scope of Compromise**

The primary impacted system is the Windows workstation used by user 'informant' at NIST. The removable media (RM2 USB drive and RM3 CD) were also involved as exfiltration vectors.

The investigation identified 17 deleted files on the USB drive representing sensitive business documents with mislabeled extensions. The CD (RM3) contained substantially more deleted file data from 9 prior sessions, including design documents, pricing decisions, technical reviews, proposals, progress reports, and personal diary files.

**Data at Risk**

Based on file listing analysis, the following categories of data were potentially exfiltrated:

- Design documents and technical specifications
- Pricing decisions and business proposals
- Progress reports and project documentation
- Personal diary files with potentially sensitive content
- Multiple Office document formats (DOCX, XLSX, PPTX)

The precise business impact depends on the sensitivity classification of these documents, which would require coordination with the NIST data governance team.

**Credential Exposure**

The user account 'informant' was the primary active account during the exfiltration window. No evidence of credential theft or privilege escalation was identified. The activity appears to have been conducted using legitimate user credentials.

## Immediate Tactical Containment

The following containment actions should be implemented immediately, assuming the threat is still active:

1. **Isolate the system**: If the workstation (IP or hostname to be determined from registry) is still networked, isolate it immediately to prevent further data exfiltration or lateral movement.

2. **Disable user account**: Immediately disable the NIST user account 'informant' pending investigation completion. Use Active Directory console or `net user informant /active:no`.

3. **Collect USB devices**: Search for and seize any removable media belonging to user 'informant' or matching the "IAMAN $_@" labeling observed on RM2.

4. **Preserve evidence**: Create forensic images of the workstation if not already done, and ensure chain of custody is maintained for all evidence.

5. **Revoke OAuth/Cloud access**: If Google Drive or other cloud storage was configured for user 'informant', revoke all OAuth tokens and change passwords for any connected accounts.

6. **Block file access**: Add detection rule for file masquerading: files with .zip/.7z/.jpg/.png/.gif extensions that contain Office document magic bytes (50 4B).

7. **Monitor for recurrence**: Implement enhanced monitoring on user 'informant' Active Directory account for any reactivation attempts.

## Strategic Remediation

The following recommendations are directly tied to specific findings and attack techniques observed in this case:

**Finding: USB Exfiltration with Mislabeled Extensions (T1048, T1025)**

Specific control failure: The organization lacks device-level data loss prevention (DLP) or USB control mechanisms to block or monitor file transfers to unauthorized removable media. Additionally, there was no file type inspection at the USB/gateway level to detect masqueraded files.

Remediation: Deploy USB control software (e.g., Microsoft Endpoint Manager, CrowdStrike Falcon Device Control, or equivalent) to whitelist approved USB devices and log all file transfers. Implement DLP inspection at the endpoint and network perimeter to inspect file content regardless of extension, and alert on or block files with mismatched magic bytes.

**Finding: User 'informant' Valid Account Misuse (T1078)**

Specific control failure: The organization relied on valid credentials without sufficient behavioral analytics or access logging to detect data handling anomalies. User activity preceded the exfiltration with legitimate business application usage, making the threat difficult to distinguish from normal activity without additional context.

Remediation: Implement user behavior analytics (UBA/UEBA) to detect anomalous data handling patterns (e.g., bulk file access followed by removable media connection). Deploy Data Loss Prevention policies that trigger alerts when sensitive file categories are accessed in combination with USB device connections within a short time window.

**Finding: Data Staging on Removable Media (RM3 CD → RM2 USB)**

Specific control failure: Optical disc burning and USB device usage were not centrally logged or restricted. The CD pre-dates the incident and was likely used over multiple sessions without detection.

Remediation: Disable or restrict writable optical drive functionality where not required for business operations. Implement comprehensive removable media logging using Windows Group Policy or Endpoint Detection and Response solutions. Consider network-based blocking of writeable media endpoints to unauthorized systems.

**Finding: Post-Exfiltration Program Execution**

Specific control failure: The xpsrchvw.exe execution on March 25 and prior Office application usage represent normal workflow but provided opportunity for post-exfiltration validation by the user. The detection gap is in correlating document access patterns with subsequent storage device connections.

Remediation: Create correlation rules that flag document-heavy sessions followed by USB device connections, particularly when sensitive file paths are involved. Implement alert prioritization for users with access to high-value data assets.

## Conclusion

**Q1. What systems were compromised?**

The primary compromised system is the Windows workstation used by user 'informant' at NIST. Both removable media devices (RM2 USB drive labeled "IAMAN $_@" and RM3 CD labeled "IAMAN CD") were involved in the exfiltration chain.

**Q2. How did the attacker gain initial access?**

This incident represents insider threat, not external attack. The user 'informant' had legitimate access to the workstation and used that access to copy data to removable media. No unauthorized initial access was required.

**Q3. What lateral movement occurred?**

No lateral movement was detected. The activity was contained to a single workstation with data copied to locally attached removable media.

**Q4. What persistence mechanisms were installed?**

No persistence mechanisms were identified. The data exfiltration was a one-time event using USB removable media. No malware, scheduled tasks, or service installations were observed.

**Q5. Was data exfiltrated, and if so, what and how much?**

Yes, data was exfiltrated. At minimum, 17 files with mislabeled extensions were copied from CD to USB on March 24, 2015. These include business documents (pricing decisions, technical reviews, proposals, progress reports) and personal diary files. The source CD contained substantially more data from prior sessions. Precise file counts and sizes would require further detailed analysis of the CD image's deleted file structures.

**Q6. What is the full timeline of the incident?**

March 22, 2015: User informant logged in, used Microsoft Office applications (Excel, Outlook, PowerPoint), Windows Mail. Users admin11 and temporary also accessed the system. March 23, 2015: Google Drive sync active (20:02-20:05 UTC). March 24, 2015: Data exfiltration to USB removable media (09:59-10:00 UTC). USBSTOR driver loaded (13:37:59). Files deleted from CD (20:54-20:55). March 25, 2015: User informant executed xpsrchvw.exe and Office applications. LastLoggedOnUser registry updated to "informant."

**Q7. What is the total scope and business impact?**

The scope includes one workstation and two removable media devices. The business impact involves potential exposure of sensitive business documents including design documents, pricing decisions, technical reviews, proposals, progress reports, and personal diary files. The NIST data governance team should determine the sensitivity classification of these materials and whether regulatory notification is required.

**Q8. What are the recommended remediation actions?**

1. Disable user account 'informant' immediately.
2. Deploy USB control and endpoint DLP to prevent similar incidents.
3. Conduct comprehensive audit of user 'informant' account activity and data access.
4. Engage NIST security team to classify exposed data and determine notification requirements.
5. Review and strengthen removable media policies organization-wide.
6. Consider implementing user behavior analytics for high-value data users.
7. Conduct peer user awareness training on data handling policies.


---

## Overview

| | |
|---|---|
| Findings | **13** (7 confirmed, 6 inference) |
| Severity | 0 critical, 3 high, 6 medium, 0 low, 4 info |
| Sources | 11 evidence sources across 323 tool calls |


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
| 2015-01-05T19:15:08 | CD (RM3) to USB (RM2) Data Staging Path Confirmed | HIGH | optical.listing, tsk.masquerade |
| 2015-01-05T19:15:08Z | RM3 Optical Media Contains Business and Personal Data | MEDIUM | optical.listing |
| 2015-03-22T14:34:41 | Suspicious User Activity Timeline March 22-25 2015 | MEDIUM | ez.mft, bulk.email |
| 2015-03-22T14:34:41 | PC Activity Preceding USB Data Exfiltration | INFO | composite.correlation |
| 2015-03-22T15:54:20 | Program executions preceding data exfiltration | MEDIUM | registry.ntuser.informant, registry.ntuser.admin11, registry.ntuser.temporary |
| 2015-03-23T20:02:43 | Google Drive Cloud Sync Active During Investigation Window | MEDIUM | ez.mft |
| 2015-03-23T20:02:43 | Google Drive Sync Not Source of USB Business Documents | INFO | tsk.filelist, tsk.masquerade |
| 2015-03-24T09:59:27 | Sensitive data copied to removable media with mislabeled extensions | HIGH | tsk.masquerade |
| 2015-03-24T09:59:27 | Timeline of data exfiltration on March 24 2015 | MEDIUM | tsk.masquerade, registry.system |
| 2015-03-24T13:37:59 | USB mass storage device connected to system | MEDIUM | registry.system |
| 2015-03-25T13:05:47 | User account 'informant' likely performed the data leakage based on March 24 activity | HIGH | registry.system, registry.ntuser.informant |





---

## Appendix A: Verified Forensic Findings


### 1. [HIGH] Sensitive data copied to removable media with mislabeled extensions

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:27 to 2015-03-24T10:00:18 |
| **Sources** | tsk.masquerade |
| **Evidence Refs** | tc_65510eb9 |
| **ATT&CK** | [T1048](https://attack.mitre.org/techniques/T1048/) |


Analysis of the removable media (RM2) disk image reveals 17 deleted files in the OrphanFiles directory that were likely copied to external media. These files have mislabeled extensions indicating intentional data hiding:
- winter_whether_advisory.zip → actually PPTX
- my_favorite_movies.7z → actually XLSX  
- new_years_day.jpg → actually XLSX
- my_smartphone.png → actually DOCX
- new_year_calendar.one → actually DOCX
- a_gift_from_you.gif → actually DOCX
- landscape.png → actually DOCX
- diary_#1d.txt → actually DOCX
- diary_#1p.txt → actually PPTX
- diary_#2d.txt → actually DOCX
Plus 7 additional OLE files with mislabeled extensions.



### 2. [HIGH] User account 'informant' likely performed the data leakage based on March 24 activity

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2015-03-25T13:05:47 to 2015-03-25T15:28:47 |
| **Sources** | registry.system, registry.ntuser.informant |
| **Evidence Refs** | tc_d41024b2, tc_48458b94 |
| **ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/) |


Revised counter-analysis: The user 'informant' is the likely source of the data leakage, but the attribution evidence needs correction:

1. LastLoggedOnUser registry key shows "informant" but LastWrite time is 2015-03-25 13:05:47Z - this reflects the state ON MARCH 25, not during the data exfiltration on March 24.

2. xpsrchvw.exe UserAssist entry shows execution on 2015-03-25 15:24-15:28 - this is ONE DAY AFTER the USB data exfiltration (which occurred at 09:59-10:00 on March 24). This execution does NOT prove who performed the March 24 data leakage.

3. CORRECT EVIDENCE: RecentDocs shows informant was active on March 24, 2015 accessing:
   - winter_whether_advisory.zip (20:44:18Z)
   - BD-RE Drive (D:) IAMAN CD (21:01:14Z)
   - Koala.jpg, Tulips.jpg, Penguins.jpg (from the CD)
   
   These files match the data that was exfiltrated to USB. This is the strongest evidence for attributing the exfiltration to informant.

4. OTHER USERS: admin11 and temporary were only active on March 22 (2 days BEFORE the exfiltration), not on March 24.

ATTRIBUTION VERDICT: informant is the most likely user based on March 24 activity, but there is no direct evidence (such as USN journal or process logs) showing WHO performed the actual USB copy operation. Confidence is downgraded to "inference".



### 3. [HIGH] CD (RM3) to USB (RM2) Data Staging Path Confirmed

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-01-05T19:15:08 to 2015-03-24T20:55:46 |
| **Sources** | optical.listing, tsk.masquerade |
| **Evidence Refs** | tc_fdec1b6f, tc_2bc7029f |
| **ATT&CK** | [T1048](https://attack.mitre.org/techniques/T1048/) |


Investigation of Question 2 and Question 5 confirms the data staging path: files were copied from CD (RM3) to USB (RM2), NOT directly from PC. Evidence includes:

1. File sizes match exactly between CD and USB - e.g., winter_storm.amr = 14547968 bytes on both, winter_whether_advisory.zip = 16381123 bytes on both, my_favorite_movies.7z = 100078 bytes on both, etc.

2. Directory structure matches: CD has /design, /pricing decision, /progress, /proposal, /technical review; USB has $OrphanFiles/design, $OrphanFiles/PRICIN~1, $OrphanFiles/progress, $OrphanFiles/proposal, $OrphanFiles/TECHNI~1

3. File modification timestamps match: winter_storm.amr modified=2015-01-23T20:47:10Z on CD, mtime=2015-01-23 16:47:10 UTC on USB; winter_whether_advisory.zip modified=2014-12-16T16:10:26Z on CD, mtime=2014-12-16 12:10:26 UTC on USB

4. CD deletion timeline: Files were deleted from CD during session -1 around 20:54-20:55 on March 24, 2015. USB file creation times (crtimes) show 09:59:27-10:00:18 on March 24, 2015.

This confirms the exfiltration path: CD (RM3) → USB (RM2).



### 4. [MEDIUM] Google Drive Cloud Sync Active During Investigation Window

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T20:02:43 to 2015-03-23T20:05:00 |
| **Sources** | ez.mft |
| **Evidence Refs** | tc_67d8f7c2 |


Google Drive was actively used on March 23, 2015 around 20:02-20:05 UTC. Evidence includes: Google Drive installation at Program Files (x86)\Google\Drive, user data folders at \Users\informant\AppData\Local\Google\Drive and \Users\informant\Google Drive, language pack access, and a lockfile indicating active synchronization. This represents cloud-based data exfiltration capability.



### 5. [MEDIUM] Suspicious User Activity Timeline March 22-25 2015

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:34:41 to 2015-03-25T23:59:59 |
| **Sources** | ez.mft, bulk.email |
| **Evidence Refs** | tc_c509ea9e, tc_58dce58f |


User 'informant' was actively using the system during March 22-25, 2015, with peak activity around March 23. Evidence includes MFT timestamps showing file access in user directories (Documents, Recent, SendTo, Temporary Internet Files), browser usage (Chrome and IE), and email activity through Windows Mail. This establishes the timeline window for potential data leakage.



### 6. [MEDIUM] Timeline of data exfiltration on March 24 2015

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-24T09:59:27 to 2015-03-24T13:37:59 |
| **Sources** | tsk.masquerade, registry.system |
| **Evidence Refs** | tc_65510eb9, tc_7cece0d0 |
| **ATT&CK** | [T1048](https://attack.mitre.org/techniques/T1048/), [T1078](https://attack.mitre.org/techniques/T1078/) |


The data exfiltration occurred around March 24, 2015. Analysis of the OrphanFiles directory on RM2 shows files with creation timestamps between 09:59:27 and 10:00:18 on March 24, 2015. The USB Mass Storage Driver (USBSTOR) was loaded and active on March 24, 2015 at 13:37:59, indicating active use of removable media on that date. This correlates with the file creation times on the removable media.



### 7. [MEDIUM] USB mass storage device connected to system

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-24T13:37:59 |
| **Sources** | registry.system |
| **Evidence Refs** | tc_7cece0d0, tc_fbfbb692 |
| **ATT&CK** | [T1025](https://attack.mitre.org/techniques/T1025/) |


Registry analysis shows that at least one USB mass storage device was connected to the system. The USBSTOR registry key contained one subkey, and the USB Mass Storage Driver (USBSTOR.SYS) was loaded and active on March 24, 2015 at 13:37:59. This indicates removable media was connected to the system around the time of the data exfiltration.



### 8. [MEDIUM] Program executions preceding data exfiltration

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T15:54:20 |
| **Sources** | registry.ntuser.informant, registry.ntuser.admin11, registry.ntuser.temporary |
| **Evidence Refs** | tc_48458b94 |
| **ATT&CK** | [T1059](https://attack.mitre.org/techniques/T1059/) |


UserAssist registry analysis reveals program executions by multiple users prior to and around the time of data exfiltration:
- informant user: xpsrchvw.exe (March 25, 2015 at 15:24-15:28), Microsoft Office programs
- admin11 user: NOTEPAD.EXE, explorer.exe (March 22, 2015 at 15:54-15:57)
- temporary user: explorer.exe, GettingStarted (March 22, 2015 at 15:54-15:56)

These program executions precede the data exfiltration event on March 24, 2015.



### 9. [MEDIUM] RM3 Optical Media Contains Business and Personal Data

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-01-05T19:15:08Z to 2015-03-24T20:57:03Z |
| **Sources** | optical.listing |
| **Evidence Refs** | tc_44ba2a16 |


Analysis of the RM3 optical media (write-once CD labeled "IAMAN CD") shows files were stored and deleted over 9 sessions, indicating extensive use. Currently present are 3 legitimate JPEG images (Koala.jpg, Penguins.jpg, Tulips.jpg totaling ~2.1MB). However, deleted files from previous sessions reveal extensive business and personal data that was stored on this CD, including: design documents, pricing decisions, technical reviews, proposals, and progress reports, as well as personal diary files. This CD was likely used as a data staging location before copying to other removable media (as evidenced by the RM2 findings showing USB connection on March 24, 2015).



### 10. [INFO] Archive Files Found on Removable Media

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_9033c3e0 |


Removable media (labeled "IAMAN $_@") contains archive files that may be related to data staging for exfiltration. The media contained an orphan files directory with: winter_whether_advisory.zip and winter_storm.amr. The presence of a .zip archive on removable media suggests data may have been copied from the PC to external media.



### 11. [INFO] PC Activity Preceding USB Data Exfiltration

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | inference |
| **Time** | 2015-03-22T14:34:41 to 2015-03-22T15:23:10 |
| **Sources** | composite.correlation |
| **Evidence Refs** | tc_9245f6d5 |
| **ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/) |


Investigation of Question 1 reveals user 'informant' was actively using the PC in the hours leading up to the USB data exfiltration on March 24, 2015 at 09:59:27. Evidence from composite.correlation shows:

1. On March 22, 2015 around 14:34-14:41, user 'informant' logged in and accessed their user profile directories (AppData, SendTo, Start Menu, etc.)
2. Microsoft Office applications were actively used on March 22, 2015 around 15:03-15:23: Excel (EXCEL.EXE) at 15:03:29, Outlook (OUTLOOK.EXE) at 15:03:42, PowerPoint at 15:23:10
3. Windows Mail was accessed on March 22 at 14:34:53

However, the specific business documents on USB (RM2) were staged from CD (RM3), not directly from PC.



### 12. [INFO] Google Drive Sync Not Source of USB Business Documents

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | inference |
| **Time** | 2015-03-23T20:02:43 to 2015-03-23T20:05:00 |
| **Sources** | tsk.filelist, tsk.masquerade |
| **Evidence Refs** | tc_0c76116f, tc_2bc7029f |
| **ATT&CK** | [T1048](https://attack.mitre.org/techniques/T1048/) |


Investigation of Question 3 confirms that Google Drive sync activity on March 23 (20:02-20:05 UTC) was NOT the source of the business documents copied to USB on March 24. Evidence:

1. Google Drive sync was active on March 23 around 20:02-20:05 UTC (documented in existing finding f_b182f58d)
2. The business documents copied to USB on March 24 (winter_storm.amr, winter_whether_advisory.zip, diary files, etc.) were staged from CD (RM3), not from Google Drive cloud sync
3. The files on RM2 have file modification timestamps from December 2014 - January 2015, predating the March 23 Google Drive activity
4. The PC's Google Drive sync-related OrphanFiles show different files (Google Drive installer components, sync client resources) than the business documents found on USB

This confirms the USB files came from CD staging, not cloud sync.



### 13. [INFO] Network Connection to 10.11.11.128 (secured_drive) Detected

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | inference |
| **Sources** | bulk.domain |
| **Evidence Refs** | tc_0f140eaf |
| **ATT&CK** | [T1041](https://attack.mitre.org/techniques/T1041/) |


Investigation of Question 4 reveals network connections to IP address 10.11.11.128 labeled as "SECURED_DRIVE" or "secured_drive" in bulk_extractor domain analysis. Evidence from bulk.domain shows multiple references to this IP with the label "SECURED_DRIVE" (e.g., "10.11.11.128\tSECURED_DRIVE"). 

Analysis:
- 10.11.11.128 is a private IP address (10.x.x.x range), suggesting a local network resource
- The label "secured_drive" suggests this may have been a network-attached storage (NAS) or secure network drive
- However, no direct evidence was found showing data was actually transferred to this IP address during the investigation window
- The discovery timeline shows this IP appears in the dataset but correlation with the actual data exfiltration event (USB copy at 09:59:27 on March 24) is not clearly established

This may represent an alternative exfiltration vector that was considered or attempted but not confirmed as the primary method used for the March 24 data leakage.



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

5 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) > Execution (1) > Persistence (1) > Privilege Escalation (1) > Defense Evasion (1) > Collection (1) > Exfiltration (2)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User account 'informant' likely performed the...; Timeline of data exfiltration on March 24 2015; PC Activity Preceding USB Data Exfiltration |


### Execution

| Technique | Name | Findings |
|-----------|------|----------|
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Program executions preceding data exfiltration |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User account 'informant' likely performed the...; Timeline of data exfiltration on March 24 2015; PC Activity Preceding USB Data Exfiltration |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User account 'informant' likely performed the...; Timeline of data exfiltration on March 24 2015; PC Activity Preceding USB Data Exfiltration |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User account 'informant' likely performed the...; Timeline of data exfiltration on March 24 2015; PC Activity Preceding USB Data Exfiltration |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1025](https://attack.mitre.org/techniques/T1025/) | Data from Removable Media | USB mass storage device connected to system |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | Network Connection to 10.11.11.128... |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Sensitive data copied to removable media with...; Timeline of data exfiltration on March 24 2015; CD (RM3) to USB (RM2) Data Staging Path Confirmed; Google Drive Sync Not Source of USB Business Documents |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 323 |
| Findings submitted | 13 |
| Confirmed | 7 |
| Inferences | 6 |
| Input tokens | 7.1M |
| Output tokens | 116.9K |
| Total tokens | 7.2M |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| bedrock/minimax.minimax-m2.5 | 7.1M | 116.9K | 7.2M |




<details>
<summary>Evidence Sources (99)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 9 |
| tsk.fsstat | sleuthkit | 40 |
| tsk.partitions | sleuthkit | 8 |
| tsk.partitions | sleuthkit | 9 |
| tsk.partitions | sleuthkit | 10 |
| tsk.filelist | sleuthkit | 51 |
| tsk.filelist | sleuthkit | 27 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist.p1 | sleuthkit | 93 |
| tsk.partitions | sleuthkit | 8 |
| tsk.partitions | sleuthkit | 10 |
| tsk.partitions | sleuthkit | 9 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 264 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.email | bulk_extractor | 43 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 288 |
| bulk.url_services | bulk_extractor | 19 |
| tsk.partitions | sleuthkit | 9 |
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
| tsk.masquerade | sleuthkit | 0 |
| tsk.masquerade | sleuthkit | 17 |
| ez.mft | eztools | 98918 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.system | regripper | 418 |
| exiftool.metadata | exiftool | 9 |
| registry.system | regripper | 186 |
| registry.system | regripper | 7 |
| registry.system | regripper | 7 |
| registry.security | regripper | 69 |
| registry.security | regripper | 8 |
| exiftool.metadata | exiftool | 9 |
| registry.system | regripper | 33492 |
| registry.system | regripper | 283 |
| registry.system | regripper | 283 |
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
| composite.file_staging | composite | 578 |
| tsk.masquerade | sleuthkit | 3 |
| optical.listing | mulder-optical | 58 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 237 |
| bulk.email | bulk_extractor | 12 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 300 |
| bulk.url_services | bulk_extractor | 21 |
| exiftool.metadata | exiftool | 9 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 403827 |
| bulk.duplicates | bulk_extractor | 6623 |
| bulk.email | bulk_extractor | 6881 |
| bulk.ether | bulk_extractor | 6 |
| bulk.exif | bulk_extractor | 794 |
| bulk.jpeg | bulk_extractor | 9 |
| bulk.rfc822 | bulk_extractor | 7326 |
| bulk.sqlite_carved | bulk_extractor | 95 |
| bulk.url | bulk_extractor | 458564 |
| bulk.url_facebook-address | bulk_extractor | 19 |
| bulk.url_searches | bulk_extractor | 155 |
| bulk.url_services | bulk_extractor | 3681 |
| bulk.zip_carved | bulk_extractor | 22411 |
| exiftool.metadata | exiftool | 9 |
| registry.query.system | python-registry | 1 |
| ez.shimcache | eztools | 307 |
| evtx.manifest | evtx-extract | 54 |
| composite.correlation | composite | 1 |
| composite.timeline | composite | 172 |
| composite.correlation | composite | 1 |
| composite.file_staging | composite | 578 |
| composite.exfil | composite | 4928 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
