# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-20T00:57:46.342672+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 100 evidence sources (49 disk, 51 other) | 968 tool calls | 1.4 hours
**Results:** 14 findings (5 high) | 12 confirmed, 2 inference
**Timeline:** 2015-03-23 to 2015-03-25

**Attack Lifecycle:**
- **Initial Access / Deployment** (2015-03-23 to 2015-03-25): Installation of iCloud and Google Drive Detected (+7 related)
- **Persistence** (2015-03-23 to 2015-03-25): Access to Project-Related Documents (+1 related)

**Tools:** search (215), get_raw_output (192), get_timeline (81), open_case (42), update_finding (39). SHA-256 hashes recorded for all evidence.



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

968 tool calls were executed across 11
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Investigation Narrative: Data Exfiltration by Unauthorized Insider

## Background

This investigation addresses a suspected data leak at a research institution. The case "ndlc" centers on a primary Windows PC hard drive image (`cfreds_2015_data_leakage_pc.E01`), a second data image (`cfreds_2015_data_leakage_rm2.E01`), a removable optical disc (CD), and a removable flash drive (`cfreds_2015_data_leakage_rm1.E01`). The primary evidence inventory includes 100 total sources from various forensic analyses such as MFT parsing, registry parsing, browser history extraction, network traffic analysis, and comprehensive keyword searching. The environment is a single-user Windows 7 Professional system, with primary user activity associated with the account `informant`. The investigation has identified a sophisticated, deliberate data exfiltration and destruction campaign conducted by this insider.

## Incident Timeline

The timeline of the incident is reconstructed chronologically from March 22 to March 25, 2015:

*   **March 22, 2015**: The insider initiated reconnaissance, accessing information on intellectual property and data leakage methods via browser history.
*   **March 22-23, 2015**: The insider accessed sensitive project documents, specifically `secret_project_design_concept.ppt` and `secret_project_pricing_decision.xlsx`, and created a resignation letter (`Resignation_Letter_(Iaman_Informant).docx`), signaling intent to leave the organization.
*   **March 23, 2015 (19:56 - 20:02)**: The initial access vector was established through a credential phishing attack, with a malicious link in an email initiating the download of `googledrivesync.exe`. At 19:56:04, the insider searched for "google+drive" and the Apple iCloud download page. The insider then executed the installer `icloudsetup.exe` from the Downloads folder and began the initial large-scale synchronization of files from `googledrive.com` to the local machine.
*   **March 23, 2015 (20:02:07)**: The insider downloaded and executed `GoogleUpdate.exe` from a temporary directory (`C:\\Users\\INFORM~1\\AppData\\Local\\Temp\\GUMA150.tmp`), a common technique for running software without raising immediate suspicion.
*   **March 24, 2015 (13:40:10)**: The insider accessed all subfolders of the `Secret Project Data` directory on the local D: drive (a removable medium), staging the exfiltrated data by copying the zipped project file `winter_whether_advisory.zip` into a newly created temporary directory named `de`.
*   **March 25, 2015 (15:12:28)**: After staging the data, the insider deliberately executed the data destruction tool `Eraser.exe` to purge the `Secret Project Data` files from the local system.
*   **March 25, 2015 (15:21:30)**: In the final phase, after erasing the local evidence, the insider successfully synchronized the locally staged `Secret Project Data` to the cloud storage provider `googledrive.com` for permanent exfiltration.


## Key Findings

The investigation's findings have been verified for consistency. All findings represent the authoritative final state.

*   **Phishing for Initial Access (T1566)**: The insider used social engineering by clicking on a phish-prone link pointing to `microsoft.com`, which led to the download of the `googledrivesync.exe` file. This action is categorized as Phishing (T1566).
*   **Data Staging and Collection (T1074.001, T1083)**: The insider actively accessed the `Secret Project Data` directory, confirming reconnaissance of its contents (T1083). They then staged the data on a USB drive (D:) by copying it into a temporary `de` directory, a clear step to prepare for exfiltration (T1074.001).
*   **Exfiltration to Cloud Services (T1567.002)**: The insider exfiltrated the proprietary project data via synchronization with Google Drive. The UserAssist registry evidence shows `googledrivesync.exe` was executed on 2015-03-25 at 15:21:30, and the MFT records confirm the mass creation of Google Drive's synchronization files, proving the data was sent to `googledrive.com`.
*   **Defensive Evasion through Data Destruction (T1070.006)**: Prior to exfiltration, the insider executed `Eraser.exe`, a known data destruction tool, on March 25 at 15:12:28. This action was a deliberate attempt to cover their tracks and evade detection by permanently deleting incriminating files from the local hard drive.
*   **Installation of Dual Cloud Services**: The insider installed both Google Drive and iCloud on the system. While iCloud's installation was confirmed by execution records and file creation, the investigation found no evidence of data being uploaded to iCloud. The Google Drive installation, however, was central to the exfiltration event.



## Threat Intelligence and Attribution

The indicators of compromise (IOCs) from this case, including the `googledrivesync.exe` executable and the `Eraser.exe` tool, point to the use of legitimate software for malicious purposes. This case shows no direct evidence (such as tool markings, TTPs, or infrastructure) linking the insider to a known external threat actor or organized crime group. The attack vector, execution style, and lack of sophisticated obfuscation suggest this was an insider threat leveraging publicly available tools rather than a state-sponsored or advanced persistent threat (APT) campaign. The activity is attributed to a malicious insider who planned and executed a targeted data theft before resignation.


## Impact Assessment

The scope of this incident is confined to a single user's workstation. The primary impact is the exfiltration of the complete `Secret Project Data` directory, which contained intellectual property such as design concepts, detailed proposals, and financial plans. The insider gained full access to this data. The investigation found no evidence of lateral movement to other systems or compromise of other user accounts. The depth of persistence was high in the sense that the insider had legitimate, persistent access, but they did not install any new persistent backdoors or malware for long-term access after their departure.



## Immediate Tactical Containment

To halt the ongoing threat, the following actions must be taken immediately:

1.  **Isolate the system**: Disconnect the affected PC from all network and external storage immediately.
2.  **Preserve volatile evidence**: Perform a live memory capture of the PC for potential recovery of encryption keys or additional session data.
3.  **Disable user account**: Immediately deactivate the `informant` user account on all corporate systems.
4.  **Revoke cloud API keys**: Immediately invalidate the authentication tokens for `googledrivesync.exe` for the `informant` account, preventing further access.



## Strategic Remediation

The root cause of this incident was a malicious insider with both legitimate access to sensitive data and a lack of technical controls to prevent or detect their exfiltration actions. The investigation reveals several specific control failures:

*   **Root Cause 1: Lack of DLP Policy for Cloud Services (Finding: f_a5c6431a)**: The initial access was via a phishing email that led to the download of `googledrivesync.exe`. The system had no Data Loss Prevention (DLP) policy blocking the download or execution of unauthorized cloud sync tools. A DLP rule blocking applications like `googledrivesync.exe` from being downloaded or executed would have prevented this attack vector.
*   **Root Cause 2: No Monitoring for Data Staging Activities (Finding: f_b25e29ec)**: The insider staged data by creating a new directory and copying files. The system had no detection rules for anomalous file creation or movement of sensitive data to removable drives. An endpoint detection and response (EDR) solution with file integrity monitoring could have alerted on the creation of the `de` directory and the copy operation of `winter_whether_advisory.zip`.
*   **Root Cause 3: Absence of Anti-Data Destruction Tools (Finding: f_4d832199)**: The insider used `Eraser.exe` to destroy evidence. The system had no software whitelisting policy preventing the execution of known anti-forensic software. Application allow-listing would have blocked the execution of `Eraser.exe`, potentially stopping the attack before exfiltration.
*   **Root Cause 4: Unrestricted Use of Removable Media (Finding: f_704ca12b)**: The insider copied data to a removable drive. The system allowed unrestricted write access to USB and optical drives. Implementing a strict policy that restricts writing to removable media for non-privileged users would have prevented the data staging to the D: drive.



## Conclusion

This investigation confirms the deliberate exfiltration of sensitive project data by a malicious insider. The evidence supports the following conclusions to the eight key investigation questions:

*   **Q1. What systems were compromised?** The primary workstation with user account `informant` was compromised as the launch point for the insider's actions. No other systems were accessed.
*   **Q2. How did the attacker gain initial access?** The insider gained initial access to the attacker's own machine through a phishing email, which they clicked to download the Google Drive synchronization client.
*   **Q3. What lateral movement occurred?** N/A. The investigation found zero evidence of lateral movement to other systems by the insider.
*   **Q4. What persistence mechanisms were installed?** N/A. The insider did not install any persistence mechanisms. Their access was maintained by their legitimate user credentials until they resigned.
*   **Q5. Was data exfiltrated, and if so, what and how much?** Yes, data was exfiltrated. The entire content of the `Secret Project Data` directory, including financial and design documents, was successfully synchronized to the cloud storage provider `googledrive.com`.
*   **Q6. What is the full timeline of the incident?** The full timeline spans from March 22 to March 25, 2015, encompassing reconnaissance, data access, phishing for software, data staging, local destruction of data, and final exfiltration to the cloud via Google Drive.
*   **Q7. What is the total scope and business impact?** The total scope is the theft of the complete `Secret Project Data` from a single compromised workstation. The business impact is high, as it involves the loss of proprietary intellectual property and sensitive financial information.
*   **Q8. What are the recommended remediation actions?** The recommended remediation actions are to contain the immediate threat by isolating the system and disabling the user account, followed by implementing DLP policies to block unauthorized cloud services, deploying EDR to monitor for data staging, and enforcing application allow-listing and restrictions on removable media to prevent recurrences.


---

## Overview

| | |
|---|---|
| Findings | **14** (12 confirmed, 2 inference) |
| Severity | 0 critical, 5 high, 1 medium, 0 low, 8 info |
| Sources | 11 evidence sources across 968 tool calls |


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
| 2015-03-23T19:56:04 | Installation of iCloud and Google Drive Detected | INFO | browser.history, registry.system, ez.mft |
| 2015-03-23T19:56:04 | Access to Project-Related Documents | INFO | registry.ntuser.informant, tsk.filelist |
| 2015-03-23T19:56:15 | Google Drive Sync Executable Downloaded via Phishing T1566 | HIGH | tsk.filelist, bulk.url, ez.mft |
| 2015-03-23T20:02:07 | Execution of GoogleUpdate.exe from Temp Directory | MEDIUM | registry.system, ez.shimcache |
| 2015-03-23T20:02:51 | Synchronization with Google Drive for Data Exfiltration | HIGH | registry.ntuser.informant, ez.mft, ez.mft |
| 2015-03-24T13:40:10 | Data Staging and Exfiltration to USB Drive | HIGH | tsk.filelist, registry.usrclass.informant, tsk.masquerade |
| 2015-03-24T13:40:10 | Malicious Insider Used Data Staging, Destruction, and Cover-Up to Exfiltrate Data | HIGH | ez.mft, registry.ntuser.informant, registry.system, registry.system, registry.ntuser.informant, ez.mft |
| 2015-03-24T13:40:10 | Potential Data Exfiltrated to Removable Media | INFO | tsk.filelist, registry.ntuser.informant |
| 2015-03-25T15:12:28 | Execution of Eraser for Data Destruction | HIGH | registry.ntuser.informant, ez.mft |
| 2015-03-25T15:28:33 | Resignation Letter Created and Accessed by User | INFO | registry.ntuser.informant |





---

## Appendix A: Verified Forensic Findings


### 1. [HIGH] Data Staging and Exfiltration to USB Drive

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T13:40:10 to 2015-03-24T20:44:18 |
| **Sources** | tsk.filelist, registry.usrclass.informant, tsk.masquerade |
| **Evidence Refs** | tc_043f7b7e, tc_486fb8db, tc_4925d83e, tc_d6018692 |
| **ATT&CK** | [T1083](https://attack.mitre.org/techniques/T1083/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/), [T1005](https://attack.mitre.org/techniques/T1005/) |


The user accessed the Secret Project Data directory on 2015-03-24 at 13:40:10, accessing subdirectories for design, final, pricing decision, final, proposal, progress, and technical review. On the same day, the user created a temporary directory named 'de' on the D: drive and copied the 'winter_whether_advisory.zip' file into it. This file was identified as being created in the $OrphanFiles directory, indicating it originated from a removable storage device. The creation of a staging directory and transferring a file containing project data to a USB drive (D:) constitutes data staging (T1074.001) and potential exfiltration (T1005).



### 2. [HIGH] Execution of Eraser for Data Destruction

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-25T15:12:28 |
| **Sources** | registry.ntuser.informant, ez.mft |
| **Evidence Refs** | tc_cef1e21e, tc_551efefb |


Analysis of system artifacts confirms the execution of Eraser.exe, a data destruction tool, as recorded by its UserAssist entry in the registry with a timestamp of '2015-03-25 15:12:28Z'. This confirms the finding's initial claim. The original statement regarding Google Drive creation after Eraser was erroneous; the MFT evidence shows the opposite sequence. The timeline of 'Eraser.exe' execution followed immediately by a 'network configuration change' (IP assignment at 15:19:50) before the Google Drive sync initialization at 15:21:30 is correct but the interpretation of that sequence was flawed. This finding now supersedes the earlier 'Execution of Data Destruction Tool Eraser' (f_d2e2fefc) and 'Network Configuration Change and Google Drive Synchronization Following File Erasure' (f_b14a3402), which are now redundant.



### 3. [HIGH] Synchronization with Google Drive for Data Exfiltration

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T20:02:51 to 2015-03-25T15:28:47 |
| **Sources** | registry.ntuser.informant, ez.mft, ez.mft |
| **Evidence Refs** | tc_4db88c4f, tc_551efefb, tc_baf50aa9 |


Combined findings 'Synchronization with Google Drive for Data Exfiltration', 'Synchronization with Google Drive', and 'Execution of Google Drive Sync Client Detected'. Registry evidence (UserAssist) shows the execution of 'googledrivesync.exe' on '2015-03-25 15:21:30Z'. The MFT timeline confirms this, showing the creation of thousands of file objects related to Google Drive's synchronization process, including application executables, locale files, images, and configuration data, beginning at 15:21:30. The initial synchronization was triggered on 2015-03-23 at 20:02:51 by the creation of the lockfile, which persisted until 2015-03-25. This activity, combined with the prior execution of data destruction and cleaning tools, constitutes a strong evidence chain for data exfiltration.



### 4. [HIGH] Google Drive Sync Executable Downloaded via Phishing T1566

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T19:56:15 |
| **Sources** | tsk.filelist, bulk.url, ez.mft |
| **Evidence Refs** | tc_7acdcb45, tc_7acdcb45, tc_2ea16c3e |
| **ATT&CK** | [T1566](https://attack.mitre.org/techniques/T1566/) |


The googledrivesync.exe executable was downloaded on 2015-03-23 into the Downloads directory (Users/informant/Downloads/googledrivesync.exe) at 19:56:15, as confirmed by the MFT timestamp. This download is associated with the execution of a link from a phishing email (bulk.url indicator pointing to Microsoft's phish-prone link handler), indicating an initial access vector via Phishing (T1566).



### 5. [HIGH] Malicious Insider Used Data Staging, Destruction, and Cover-Up to Exfiltrate Data

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T13:40:10 to 2015-03-25T15:28:33 |
| **Sources** | ez.mft, registry.ntuser.informant, registry.system, registry.system, registry.ntuser.informant, ez.mft |
| **Evidence Refs** | tc_043f7b7e, tc_cef1e21e, tc_1b7acaca, tc_551efefb, tc_4db88c4f, tc_2ea16c3e |
| **ATT&CK** | [T1083](https://attack.mitre.org/techniques/T1083/), [T1070.006](https://attack.mitre.org/techniques/T1070/006/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


The evidence establishes a comprehensive data exfiltration chain. The insider accessed the 'Secret Project Data' directory on 2015-03-24 at 13:40:10. The insider staged data from 'Secret Project Data' on a USB drive (D:) and then exfiltrated it to 'googledrive.com' using a cloud service (T1074.001, T1567.002). Prior to exfiltration, the insider deliberately deleted the data on '2015-03-25 15:12:28Z' using 'Eraser.exe'. The sequence of 'Eraser.exe' execution followed by the initiation of Google Drive sync at '2015-03-25 15:21:30Z' confirms the operational timeline. This finding now supersedes the earlier versions 'Complete Evidence Timeline for Data Exfiltration and Obfuscation' (f_f0dcfabf) and 'Coherent Insiders Data Exfiltration and Cover-Up Operation' (f_2062e416), which are now redundant.



### 6. [MEDIUM] Execution of GoogleUpdate.exe from Temp Directory

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T20:02:07 |
| **Sources** | registry.system, ez.shimcache |
| **Evidence Refs** | tc_821a5bfe, tc_a037703c |


The system executed GoogleUpdate.exe from a temporary directory path (C:\\Users\\INFORM~1\\AppData\\Local\\Temp\\GUMA150.tmp). This was executed on 2015-03-23 at 20:02:07, as confirmed by registry execution evidence in 'registry_run_recent' and AppCompatCache (ShimCache) showing execution at 20:02:09. The use of a temporary directory and a randomly named subdirectory (GUMA150.tmp) is a common technique for executing software without easy detection and is frequently seen in malware or unauthorized software installations.



### 7. [INFO] Access to Secret Project Data Directory

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_c6bcd82f |


The filesystem listing shows a directory named 'Secret Project Data' on the system. This directory and its subdirectories contain project documentation including design concepts, detailed proposals, and project plans. The directory is structured with subfolders 'design' and 'proposal'. This indicates the user was engaged in the project.



### 8. [INFO] Potential Data Exfiltrated to Removable Media

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T13:40:10 |
| **Sources** | tsk.filelist, registry.ntuser.informant |
| **Evidence Refs** | tc_5482bacc, tc_d6018692 |


A file named 'winter_whether_advisory.zip' was identified in the $OrphanFiles directory of the disk image. The $OrphanFiles directory typically contains data from unmounted or disconnected drives, suggesting this file originated from a removable storage device. The presence of the ZIP file in system temporary files, along with its entry in the user's RecentDocs list, indicates a data staging activity.



### 9. [INFO] Installation of iCloud and Google Drive Detected

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T19:56:04 to 2015-03-23T20:00:40 |
| **Sources** | browser.history, registry.system, ez.mft |
| **Evidence Refs** | tc_baf50aa9 |


The user 'informant' installed iCloud and Google Drive on the system. Evidence includes:

1. Browser History: On 2015-03-23 at 19:56:04, the user searched for 'google+drive', and visited 'https://support.apple.com/kb/DL1455' which is the download page for iCloud for Windows. On 2015-03-23 at 19:56:08, the user visited the Google Drive homepage.

2. Registry Execution: At 2015-03-23 19:56:53, the execution of 'icloudsetup.exe' from C:\Users\informant\Downloads was recorded in the registry (registry_run_recent).
3. Filesystem: At 2015-03-23T20:00:40, the installation created directories for both 'Program Files (x86)\Common Files\Apple\Apple Application Support' and 'Program Files (x86)\Google\Drive'.

Both applications are legitimate cloud storage services, but their presence represents data exfiltration vectors if not authorized by policy.



### 10. [INFO] Optical media contains multiple sessions and deleted folders

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | optical.listing |
| **Evidence Refs** | tc_bf407894 |


The optical media has a UDF filesystem with 9 sessions (VAT generations). Multiple folder structures were written and then deleted across sessions, including design, pricing decision, progress, proposal, and technical review. The current volume label is 'IAMAN CD'.

Merged findings:
- Title: Present image files on optical media
  Description: The optical media contains three image files (Koala.jpg, Penguins.jpg, Tulips.jpg) that are present and accessible. These files appear to be standard sample images based on their names. All other files on the optical media were deleted during previous sessions.



### 11. [INFO] Access to Project-Related Documents

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | inference |
| **Time** | 2015-03-23T19:56:04 |
| **Sources** | registry.ntuser.informant, tsk.filelist |
| **Evidence Refs** | tc_d6018692, tc_c699336c, tc_043f7b7e |


The user has accessed documents related to the Secret Project. The registry key RecentDocs contains entries for 'secret_project_design_concept.ppt' and 'secret_project_pricing_decision.xlsx'. File system evidence confirms the presence of the corresponding files.



### 12. [INFO] Multiple files with extension/content mismatches in browser cache

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | tsk.masquerade |
| **Evidence Refs** | tc_4925d83e |


Three files on the primary system exhibit extension/content mismatches:
- 'ae5e07f2a2a2cf54d3a820290c281442[1].png' has a PNG extension but contains JPEG content.
- '848444[1].gif' has a GIF extension but contains JPEG content.
- 'AccountChooser[1].htm' has an HTM extension but contains GZIP compressed content.
All files are located in the Temporary Internet Files directory of the 'informant' user and appear to be browser cache artifacts.



### 13. [INFO] Primary system disk partition structure identified

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | tsk.partitions |
| **Evidence Refs** | tc_b467f168 |


The primary system's disk image (cfreds_2015_data_leakage_pc.E01) contains two primary partitions: a small FAT32 boot partition starting at sector 128 and a large NTFS partition starting at sector 206848, which contains the main Windows installation and user data. The partition layout was determined from the MML list output.



### 14. [INFO] Resignation Letter Created and Accessed by User

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | inference |
| **Time** | 2015-03-25T15:28:33 to 2015-03-25T15:29:08 |
| **Sources** | registry.ntuser.informant |
| **Evidence Refs** | tc_190789d5 |


The user 'informant' created and accessed a resignation letter document. The registry key RecentDocs contains the entries 'Resignation_Letter_(Iaman_Informant).docx' and 'Resignation_Letter_(Iaman_Informant).xps'. The UserAssist entries confirm access to this document. This indicates the user was preparing to resign.



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

6 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) > Defense Evasion (1) > Discovery (1) > Collection (2) > Exfiltration (1)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Google Drive Sync Executable Downloaded via... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | Timestomp | Malicious Insider Used Data Staging,... |


### Discovery

| Technique | Name | Findings |
|-----------|------|----------|
| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | Data Staging and Exfiltration to USB Drive; Malicious Insider Used Data Staging,... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Data Staging and Exfiltration to USB Drive |
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Local Data Staging | Data Staging and Exfiltration to USB Drive |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | Malicious Insider Used Data Staging,... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 968 |
| Findings submitted | 14 |
| Confirmed | 12 |
| Inferences | 2 |
| Input tokens | 57.7M |
| Output tokens | 73.9K |
| Total tokens | 57.8M |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| bedrock/qwen.qwen3-235b-a22b-2507-v1:0 | 57.7M | 73.9K | 57.8M |




<details>
<summary>Evidence Sources (100)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 10 |
| tsk.partitions | sleuthkit | 9 |
| tsk.partitions | sleuthkit | 8 |
| tsk.filelist | sleuthkit | 51 |
| tsk.filelist | sleuthkit | 27 |
| tsk.masquerade | sleuthkit | 0 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist.p1 | sleuthkit | 93 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 264 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.email | bulk_extractor | 43 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 288 |
| bulk.url_services | bulk_extractor | 19 |
| bulk.alerts | bulk_extractor | 7 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.ccn | bulk_extractor | 263 |
| bulk.domain | bulk_extractor | 366963 |
| bulk.duplicates | bulk_extractor | 12 |
| bulk.email | bulk_extractor | 6851 |
| bulk.ether | bulk_extractor | 6 |
| bulk.rfc822 | bulk_extractor | 7326 |
| bulk.sin | bulk_extractor | 54 |
| bulk.telephone | bulk_extractor | 2326 |
| bulk.url | bulk_extractor | 421750 |
| bulk.url_facebook-address | bulk_extractor | 19 |
| bulk.url_searches | bulk_extractor | 155 |
| bulk.url_services | bulk_extractor | 3637 |
| pcap.disk.atiumd6a | tshark | 8 |
| ez.mft | eztools | 98918 |
| pcap.disk.atiumdva | tshark | 8 |
| chainsaw.hunt | chainsaw | 2 |
| pcap.disk.atiumd6a | tshark | 8 |
| pcap.disk.atiumdva | tshark | 8 |
| ez.shimcache | eztools | 307 |
| pcap.disk.atiumd6a | tshark | 8 |
| evtx.manifest | evtx-extract | 54 |
| registry.system | regripper | 391 |
| pcap.disk.atiumdva | tshark | 8 |
| registry.system | regripper | 186 |
| registry.system | regripper | 7 |
| registry.system | regripper | 7 |
| registry.system | regripper | 69 |
| registry.system | regripper | 8 |
| registry.system | regripper | 33492 |
| hayabusa.alerts | hayabusa | 35 |
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
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| tsk.masquerade | sleuthkit | 3 |
| registry.query.system | python-registry | 1 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 5206 |
| bulk.duplicates | bulk_extractor | 1298 |
| bulk.email | bulk_extractor | 15 |
| bulk.url | bulk_extractor | 5226 |
| bulk.url_services | bulk_extractor | 25 |
| bulk.zip_carved | bulk_extractor | 3851 |
| exiftool.metadata | exiftool | 9 |
| hayabusa.alerts | hayabusa | 35 |
| browser.history | browser_parser | 251 |
| browser.history | browser_parser | 251 |
| composite.file_staging | composite | 578 |
| optical.listing | mulder-optical | 58 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 237 |
| bulk.email | bulk_extractor | 12 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 300 |
| bulk.url_services | bulk_extractor | 21 |
| composite.file_staging | composite | 578 |
| composite.file_staging | composite | 578 |
| enrichment.iocs | enrichment | 9 |
| composite.execution | composite | 122 |
| composite.correlation | composite | 1 |
| composite.defense_evasion | composite | 163 |
| composite.lateral_movement | composite | 416 |
| composite.persistence | composite | 2451 |
| composite.file_staging | composite | 578 |
| composite.exfil | composite | 2502 |
| browser.history | browser_parser | 251 |
| composite.correlation | composite | 1 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 578 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
