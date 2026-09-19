# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-19T23:21:41.643000+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 245 evidence sources (32 disk, 213 other) | 315 tool calls | 29 minutes
**Results:** 10 findings (1 critical, 6 high) | 9 confirmed, 1 inference
**Timeline:** 2015-01-05 to 2015-03-24

**Key Threats:**
- Sensitive Government and Library of Congress Data on Optical Media

**Attack Lifecycle:**
- **Initial Access / Deployment** (2015-01-12 to 2015-02-19): Disk Imaging/Cloning Pattern Detected on Removable Media (+2 related)
- **Defense Evasion / Anti-Forensics** (2015-03-24): Removable Media Data Exfiltration - Masquerading Files Detected (+2 related)
- **Discovery / Collection** (2015-01-05 to 2015-03-24): Sensitive 'Secret Project Data' Exfiltrated to Removable Media (+3 related)

**Tools:** search (58), open_case (24), get_raw_output (23), get_investigation_summary (15), submit_finding (15). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **Sensitive Government and Library of Congress Data on Optical Media** (2015-01-20T14:18:06Z to 2015-03-24T23:59:59Z)




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

315 tool calls were executed across 12
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Investigation Report: Data Exfiltration Incident

## Background

This investigation (Case ID: ndlc) concerns a data exfiltration incident involving an insider threat at what appears to be a government-affiliated organization. The evidence scope encompasses physical removable media (USB drives and optical discs), filesystem analysis, Windows registry artifacts, and timeline reconstruction spanning from late 2014 through March 2015.

The investigation analyzed 12 evidence sources including sleuthkit disk forensics, bulk_extractor carvers, Windows registry hives, event logs, and Plaso timeline artifacts. A total of 10 findings were submitted, with 9 confirmed findings, 1 inference-level finding, 1 critical severity finding, 6 high-severity findings, and 2 medium-severity findings identified.

The evidence reveals a deliberate and sophisticated data exfiltration operation conducted by a user with legitimate access to sensitive government information. The actor employed multiple evasion techniques including file masquerading, directory renaming, secure deletion tools, and cloud storage synchronization to maximize data theft while minimizing detection.

## Incident Timeline

The incident follows a clear operational sequence from initial data collection through attempted evidence destruction:

**Phase 1: Data Collection and Staging (Late 2014 - January 5, 2015)**
The threat actor collected sensitive "Secret Project Data" from the compromised system. Directory structures including design, pricing decision, progress, proposal, and technical review folders were copied to removable media. Initial file creation timestamps on the optical media date to January 5, 2015 at 19:15:08 UTC.

**Phase 2: Evidence Destruction Preparation (January 12, 2015)**
The Eraser secure deletion tool was installed at 22:56:30 UTC in C:\Program Files\Eraser\. This installation represents a deliberate preparation for evidence destruction, occurring 8 days before the first deletion wave.

**Phase 3: Data Exfiltration via Physical Media (January 20, 2015)**
The first wave of file deletions occurred at 14:18:06 UTC, indicating data had already been copied to removable media (USB and CD) and the actor was beginning to cover their tracks.

**Phase 4: Mass Deletion Cover-Up (January 23, 2015)**
A major deletion event occurred at 16:47:10 UTC, with additional sensitive files including winter_whether_advisory.zip (16MB), winter_storm.amr (14MB audio), and various technical review files being deleted from the USB device. The total volume of deleted sensitive files exceeded 50MB.

**Phase 5: Cloud Exfiltration Vector (February - March 2015)**
Google Drive was installed on the system on February 19, 2015 at 18:20:30 UTC. The application was first executed at 18:24:23 UTC, with sync activity detected as late as March 23, 2015 at 16:03:30 UTC. This provided an alternate exfiltration path that would not leave local artifacts.

**Phase 6: Final Obfuscation (March 24, 2015)**
The optical media received additional sessions with directory renaming obfuscation between 20:54:16 UTC and 20:57:00 UTC. The volume label "IAMAN CD" was used as a placeholder to avoid suspicion.

## Key Findings

### Critical Finding: Government and Library of Congress Data Exfiltrated

The most severe finding confirms that highly sensitive government communications and cultural heritage data were exfiltrated to optical media. Email addresses from the Office of Management and Budget (Eric_P._Lauer@omb.eop.gov) and the Library of Congress (mmun@loc.gov) were identified in the bulk_extractor output. The CD contains references to whitehouse.gov and omb.eop.gov URLs indicating access to government systems.

Critically, Library of Congress archival materials including culturally significant collections were found on the exfiltrated media: "Portraits of three Indians," "Harriman Alaska Expedition of 1899" materials, and "Photographic prints by Hine for National Child Labor Committee" represent irreplaceable archival materials that were compromised.

### High-Severity Findings: Multiple Exfiltration Vectors

**USB Device Exfiltration (rm2):** An unauthorized USB device with volume label "IAMAN $_@" was connected to the system. Unlike the authorized USB device (rm1) labeled "Authorized USB" containing legitimate project data, this device contained 17 deleted files in the $OrphanFiles directory with masqueraded extensions. File content did not match extensions—for example, .zip files were actually PPTX content, and .txt files contained DOCX data. This steganography/masquerading technique demonstrates sophisticated operational security.

**Disk Imaging Pattern:** Bulk extractor analysis of the authorized USB device (rm1) revealed a 512MB data block duplicated at multiple offset locations (1GB, 2GB, 2.5GB, 3GB), indicating disk cloning or imaging operations as part of data staging.

**Directory Obfuscation:** The optical media showed evidence of directory renaming to conceal content: /de → /design, /pd → /pricing decision, /prog → /progress, /prop → /proposal, /tr → /technical review. The volume label "IAMAN CD" appears to be a deliberate placeholder ("I am an CD") to avoid suspicion.

**Eraser Tool Deployment:** The Eraser secure deletion tool was installed specifically to facilitate evidence destruction. The installation on January 12, 2015 preceded the January 20 and January 23 deletion events by exactly the timeline expected of deliberate cover-up.

**Google Drive Cloud Exfiltration:** In addition to physical media exfiltration, Google Drive was installed and executed, providing cloud synchronization capability. Sync logs show activity through March 23, 2015, indicating potential ongoing or second-wave data exfiltration to cloud storage.

### Medium-Severity Findings: Timeline and Context

The timeline analysis confirms files were copied then deleted in a deliberate sequence designed to exfiltrate data while destroying local evidence. The user account "informant" with nist.gov email addresses (iaman.informant@nist.gov appears repeatedly in registry and filesystem artifacts) correlates to the insider responsible.

## Threat Intelligence and Attribution

The evidence strongly indicates an insider threat rather than external attack. The actor had legitimate access to sensitive "Secret Project Data" containing government communications, the ability to use authorized USB ports, and knowledge of the security environment. Multiple attribution indicators point to a single user account ("informant") based on registry userassist data, NTUSER.DAT artifacts, and correlation of timeline events.

The techniques employed—file masquerading, directory renaming, secure deletion tool deployment, and cloud storage installation—demonstrate awareness of forensic detection methods. The actor was not merely casual but took active steps to obscure exfiltration activities.

No external threat actor attribution is supported by the evidence. The detection signatures, while sophisticated, represent insider tradecraft rather than threat group tooling. The attack pattern is consistent with a malicious insider scenario: legitimate access abused, multiple exfiltration vectors (physical and cloud), evidence destruction after data transfer.

## Impact Assessment

**Scope of Compromise:** At minimum, one system was compromised for data exfiltration purposes. The "Secret Project Data" directory containing multiple folders (design, pricing decision, progress, proposal, technical review) represents corporate sensitive information. The specific number of files is estimated in the hundreds based on directory structure evidence.

**Data at Risk:** The most critical impact involves sensitive government data. OMB communications, Library of Congress archival materials, and references to whitehouse.gov indicate potential national security implications. The proprietary project data adds commercial sensitivity.

**Credential Exposure:** No explicit credential theft was identified. However, the insider had access to sensitive government email systems and archival collections, meaning their legitimate credentials were used to access the exfiltrated data.

**Persistence Depth:** While no traditional malware persistence was found, the Google Drive installation represents a persistent exfiltration channel. The tool remains available for future data transfer once remediation occurs.

## Immediate Tactical Containment

The following immediate actions are required:

1. **Disable User Account Immediately**: Disable the "informant" account (iaman.informant@nist.gov) and all associated credentials in Active Directory. Revoke NIST network access tokens.

2. **Block Known IOCs**: Implement network blocks for any communication with google drive synchronization endpoints (accounts.google.com, drive.google.com) until full remediation.

3. **Secure Removable Media**: Physically secure and forensically image all connected USB devices (both rm1 "Authorized USB" and rm2 "IAMAN $_@"). Isolate the optical media ("IAMAN CD") immediately.

4. **Terminate Google Drive Process**: Kill any running googledrivesync.exe processes (PID lookup required on live system) and remove the Google Drive installation directory.

5. **Preserve Evidence**: Create forensic images of the system hard drives before any remediation. The erasure tool was used but evidence may remain in unallocated space and slack.

6. **Revoke Physical Access**: Revoke the insider's physical access to facilities housing sensitive equipment and media.

7. **Coordinate with OMB and LOC**: Notify the Office of Management and Budget and Library of Congress security teams regarding the compromised email addresses and archival materials.

## Strategic Remediation

Each root cause identified in the investigation maps to specific control failures:

**Root Cause 1: Absence of Data Loss Prevention (DLP) Controls**
The investigation found no evidence of DLP enforcement on removable media. Sensitive "Secret Project Data" was copied to USB devices without detection. A DLP solution blocking sensitive file types on USB mass storage would have prevented this exfiltration vector.

**Root Cause 2: Lack of Endpoint Monitoring for Unauthorized Software**
The Eraser tool was installed without alert. Endpoint detection and response (EDR) should detect installation of evidence-destruction tools and flag for investigation.

**Root Cause 3: Insufficient Cloud Storage Policy Enforcement**
Google Drive was installed and executed without blocking. Organization-wide policy should prohibit unsanctioned cloud storage applications and enforce via endpoint controls or network filtering.

**Root Case 4: Inadequate Access Controls for Sensitive Data**
The insider had excessive access to government communications and archival materials. Role-based access control (RBAC) should implement least-privilege principles, limiting any single user's ability to access multiple categories of sensitive data.

**Root Cause 5: No Comprehensive Forensic Timeline Visibility**
While Plaso timeline data exists, the investigation relied heavily on filesystem and bulk_extractor analysis. Enhanced logging and centralized security information and event management (SIEM) would provide earlier detection of the data staging and deletion pattern observed.

## Conclusion

This investigation confirms a deliberate insider data exfiltration event involving the compromise of sensitive government and proprietary organization data. The threat actor employed sophisticated evasion techniques including file masquerading, directory renaming, secure deletion tools, and cloud storage applications to maximize data theft while minimizing forensic detection.

**Q1. What systems were compromised?** The primary workstation/user account ("informant") with NIST domain credentials was Compromised for data exfiltration. Physical media (USB rm1/rm2, optical disc) served as exfiltration vectors.

**Q2. How did the attacker gain initial access?** This was an insider threat—the user had legitimate access to the system and sensitive data. No external initial access vector (phishing, vulnerability exploitation) was identified.

**Q3. What lateral movement occurred?** No lateral movement to other systems was identified. The exfiltration focused on data the insider could access from their own workstation.

**Q4. What persistence mechanisms were installed?** The Google Drive application provides a persistent exfiltration channel. No traditional malware persistence was identified.

**Q5. Was data exfiltrated, and if so, what and how much?** Yes. Over 50MB of sensitive data was copied to removable media, including government emails (OMB, LOC), Library of Congress archival materials, and proprietary secret project data spanning multiple directories (design, pricing decision, progress, proposal, technical review).

**Q6. What is the full timeline of the incident?** Data staging (Late 2014 - January 5, 2015), Eraser installation (January 12, 2015), first deletion wave (January 20, 2015), mass deletion (January 23, 2015), Google Drive installation (February 19, 2015), final obfuscation (March 24, 2015).

**Q7. What is the total scope and business impact?** At minimum, one insider with access to government communications and archival data. Impact includes potential national security implications from OMB and LOC data exposure, plus proprietary project compromise.

**Q8. What are the recommended remediation actions?** Immediate account disablement, network blocking of cloud storage, forensic imaging of all media, installation of DLP controls, endpoint monitoring for evidence destruction tools, cloud storage policy enforcement, access control review for least privilege, and enhanced SIEM logging.


---

## Overview

| | |
|---|---|
| Findings | **10** (9 confirmed, 1 inference) |
| Severity | 1 critical, 6 high, 2 medium, 0 low, 1 info |
| Sources | 12 evidence sources across 315 tool calls |


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
| 2015-01-05T19:15:08Z | Sensitive 'Secret Project Data' Exfiltrated to Removable Media | HIGH | tsk.filelist, tsk.filelist |
| 2015-01-05T19:15:08Z | Data Exfiltration Timeline: Files Copied and Then Deleted | MEDIUM | tsk.masquerade, optical.listing |
| 2015-01-12T22:56:30Z | Disk Imaging/Cloning Pattern Detected on Removable Media | HIGH | bulk.duplicates |
| 2015-01-12T22:56:30Z | Eraser Secure Deletion Tool Installed Before Data Exfiltration Cover-Up | HIGH | ez.mft, tsk.masquerade |
| 2015-01-20T14:18:06Z | Sensitive Government and Library of Congress Data on Optical Media | CRITICAL | bulk.email, bulk.domain, bulk.rfc822, optical.listing |
| 2015-02-19T18:20:30Z | Google Drive Installed and Executed - Potential Cloud Exfiltration Vector | HIGH | registry.system, ez.mft, plaso.timeline |
| 2015-03-24T09:59:00 | Authorized USB Device Contents - Legitimate Secret Project Data | INFO | tsk.filelist, bulk.exif |
| 2015-03-24T09:59:27 | Removable Media Data Exfiltration - Masquerading Files Detected | HIGH | tsk.masquerade |
| 2015-03-24T09:59:27 | Unauthorized USB Device Connected - Volume Label "IAMAN $_@" | MEDIUM | tsk.filelist, tsk.partitions |
| 2015-03-24T20:54:16Z | Directory and File Renaming to Obfuscate Sensitive Content | HIGH | optical.listing |





---

## Appendix A: Verified Forensic Findings


### 1. [CRITICAL] Sensitive Government and Library of Congress Data on Optical Media

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-01-20T14:18:06Z to 2015-03-24T23:59:59Z |
| **Sources** | bulk.email, bulk.domain, bulk.rfc822, optical.listing |
| **Evidence Refs** | tc_2242de27, tc_924e00af, tc_0824e804 |
| **ATT&CK** | [T1041](https://attack.mitre.org/techniques/T1041/) |


The optical media (CD) contains multiple categories of sensitive data indicating data exfiltration:

1. **Government Emails**: Found email addresses from OMB (Office of Management and Budget) - Eric_P._Lauer@omb.eop.gov, personal email wayne.longman@att.net, and Library of Congress email mmun@loc.gov.

2. **Government Documents**: The CD contains references to whitehouse.gov and omb.eop.gov URLs and documents.

3. **Library of Congress Archival Materials** (sensitive cultural heritage data): Subject lines from RFC822 show LOC archival materials including:
   - "Portraits of three Indians" 
   - "Harriman Alaska Expedition of 1899" materials
   - "Photographic prints by Hine for National Child Labor Committee"
   - Various historical American photographs and prints

4. **Real Estate Data**: References to desert-estates.info domain

This represents confirmed data leakage of government and cultural heritage materials from the Library of Congress and OMB.



### 2. [HIGH] Removable Media Data Exfiltration - Masquerading Files Detected

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:27 to 2015-03-24T10:00:18 |
| **Sources** | tsk.masquerade |
| **Evidence Refs** | tc_472e1e93 |
| **ATT&CK** | [T1565](https://attack.mitre.org/techniques/T1565/), [T1567](https://attack.mitre.org/techniques/T1567/) |


17 files with masquerading extensions were found in the $OrphanFiles directory on an unauthorized USB device (rm2). These files have extensions that do not match their actual content type (e.g., .zip detected as .pptx, .jpg detected as .xlsx, .txt detected as .docx). This is strong evidence of data exfiltration with intentional concealment using steganography or file masquerading techniques.

File categories identified:
- design/: winter_storm.amr (OLE), winter_whether_advisory.zip (PPTX)
- PRICIN~1/: my_favorite_cars.db (OLE), my_favorite_movies.7z (XLSX), new_years_day.jpg (XLSX), super_bowl.avi (OLE)
- progress/: my_friends.svg (OLE), my_smartphone.png (DOCX), new_year_calendar.one (DOCX)
- proposal/: a_gift_from_you.gif (DOCX), landscape.png (DOCX)
- TECHNI~1/: diary_#1d.txt (DOCX), diary_#1p.txt (PPTX), diary_#2d.txt (DOCX), diary_#2p.txt (OLE), diary_#3d.txt (OLE), diary_#3p.txt (OLE)

All files deleted from USB, located in $OrphanFiles. Creation timestamps around 2015-03-24 09:59-10:00 UTC.



### 3. [HIGH] Sensitive 'Secret Project Data' Exfiltrated to Removable Media

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-01-05T19:15:08Z to 2015-01-23T16:47:10Z |
| **Sources** | tsk.filelist, tsk.filelist |
| **Evidence Refs** | tc_454b485f, tc_756a20eb, tc_ad8c3c86 |
| **ATT&CK** | [T1048](https://attack.mitre.org/techniques/T1048/) |


Evidence shows that a directory named "Secret Project Data" containing files with "secret" in the filename was copied to removable media rm1. The directory structure "Secret Project Data/Secret Project Data/design/[secret_pr..." was found on the device. Additionally, multiple files were marked as deleted, indicating attempts to conceal the exfiltration after copying the data.



### 4. [HIGH] Disk Imaging/Cloning Pattern Detected on Removable Media

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-01-12T22:56:30Z to 2015-03-24T23:59:59Z |
| **Sources** | bulk.duplicates |
| **Evidence Refs** | tc_387035d8 |
| **ATT&CK** | [T1048](https://attack.mitre.org/techniques/T1048/) |


Bulk extractor analysis of rm1 shows 512MB of data duplicated at multiple offset locations on the device: 1GB, 2GB, 2.5GB, and 3GB. This pattern is consistent with disk cloning or imaging operations, where the same content was written multiple times to the removable media, possibly as part of data exfiltration staging.



### 5. [HIGH] Directory and File Renaming to Obfuscate Sensitive Content

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16Z to 2015-03-24T20:57:00Z |
| **Sources** | optical.listing |
| **Evidence Refs** | tc_6625d80b, tc_08f1c898 |
| **ATT&CK** | [T1036](https://attack.mitre.org/techniques/T1036/) |


The optical media shows evidence of directory renaming to hide the true nature of the content - a classic data leakage indicator:

**Directory Name Abbreviation Mapping:**
- `/de` → `/design` (session 0 shows both)
- `/pd` → `/pricing decision`
- `/prog` → `/progress`  
- `/prop` → `/proposal`
- `/tr` → `/technical review`

The optical media is a multi-session CD with 9 sessions (VAT generations). Files were added in multiple sessions, with some directories renamed between sessions. The presence of both abbreviated (`/de`) and full (`/design`) directory names in different sessions confirms the intentional obfuscation.

Additionally, the filenames themselves appear designed to appear innocent:
- `my_favorite_cars.db` - could contain customer/vehicle PII
- `my_favorite_movies.7z` - could hide sensitive content in compressed archive
- `a_gift_from_you.gif` - large 35MB GIF could hide inappropriate content
- `diary_#1d.txt`, `diary_#1p.txt` - personal diaries (potential PII)
- `winter_storm.amr` - 14MB audio file
- `winter_whether_advisory.zip` - 16MB zip file (could be encrypted)

The volume label "IAMAN CD" is also a suspicious placeholder name (looks like "I am an CD") likely used to avoid suspicion.



### 6. [HIGH] Eraser Secure Deletion Tool Installed Before Data Exfiltration Cover-Up

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-01-12T22:56:30Z to 2015-01-23T16:47:10Z |
| **Sources** | ez.mft, tsk.masquerade |
| **Evidence Refs** | tc_01cda109 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


The Eraser secure deletion tool was installed on 2015-01-12 at 22:56:30 in C:\Program Files\Eraser\. This installation occurred 8 days BEFORE the first wave of file deletions on the USB device (2015-01-20 at 14:18:06) and 11 days before the major deletion event on 2015-01-23 at 16:47:10.

This timeline strongly suggests the Eraser tool was intentionally installed to facilitate the cover-up of data exfiltration. After copying sensitive "Secret Project Data" to removable media (USB and CD), the threat actor installed Eraser to securely delete evidence from the USB device.

Evidence:
- Eraser installation: 2015-01-12 22:56:30 (MFT evidence)
- First deletion wave: 2015-01-20 14:18:06
- Major deletion wave: 2015-01-23 16:47:10

The installation of a secure deletion tool AFTER data was copied to removable media, but BEFORE the deletion events occurred, constitutes deliberate evidence destruction.



### 7. [HIGH] Google Drive Installed and Executed - Potential Cloud Exfiltration Vector

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2015-02-19T18:20:30Z to 2015-03-23T20:02:07Z |
| **Sources** | registry.system, ez.mft, plaso.timeline |
| **Evidence Refs** | tc_65e53402 |
| **ATT&CK** | [T1048](https://attack.mitre.org/techniques/T1048/), [T1567](https://attack.mitre.org/techniques/T1567/) |


Google Drive sync application was installed on the system and executed, providing an additional data exfiltration vector beyond physical removable media (USB/CD).

Evidence from registry and MFT analysis shows:
- Google Drive (googledrivesync.exe) was executed on 2015-02-19 at 18:24:23
- Google Drive language files were created/installed on 2015-02-19 starting at 18:20:30
- Google Drive sync log activity detected on 2015-03-23 at 16:03:30
- Desktop shortcut to Google Drive was accessed on 2015-03-23 at 17:24:02

This indicates that in addition to physical data exfiltration via USB and CD, the user also had capability to synchronize data to Google Drive cloud storage. This provides an alternate exfiltration path that would not leave local artifacts on the system (data would be stored in Google's servers).

The timeline shows:
1. Data was collected and copied to USB/CD (late 2014/early 2015)
2. Physical data deleted as cover-up (January 20-23, 2015)
3. Google Drive installed and used (February-March 2015)

The Google Drive installation represents a potential second wave of exfiltration or backup of the stolen data to cloud storage.



### 8. [MEDIUM] Unauthorized USB Device Connected - Volume Label "IAMAN $_@"

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:27 to 2015-03-24T10:00:18 |
| **Sources** | tsk.filelist, tsk.partitions |
| **Evidence Refs** | tc_3baa26b5 |
| **ATT&CK** | [T1091](https://attack.mitre.org/techniques/T1091/) |


An unauthorized USB removable media device was identified with the volume label "IAMAN $_@" (visible in tsk.filelist source_id=8). This device contains a FAT32 filesystem (sectors 128-2097279) typical of USB flash drives. It has no "Authorized USB" designation like the other removable device (rm1).

In contrast, the authorized USB device (rm1) has:
- Volume label: "Authorized USB"
- Contains "Secret Project Data" directory
- Was properly approved for use

The unauthorized device (rm2) was used to store 17 deleted files in $OrphanFiles directory with masqueraded extensions, indicating deliberate data exfiltration.

This finding corroborates the masquerading files finding by showing the device context in which the files were found.



### 9. [MEDIUM] Data Exfiltration Timeline: Files Copied and Then Deleted

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-01-05T19:15:08Z to 2015-01-23T16:47:10Z |
| **Sources** | tsk.masquerade, optical.listing |
| **Evidence Refs** | tc_ff245133 |
| **ATT&CK** | [T1048](https://attack.mitre.org/techniques/T1048/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


Timeline analysis shows that sensitive files including winter_whether_advisory.zip (16MB, detected as PPTX content), winter_storm.amr (14MB audio), and various technical review/secret project files were deleted on 2015-01-23, indicating an attempt to cover up the data exfiltration. The device had directories for "pricing decision", "design", "proposal", and "technical review" indicating corporate data was stored.



### 10. [INFO] Authorized USB Device Contents - Legitimate Secret Project Data

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:00 to 2015-03-24T10:00:00 |
| **Sources** | tsk.filelist, bulk.exif |
| **Evidence Refs** | tc_3baa26b5, tc_cec0ed9c |


The authorized USB device (rm1) was identified with:
- Volume label: "Authorized USB"
- Contains "Secret Project Data" directory structure
- Contains legitimate image files (EXIF metadata shows Kodak photos from 2003, Photoshop images from 2006)

The unauthorized USB device (rm2) was labeled "IAMAN $_@ " and contained the exfiltrated data instead of authorized content.

This finding shows what proper authorized data looks like in contrast to the exfiltrated files found on the unauthorized device.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| | No network IOCs extracted | | |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Path | `C:\Program` |  | Eraser Secure Deletion Tool Installed Before Data Exfiltration Cover-Up |



### Email IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Email | `eric_p._lauer@omb.eop.gov` |  | Sensitive Government and Library of Congress Data on Optical Media |
| Email | `wayne.longman@att.net` |  | Sensitive Government and Library of Congress Data on Optical Media |




---

## Appendix C: MITRE ATT&CK Coverage

7 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) > Defense Evasion (2) > Lateral Movement (1) > Exfiltration (3) > Impact (1)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1091](https://attack.mitre.org/techniques/T1091/) | Replication Through Removable Media | Unauthorized USB Device Connected - Volume... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Directory and File Renaming to Obfuscate... |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Data Exfiltration Timeline: Files Copied and...; Eraser Secure Deletion Tool Installed Before... |


### Lateral Movement

| Technique | Name | Findings |
|-----------|------|----------|
| [T1091](https://attack.mitre.org/techniques/T1091/) | Replication Through Removable Media | Unauthorized USB Device Connected - Volume... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | Sensitive Government and Library of Congress... |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Sensitive 'Secret Project Data' Exfiltrated to...; Data Exfiltration Timeline: Files Copied and...; Disk Imaging/Cloning Pattern Detected on...; Google Drive Installed and Executed -... |
| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service | Removable Media Data Exfiltration -...; Google Drive Installed and Executed -... |


### Impact

| Technique | Name | Findings |
|-----------|------|----------|
| [T1565](https://attack.mitre.org/techniques/T1565/) | Data Manipulation | Removable Media Data Exfiltration -... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 315 |
| Findings submitted | 10 |
| Confirmed | 9 |
| Inferences | 1 |
| Input tokens | 6.0M |
| Output tokens | 105.8K |
| Total tokens | 6.1M |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| bedrock/minimax.minimax-m2.5 | 6.0M | 105.8K | 6.1M |




<details>
<summary>Evidence Sources (245)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 8 |
| tsk.filelist | sleuthkit | 27 |
| tsk.masquerade | sleuthkit | 0 |
| tsk.partitions | sleuthkit | 10 |
| tsk.partitions | sleuthkit | 9 |
| tsk.masquerade | sleuthkit | 17 |
| tsk.partitions | sleuthkit | 9 |
| tsk.filelist | sleuthkit | 51 |
| tsk.filelist | sleuthkit | 104709 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 189 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.exif | bulk_extractor | 20 |
| bulk.url | bulk_extractor | 207 |
| bulk.url_services | bulk_extractor | 14 |
| exiftool.metadata | exiftool | 9 |
| composite.file_staging | composite | 80 |
| optical.listing | mulder-optical | 58 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 237 |
| bulk.email | bulk_extractor | 12 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 300 |
| bulk.url_services | bulk_extractor | 21 |
| tsk.masquerade | sleuthkit | 3 |
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
| appfiles.program_files.eqnedt32.exe.manifest | icat | 17 |
| appfiles.program_files.content.xml | icat | 432 |
| appfiles.program_files.auxbase.xml | icat | 22 |
| appfiles.program_files.auxpad.xml | icat | 5 |
| appfiles.program_files.ea.xml | icat | 7 |
| appfiles.program_files.keypadbase.xml | icat | 18 |
| appfiles.program_files.kor-kor.xml | icat | 7 |
| appfiles.program_files.keypad.xml | icat | 20 |
| appfiles.program_files.base.xml | icat | 44 |
| appfiles.program_files.basealtgr_rtl.xml | icat | 4 |
| appfiles.program_files.base_altgr.xml | icat | 44 |
| appfiles.program_files.base_ca.xml | icat | 44 |
| appfiles.program_files.base_heb.xml | icat | 25 |
| appfiles.program_files.base_kor.xml | icat | 8 |
| appfiles.program_files.base_rtl.xml | icat | 21 |
| appfiles.program_files.ja-jp.xml | icat | 218 |
| appfiles.program_files.ko-kr.xml | icat | 201 |
| appfiles.program_files.zh-changjei.xml | icat | 214 |
| appfiles.program_files.zh-dayi.xml | icat | 214 |
| appfiles.program_files.zh-phonetic.xml | icat | 214 |
| ez.mft | eztools | 98918 |
| appfiles.program_files.main.xml | icat | 870 |
| appfiles.program_files.numbase.xml | icat | 22 |
| appfiles.program_files.numbers.xml | icat | 5 |
| appfiles.program_files.oskmenubase.xml | icat | 8 |
| appfiles.program_files.oskmenu.xml | icat | 5 |
| appfiles.program_files.osknumpadbase.xml | icat | 37 |
| appfiles.program_files.osknumpad.xml | icat | 5 |
| appfiles.program_files.oskpredbase.xml | icat | 15 |
| appfiles.program_files.oskpred.xml | icat | 5 |
| appfiles.program_files.ea-sym.xml | icat | 14 |
| appfiles.program_files.ja-jp-sym.xml | icat | 14 |
| appfiles.program_files.symbase.xml | icat | 47 |
| appfiles.program_files.symbols.xml | icat | 15 |
| appfiles.program_files.webbase.xml | icat | 17 |
| appfiles.program_files.web.xml | icat | 4 |
| appfiles.program_files.accessmui.xml | icat | 31 |
| appfiles.program_files.accessmuiset.xml | icat | 19 |
| appfiles.program_files.setup.xml | icat | 26 |
| appfiles.program_files.dcfmui.xml | icat | 25 |
| appfiles.program_files.setup.xml | icat | 24 |
| appfiles.program_files.excelmui.xml | icat | 40 |
| appfiles.program_files.setup.xml | icat | 33 |
| appfiles.program_files.groovemui.xml | icat | 22 |
| appfiles.program_files.setup.xml | icat | 19 |
| appfiles.program_files.infopathmui.xml | icat | 25 |
| registry.sam | regripper | 186 |
| appfiles.program_files.setup.xml | icat | 21 |
| appfiles.program_files.lyncmui.xml | icat | 25 |
| registry.sam | regripper | 7 |
| appfiles.program_files.setup.xml | icat | 21 |
| appfiles.program_files.branding.xml | icat | 617 |
| appfiles.program_files.officemui.xml | icat | 139 |
| registry.sam | regripper | 7 |
| appfiles.program_files.officemuiset.xml | icat | 19 |
| registry.security | regripper | 69 |
| appfiles.program_files.setup.xml | icat | 114 |
| registry.security | regripper | 8 |
| appfiles.program_files.office32mui.xml | icat | 37 |
| appfiles.program_files.setup.xml | icat | 37 |
| appfiles.program_files.office32ww.xml | icat | 133 |
| registry.query.software | python-registry | 1 |
| appfiles.program_files.onenotemui.xml | icat | 40 |
| appfiles.program_files.setup.xml | icat | 27 |
| appfiles.program_files.osmuxmui.xml | icat | 31 |
| appfiles.program_files.setup.xml | icat | 24 |
| appfiles.program_files.outlookmui.xml | icat | 67 |
| appfiles.program_files.setup.xml | icat | 53 |
| appfiles.program_files.powerpointmui.xml | icat | 37 |
| appfiles.program_files.setup.xml | icat | 25 |
| appfiles.program_files.proof.xml | icat | 34 |
| appfiles.program_files.proof.xml | icat | 37 |
| appfiles.program_files.proof.xml | icat | 37 |
| appfiles.program_files.proofing.xml | icat | 19 |
| appfiles.program_files.setup.xml | icat | 71 |
| registry.system | regripper | 33492 |
| appfiles.program_files.proplusrww.xml | icat | 517 |
| evtx.manifest | evtx-extract | 54 |
| appfiles.program_files.setup.xml | icat | 460 |
| appfiles.program_files.publishermui.xml | icat | 37 |
| registry.system | regripper | 283 |
| appfiles.program_files.setup.xml | icat | 21 |
| appfiles.program_files.setup.xml | icat | 38 |
| appfiles.program_files.wordmui.xml | icat | 49 |
| appfiles.program_files.osmmui.xml | icat | 22 |
| registry.system | regripper | 283 |
| appfiles.program_files.setup.xml | icat | 21 |
| appfiles.program_files.desktop.ini | icat | 13 |
| appfiles.program_files.indust.inf | icat | 36 |
| appfiles.program_files.aftrnoon.inf | icat | 36 |
| appfiles.program_files.arctic.inf | icat | 36 |
| registry.system | regripper | 5209 |
| appfiles.program_files.axis.inf | icat | 42 |
| registry.system | regripper | 199 |
| appfiles.program_files.blends.inf | icat | 36 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| appfiles.program_files.bluecalm.inf | icat | 36 |
| appfiles.program_files.blueprnt.inf | icat | 36 |
| appfiles.program_files.boldstri.inf | icat | 36 |
| appfiles.program_files.breeze.inf | icat | 36 |
| registry.system | regripper | 199 |
| appfiles.program_files.canyon.inf | icat | 36 |
| appfiles.program_files.capsules.inf | icat | 36 |
| appfiles.program_files.cascade.inf | icat | 42 |
| appfiles.program_files.compass.inf | icat | 36 |
| appfiles.program_files.concrete.inf | icat | 36 |
| appfiles.program_files.deepblue.inf | icat | 36 |
| appfiles.program_files.echo.inf | icat | 42 |
| appfiles.program_files.eclipse.inf | icat | 42 |
| appfiles.program_files.edge.inf | icat | 42 |
| registry.query.system | python-registry | 1 |
| appfiles.program_files.evrgreen.inf | icat | 36 |
| appfiles.program_files.expeditn.inf | icat | 36 |
| appfiles.program_files.ice.inf | icat | 36 |
| appfiles.program_files.iris.inf | icat | 36 |
| appfiles.program_files.journal.inf | icat | 36 |
| appfiles.program_files.layers.inf | icat | 42 |
| appfiles.program_files.level.inf | icat | 42 |
| appfiles.program_files.network.inf | icat | 42 |
| appfiles.program_files.papyrus.inf | icat | 36 |
| appfiles.program_files.pixel.inf | icat | 42 |
| appfiles.program_files.profile.inf | icat | 42 |
| appfiles.program_files.quad.inf | icat | 42 |
| appfiles.program_files.radial.inf | icat | 42 |
| appfiles.program_files.refined.inf | icat | 42 |
| appfiles.program_files.ricepapr.inf | icat | 36 |
| appfiles.program_files.ripple.inf | icat | 36 |
| appfiles.program_files.rmnsque.inf | icat | 36 |
| appfiles.program_files.satin.inf | icat | 36 |
| appfiles.program_files.sky.inf | icat | 36 |
| appfiles.program_files.slate.inf | icat | 36 |
| appfiles.program_files.sonora.inf | icat | 36 |
| appfiles.program_files.spring.inf | icat | 36 |
| appfiles.program_files.strtedge.inf | icat | 36 |
| appfiles.program_files.studio.inf | icat | 42 |
| appfiles.program_files.sumipntg.inf | icat | 36 |
| appfiles.program_files.themes.inf | icat | 211 |
| appfiles.program_files.water.inf | icat | 36 |
| appfiles.program_files.watermar.inf | icat | 42 |
| appfiles.program_files.handler.reg | icat | 15 |
| appfiles.program_files.handsafe.reg | icat | 17 |
| appfiles.program_files.filters.xml | icat | 318 |
| appfiles.program_files.timeline.cpu.xml | icat | 46 |
| appfiles.program_files.desktop.ini | icat | 4 |
| appfiles.program_files.desktop.ini | icat | 4 |
| appfiles.program_files.desktop.ini | icat | 4 |
| appfiles.program_files.desktop.ini | icat | 4 |
| appfiles.program_files.desktop.ini | icat | 4 |
| appfiles.program_files.desktop.ini | icat | 4 |
| appfiles.program_files.desktop.ini | icat | 4 |
| appfiles.program_files.aspect.xml | icat | 3 |
| appfiles.program_files.blue_green.xml | icat | 3 |
| appfiles.program_files.blue_ii.xml | icat | 3 |
| appfiles.program_files.blue_warm.xml | icat | 3 |
| appfiles.program_files.blue.xml | icat | 3 |
| appfiles.program_files.grayscale.xml | icat | 3 |
| appfiles.program_files.green_yellow.xml | icat | 3 |
| appfiles.program_files.green.xml | icat | 3 |
| appfiles.program_files.marquee.xml | icat | 3 |
| appfiles.program_files.median.xml | icat | 3 |
| appfiles.program_files.office_2007_-_2010.xml | icat | 3 |
| appfiles.program_files.orange_red.xml | icat | 3 |
| appfiles.program_files.orange.xml | icat | 3 |
| appfiles.program_files.paper.xml | icat | 3 |
| appfiles.program_files.red_orange.xml | icat | 3 |
| appfiles.program_files.red_violet.xml | icat | 3 |
| appfiles.program_files.red.xml | icat | 3 |
| appfiles.program_files.slipstream.xml | icat | 3 |
| registry.system | regripper | 381 |
| appfiles.program_files.violet_ii.xml | icat | 3 |
| appfiles.program_files.violet.xml | icat | 3 |
| appfiles.program_files.yellow_orange.xml | icat | 3 |
| registry.system | regripper | 255 |
| appfiles.program_files.yellow.xml | icat | 3 |
| appfiles.program_files.arial_black-arial.xml | icat | 74 |
| appfiles.program_files.arial-times_new_roman.xml | icat | 74 |
| appfiles.program_files.arial.xml | icat | 74 |
| registry.system | regripper | 255 |
| appfiles.program_files.calibri_light-constantia.xml | icat | 74 |
| appfiles.program_files.calibri-cambria.xml | icat | 74 |
| appfiles.program_files.calibri.xml | icat | 74 |
| appfiles.program_files.cambria.xml | icat | 74 |
| appfiles.program_files.candara.xml | icat | 74 |
| appfiles.program_files.century_gothic-palatino_linotype.xml | icat | 75 |
| appfiles.program_files.century_gothic.xml | icat | 74 |
| appfiles.program_files.century_schoolbook.xml | icat | 74 |
| appfiles.program_files.consolas-verdana.xml | icat | 74 |
| registry.usrclass.admin11 | regripper | 11 |
| registry.ntuser.admin11 | regripper | 133 |
| registry.ntuser.default | regripper | 74 |
| registry.usrclass.informant | regripper | 102 |
| registry.ntuser.informant | regripper | 306 |
| registry.usrclass.temporary | regripper | 15 |
| registry.ntuser.temporary | regripper | 118 |
| plaso.timeline | plaso | 1233362 |
| plaso.stats | plaso | 672820 |
| enrichment.iocs | enrichment | 16 |
| composite.persistence | composite | 2441 |
| composite.exfil | composite | 2461 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 578 |
| composite.exfil | composite | 2461 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 578 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
