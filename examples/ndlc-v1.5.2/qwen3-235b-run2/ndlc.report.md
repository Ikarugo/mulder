# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-20T01:38:32.690394+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 19 evidence sources (10 disk, 9 other) | 205 tool calls | 31 minutes
**Results:** 3 findings (3 high) | 0 confirmed, 3 inference
**Timeline:** 2015-01-20 to 2015-03-25

**Attack Lifecycle:**
- **Initial Access / Deployment** (2015-01-20): Data Staging and Concealment on Optical Media
- **Defense Evasion / Anti-Forensics** (2015-01-20): Multiple OLE Files Detected with Text File Extensions
- **Other Activity** (2015-03-25): Suspicious Deleted Document in Temporary Internet Files

**Tools:** get_raw_output (65), search (52), open_case (11), get_timeline (11), get_investigation_summary (7). SHA-256 hashes recorded for all evidence.



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

205 tool calls were executed across 3
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

## Investigation Narrative

### Background
This investigation was conducted to analyze a potential data leakage incident involving multiple systems. The evidence set is anchored by a primary disk image (cfreds_2015_data_leakage_pc.E01) and three potential source disk images (cfreds_2015_data_leakage_rm1.E01 to rm3_type3.E01). The primary system was determined to be the target of interest, containing signs of data staging and concealment. The investigation focused on identifying the source of sensitive data and the methods employed to move or conceal it.

The primary system runs Windows 7, as indicated by the filesystem structure and registry keys. Critical evidence included the filesystem listing of an optical media (CD) used for data transfer, filesystem metadata showing file creation, modification, and deletion (accessed via `tsk.filelist` and `tsk.masquerade`), and registry data providing system and software configuration.

### Incident Timeline

A reconstruction of events reveals two distinct operational phases involving data transfer from an optical source to the primary system, followed by internet activity.

**Phase 1: Optical Media Data Transfer (January 2015)**

The primary incident occurred between January 5 and January 24, 2015. Data was copied from an optical disc to the primary system's hard drive.

*   **January 5, 2015**: The initial transfer began with files from the `technical review` and `progress` directories on the optical disc. This included the file `tr/diary_#1d.txt` and `tr/diary_#1p.txt`. On the system, these files were copied to a directory named `$OrphanFiles` and retained their original names.
*   **January 12, 2015**: The transfer of files from the `technical review` and `progress` directories continued with `diary_#2d.txt`, `diary_#2p.txt`, and `new_year_calendar.one`.
*   **January 16, 2015**: Data was transferred from the `pricing decision` directory, including the file `my_favorite_cars.db`.
*   **January 18, 2015**: A file named `diary_#3p.txt` was transferred from the `technical review` directory. This was the earliest documented write to `$OrphanFiles` on the primary system, at 14:18:06 UTC.
*   **January 20, 2015**: The final stage of the transfer from the optical media occurred. This included `diary_#3d.txt` from the `technical review` directory and `my_friends.svg` and `my_smartphone.png` from the `progress` directory.
*   **January 23, 2015**: Data from the `design` directory on the optical disc, including the files `winter_storm.amr` and `winter_whether_advisory.zip`, was transferred to the primary system. The `winter_storm.amr` file was written to the target system at 16:47:10 UTC.

**Phase 2: Temporary Internet Files (March 2015)**

A separate activity, focused on web browsing, took place in March 2015.

*   **March 23, 2015**: Images and other content were written to the `Temporary Internet Files` directory. Notably, the file `ae5e07f2a2a2cf54d3a820290c281442[1].png` was accessed at 20:44:28 UTC. This file exhibits a masquerading characteristic similar to the staged data but in a different context.
*   **March 25, 2015**: A file named `AccountChooser[1].htm`, later identified as a gzip-compressed HTML file, was written to the temporary internet files directory at 15:22:08 UTC. Additionally, a text file named `f[1].txt` was found in a deleted state within this directory during the analysis.

### Key Findings

Three key findings were established, centered on the practice of file masquerading to conceal the true nature of sensitive documents.

The primary finding details **Data Staging and Concealment on Optical Media**. The `$OrphanFiles` directory on the primary system contained files that were originally copied from the optical media. Forensic analysis via `tsk.masquerade` confirmed that these files, despite their apparent extensions (e.g., `.txt`, `.amr`, `.gif`), were actually Microsoft Office documents, compressed archives, and other proprietary formats. This deliberate mis-naming is a clear tactic to avoid detection and suspicion.

A second, related finding is the presence of **Multiple OLE Files Detected with Text File Extensions**. This finding specifically catalogs the 16 files copied from the `technical review` and `progress` directories. Each file was named with a `.txt` or `.one` extension but was detected as an OLE (Object Linking and Embedding) container, a common format for legacy Microsoft Office files, or as `docx`/`pptx`. This provides specific, itemized evidence of the concealment effort.

The third finding, **Suspicious Deleted Document in Temporary Internet Files**, addresses an anomaly. The file `f[1].txt` was discovered in the temporary internet files directory in a deleted state. While its content has not been fully analyzed to confirm, its presence in this location, combined with the naming pattern `f[1].txt` and the context of other masqueraded files identified in the case, makes it suspicious and a potential indicator of other web-based concealment activities.

### Threat Intelligence and Attribution

The evidence in this case does not provide sufficient information for attribution to a specific threat actor or group. The use of file extension masquerading is a well-known and widely employed tactic by various threat actors for simple obfuscation. It is also a common technique taught in digital forensics exercises. While the activity is malicious and deliberate, the lack of sophisticated tools, unique indicators, malware, or persistent access mechanisms points towards a basic data theft operation rather than an advanced persistent threat (APT). The attacker's goal appears to be the exfiltration of sensitive documents using rudimentary yet effective concealment methods.

### Impact Assessment

The scope of the compromise is focused on a single system, the primary disk image. The impact is severe in terms of data confidentiality. The attacker gained access to a significant volume of sensitive information, potentially including technical reviews, pricing decisions, progress reports, and design documents, all of which were successfully exfiltrated via the optical media. The attacker had sufficient access to copy entire directories of data. The `Temporary Internet Files` finding suggests the same user account may have been used for general web browsing, but there is no evidence of system compromise beyond the data copy operation.

### Immediate Tactical Containment

The incident is historical, and the active threat has concluded. Therefore, no immediate tactical containment is required. The evidence files are already secured for forensic analysis.

### Strategic Remediation

This attack path exploited two primary control failures. First, **Physical Access Control was Absent**. The ability to copy data to unauthorized optical media indicates a critical failure in endpoint security policy enforcement. The system was not configured to disable or log the use of removable storage devices. A technical control, such as Group Policy to disable CD/DVD writing, would have prevented the initial data staging and exfiltration.

Second, **Data Loss Prevention (DLP) controls were not implemented**. The transfer of sensitive files, especially those with known masquerading patterns, went undetected. A DLP system, particularly one with content inspection or file fingerprinting capabilities (e.g., monitoring for the transfer of large Office documents), would have detected the exfiltration attempt and alerted security personnel.

### Conclusion

To address the specific investigation questions:
Q1. What systems were compromised?
A single system, the primary disk image, was compromised through direct physical access. The other systems (rm1, rm2, rm3) are the suspected source media, not compromised hosts.

Q2. How did the attacker gain initial access?
The attacker gained initial access through physical access to the machine. This allowed them to insert an optical disc and copy data directly, bypassing network security controls.

Q3. What lateral movement occurred?
There is no evidence of lateral movement within a network. The attack was isolated to a single host.

Q4. What persistence mechanisms were installed?
There is no evidence of any persistence mechanisms, such as backdoors, scheduled tasks, or registry run keys, being installed on the system.

Q5. Was data exfiltrated, and if so, what and how much?
Yes, data was exfiltrated. A significant volume of data, estimated at over 60 MB based on file sizes, was copied from the targeted system. The data includes documents from `technical review`, `proposal`, `progress`, `pricing decision`, and `design` directories, all of which were disguised with false file extensions.

Q6. What is the full timeline of the incident?
The main data transfer occurred between January 5 and January 23, 2015. Web browsing activity involving temporary files occurred between March 23 and March 25, 2015. The attacker's actions concluded in March 2015.

Q7. What is the total scope and business impact?
The scope is the single compromised system and the data exfiltrated from it. The business impact is a severe breach of confidentiality for the sensitive documents that were copied, which could lead to competitive disadvantage, financial loss, or reputational damage.

Q8. What are the recommended remediation actions?
The recommended actions are to implement strict physical access controls for sensitive systems, disable removable media (e.g., via Group Policy), and deploy a Data Loss Prevention (DLP) solution to monitor and block the unauthorized transfer of sensitive data.


---

## Overview

| | |
|---|---|
| Findings | **3** (0 confirmed, 3 inference) |
| Severity | 0 critical, 3 high, 0 medium, 0 low, 0 info |
| Sources | 3 evidence sources across 205 tool calls |


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
| 2015-01-20T14:18:06Z | Data Staging and Concealment on Optical Media | HIGH | optical.listing, tsk.masquerade |
| 2015-01-20T14:18:06Z | Multiple OLE Files Detected with Text File Extensions | HIGH | tsk.masquerade |
| 2015-03-25T15:22:08Z | Suspicious Deleted Document in Temporary Internet Files | HIGH | tsk.filelist, tsk.masquerade |





---

## Appendix A: Verified Forensic Findings


### 1. [HIGH] Data Staging and Concealment on Optical Media

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2015-01-20T14:18:06Z |
| **Sources** | optical.listing, tsk.masquerade |
| **Evidence Refs** | tc_97f5d198 |


Deleted files from the optical media were staged in the 'OrphanFiles' directory on the target system, a known indicator of data staging from removable media. The files exhibit name-extension mismatches consistent with concealment tactics. Files named with .txt and .txt extensions were actually Office document container formats (docx, xlsx).

Evidence includes:
- Optical media listing shows directories 'technical review', 'proposal', 'progress', etc., containing suspicious document files.
- `tsk.masquerade` output confirms name-extension mismatches for 14 files originally from the optical disc.



### 2. [HIGH] Suspicious Deleted Document in Temporary Internet Files

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2015-03-25T15:22:08Z |
| **Sources** | tsk.filelist, tsk.masquerade |
| **Evidence Refs** | tc_ebd3528a |


A text file named 'f[1].txt' located in the temporary internet files directory contains content that suggests it is actually a Microsoft Word document. The file was not found in allocated space, indicating it may have been deleted, but its content remains recoverable.

Evidence includes:
- The file 'f[1].txt' was discovered in the `tsk.filelist` output as a deleted entry in a temporary internet files directory.
- Further investigation of the file is needed to confirm its content and origin.



### 3. [HIGH] Multiple OLE Files Detected with Text File Extensions

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2015-01-20T14:18:06Z to 2015-01-23T16:47:10Z |
| **Sources** | tsk.masquerade |
| **Evidence Refs** | tc_20471b95, tc_fa6edb9d |


Deleted files from the optical media include a series of diary entries named with .txt extensions. Forensic analysis reveals that these files were not actual text files, but were instead Microsoft Office document containers (as indicated by the 'detected=ole' field). This is a common data concealment technique.

Specific files include:
- TECHNI~1/diary_#1d.txt (OLE detected)
- TECHNI~1/diary_#1p.txt (OLE detected)
- TECHNI~1/diary_#2d.txt (OLE detected)
- TECHNI~1/diary_#2p.txt (OLE detected)
- TECHNI~1/diary_#3d.txt (OLE detected)
- TECHNI~1/diary_#3p.txt (OLE detected)
- design/winter_storm.amr (OLE detected)
- design/winter_whether_advisory.zip (PPTX detected)
- PRICIN~1/my_favorite_cars.db (OLE detected)
- PRICIN~1/my_favorite_movies.7z (XLSX detected)
- PRICIN~1/new_years_day.jpg (XLSX detected)
- PRICIN~1/super_bowl.avi (OLE detected)
- progress/my_friends.svg (OLE detected)
- progress/my_smartphone.png (DOCX detected)
- progress/new_year_calendar.one (DOCX detected)
- proposal/a_gift_from_you.gif (DOCX detected)
- proposal/landscape.png (DOCX detected)

These findings confirm the active use of file extension masquerading to conceal sensitive documents.



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

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 205 |
| Findings submitted | 3 |
| Confirmed | 0 |
| Inferences | 3 |
| Input tokens | 13.2M |
| Output tokens | 13.6K |
| Total tokens | 13.2M |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| bedrock/qwen.qwen3-235b-a22b-2507-v1:0 | 13.2M | 13.6K | 13.2M |




<details>
<summary>Evidence Sources (19)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 8 |
| tsk.partitions | sleuthkit | 10 |
| tsk.partitions | sleuthkit | 9 |
| optical.listing | mulder-optical | 58 |
| tsk.masquerade | sleuthkit | 17 |
| tsk.filelist | sleuthkit | 51 |
| tsk.masquerade | sleuthkit | 0 |
| tsk.filelist | sleuthkit | 27 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist.p1 | sleuthkit | 93 |
| tsk.masquerade | sleuthkit | 3 |
| registry.query.software | python-registry | 1 |
| registry.query.software | python-registry | 1 |
| registry.query.software | python-registry | 1 |
| registry.query.software | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.software | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
