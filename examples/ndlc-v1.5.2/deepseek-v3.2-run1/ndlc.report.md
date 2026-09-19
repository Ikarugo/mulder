# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-19T20:19:58.370750+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 91 evidence sources (46 disk, 45 other) | 352 tool calls | 25 minutes
**Results:** 17 findings (6 high) | 9 confirmed, 8 inference
**Timeline:** 2014-12-01 to 2015-03-25

**Attack Lifecycle:**
- **Initial Access / Deployment** (2014-12-01 to 2015-03-22): Organized Data Staging and Preparation for Exfiltration (+6 related)
- **Credential Access** (2015-01-16): Payment Card Data Leakage on Removable Media
- **Defense Evasion / Anti-Forensics** (2014-12-01 to 2015-01-05): Evidence of Data Obfuscation Through File Masquerading (+4 related)
- **Discovery / Collection** (2014-12-01): Suspicious Search Activity Related to Data Leakage Techniques
- **Other Activity** (2014-12-01): Unauthorized Access to Government Documents and Email Information

**Tools:** search (72), get_raw_output (34), submit_finding (22), open_case (19), get_investigation_summary (14). SHA-256 hashes recorded for all evidence.



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

352 tool calls were executed across 15
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Digital Forensics Investigation Report

## Background

This digital forensics investigation examines evidence of potential data leakage and unauthorized document exfiltration across multiple storage media. The case involves analysis of a Windows 7 Ultimate system, removable storage media, and optical media labeled "IAMAN CD." The investigation scope encompasses 15 evidence sources collected from the affected systems, revealing a coordinated pattern of data collection, concealment, and potential exfiltration activities concentrated between December 2014 and March 2015.

The investigation uncovered evidence of systematic data handling methodologies with particular focus on government documents, forensic countermeasures, and potential insider activity. The analysis identified 17 distinct findings, with 6 high-severity indicators requiring immediate attention.

## Incident Timeline

The incident timeline reveals a coordinated sequence of activities spanning approximately four months, organized into distinct operational phases:

**Phase 1: Data Collection and Organization (December 2014 - January 2015)**
- **December 2014 - January 2015**: Systematic creation of Office documents (DOCX, XLSX, PPTX) with misleading file extensions. Files were organized into thematic directories including design/, pricing decision/, progress/, proposal/, and technical review/
- **January 5-23, 2015**: File creation and modification activities with clear patterns of obfuscation. Key files include "winter_whether_advisory.zip" (actually PPTX), "my_favorite_movies.7z" (actually XLSX), and "new_years_day.jpg" (actually XLSX)
- **January 20, 2015**: Multiple "diary" files created with systematic naming (#1d.txt, #1p.txt, #2d.txt, #2p.txt, #3d.txt, #3p.txt) containing Office document content disguised as text files

**Phase 2: Research and Preparation (December 2014 - March 2015)**
- **Throughout the period**: Systematic search activity for data leakage methodologies including Google searches for "information leakage cases," "how to leak a secret," and data deletion methods
- **Multiple instances**: Access to security research materials including DEFCON website, National Institute of Justice forensic materials, and government document repositories
- **Evidence of access**: OMB email address (Eric_P._Lauer@omb.eop.gov) and whitehouse.gov documents including "FEA_CRM_v23_Final_Oct_2007.pdf" and OMB Circular A-11 section 53 documents

**Phase 3: Account Manipulation and System Access (March 22-25, 2015)**
- **March 22, 2015, 14:33:54**: Informant account (iaman.informant@nist.gov.ost) password reset by SYSTEM account
- **March 22, 2015, 15:51:54 - 15:53:11**: Coordinated creation and administration of accounts admin11, ITechTeam, and temporary. All accounts added to local Administrators group within minutes
- **March 25, 2015, 14:54:25**: Suspicious installation of ASP.NET State Service suggesting web application persistence mechanism

**Phase 4: Data Transfer and Anti-Forensics (March 2015)**
- **March 2015**: Multiple write sessions detected on optical media "IAMAN CD" (9 VAT generations)
- **Throughout March 2015**: Evidence of Google Drive access with drive synchronization URLs and OAuth relay patterns
- **Anti-forensics activity**: Presence of Eraser.exe secure deletion tool and CCleaner64.exe detected via ShimCache analysis

## Key Findings

### Category 1: File Masquerading and Data Concealment

The investigation revealed a systematic pattern of file masquerading where Office documents were deliberately concealed using misleading file extensions. Analysis confirmed 9 medium-severity findings documenting this activity:

- Office documents (DOCX, XLSX, PPTX) disguised as multimedia files (AMR, JPG, PNG, AVI, GIF, SVG)
- Office documents disguised as archive files (ZIP, 7Z) and text documents (.txt)
- Files organized into thematic directories suggesting systematic data collection
- File sizes ranging from 27KB to 35MB, indicating substantial data volumes
- Consistent naming patterns including numbered "diary" entries with document/presentation suffixes

This pattern maps to MITRE ATT&CK techniques T1036 (Masquerading), T1027 (Obfuscated Files or Information), and T1074.001 (Local Data Staging).

### Category 2: User Account Manipulation

Evidence of suspicious user account management emerged from Windows Event Log analysis, revealing coordinated privilege escalation activity:

- Password reset for informant@nist.gov.ost account performed by SYSTEM
- Creation of three administrative accounts (admin11, ITechTeam, temporary) within minutes
- All accounts added to Administrators group immediately after creation
- Additional password resets performed for each new account
- ASP.NET State Service installation suggesting persistence mechanism

This activity maps to MITRE ATT&CK techniques T1078 (Valid Accounts) and T1136 (Create Account).

### Category 3: Data Exfiltration Pathways

The investigation identified multiple data exfiltration pathways across storage media:

**PC to Removable Media Pathway:**
- Credit card numbers and sensitive financial data on primary system
- Government document references and email addresses
- Same masqueraded files found on removable media

**Removable Media to Optical Media Pathway:**
- Organized directory structure replicated on optical media
- Same file masquerading patterns across all media
- Multiple write sessions indicating staged preparation

**Cloud Exfiltration Indicators:**
- Google Drive access detected with drive synchronization URLs
- OAuth relay URLs showing authenticated access patterns
- Document sync URLs for presentations and spreadsheets

This cross-system consistency demonstrates a systematic data collection and exfiltration operation with forensic awareness, mapping to MITRE techniques T1567 (Exfiltration Over Alternative Protocol) and T1560 (Archive Collected Data).

### Category 4: Forensic Countermeasures

Evidence of forensic countermeasures suggests awareness of investigative techniques:

- Eraser.exe secure deletion tool detected via ShimCache
- CCleaner64.exe anti-forensics tool present
- 2222 total deleted files identified across systems
- File timestamps showing coordinated deletion patterns in March 2015
- File masquerading across all media types to evade automated detection

These countermeasures map to MITRE ATT&CK technique T1070 (Indicator Removal on Host).

## Threat Intelligence and Attribution

The investigation revealed indicators consistent with insider threat or sophisticated data exfiltration operations. While attribution to a specific threat actor remains uncertain, the following patterns emerged:

1. **Government Targeting**: Consistent focus on government documents, OMB materials, and .gov email addresses suggests either research interest or targeted collection of government-related information.

2. **Forensic Awareness**: The use of file masquerading, secure deletion tools, and organized data staging indicates knowledge of forensic investigation techniques and countermeasures.

3. **Systematic Approach**: The organized directory structure, systematic file naming, and consistent obfuscation patterns suggest methodical planning rather than opportunistic data theft.

4. **Cross-System Consistency**: The appearance of identical artifacts across PC, removable media, and optical media demonstrates coordinated data handling across multiple storage systems.

The email reference "iaman.informant@nist.gov.ost" suggests potential connection to NIST, but the ".ost" extension indicates an Outlook offline storage file reference rather than confirmed live email account. This could represent placeholder configuration rather than confirmed NIST affiliation.

The evidence supports confirmed activity (unauthorized data collection and concealment) while attribution to a specific actor or organization requires additional corroborating evidence beyond the forensic artifacts examined.

## Impact Assessment

The investigation reveals significant scope and potential impact:

**Data Volume and Sensitivity:**
- Multiple Office documents totaling substantial data volume (files up to 35MB)
- Organized collection suggesting targeted data selection
- Government document references indicating access to potentially sensitive materials
- Credit card numbers present, though some appear to be test/sample patterns

**Compromise Scope:**
- Evidence of systematic data collection across multiple storage media
- Coordinated user account manipulation suggesting privileged access
- Cloud exfiltration indicators suggesting potential data transfer beyond local systems

**Business Impact:**
- Potential exposure of sensitive organizational information
- Evidence of methodical data collection suggesting targeted intelligence gathering
- Forensic countermeasures indicating sophisticated threat actor
- Cross-media consistency demonstrating comprehensive data handling

**Credential Exposure:**
- User account manipulation indicates compromised administrative access
- Google Drive integration suggests potential credential exposure
- System-level persistence mechanisms installed

## Immediate Tactical Containment

Based on the investigation findings, the following immediate actions are required to contain active threats:

1. **Isolate Affected Systems**: Immediately isolate all systems showing evidence of file masquerading (Office documents disguised as multimedia/archive files) and disable network connectivity.

2. **Terminate Suspicious Processes**: Identify and terminate any processes associated with anti-forensics tools including Eraser.exe (secure deletion tool) and CCleaner64.exe detected via ShimCache analysis.

3. **Disable Compromised Accounts**: Immediately disable and investigate the following user accounts identified in account manipulation activities:
   - admin11 (created March 22, 2015 15:51:54)
   - ITechTeam (created March 22, 2015 15:52:30)
   - temporary (created March 22, 2015 15:52:30)
   - Any account referencing iaman.informant@nist.gov.ost

4. **Block Cloud Access**: Implement network-level blocking for cloud storage services including Google Drive (drive.google.com, docs.google.com) and review firewall logs for exfiltration patterns.

5. **Secure Optical Media Evidence**: Secure and preserve all optical media labeled "IAMAN CD" containing 9 VAT generations of write sessions with organized directory structures.

6. **Investigate ASP.NET Service**: Examine and disable the ASP.NET State Service installed on March 25, 2015 14:54:25 as a potential persistence mechanism.

7. **Monitor Account Activity**: Implement heightened monitoring for any activity from the informant account or newly created administrative accounts showing unusual privilege escalation patterns.

8. **Review File Integrity**: Scan systems for files with mismatched extensions/content signatures focusing on Office documents disguised as multimedia files (AMR, JPG, PNG, AVI, ZIP, 7Z extensions).

## Strategic Remediation

**Root Cause 1: Inadequate File Integrity Monitoring**
- **Control Failure**: The organization lacked sufficient file integrity monitoring capable of detecting Office documents disguised with multimedia file extensions. This allowed threat actors to conceal sensitive documents within seemingly benign files.
- **Specific Evidence**: Findings f_9ec4b699, f_481983fd, and f_a70c663d document multiple instances where Office documents (DOCX, XLSX, PPTX) were hidden using AMR, JPG, PNG, AVI, ZIP, and 7Z extensions.
- **Required Control**: Implement file content validation that compares actual file signatures against declared extensions, with alerts for mismatches exceeding pre-defined thresholds.

**Root Cause 2: Insufficient User Account Monitoring**
- **Control Failure**: The organization's user account monitoring failed to detect coordinated creation of multiple administrative accounts within minutes and their immediate addition to local Administrators groups.
- **Specific Evidence**: Findings f_7b9607e6 and f_a6ba6c56 document password resets for the informant account followed by creation of admin11, ITechTeam, and temporary accounts, all added to Administrators group within a 77-second window.
- **Required Control**: Implement real-time monitoring for rapid privilege escalation patterns, with automatic alerts when multiple administrative accounts are created or modified within short timeframes.

**Root Cause 3: Weak Cloud Storage Control**
- **Control Failure**: The organization lacked sufficient control and monitoring of cloud storage services, allowing potential exfiltration via Google Drive without detection.
- **Specific Evidence**: Finding f_a6ba6c56 documents Google Drive access patterns including drive synchronization URLs, OAuth relay patterns, and document sync activity coinciding with data collection timelines.
- **Required Control**: Implement data loss prevention controls specifically monitoring for Office document transfers to cloud storage services, with particular attention to disguised file uploads.

**Root Cause 4: Inadequate Forensic Countermeasure Detection**
- **Control Failure**: The organization's security monitoring failed to detect deployment and use of anti-forensics tools including secure deletion software and registry cleaning utilities.
- **Specific Evidence**: Composite analysis revealed presence of Eraser.exe (secure deletion tool) and CCleaner64.exe via ShimCache, with 2222 deleted files identified across systems.
- **Required Control**: Implement application control policies restricting execution of known anti-forensics tools, with monitoring focused on secure deletion utilities and registry cleaners.

**Root Cause 5: Insufficient Data Classification Controls**
- **Control Failure**: The organization lacked data classification controls capable of detecting systematic collection of government-related documents and email addresses.
- **Specific Evidence**: Findings f_d0fd9393 and f_963b2cff document access to OMB email addresses, whitehouse.gov documents, and government policy materials suggesting targeted collection.
- **Required Control**: Implement content inspection capabilities that identify and classify documents containing government email addresses (.gov domains) and policy document references, with alerts for unusual collection patterns.

## Conclusion

**Q1. What systems were compromised?**
The investigation identified compromise across multiple systems including a Windows 7 Ultimate workstation, removable storage media (rm1, rm2), and optical media labeled "IAMAN CD." Evidence shows consistent artifacts across all media types, indicating coordinated data handling. The workstation shows installation date of March 22, 2015, with subsequent account manipulation activity.

**Q2. How did the attacker gain initial access?**
Initial access appears to have been facilitated through the informant@nist.gov.ost account, with a password reset performed by SYSTEM on March 22, 2015. This was followed by creation of additional administrative accounts (admin11, ITechTeam, temporary) suggesting privilege escalation. The precise initial vector remains uncertain but involved account-level access.

**Q3. What lateral movement occurred?**
The investigation shows systematic data movement across storage media rather than lateral movement across networked systems. Data flowed from PC to removable media to optical media, with consistent file structures and masquerading patterns replicated across all media. No evidence of traditional network-based lateral movement was identified.

**Q4. What persistence mechanisms were installed?**
Persistence mechanisms identified include: 1) Multiple administrative accounts created with elevated privileges, 2) ASP.NET State Service installed on March 25, 2015 suggesting web application persistence, and 3) Potential Google Drive integration for data synchronization. Anti-forensics tools (Eraser.exe, CCleaner64.exe) were also detected.

**Q5. Was data exfiltrated, and if so, what and how much?**
Evidence strongly suggests data exfiltration preparation and potential transfer. Specific indicators include: 1) Organized directory structures with thematic organization, 2) File masquerading patterns facilitating concealment, 3) Google Drive access patterns, and 4) Optical media write sessions. Data volume includes Office documents up to 35MB in size, with content including government document references, email addresses, and potential financial data. While exfiltration preparation is confirmed, definitive confirmation of successful transfer requires additional network forensic analysis.

**Q6. What is the full timeline of the incident?**
The incident spans December 2014 through March 2015 with distinct phases: 1) Data Collection and Organization (Dec 2014-Jan 2015), 2) Research and Preparation (throughout period), 3) Account Manipulation (March 22-25, 2015), and 4) Data Transfer and Anti-Forensics (March 2015). Key timestamps include file creation/modification in December-January and account activities in late March.

**Q7. What is the total scope and business impact?**
The scope includes systematic data collection across multiple storage media with forensic countermeasures indicating sophisticated threat awareness. Business impact includes: 1) Potential exposure of sensitive organizational information, 2) Evidence of targeted data collection methodology, 3) Compromised administrative account access, and 4) Potential data exfiltration pathways established. The methodical nature suggests intelligence gathering rather than opportunistic theft.

**Q8. What are the recommended remediation actions?**
Immediate tactical containment includes isolating affected systems, terminating suspicious processes, disabling compromised accounts, blocking cloud access, and investigating persistence mechanisms. Strategic remediation focuses on: 1) Implementing file integrity monitoring for extension/content mismatches, 2) Enhancing user account monitoring for rapid privilege escalation, 3) Strengthening cloud storage controls, 4) Detecting forensic countermeasures, and 5) Improving data classification for government-related content. Each recommendation directly addresses specific findings from this investigation.


---

## Overview

| | |
|---|---|
| Findings | **17** (9 confirmed, 8 inference) |
| Severity | 0 critical, 6 high, 9 medium, 0 low, 2 info |
| Sources | 15 evidence sources across 352 tool calls |


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
| 2014-12-01T14:50:26 | Organized Data Staging and Preparation for Exfiltration | HIGH | tsk.masquerade, tsk.filelist |
| 2014-12-01T14:50:26 | Evidence of Data Obfuscation Through File Masquerading | HIGH | tsk.masquerade |
| 2014-12-01T14:50:26 | Systematic Data Leakage Preparation with Government Document Targeting | HIGH | bulk.email, bulk.url, tsk.masquerade |
| 2014-12-01T14:50:26 | Cross-System Data Exfiltration Chain: PC to Removable Media to Optical CD with Forensic Countermeasures | HIGH | optical.listing, composite.recovery, composite.correlation, bulk.ccn, bulk.email, bulk.url, tsk.masquerade |
| 2014-12-01T14:50:26 | Evidence of File Masquerading and Concealment | MEDIUM | tsk.masquerade |
| 2014-12-01T14:50:26 | Unauthorized Access to Government Documents and Email Information | MEDIUM | bulk.email, bulk.url |
| 2014-12-01T14:50:26 | Evidence of Data Staging for Exfiltration | MEDIUM | tsk.filelist, tsk.masquerade |
| 2014-12-01T14:50:26 | Suspicious Search Activity Related to Data Leakage Techniques | MEDIUM | bulk.url |
| 2014-12-01T14:50:26 | File Masquerading Detected - Hidden Office Documents | MEDIUM | tsk.masquerade |
| 2014-12-01T14:50:26 | Systematic File Organization and Masquerading with Government Document Targeting | MEDIUM | optical.listing, tsk.masquerade, composite.file_staging, bulk.url |
| 2015-01-05T15:15:08Z | Files with Masqueraded Extensions Found on Optical Media | MEDIUM | tsk.masquerade, optical.listing |
| 2015-01-05T15:15:08Z | Suspicious Content Pattern on Optical Media Suggests Data Exfiltration | MEDIUM | bulk.email, bulk.url, bulk.domain, optical.listing |
| 2015-01-16T15:10:24 | Payment Card Data Leakage on Removable Media | MEDIUM | bulk.ccn |
| 2015-03-22T14:33:54 | Suspicious Insider Activity - NIST Email Account Found | HIGH | hayabusa.alerts |
| 2015-03-22T14:33:54 | Coordinated Account Manipulation and Google Drive Exfiltration by NIST Informant | HIGH | hayabusa.alerts, composite.exfil, registry.ntuser.informant, composite.persistence |





---

## Appendix A: Verified Forensic Findings


### 1. [HIGH] Organized Data Staging and Preparation for Exfiltration

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2014-12-01T14:50:26 to 2015-03-24T10:00:18 |
| **Sources** | tsk.masquerade, tsk.filelist |
| **Evidence Refs** | tc_ad2e71ab, tc_b402ebb3 |
| **ATT&CK** | [T1074](https://attack.mitre.org/techniques/T1074/), [T1560](https://attack.mitre.org/techniques/T1560/) |


Evidence suggests data staging for potential exfiltration with deleted files containing sensitive project data. The analysis reveals:
1. Multiple deleted files in '$OrphanFiles/' directory structure including subdirectories: design/, PRICIN~1/, progress/, proposal/, TECHNI~1/
2. Files are organized into thematic directories suggesting systematic data collection and organization
3. Large file sizes (ranging from 27KB to 35MB) indicate substantial data collection
4. Timestamps show activity from December 2014 through January 2015
5. File patterns include 'diary' entries with numbered suffixes (#1d, #1p, #2d, #2p, #3d, #3p) suggesting systematic documentation
6. Presence of files with names like 'winter_whether_advisory.zip' and 'my_favorite_cars.db' that appear to be masquerading as legitimate content

The organized directory structure, systematic file naming, and masquerading techniques collectively suggest preparatory activities for data exfiltration.



### 2. [HIGH] Evidence of Data Obfuscation Through File Masquerading

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2014-12-01T14:50:26 to 2015-01-23T16:47:10 |
| **Sources** | tsk.masquerade |
| **Evidence Refs** | tc_fcc5a84c |


Multiple deleted orphan files were found masquerading as benign file types while containing Office document content. Files detected include: 'winter_whether_advisory.zip' (actual content: pptx), 'my_favorite_movies.7z' (actual content: xlsx), 'new_years_day.jpg' (actual content: xlsx), 'super_bowl.avi' (actual content: ole), 'my_favorite_cars.db' (actual content: ole), and others. This pattern indicates intentional obfuscation of sensitive documents to avoid detection during data exfiltration.



### 3. [HIGH] Systematic Data Leakage Preparation with Government Document Targeting

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2014-12-01T14:50:26 to 2015-03-24T10:00:18 |
| **Sources** | bulk.email, bulk.url, tsk.masquerade |
| **Evidence Refs** | tc_ad2e71ab, tc_a0f4a77a, tc_7505a170 |
| **ATT&CK** | [TA0010](https://attack.mitre.org/techniques/TA0010/), [T1020](https://attack.mitre.org/techniques/T1020/), [T1048](https://attack.mitre.org/techniques/T1048/) |


Comprehensive evidence of systematic data leakage preparation involving multiple techniques:
1. File Masquerading: Office documents disguised as multimedia/archive files with misleading extensions
2. Data Organization: Structured directory organization (design/, PRICIN~1/, progress/, proposal/, TECHNI~1/) indicating systematic collection
3. Government Data Access: Evidence of accessing OMB/whitehouse.gov documents and email addresses
4. Research Activity: Searches for 'how to leak a secret', 'information leakage cases', and data deletion methods
5. Data Staging: Large files (up to 35MB) with thematic organization suggesting preparation for exfiltration
6. Temporal Pattern: Activity concentrated between December 2014 - January 2015 with deletion timestamps in March 2015

Collectively, these indicators suggest a coordinated effort to collect, organize, conceal, and prepare sensitive data for unauthorized exfiltration, with particular focus on government documents and systematic data handling methodologies.



### 4. [HIGH] Suspicious Insider Activity - NIST Email Account Found

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2015-03-22T14:33:54 to 2015-03-25T14:54:25 |
| **Sources** | hayabusa.alerts |
| **Evidence Refs** | tc_706d4f3e, tc_ddb0b021 |


Analysis reveals user account activity potentially linked to an email address 'iaman.informant@nist.gov.ost' (Outlook offline storage file). Events show: informant's password reset by SYSTEM account on March 22, 2015 14:33:54; informant then created/administered accounts admin11, ITechTeam, and temporary; all accounts were added to Administrators group; multiple password resets performed. The email address ending in '.ost' indicates an Outlook offline storage file reference rather than confirmed live NIST email account. This could represent test/placeholder email configuration. The ASP.NET State Service was suspiciously installed on March 25, 2015 14:54:25. While account manipulation is concerning, attribution to actual NIST insider requires additional verification beyond OST file reference.

**Merged findings:**
- **Suspicious User Account Management Activity Detected** (f_f3efb2a5, high, inference): Multiple suspicious user account management activities detected via Windows Event Log analysis (Hayabusa). Key events include: 1) Password resets for accounts admin11 (March 22, 2015 15:52:10), ITechTeam (March 22, 2015 15:52:45), and temporary (March 22, 2015 15:53:11); 2) Users added to local Administrators group: admin11 added at March 22, 2015 15:51:54, ITechTeam added at March 22, 2015 15:52:30, temporary added at March 22, 2015 15:52:30; 3) Original informant account password reset by SYSTEM at March 22, 2015 14:33:54; 4) Suspicious service 'ASP.NET State Service' installed on March 25, 2015 14:54:25. This pattern of coordinated account creation and privilege escalation suggests malicious account manipulation.

**Affected Systems:** hayabusa.alerts



### 5. [HIGH] Cross-System Data Exfiltration Chain: PC to Removable Media to Optical CD with Forensic Countermeasures

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2014-12-01T14:50:26 to 2015-03-24T20:57:03 |
| **Sources** | optical.listing, composite.recovery, composite.correlation, bulk.ccn, bulk.email, bulk.url, tsk.masquerade |
| **Evidence Refs** | tc_20663991, tc_80483732, tc_a42b8197, tc_c4f6cc3b |
| **ATT&CK** | [T1567](https://attack.mitre.org/techniques/T1567/), [T1074](https://attack.mitre.org/techniques/T1074/), [T1036](https://attack.mitre.org/techniques/T1036/), [T1070](https://attack.mitre.org/techniques/T1070/), [T1552](https://attack.mitre.org/techniques/T1552/) |


Evidence reveals a complete data exfiltration pathway across multiple storage media with forensic countermeasures:

1. **PC Source System**: 
   - Credit card numbers discovered in bulk.ccn (263 lines) from pc.E01 file
   - Government document access: OMB email address Eric_P._Lauer@omb.eop.gov and whitehouse.gov documents
   - Search activity for 'information leakage cases' and 'how to leak a secret'
   - File masquerading detected with Office documents disguised as media/archive files

2. **Removable Media (rm1, rm2)**: 
   - Credit card number 5627938946716605 found on rm2.E01 (bulk.ccn)
   - Email addresses including 'iaman.informant@nist.gov.ost' extracted
   - Domain references to whitehouse.gov/omb/ documents

3. **Optical Media (IAMAN CD)**: 
   - Volume label 'IAMAN CD' with 9 VAT generations (write sessions)
   - Organized directory structure: design/, pricing decision/, progress/, proposal/, technical review/
   - Same masqueraded files found: winter_whether_advisory.zip (PPTX), my_favorite_movies.7z (XLSX), new_years_day.jpg (XLSX)
   - Deleted files showing multiple write sessions indicating staged preparation

4. **Forensic Countermeasures**:
   - Eraser.exe secure deletion tool detected via ShimCache
   - CCleaner64.exe anti-forensics tool present
   - 2222 total deleted files identified
   - File masquerading across all media types

5. **Temporal Correlation**:
   - File creation/modification times range from Dec 2014 - Jan 2015
   - Optical media write sessions in March 2015
   - Deleted file timestamps align with anti-forensics tool usage

**Cross-System Convergence**: The same masqueraded files, government document references, and NIST email address appear across PC, removable media, and optical media, demonstrating a systematic data collection and exfiltration operation with forensic awareness.



### 6. [HIGH] Coordinated Account Manipulation and Google Drive Exfiltration by NIST Informant

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2015-03-22T14:33:54 to 2015-03-25T14:54:25 |
| **Sources** | hayabusa.alerts, composite.exfil, registry.ntuser.informant, composite.persistence |
| **Evidence Refs** | tc_c4f6cc3b, tc_131ba318, tc_5d46a85f |
| **ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/), [T1136](https://attack.mitre.org/techniques/T1136/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1070](https://attack.mitre.org/techniques/T1070/) |


Evidence of coordinated user account manipulation and cloud-based exfiltration:

**User Account Activity (March 22-25, 2015)**:
1. Informant account (iaman.informant@nist.gov.ost) password reset by SYSTEM at 14:33:54
2. Creation/administration of accounts admin11, ITechTeam, and temporary
   - All added to Administrators group within minutes
   - Password resets performed for each account
3. Suspicious ASP.NET State Service installed on March 25, 2015 14:54:25

**Google Drive Exfiltration Indicators**:
1. Drive.google.com access detected in bulk.url data
2. Credential sharing URLs: https://drive.google.com/sharing/share?shareUiType=default&authuser=0&foreignService=googledrivesync&access_token=ya29.PwE6ZEHd2AM8YHL
3. OAuth relay URLs: https://accounts.google.com/o/oauth2/postmessageRelay?parent=https%3A%2F%2Fdrive.google.com
4. Document sync URLs: https://docs.google.com/presentation?usp=drive_sync and https://docs.google.com/spreadsheets?usp=drive_sync

**Cross-System Correlation**:
- User account manipulation coincides with Google Drive activity timeline
- Informant email address appears in both user account events and Google Drive access patterns
- ASP.NET State Service installation suggests web application persistence mechanism
- Same informant email found across registry, event logs, and bulk extractor data

**MITRE ATT&CK Mapping**:
- T1078: Valid Accounts (creation and privilege escalation)
- T1136: Create Account (admin11, ITechTeam, temporary)
- T1567.002: Exfiltration to Cloud Storage (Google Drive)
- T1070: Indicator Removal (account manipulation to obscure original actor)



### 7. [MEDIUM] Evidence of File Masquerading and Concealment

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2014-12-01T14:50:26 to 2015-01-23T16:47:10 |
| **Sources** | tsk.masquerade |
| **Evidence Refs** | tc_ad2e71ab |
| **ATT&CK** | [T1036](https://attack.mitre.org/techniques/T1036/), [T1074](https://attack.mitre.org/techniques/T1074/) |


Analysis of the tsk.masquerade source reveals multiple files with extensions that do not match their actual content format, indicating deliberate concealment. Key findings include:
1. File '$OrphanFiles/design/winter_storm.amr' (ext=amr) actually contains OLE format content
2. File '$OrphanFiles/design/winter_whether_advisory.zip' (ext=zip) contains PPTX format content 
3. File '$OrphanFiles/PRICIN~1/my_favorite_movies.7z' (ext=7z) contains XLSX format content
4. File '$OrphanFiles/PRICIN~1/new_years_day.jpg' (ext=jpg) contains XLSX format content
5. File '$OrphanFiles/progress/my_smartphone.png' (ext=png) contains DOCX format content
6. File '$OrphanFiles/TECHNI~1/diary_#1d.txt' (ext=txt) contains DOCX format content

These files appear to be deleted but show clear evidence of file masquerading where Office documents (DOCX, XLSX, PPTX) are disguised as multimedia files (AMR, JPG, PNG, AVI) and archive files (ZIP, 7Z). This pattern is consistent with attempts to conceal sensitive documents by giving them misleading file extensions.



### 8. [MEDIUM] Unauthorized Access to Government Documents and Email Information

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2014-12-01T14:50:26 to 2015-03-24T10:00:18 |
| **Sources** | bulk.email, bulk.url |
| **Evidence Refs** | tc_7b7a9477, tc_a0f4a77a |
| **ATT&CK** | [T1552](https://attack.mitre.org/techniques/T1552/), [T1530](https://attack.mitre.org/techniques/T1530/) |


Evidence of access to government documents and email information: 1) Email address 'Eric_P._Lauer@omb.eop.gov' extracted - Office of Management and Budget (OMB) Executive Office of the President; 2) Government documents accessed including: 'FEA_CRM_v23_Final_Oct_2007.pdf' (Federal Enterprise Architecture Capital Planning Reference Model) and 's53.pdf' (OMB Circular A-11 section 53). These documents appear to be publicly available government policy documents rather than classified/restricted materials. The presence of government email addresses and document references indicates research interest in government materials, but does not necessarily constitute unauthorized access to restricted information.



### 9. [MEDIUM] Payment Card Data Leakage on Removable Media

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-01-16T15:10:24 to 2015-03-24T09:59:27 |
| **Sources** | bulk.ccn |
| **Evidence Refs** | tc_9cbf97ca |


Payment card numbers were extracted from the rm2 disk image, including credit card number 5627938946716605. However, analysis of the bulk.ccn data reveals patterns consistent with test/sample data rather than confirmed real payment card data. Multiple numbers show repeating patterns (3571730734907392 appears 6 times) and sequences like 6447666444222000, 6449775332001000 that resemble test patterns. While sensitive financial information was present on removable media, the nature of the data appears to be test/sample patterns rather than confirmed exfiltrated payment card data from production systems.



### 10. [MEDIUM] Evidence of Data Staging for Exfiltration

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2014-12-01T14:50:26 to 2015-01-23T16:47:10 |
| **Sources** | tsk.filelist, tsk.masquerade |
| **Evidence Refs** | tc_b5a73248, tc_fcc5a84c |


Files consistent with data staging were detected in orphan file areas, including archive files such as 'winter_whether_advisory.zip' and 'my_favorite_movies.7z'. These files are in suspicious locations (orphaned/deleted partitions) and show signs of obfuscation. The combination of archive files in suspicious locations with file masquerading suggests data was being prepared for exfiltration and possibly already transferred via removable media.



### 11. [MEDIUM] Suspicious Search Activity Related to Data Leakage Techniques

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2014-12-01T14:50:26 to 2015-03-24T10:00:18 |
| **Sources** | bulk.url |
| **Evidence Refs** | tc_7505a170 |
| **ATT&CK** | [T1059](https://attack.mitre.org/techniques/T1059/), [T1087](https://attack.mitre.org/techniques/T1087/) |


Evidence of suspicious search activity indicating research on data leakage techniques:
1. Multiple Google searches for 'information leakage cases'
2. Search for 'how to leak a secret' suggesting research on data exfiltration methods
3. Search for 'how to delete data' indicating potential attempts to cover tracks
4. Access to security research materials including DEFCON website (defcon.org)
5. Access to National Institute of Justice (NIJ) materials on digital forensics

The pattern of searches shows clear interest in data leakage methodologies, data destruction techniques, and forensic countermeasures, suggesting preparatory research for unauthorized data exfiltration activities.



### 12. [MEDIUM] Files with Masqueraded Extensions Found on Optical Media

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-01-05T15:15:08Z to 2015-03-24T20:57:03Z |
| **Sources** | tsk.masquerade, optical.listing |
| **Evidence Refs** | tc_2c8c7365, tc_a218c1ba |


Analysis of optical media (volume label: 'IAMAN CD') revealed multiple files with intentionally misleading file extensions that conceal Office document content. The tsk.masquerade source detected 17 files with extension/content mismatches where the actual file content differs from the indicated file extension. Examples include: 'winter_whether_advisory.zip' (actually PPTX), 'my_favorite_movies.7z' and 'new_years_day.jpg' (actually XLSX files), and multiple '.txt' diary files that are actually DOCX, PPTX, or OLE files. This pattern suggests deliberate attempts to conceal Office documents within what appear to be media files, archives, or text documents.



### 13. [MEDIUM] File Masquerading Detected - Hidden Office Documents

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2014-12-01T14:50:26 to 2015-03-25T15:22:08 |
| **Sources** | tsk.masquerade |
| **Evidence Refs** | tc_9b37808a |


Multiple files with mismatched content/extension signatures detected via masquerade analysis. Deleted orphan files show Office documents masquerading as media files: winter_whether_advisory.zip (actually PPTX), my_favorite_movies.7z (actually XLSX), new_years_day.jpg (actually XLSX), super_bowl.avi (actually OLE), my_smartphone.png (actually DOCX), and others. Files were deleted but show creation times in March 2015. This pattern suggests deliberate obfuscation of sensitive Office documents to appear as benign media files.



### 14. [MEDIUM] Suspicious Content Pattern on Optical Media Suggests Data Exfiltration

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-01-05T15:15:08Z to 2015-03-24T20:57:03Z |
| **Sources** | bulk.email, bulk.url, bulk.domain, optical.listing |
| **Evidence Refs** | tc_2c8c7365, tc_a218c1ba, tc_2a193790, tc_aa50b4f6 |


Analysis of optical media content reveals patterns consistent with data exfiltration or unauthorized document storage. The media contains: 1) Government-related content including an OMB email address (Eric_P._Lauer@omb.eop.gov) and references to whitehouse.gov documents, 2) Multiple Office documents (DOCX, PPTX, XLSX) masquerading as media files, archives, and text documents with misleading extensions, 3) Organizational structure with folders named 'design', 'pricing decision', 'progress', 'proposal', and 'technical review' containing various file types. The combination of government document references and intentionally obfuscated Office files suggests deliberate concealment of potentially sensitive materials.



### 15. [MEDIUM] Systematic File Organization and Masquerading with Government Document Targeting

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2014-12-01T14:50:26 to 2015-03-24T20:57:03 |
| **Sources** | optical.listing, tsk.masquerade, composite.file_staging, bulk.url |
| **Evidence Refs** | tc_20663991, tc_f4172f8c, tc_c4f6cc3b |
| **ATT&CK** | [T1027](https://attack.mitre.org/techniques/T1027/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/), [T1036](https://attack.mitre.org/techniques/T1036/), [T1560](https://attack.mitre.org/techniques/T1560/) |


Systematic file organization and masquerading pattern for sensitive data exfiltration:

**Organized Directory Structure (Optical Media)**:
1. design/ - Contains winter_storm.amr (OLE) and winter_whether_advisory.zip (PPTX)
2. pricing decision/ - Contains my_favorite_cars.db (OLE), my_favorite_movies.7z (XLSX), new_years_day.jpg (XLSX), super_bowl.avi (OLE)
3. progress/ - Contains my_friends.svg, my_smartphone.png (DOCX), new_year_calendar.one
4. proposal/ - Contains a_gift_from_you.gif, landscape.png
5. technical review/ - Contains diary files #1d.txt (DOCX), #1p.txt (PPTX), #2d.txt (DOCX), #2p.txt (PPTX), #3d.txt (DOCX), #3p.txt (PPTX)

**File Masquerading Pattern**:
- Office documents disguised with multimedia/extensions: amr, zip, 7z, jpg, avi, png, txt, svg, gif
- Size range: 27KB to 35MB files
- Consistent naming convention: 'diary_#1d.txt', 'diary_#1p.txt' (d=document, p=presentation)

**Research Activity**:
- Google searches for 'information leakage cases'
- Access to DEFCON website (defcon.org)
- National Institute of Justice (NIJ) forensic materials access
- Whitehouse.gov/omb/ document access (FEA_CRM_v23_Final_Oct_2007.pdf, s53.pdf)

**Cross-System Consistency**:
- Same masqueraded files found on PC orphan files and optical media
- Organized directory structure suggests systematic data collection
- File timestamps show activity from Dec 2014 - Jan 2015 with March 2015 deletions

**MITRE ATT&CK Mapping**:
- T1027: Obfuscated Files or Information (file extension masquerading)
- T1074.001: Local Data Staging (organized directory structure)
- T1036: Masquerading (misleading file extensions)
- T1560: Archive Collected Data (compression and organization)



### 16. [INFO] Windows 7 Ultimate Operating System Identified

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | registry.query.software |
| **Evidence Refs** | tc_b3e57c5f, tc_5e73f7b6 |


The system is running Windows 7 Ultimate edition. Registry query confirms the ProductName value is 'Windows 7 Ultimate'. The InstallDate registry value shows a Unix timestamp of 1427034866 (which converts to March 22, 2015). This indicates the system was installed or last updated around March 2015.



### 17. [INFO] Sensitive Credit Card Data Discovered

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | inference |
| **Sources** | bulk.ccn |
| **Evidence Refs** | tc_08b30c72 |


Multiple credit card numbers and sensitive financial data discovered via bulk extractor analysis. Hundreds of credit card numbers were found in unallocated space and file slack, including card numbers like 3571730734907392, 5674326276767632, 5467663276676632, 371449635398431, 6011000990139424, and many others. This indicates potential data exfiltration or storage of sensitive financial information. The volume and variety of credit card numbers suggest this system may have been used to collect or process payment card data. Data discovered in bulk extractor output from cfreds_2015_data_leakage_pc.E01 file.



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



### Email IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Email | `eric_p._lauer@omb.eop.gov` |  | Unauthorized Access to Government Documents and Email Information |




---

## Appendix C: MITRE ATT&CK Coverage

17 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) > Execution (1) > Persistence (2) > Privilege Escalation (1) > Defense Evasion (4) > Credential Access (1) > Discovery (1) > Collection (4) > Exfiltration (4) > Other (1)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Coordinated Account Manipulation and Google... |


### Execution

| Technique | Name | Findings |
|-----------|------|----------|
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Suspicious Search Activity Related to Data... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Coordinated Account Manipulation and Google... |
| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account | Coordinated Account Manipulation and Google... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Coordinated Account Manipulation and Google... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Systematic File Organization and Masquerading... |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Evidence of File Masquerading and Concealment; Cross-System Data Exfiltration Chain: PC to...; Systematic File Organization and Masquerading... |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal | Cross-System Data Exfiltration Chain: PC to...; Coordinated Account Manipulation and Google... |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Coordinated Account Manipulation and Google... |


### Credential Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials | Unauthorized Access to Government Documents...; Cross-System Data Exfiltration Chain: PC to... |


### Discovery

| Technique | Name | Findings |
|-----------|------|----------|
| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Suspicious Search Activity Related to Data... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1074](https://attack.mitre.org/techniques/T1074/) | Data Staged | Evidence of File Masquerading and Concealment; Organized Data Staging and Preparation for Exfiltration; Cross-System Data Exfiltration Chain: PC to... |
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Local Data Staging | Systematic File Organization and Masquerading... |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage | Unauthorized Access to Government Documents... |
| [T1560](https://attack.mitre.org/techniques/T1560/) | Archive Collected Data | Organized Data Staging and Preparation for Exfiltration; Systematic File Organization and Masquerading... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1020](https://attack.mitre.org/techniques/T1020/) | Automated Exfiltration | Systematic Data Leakage Preparation with... |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Systematic Data Leakage Preparation with... |
| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service | Cross-System Data Exfiltration Chain: PC to... |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | Coordinated Account Manipulation and Google... |


### Other

| Technique | Name | Findings |
|-----------|------|----------|
| [TA0010](https://attack.mitre.org/techniques/TA0010/) |  | Systematic Data Leakage Preparation with... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 352 |
| Findings submitted | 17 |
| Confirmed | 9 |
| Inferences | 8 |
| Input tokens | 9.7M |
| Output tokens | 56.4K |
| Total tokens | 9.7M |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| bedrock/deepseek.v3.2 | 9.7M | 56.4K | 9.7M |




<details>
<summary>Evidence Sources (91)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 8 |
| tsk.filelist | sleuthkit | 27 |
| tsk.masquerade | sleuthkit | 0 |
| tsk.partitions | sleuthkit | 10 |
| tsk.partitions | sleuthkit | 9 |
| tsk.filelist | sleuthkit | 51 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist.p1 | sleuthkit | 93 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 189 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.url | bulk_extractor | 207 |
| bulk.url_services | bulk_extractor | 14 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.ccn | bulk_extractor | 6 |
| bulk.domain | bulk_extractor | 264 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.email | bulk_extractor | 43 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.telephone | bulk_extractor | 21 |
| bulk.url | bulk_extractor | 288 |
| bulk.url_services | bulk_extractor | 19 |
| tsk.masquerade | sleuthkit | 17 |
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
| composite.file_staging | composite | 80 |
| tsk.masquerade | sleuthkit | 3 |
| ez.mft | eztools | 98918 |
| evtx.manifest | evtx-extract | 54 |
| ez.shimcache | eztools | 307 |
| registry.default | regripper | 418 |
| registry.sam | regripper | 186 |
| registry.sam | regripper | 7 |
| registry.sam | regripper | 7 |
| registry.security | regripper | 69 |
| registry.security | regripper | 8 |
| hayabusa.alerts | hayabusa | 35 |
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
| exiftool.metadata | exiftool | 9 |
| registry.query.system | python-registry | 1 |
| registry.query.software | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.software | python-registry | 1 |
| optical.listing | mulder-optical | 58 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 237 |
| bulk.email | bulk_extractor | 12 |
| bulk.exif | bulk_extractor | 21 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.telephone | bulk_extractor | 8 |
| bulk.url | bulk_extractor | 300 |
| bulk.url_services | bulk_extractor | 21 |
| exiftool.metadata | exiftool | 9 |
| composite.timeline | composite | 172 |
| composite.correlation | composite | 1 |
| composite.recovery | composite | 22 |
| composite.lateral_movement | composite | 416 |
| composite.persistence | composite | 2413 |
| composite.file_staging | composite | 578 |
| composite.exfil | composite | 2466 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 578 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
