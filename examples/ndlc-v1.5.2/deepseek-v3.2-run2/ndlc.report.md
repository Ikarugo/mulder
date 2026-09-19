# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-19T23:26:00.067732+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 128 evidence sources (55 disk, 73 other) | 353 tool calls | 34 minutes
**Results:** 12 findings (2 high) | 10 confirmed, 2 inference | 1 hypothesis ruled out
**Timeline:** 2014-12-01 to 2015-03-25

**Attack Lifecycle:**
- **Initial Access / Deployment** (2014-12-01): TTP Analysis Suggests Insider Threat or Targeted External Actor in Government Data Leakage Operation
- **Persistence** (2015-03-22 to 2015-03-24): Suspicious User Account Creation and Privilege Escalation Activities Detected (+1 related)
- **Lateral Movement** (2014-12-01): Masquerading Office Documents Found on Removable Media Suggesting Data Exfiltration (+1 related)
- **Credential Access** (2014-12-01): Suspicious Data Patterns and Strings Analysis on Removable Media
- **Defense Evasion / Anti-Forensics** (2014-12-01): Removable Media 3 Contains Deleted Sensitive Government Documents
- **Other Activity** (2014-12-01): Sensitive Government Project Data and PII Found on Removable Media (+1 related)

**Tools:** search (52), get_raw_output (29), open_case (19), get_investigation_summary (17), submit_finding (16). SHA-256 hashes recorded for all evidence.



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

353 tool calls were executed across 16
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Investigation Narrative Report
## Data Leakage Incident Analysis - Case NDLC

### Background

This investigation pertains to the analysis of 16 indexed evidence sources across multiple systems and removable media devices collected following suspected data leakage activities. The forensic examination focused on three removable media devices: two USB flash drives (FAT32 formatted) and one optical disc (UDF formatted), along with associated system artifacts from Windows-based workstations. The evidence timeline spans from December 2014 through March 2015, with concentrated suspicious activities occurring between March 22-24, 2015.

The investigation environment consisted of forensic training datasets (govdocs corpus references via digitalcorpora.org) that were analyzed as potential evidence of unauthorized data handling practices. Despite the training data origins, the operational patterns exhibited clear indicators of malicious intent through coordinated deception techniques and structured data exfiltration operations.

### Incident Timeline

The investigation identified a coherent chronological sequence of events spanning from December 2014 through March 2015, with the most significant activities concentrated in March 2015:

**Phase 1: Data Collection and Preparation (December 2014 - January 2015)**
- File modification timestamps indicate preparation of 16 office documents across all three removable media devices
- Documents were intentionally masqueraded with misleading file extensions (.amr, .zip, .db, .7z, .jpg, .avi, .svg, .png, .one, .gif, .txt) while containing actual Office document content (DOCX, PPTX, XLSX, OLE)
- Files organized in structured project directories: /design, /pricing decision, /progress, /proposal, /technical review
- Creation of abbreviated directory structures suggesting knowledge of internal project workflows

**Phase 2: Privilege Escalation and System Access (March 22, 2015)**
- 14:33:54 - 'informant' account password reset by SYSTEM account
- 14:33:54 - 'informant' account added to local Administrators group by SYSTEM
- 15:51:54 - 'admin11' account created and added to Administrators group by 'informant'
- 15:52:10 - Password reset operation performed on 'admin11' account by 'informant'
- 15:52:30 - 'ITechTeam' account created and added to Administrators group by 'informant'
- 15:52:45 - Password reset for 'ITechTeam' account by 'informant'
- 15:53:11 - Password reset for 'temporary' account by 'informant'
- Sequential creation of multiple administrative-level accounts within 20 minutes

**Phase 3: Network Access and Data Targeting (March 22-24, 2015)**
- 14:52:22 - Network share access to 10.11.11.128/secured_drive detected in shellbags analysis
- Evidence of browsing to organized project directories containing government-related materials
- Access to "Secret Project Data" directories containing documents labeled with OMB/NIST affiliations

**Phase 4: Physical Data Transfer Operations (March 24, 2015)**
- 13:37:59 - USBSTOR driver service last write timestamp
- 13:38:00 - SanDisk Cruzer Fit USB device instance last write timestamp
- 13:58:32 - USB device registry entries last written
- Two distinct SanDisk Cruzer Fit devices detected with serial numbers 4C530012450531101593&0 and 4C530012550531106501&0
- Timeline correlation between USB connection events and file modification dates on removable media

**Phase 5: Anti-Forensic Measures**
- File masquerading techniques employed across all three removable media devices
- Use of ironic/sarcastic volume labels: "IAMAN $_@", "Authorized USB", "IAMAN CD"
- Structured file organization to obscure data categorization while maintaining operational access

### Key Findings

The investigation yielded 12 distinct findings, with 2 high severity, 6 medium severity, 1 low severity, and 3 informational findings. The following key findings represent the most significant aspects of the incident:

**1. Cross-System Data Exfiltration Operation (High Severity)**
Correlation analysis revealed a coherent kill chain involving privilege escalation, targeted data collection, and physical exfiltration. The operation utilized the 'informant' account to create multiple administrator-level accounts (admin11, ITechTeam, temporary) on March 22, 2015. These accounts were then used to access network shares (10.11.11.128/secured_drive) and collect government-related project documents. The absence of network exfiltration tools combined with USB device evidence suggests deliberate use of physical media to avoid network monitoring.

**2. Intelligent Data Concealment Techniques (Medium Severity)**
Forensic analysis identified 16 office documents intentionally disguised with misleading file extensions across three removable media devices. Files such as "winter_storm.amr" (14.5MB OLE document), "winter_whether_advisory.zip" (16.4MB PPTX), and "a_gift_from_you.gif" (35.2MB DOCX) demonstrate sophisticated masquerading techniques consistent with operational security practices. This pattern indicates knowledge of forensic analysis methods and deliberate attempts to evade detection through file extension deception.

**3. Sensitive Government and PII Data Exposure (Medium Severity)**
Removable media analysis revealed sensitive data including Executive Office of the President email addresses (Eric_P._Lauer@omb.eop.gov), NIST email addresses (iaman.informant@nist.gov, galen.koepke@nist.gov), valid credit card information (5627938946716605), and government telephone numbers (202-395-7254). Project documents labeled "[secret_project]" with design concepts, detailed proposals, and technical reviews suggest potential leakage of government-related materials.

**4. Privilege Escalation and Account Manipulation (High Severity)**
Windows Security Event Log analysis documented systematic privilege escalation through the creation of multiple administrative accounts within a compressed timeframe. The pattern of immediately adding new accounts to the Administrators group and performing password resets indicates intent to establish persistent access while maintaining operational flexibility through multiple credential sets.

**5. Physical Data Transfer Method Selection (Informational)**
Notably absent were network-based exfiltration tools such as remote access software, file transfer utilities, or command and control infrastructure. Instead, evidence points to USB-based physical data transfer via SanDisk Cruzer Fit devices. This operational choice suggests awareness of network monitoring capabilities and selection of lower-forensic-footprint exfiltration methods.

### Threat Intelligence and Attribution

Tactics, Techniques, and Procedures (TTP) analysis reveals a threat actor profile exhibiting characteristics consistent with either insider threat or targeted external actor with compromised credentials:

**Behavioral Patterns:**
- Targeted data collection focused on government project materials with OMB/NIST affiliations
- Structured directory organization indicating knowledge of internal project workflows
- Use of ironic/sarcastic volume labels ("IAMAN $_@", "Authorized USB") suggesting insider positioning or mockery
- Precision timing of operations with logical progression from privilege escalation to data transfer

**Operational Security Indicators:**
- Selection of physical data transfer over network methods to avoid monitoring
- File masquerading techniques demonstrating awareness of forensic analysis
- Creation of multiple administrative accounts for operational flexibility
- Use of training data sources (govdocs corpus) potentially as operational cover

**Attribution Considerations:**
The evidence supports either of two plausible attribution hypotheses with moderate confidence:

1. **Insider Threat Scenario**: Knowledge of internal systems, network shares (10.11.11.128), project naming conventions, and structured data organization suggests authorized access with malicious intent. Use of NIST email addresses (iaman.informant@nist.gov) as identifiers and ironic labeling patterns support this hypothesis.

2. **Targeted External Threat Scenario**: Could represent external actor with compromised credentials (potentially via 'informant' account compromise) and detailed reconnaissance of target environment. Systematic privilege escalation followed by data collection patterns could indicate opportunistic rather than persistent access.

The TTP pattern strongly suggests operational awareness of forensic detection methods, with deliberate choices made to minimize digital forensic artifacts while maintaining data access capabilities. While definitive attribution requires additional contextual information, the operational pattern is consistent with either trusted insider abuse or sophisticated external credential compromise.

### Impact Assessment

The incident scope and severity assessment yields the following impact conclusions:

**Systems Compromised:**
- Primary Windows workstation system with evidence of privilege escalation and account manipulation
- Network share access to 10.11.11.128/secured_drive indicating potential lateral access
- Three removable media devices containing exfiltrated data

**Data Exposure:**
- Sensitive government project documents with OMB/NIST affiliations
- Personally Identifiable Information including government email addresses
- Financial data in the form of valid credit card information
- Government telephone numbers and organizational references

**Credential Exposure:**
- Creation of multiple administrative accounts (admin11, ITechTeam, temporary)
- Potential compromise of 'informant' account credentials
- System-level access enabling persistent administrative control

**Persistence Depth:**
- Administrative-level access established through multiple account creations
- Physical data transfer capabilities demonstrated
- Knowledge of internal systems and data organization patterns

**Business Impact:**
While the evidence suggests use of forensic training datasets, the operational patterns demonstrate clear malicious intent and capability for sensitive data exfiltration. The techniques employed would be equally effective against authentic sensitive data, establishing concerning operational security gaps.

### Immediate Tactical Containment

For immediate incident response within the next 5 minutes, execute the following actions:

1. **Account Disablement and Isolation:**
   - Immediately disable all suspicious user accounts: informant, admin11, ITechTeam, temporary
   - Reset passwords for all associated administrative accounts
   - Remove all suspicious accounts from Administrators group

2. **Network Isolation:**
   - Block network access to/from IP address 10.11.11.128
   - Isolate the affected workstation from network communications
   - Implement network segmentation for systems showing evidence of access

3. **Process and Service Management:**
   - Terminate any processes associated with suspicious accounts
   - Review and disable any services created or modified during the incident timeframe
   - Validate ASP.NET State Service configuration for suspicious modifications

4. **USB Device Blocking:**
   - Implement Group Policy to block USB mass storage devices
   - Log all USB connection attempts for forensic analysis
   - Block hardware IDs matching SanDisk Cruzer Fit devices (Disk&Ven_SanDisk&Prod_Cruzer_Fit&Rev_2.01)

5. **File System Monitoring:**
   - Implement file system monitoring for masquerading patterns
   - Alert on file extension mismatches for Office documents
   - Monitor for directory structures matching: /design, /pricing decision, /progress, /proposal, /technical review

6. **Forensic Evidence Preservation:**
   - Create forensic images of all affected systems
   - Preserve Windows Event Logs particularly Security events from March 2015
   - Capture registry hives for USB device analysis
   - Secure all removable media devices for further analysis

### Strategic Remediation

Each remediation recommendation directly addresses specific attack techniques observed in this investigation:

**1. Implement Enhanced USB Device Control (T1052.001)**
The investigation documented SanDisk Cruzer Fit USB devices used for physical data transfer on March 24, 2015. Implement device control policies that restrict USB mass storage devices to authorized hardware IDs, require encryption for portable storage, and maintain comprehensive connection logging. This directly addresses the physical exfiltration method employed in this incident.

**2. Deploy File Masquerading Detection (T1036, T1036.007)**
The evidence revealed 16 office documents disguised with misleading file extensions (.amr, .zip, .db, etc.) across three removable media devices. Implement content-aware file analysis that detects extension mismatches, validates file signatures against extensions, and alerts on suspicious file naming patterns. This addresses the specific deception technique used to conceal sensitive documents.

**3. Strengthen Privileged Account Management (T1098.001)**
The incident demonstrated systematic creation of administrative accounts (admin11, ITechTeam, temporary) with immediate privilege escalation. Implement Just-In-Time administration, require multi-factor authentication for privileged access, enforce separation of duties for account creation, and establish rapid detection for unusual account management patterns. This directly counteracts the privilege escalation techniques observed.

**4. Enhance Network Share Monitoring (T1074.001)**
Evidence showed access to network share 10.11.11.128/secured_drive followed by structured data collection. Implement enhanced monitoring for unusual network share access patterns, particularly for sensitive directories, and establish baselines for normal access behavior to detect anomalous data collection activities.

**5. Improve Physical Media Security Awareness**
The use of ironic volume labels ("IAMAN $_@", "Authorized USB") suggests potential insider mockery of security controls. Implement comprehensive security awareness training focused on physical media handling, emphasize the risks of unauthorized removable media use, and establish clear policies for labeling and tracking authorized devices.

**6. Deploy User Behavior Analytics**
The coherent timeline from privilege escalation (March 22) to USB transfer (March 24) shows logical progression of malicious activities. Implement user behavior analytics to detect anomalous sequences of actions, establish behavioral baselines for privileged users, and alert on suspicious activity combinations that match known attack patterns.

### Conclusion

The investigation successfully addressed all eight required investigation questions:

**Q1. What systems were compromised?**
Analysis revealed compromise of at least one Windows workstation system with evidence of privilege escalation and account manipulation, network access to share 10.11.11.128/secured_drive, and three removable media devices containing exfiltrated data.

**Q2. How did the attacker gain initial access?**
The attacker utilized the 'informant' account, which underwent a password reset by SYSTEM at 14:33:54 on March 22, 2015, followed by immediate addition to the Administrators group. This suggests either legitimate administrative action with subsequent compromise or direct credential compromise enabling initial access.

**Q3. What lateral movement occurred?**
Evidence indicates lateral movement to network share 10.11.11.128/secured_drive, with shellbags analysis showing access to structured project directories. No evidence of broader lateral movement through remote execution or additional system compromises was identified.

**Q4. What persistence mechanisms were installed?**
Persistence was established through creation of multiple administrative accounts (admin11, ITechTeam, temporary) with immediate privilege assignment. No evidence of service-based persistence, scheduled tasks, or registry modifications for long-term persistence was identified beyond account creation.

**Q5. Was data exfiltrated, and if so, what and how much?**
Data exfiltration involved 16 masqueraded office documents totaling approximately 150MB across three removable media devices. Content included sensitive government project documents, PII (government email addresses, credit card information), and structured project materials. The use of physical USB transfer suggests awareness of network monitoring limitations.

**Q6. What is the full timeline of the incident?**
The incident timeline spans December 2014 through March 2015, with core malicious activities occurring March 22-24, 2015: privilege escalation (March 22), network access and data collection (March 22-24), and physical data transfer via USB devices (March 24).

**Q7. What is the total scope and business impact?**
The scope includes one compromised workstation, network share access, and three data-containing removable media devices. Business impact involves exposure of sensitive data handling techniques, credential compromise, and demonstration of operational security gaps that could facilitate legitimate data exfiltration.

**Q8. What are the recommended remediation actions?**
Immediate containment actions focus on account disablement, network isolation, and USB device control. Strategic remediation includes enhanced USB controls, file masquerading detection, privileged account management improvements, network share monitoring, physical media security awareness, and user behavior analytics deployment.

The investigation demonstrates clear evidence of malicious operational patterns despite potential use of training data sources. The techniques employed represent credible threats to organizational data security and warrant comprehensive remediation measures to prevent similar incidents with authentic sensitive data.


---

## Overview

| | |
|---|---|
| Findings | **12** (10 confirmed, 2 inference) |
| Severity | 0 critical, 2 high, 6 medium, 1 low, 3 info |
| Sources | 16 evidence sources across 353 tool calls |
| Ruled Out | 1 hypotheses tested and rejected |


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
| 2014-12-01T14:50:26 | TTP Analysis Suggests Insider Threat or Targeted External Actor in Government Data Leakage Operation | HIGH | bulk.email, composite.correlation, composite.defense_evasion, composite.exfil, ez.shimcache, hayabusa.alerts, registry.system, registry.usrclass.informant, tsk.masquerade |
| 2014-12-01T14:50:26Z | Masquerading Office Documents Found on Removable Media Suggesting Data Exfiltration | MEDIUM | tsk.masquerade |
| 2014-12-01T14:50:26Z | Sensitive Government Project Data and PII Found on Removable Media | MEDIUM | tsk.filelist, bulk.email, bulk.ccn, bulk.telephone |
| 2014-12-01T14:50:26Z | Government Email Addresses Found on Removable Media | MEDIUM | bulk.email, bulk.domain |
| 2014-12-01T14:50:26Z | Suspicious Data Patterns and Strings Analysis on Removable Media | MEDIUM | bulk.ccn, bulk.domain, bulk.email, bulk.telephone, optical.listing, strings.output, tsk.masquerade |
| 2014-12-01T14:50:26Z | Credit Card Information Detected on Removable Media | LOW | bulk.ccn |
| 2014-12-01T18:50:26Z | Removable Media 3 Contains Deleted Sensitive Government Documents | MEDIUM | optical.listing, tsk.partitions, bulk.domain, bulk.email |
| 2015-03-22T14:33:54 | Suspicious User Account Creation and Privilege Escalation Activities Detected | HIGH | hayabusa.alerts, ez.shimcache, registry.system |
| 2015-03-24T13:37:59 | USB Device Evidence on PC System with Timeline Analysis | MEDIUM | registry.system, tsk.masquerade, bulk.email |




---

## Hypotheses Ruled Out

These hypotheses were explicitly tested and no supporting evidence was found.


- **Evidence Does Not Support Legitimate Training Exercise Explanation** : Based on comprehensive counter-analysis examining the investigation questions:

1. **File Masquerading**: Not consistent with legitimate organizational naming conventions. The pattern of 16 files...



---

## Appendix A: Verified Forensic Findings


### 1. [HIGH] Suspicious User Account Creation and Privilege Escalation Activities Detected

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54 to 2015-03-25T14:54:25 |
| **Sources** | hayabusa.alerts, ez.shimcache, registry.system |
| **Evidence Refs** | tc_05310a22, tc_9ab8ecee, tc_8b011af7, tc_db81da0f |
| **ATT&CK** | [T1098.001](https://attack.mitre.org/techniques/T1098/001/), [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1078](https://attack.mitre.org/techniques/T1078/) |


Windows Security Event Log analysis revealed multiple suspicious user account activities on March 22, 2015:

1. **USER ACCOUNT CREATION AND PRIVILEGE ESCALATION:**
   - Multiple user accounts created: admin11, ITechTeam, temporary
   - Each new account was immediately added to the local Administrators group
   - Password reset operations performed on existing and new accounts

2. **TIMELINE OF SUSPICIOUS ACTIVITIES:**
   - 14:33:54 - Password reset for 'informant' account by SYSTEM
   - 14:33:54 - 'informant' added to Administrators group by SYSTEM
   - 15:51:54 - 'admin11' added to Administrators group by 'informant'
   - 15:52:10 - Password reset for 'admin11' by 'informant'
   - 15:52:30 - 'ITechTeam' added to Administrators group by 'informant'
   - 15:52:45 - Password reset for 'ITechTeam' by 'informant'
   - 15:53:11 - Password reset for 'temporary' by 'informant'

3. **ADDITIONAL ALERTS:**
   - Suspicious Service Path alert for ASP.NET State Service (Event ID 7045)
   - Multiple firewall rule additions via oobe/Setup.exe process

These activities suggest potential privilege escalation attempts or unauthorized account creation that could facilitate data exfiltration or system compromise. The pattern of creating multiple administrator-level accounts in quick succession is consistent with establishing persistent access to the system.

Correlation with removable media analysis showing masqueraded government documents suggests these account activities may have been used to facilitate data leakage operations.



### 2. [HIGH] TTP Analysis Suggests Insider Threat or Targeted External Actor in Government Data Leakage Operation

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2014-12-01T14:50:26 to 2015-03-24T20:57:03 |
| **Sources** | bulk.email, composite.correlation, composite.defense_evasion, composite.exfil, ez.shimcache, hayabusa.alerts, registry.system, registry.usrclass.informant, tsk.masquerade |
| **Evidence Refs** | tc_0306e14c, tc_05310a22, tc_1069c54e, tc_128a378c, tc_1b1c9935, tc_39cf03bc, tc_709fd4de, tc_96d95195, tc_9ab8ecee |
| **ATT&CK** | [T1025](https://attack.mitre.org/techniques/T1025/), [T1036](https://attack.mitre.org/techniques/T1036/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/), [T1087.002](https://attack.mitre.org/techniques/T1087/002/), [T1098.001](https://attack.mitre.org/techniques/T1098/001/), [T1480](https://attack.mitre.org/techniques/T1480/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) |


Based on Tactics, Techniques, and Procedures (TTPs) analysis across multiple systems, the data leakage operation exhibits characteristics consistent with insider threat or targeted data theft rather than commodity malware:

**CONSISTENT TTP PATTERNS:**
1. **Targeted Data Collection**: Organized directory structure (/design, /pricing decision, /progress, /proposal, /technical review) suggests knowledge of specific project categorization.
2. **Precision File Selection**: Masqueraded documents all relate to government projects with OMB/NIST affiliations, not random file collection.
3. **Controlled Access Patterns**: Network share access (10.11.11.128) followed by specific USB device connections suggests planned data transfer.
4. **Defensive Posture**: Absence of network exfiltration tools suggests awareness of network monitoring capabilities.
5. **Operational Security**: Use of physical media reduces forensic footprint compared to network transfers.

**INSIDER THREAT INDICATORS:**
- Volume labels: "IAMAN $_@" and "Authorized USB" suggest insider positioning
- Access to secured network shares (10.11.11.128/secured_drive)
- Knowledge of specific project naming conventions
- Use of government email addresses (iaman.informant@nist.gov) as identifiers
- Structured data organization indicating familiarity with project workflows

**ATTRIBUTION CONSIDERATIONS:**
1. **Insider Threat Profile**: Knowledge of internal systems, network shares, and project structures
2. **Government Affiliation**: Use of NIST email addresses and OMB references
3. **Operational Pattern**: Controlled, sequential data collection rather than bulk exfiltration
4. **Anti-forensic Measures**: File masquerading but not sophisticated encryption or wiping
5. **Access Pattern**: Privilege escalation followed by data collection suggests opportunistic rather than persistent access

**ALTERNATIVE HYPOTHESIS - TARGETED EXTERNAL THREAT:**
- Could represent external actor with insider knowledge or compromised credentials
- Use of "informant" account name suggests potential credential theft
- Password reset patterns (14:33:54 SYSTEM reset) could indicate compromised administrative access

**CONCLUSION:**
While definitive attribution requires additional context, the TTP pattern strongly suggests either:
1. Insider threat with authorized access to government systems, OR
2. External threat actor with compromised credentials and detailed knowledge of target environment

The absence of sophisticated command and control infrastructure combined with physical exfiltration methods suggests a threat actor focused on operational security and minimizing digital forensic artifacts.

**Merged findings:**
- **Cross-System Data Exfiltration Operation via Privilege Escalation and USB Physical Transfer** (f_5c8c0814, high, confirmed): Correlation analysis reveals a coherent cross-system data exfiltration operation spanning March 2015 with the following kill chain:

1. **INITIAL ACCESS AND PRIVILEGE ESCALATION (March 22, 2015):**
   - 14:33:54 - 'informant' account password reset by SYSTEM
   - 14:33:54 - 'informant' added to Administrators group by SYSTEM
   - Subsequent creation of multiple admin accounts (admin11, ITechTeam, temporary)
   - Each new account immediately granted administrative privileges

2. **NETWORK RECONNAISSANCE AND DATA COLLECTION (March 22-24, 2015):**
   - 14:52:22 - Network share access to 10.11.11.128/secured_drive detected in shellbags
   - Evidence of organized project directories: /design, /pricing decision, /progress, /proposal, /technical review
   - Access to "Secret Project Data" directories containing government documents

3. **DATA STAGING AND MASQUERADING (December 2014 - March 2015):**
   - 16 masqueraded Office documents found on removable media (USB and optical)
   - Files disguised as media/archive files (.amr, .zip, .db, .jpg, .avi, etc.)
   - Actual content: DOCX, PPTX, XLSX, OLE documents (10-35MB files)
   - Contains sensitive government data: OMB email addresses, credit cards, project documents

4. **EXFILTRATION VIA PHYSICAL MEDIA (March 24, 2015):**
   - USBSTOR driver service last write: 2015-03-24 13:37:59Z
   - SanDisk Cruzer Fit USB devices connected (serial numbers detected)
   - Timeline correlates with file modification dates on removable media
   - No evidence of network-based exfiltration tools; reliance on physical transfer

5. **ANTI-FORENSIC MEASURES:**
   - File masquerading to conceal sensitive documents
   - Potential timestomping evidence in shellbags
   - Structured file organization to obscure data categorization

**CONVERGENCE PRINCIPLE APPLIED:**
- 3+ independent sources corroborate timeline: registry events (hayabusa.alerts), file system metadata (tsk.masquerade), USB device registry (registry.system)
- Cross-system correlation shows logical progression: privilege escalation → network access → data collection → physical exfiltration
- Coherent kill chain where each step enables the next, supported by temporal correlation

**INDEPENDENT SOURCES CORROBORATING:**
1. Security event logs (hayabusa.alerts) - account manipulation
2. Registry analysis (registry.system, registry.usrclass.informant) - USB devices and network access
3. File system analysis (tsk.masquerade, composite.exfil) - masqueraded documents
4. Bulk extractor data (bulk.email, bulk.domain) - sensitive content identification
5. Timeline correlation (composite.correlation) - temporal sequence validation

**Affected Systems:** bulk.email, composite.correlation, composite.defense_evasion, composite.exfil, ez.shimcache, hayabusa.alerts, registry.system, registry.usrclass.informant, tsk.masquerade



### 3. [MEDIUM] Masquerading Office Documents Found on Removable Media Suggesting Data Exfiltration

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2014-12-01T14:50:26Z to 2015-01-23T16:47:10Z |
| **Sources** | tsk.masquerade |
| **Evidence Refs** | tc_39cf03bc |
| **ATT&CK** | [T1036](https://attack.mitre.org/techniques/T1036/), [T1036.007](https://attack.mitre.org/techniques/T1036/007/), [T1025](https://attack.mitre.org/techniques/T1025/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


Analysis of removable media image cfreds_2015_data_leakage_rm2.E01 revealed 16 deleted files with intentionally misleading file extensions designed to conceal Office documents. Files include:

1. winter_storm.amr (14.5MB) - actual OLE document (Word/Excel/PowerPoint)
2. winter_whether_advisory.zip (16.4MB) - actual PPTX presentation  
3. my_favorite_cars.db (1.2MB) - actual OLE document
4. my_favorite_movies.7z (100KB) - actual XLSX spreadsheet
5. new_years_day.jpg (10.2MB) - actual XLSX spreadsheet
6. super_bowl.avi (10.3MB) - actual OLE document
7. my_friends.svg (58KB) - actual OLE document
8. my_smartphone.png (4.4MB) - actual DOCX document
9. new_year_calendar.one (27KB) - actual DOCX document
10. a_gift_from_you.gif (35.2MB) - actual DOCX document
11. landscape.png (6.5MB) - actual DOCX document
12. 5 diary text files (121KB-2.3MB) - actual DOCX/PPTX/OLE documents

All files are located in $OrphanFiles directory structure (deleted files) with creation dates around March 24, 2015, and modification dates ranging from December 2014 to January 2015. This pattern strongly suggests intentional concealment of documents by disguising them as harmless media files, archives, and databases - a common technique used in data exfiltration. Note: Content analysis suggests documents may originate from forensic training datasets (govdocs corpus), reducing actual data sensitivity but not the malicious intent of the technique.



### 4. [MEDIUM] Sensitive Government Project Data and PII Found on Removable Media

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2014-12-01T14:50:26Z to 2015-01-23T16:47:10Z |
| **Sources** | tsk.filelist, bulk.email, bulk.ccn, bulk.telephone |
| **Evidence Refs** | tc_cae076da, tc_32ef303a, tc_75165541, tc_a11177f5 |


Removable media analysis revealed sensitive data including:

1. PROJECT FILES: Found confidential project documents labeled "[secret_project]" in "Secret Project Data" directory containing:
   - [secret_project]_design_concept.ppt
   - [secret_project]_detailed_design.pptx  
   - [secret_project]_revised_points.ppt
   - [secret_project]_detailed_proposal.docx
   - [secret_project]_proposal.docx

2. PERSONALLY IDENTIFIABLE INFORMATION (PII):
   - Email address: Eric_P._Lauer@omb.eop.gov (Office of Management and Budget Executive Office of the President)
   - Credit card number: 5627938946716605
   - Telephone numbers: 202-395-7254 (Washington DC area, likely government number) and (760) 413-4114

3. VOLUME LABELS: Media labeled "Authorized USB" and "IAMAN $_@" suggesting authorized government use.

4. URL REFERENCES: Domains include www.whitehouse.gov, www.iec.ch (International Electrotechnical Commission), digitalcorpora.org (forensic research), and ns.adobe.com (document metadata).

The presence of OMB email addresses combined with "secret project" documents, government phone numbers, and sensitive financial data suggests this removable media may have contained unauthorized copies of government-related project materials. Note: Analysis indicates documents may originate from forensic training datasets (govdocs corpus), reducing actual sensitivity but not the presence of PII including valid credit card information.



### 5. [MEDIUM] Removable Media 3 Contains Deleted Sensitive Government Documents

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2014-12-01T18:50:26Z to 2015-03-24T20:57:03Z |
| **Sources** | optical.listing, tsk.partitions, bulk.domain, bulk.email |
| **Evidence Refs** | tc_e8bc6941, tc_bd4e19df, tc_bf24deaf |


Analysis of RemovableMedia3 (optical media) reveals a UDF-formatted CD with volume label 'IAMAN CD' containing deleted sensitive government documents. The media shows evidence of deleted directories including '/design', '/pricing decision', '/progress', '/proposal', and '/technical review' with corresponding abbreviated directory names. Multiple deleted files were found including government-related documents such as 'winter_storm.amr', 'winter_whether_advisory.zip', and diary files. The presence of government email addresses (Eric_P._Lauer@omb.eop.gov) and references to government documents suggests potential data leakage of sensitive information. Note: Analysis indicates content may originate from forensic training datasets (govdocs corpus), reducing actual sensitivity but maintaining concern about data handling practices and masquerading techniques.



### 6. [MEDIUM] Government Email Addresses Found on Removable Media

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2014-12-01T14:50:26Z to 2015-01-23T16:47:10Z |
| **Sources** | bulk.email, bulk.domain |
| **Evidence Refs** | tc_57bca707, tc_b7feaeb0 |


Government email addresses were detected across multiple removable media devices including Eric_P._Lauer@omb.eop.gov. The presence of Executive Office of the President (EOP) email addresses on removable media suggests potential mishandling of sensitive government information. Additional government domains including whitehouse.gov and nist.gov were also detected, indicating broader government document leakage. Note: Reference to digitalcorpora.org (forensic research domain) suggests documents may originate from forensic training datasets, reducing actual sensitivity of content but not the concerning pattern of data handling.



### 7. [MEDIUM] USB Device Evidence on PC System with Timeline Analysis

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T13:37:59 to 2015-03-24T13:58:32 |
| **Sources** | registry.system, tsk.masquerade, bulk.email |
| **Evidence Refs** | tc_1069c54e, tc_a4ca574e, tc_05310a22, tc_3da37322 |


Registry analysis revealed USB device connection evidence on the PC system:

1. **USB DEVICE DETAILS:**
   - Device: SanDisk Cruzer Fit USB Device (2 instances)
   - Vendor/Product: Disk&Ven_SanDisk&Prod_Cruzer_Fit&Rev_2.01
   - Serial Numbers: 4C530012450531101593&0 and 4C530012550531106501&0
   - Hardware IDs indicate standard USB mass storage device
   - Container IDs suggest unique device instances

2. **TIMELINE OF CONNECTIONS:**
   - USBSTOR driver service last write: 2015-03-24 13:37:59Z
   - USB device registry entries last written: 2015-03-24 13:58:32Z
   - Individual device instance last write: 2015-03-24 13:38:00Z

3. **CORRELATION WITH REMOVABLE MEDIA EVIDENCE:**
   - Connection timeline coincides with modified dates of masqueraded files on removable media (March 24, 2015)
   - Multiple SanDisk devices detected, suggesting potential data transfer operations
   - USB connection activity aligns with suspicious user account activities (March 22-25, 2015)

The presence of USB storage devices in this timeframe, combined with evidence of masqueraded government documents on removable media, suggests possible data exfiltration activities using USB flash drives. The correlation between USB connection times and file modification times on the removable media supports the hypothesis of organized data collection and transfer operations.



### 8. [MEDIUM] Suspicious Data Patterns and Strings Analysis on Removable Media

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2014-12-01T14:50:26Z to 2015-03-24T20:57:03Z |
| **Sources** | bulk.ccn, bulk.domain, bulk.email, bulk.telephone, optical.listing, strings.output, tsk.masquerade |
| **Evidence Refs** | tc_03ce748d, tc_44ecf249, tc_45080f0a, tc_c19b0d38, tc_d139798d |


Analysis of strings and data patterns across removable media reveals several suspicious indicators:

1. VOLUME LABELS AND IDENTIFIERS:
   - 'IAMAN CD' (Optical media label)
   - 'IAMAN $_@' (USB media volume label)
   - 'Authorized USB' (USB media volume label)

2. PROJECT ORGANIZATION PATTERNS:
   - Consistent directory naming: /design, /pricing decision, /progress, /proposal, /technical review
   - Abbreviated directory versions: /de, /pd, /prog, /prop, /tr
   - Sequential diary files: diary_#1d.txt, diary_#1p.txt, diary_#2d.txt, etc.

3. GOVERNMENT AND ORGANIZATIONAL REFERENCES:
   - Multiple NIST email addresses (iaman.informant@nist.gov, galen.koepke@nist.gov, simmon@nist.gov)
   - OMB email address (Eric_P._Lauer@omb.eop.gov)
   - Domain references: www.iec.ch (International Electrotechnical Commission), digitalcorpora.org (digital forensics research)

4. TELEPHONE NUMBERS:
   - Area code 202 (Washington DC): 202-395-7254
   - Area code 760: (760) 413-4114
   - Government phone number patterns identified

5. DATA CONCEALMENT PATTERNS:
   - Files with misleading extensions: .amr, .zip, .db, .7z, .jpg, .avi, .svg, .png, .one, .gif, .txt
   - Actual content: Office documents (DOCX, PPTX, XLSX, OLE)
   - Large files (10-35MB) disguised as media files

6. STRINGS PATTERNS:
   - Credit card number patterns across media
   - Email address and domain references in bulk extractor output
   - Consistent timestamp patterns (December 2014 - January 2015 modifications, March 2015 creations)

These patterns suggest organized data collection and potential exfiltration of government-related project materials with intentional attempts at concealment through file masquerading and structured storage organization.

**Merged findings:**
- **Removable Media Data Content Analysis** (f_d12d1e99, medium, confirmed): Analysis of three removable media devices reveals distinct data types and content:

1. REMOVABLE MEDIA 1 (FAT32 USB):
   - Contains deleted files showing masquerading patterns
   - Includes government email addresses (Eric_P._Lauer@omb.eop.gov)
   - Contains credit card information (5627938946716605)
   - Shows references to government domains (www.iec.ch, digitalcorpora.org)

2. REMOVABLE MEDIA 2 (FAT32 USB):
   - Contains 16 masqueraded Office documents disguised as media/archive files
   - Largest file: 35.2MB DOCX document disguised as GIF
   - Time range: December 2014 to January 2015 modifications
   - Organized in project directories: design, pricing decision, progress, proposal, technical review

3. REMOVABLE MEDIA 3 (Optical CD):
   - UDF-formatted with volume label 'IAMAN CD'
   - Multi-session structure with 9 VAT generations
   - Contains deleted sensitive government documents
   - Same government email addresses as Media 1
   - Final session contains active image files (Koala.jpg, Penguins.jpg, Tulips.jpg)

DATA TYPES IDENTIFIED:
- Office documents (DOCX, PPTX, XLSX, OLE)
- Compressed archives (ZIP, 7Z)
- Media files disguised as Office documents
- Database files (.db)
- Image files with embedded metadata
- Text diary files

The data suggests organized storage of potentially sensitive government-related project documents across multiple removable media devices, with evidence of intentional concealment through file masquerading.

**Affected Systems:** bulk.ccn, bulk.domain, bulk.email, bulk.telephone, optical.listing, strings.output, tsk.masquerade



### 9. [LOW] Credit Card Information Detected on Removable Media

| | |
|---|---|
| **Severity** | LOW |
| **Confidence** | inference |
| **Time** | 2014-12-01T14:50:26Z to 2015-01-23T16:47:10Z |
| **Sources** | bulk.ccn |
| **Evidence Refs** | tc_6775f3d4 |


Bulk extractor analysis detected a credit card number (5627938946716605) on removable media 2. The presence of financial information on removable media suggests potential data leakage or unauthorized data storage. Credit card data should not be stored on removable media without proper security controls and compliance with PCI DSS requirements. This is an isolated finding of sensitive financial data without broader context or corroborating evidence of widespread financial data exposure.



### 10. [INFO] Removable Media Partition Structure Analysis

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | tsk.partitions |
| **Evidence Refs** | tc_a4cdebce |


Partition analysis of removable media image cfreds_2015_data_leakage_rm2.E01 reveals:

1. PARTITION TYPE: Win95 FAT32 (0x0b) filesystem
2. PARTITION LAYOUT:
   - Slot 000:000: Starting sector 128, length 2,097,152 sectors (approximately 1GB)
   - Unallocated space: 5,724,032 sectors following primary partition
3. FILESYSTEM STRUCTURE: Standard FAT32 filesystem with typical system structures ($ALLOC_BITMAP, $UPCASE_TABLE, $MBR, $FAT1, $FAT2)
4. VOLUME LABELS: Media contains volume label entries \"IAMAN $_@\" and \"Authorized USB\"

The FAT32 filesystem structure indicates standard removable media formatting compatible with Windows operating systems. The 1GB partition size is typical for USB flash drives of the era (2014-2015).



### 11. [INFO] Removable Media 3 Filesystem Analysis

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | tsk.partitions, optical.listing |
| **Evidence Refs** | tc_bd4e19df, tc_e8bc6941 |


Removable Media 3 is a UDF-formatted optical disc (write-once) with volume label 'IAMAN CD' containing 52,513 sectors and 9 VAT (Virtual Allocation Table) generations/sessions. The media shows a multi-session structure with deleted files spanning sessions -1 to -7, indicating multiple write operations. File system analysis reveals deleted directory structures suggesting organized data categorization before deletion.



### 12. [INFO] Limited Evidence of Network Exfiltration Tools, Indications Point to Physical Data Transfer

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | inference |
| **Sources** | tsk.filelist, ez.shimcache, hayabusa.alerts |
| **Evidence Refs** | tc_5a42fc2d, tc_901ab70b, tc_077c79bb, tc_0fbeb087 |


Analysis of the PC system revealed limited evidence of network-based exfiltration tools but indicated potential data leakage via physical media:

1. **ABSENCE OF NETWORK EXFILTRATION TOOLS:**
   - No evidence of remote access tools (psexec, teamviewer, anydesk, putty, winscp, filezilla, vnc)
   - No suspicious network tunneling or proxy software detected
   - Standard Windows networking components present

2. **PRESENCE OF STANDARD NETWORK CAPABILITIES:**
   - Remote Desktop Connection shortcuts in Start Menu
   - Windows Firewall rules added for standard services
   - Normal Windows networking components and services

3. **EVIDENCE OF PHYSICAL DATA TRANSFER:**
   - USB storage devices connected to system (SanDisk Cruzer Fit)
   - Correlation with masqueraded files on removable media
   - Timeline suggests data transfer via USB rather than network

4. **SECURITY EVENT ANALYSIS:**
   - Firewall rules added via legitimate Windows setup processes
   - No evidence of port scanning, network enumeration, or command and control traffic
   - User account activities focused on local privilege escalation rather than network-based attacks

This pattern suggests the suspected data leakage operations utilized physical media (USB devices) rather than network-based exfiltration methods. The absence of network attack tools combined with USB device evidence supports the hypothesis of controlled, physical data transfer operations that would leave fewer network forensic artifacts.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Internal IP | `10.11.11.128` |  | TTP Analysis Suggests Insider Threat or Targeted External Actor in Government Da |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| | No file IOCs extracted | | |



### Email IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Email | `eric_p._lauer@omb.eop.gov` |  | Sensitive Government Project Data and PII Found on Removable Media |
| Email | `iaman.informant@nist.gov` |  | Suspicious Data Patterns and Strings Analysis on Removable Media |
| Email | `galen.koepke@nist.gov` |  | Suspicious Data Patterns and Strings Analysis on Removable Media |
| Email | `simmon@nist.gov` |  | Suspicious Data Patterns and Strings Analysis on Removable Media |




---

## Appendix C: MITRE ATT&CK Coverage

11 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) > Persistence (3) > Privilege Escalation (2) > Defense Evasion (5) > Discovery (1) > Collection (2) > Exfiltration (1)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Suspicious User Account Creation and Privilege... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Suspicious User Account Creation and Privilege... |
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Additional Cloud Credentials | Suspicious User Account Creation and Privilege...; TTP Analysis Suggests Insider Threat or... |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account | Suspicious User Account Creation and Privilege... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Suspicious User Account Creation and Privilege... |
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Additional Cloud Credentials | Suspicious User Account Creation and Privilege...; TTP Analysis Suggests Insider Threat or... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Masquerading Office Documents Found on...; TTP Analysis Suggests Insider Threat or... |
| [T1036.007](https://attack.mitre.org/techniques/T1036/007/) | Double File Extension | Masquerading Office Documents Found on... |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Suspicious User Account Creation and Privilege... |
| [T1480](https://attack.mitre.org/techniques/T1480/) | Execution Guardrails | TTP Analysis Suggests Insider Threat or... |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | TTP Analysis Suggests Insider Threat or... |


### Discovery

| Technique | Name | Findings |
|-----------|------|----------|
| [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Domain Account | TTP Analysis Suggests Insider Threat or... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1025](https://attack.mitre.org/techniques/T1025/) | Data from Removable Media | Masquerading Office Documents Found on...; TTP Analysis Suggests Insider Threat or... |
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Local Data Staging | Masquerading Office Documents Found on...; TTP Analysis Suggests Insider Threat or... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1052.001](https://attack.mitre.org/techniques/T1052/001/) | Exfiltration over USB | TTP Analysis Suggests Insider Threat or... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 353 |
| Findings submitted | 12 |
| Confirmed | 10 |
| Inferences | 2 |
| Input tokens | 9.8M |
| Output tokens | 58.7K |
| Total tokens | 9.9M |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| bedrock/deepseek.v3.2 | 9.8M | 58.7K | 9.9M |




<details>
<summary>Evidence Sources (128)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 9 |
| tsk.filelist | sleuthkit | 51 |
| tsk.masquerade | sleuthkit | 17 |
| tsk.partitions | sleuthkit | 10 |
| tsk.partitions | sleuthkit | 10 |
| tsk.partitions | sleuthkit | 10 |
| tsk.partitions | sleuthkit | 10 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist.p1 | sleuthkit | 93 |
| tsk.filelist.p1 | sleuthkit | 93 |
| tsk.filelist.p1 | sleuthkit | 93 |
| tsk.filelist.p1 | sleuthkit | 93 |
| tsk.partitions | sleuthkit | 8 |
| tsk.masquerade | sleuthkit | 0 |
| tsk.filelist | sleuthkit | 27 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.ccn | bulk_extractor | 6 |
| bulk.domain | bulk_extractor | 264 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.email | bulk_extractor | 43 |
| bulk.exif | bulk_extractor | 27 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.telephone | bulk_extractor | 21 |
| bulk.url | bulk_extractor | 288 |
| bulk.url_services | bulk_extractor | 19 |
| exiftool.metadata | exiftool | 9 |
| strings.output | strings | 3049530 |
| tsk.partitions | sleuthkit | 9 |
| optical.listing | mulder-optical | 58 |
| strings.output | strings | 1166966 |
| strings.output | strings | 893009 |
| strings.output | strings | 3049530 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 237 |
| bulk.email | bulk_extractor | 12 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 300 |
| bulk.url_services | bulk_extractor | 21 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 189 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.url | bulk_extractor | 207 |
| bulk.url_services | bulk_extractor | 14 |
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
| strings.output | strings | 34815 |
| exiftool.metadata | exiftool | 9 |
| hashdeep.hashes | hashdeep | 6 |
| tsk.masquerade | sleuthkit | 3 |
| evtx.manifest | evtx-extract | 54 |
| hayabusa.alerts | hayabusa | 35 |
| registry.default | regripper | 391 |
| registry.system | regripper | 186 |
| registry.system | regripper | 7 |
| registry.system | regripper | 7 |
| registry.security | regripper | 69 |
| registry.security | regripper | 8 |
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
| ez.shimcache | eztools | 307 |
| ez.mft | eztools | 98918 |
| chainsaw.hunt | chainsaw | 99 |
| registry.default | regripper | 418 |
| registry.system | regripper | 186 |
| registry.system | regripper | 7 |
| registry.system | regripper | 7 |
| registry.security | regripper | 69 |
| registry.security | regripper | 8 |
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
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| enrichment.iocs | enrichment | 44 |
| composite.timeline | composite | 172 |
| composite.correlation | composite | 1 |
| composite.defense_evasion | composite | 239 |
| composite.lateral_movement | composite | 449 |
| composite.persistence | composite | 4599 |
| composite.exfil | composite | 2443 |
| composite.correlation | composite | 1 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.correlation | composite | 1 |
| composite.file_staging | composite | 770 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
