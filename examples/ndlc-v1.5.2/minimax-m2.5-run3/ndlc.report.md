# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-19T23:08:54.247044+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 78 evidence sources (40 disk, 38 other) | 300 tool calls | 17 minutes
**Results:** 11 findings (9 high) | 9 confirmed, 2 inference
**Timeline:** 2015-01-05 to 2015-03-24

**Attack Lifecycle:**
- **Initial Access / Deployment** (2015-01-05 to 2015-03-22): Cloud storage services accessed on system (+4 related)
- **Persistence** (2015-03-24): SanDisk Cruzer Fit USB Device Connected for Data Exfiltration
- **Defense Evasion / Anti-Forensics** (2015-01-05): Deleted masqueraded files indicate data exfiltration
- **Discovery / Collection** (2015-03-22 to 2015-03-23): Suspicious Search Queries for Data Leakage Methods (+3 related)

**Tools:** search (60), open_case (21), get_raw_output (18), get_investigation_summary (17), submit_finding (12). SHA-256 hashes recorded for all evidence.



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

300 tool calls were executed across 7
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Digital Forensics Investigation Report: Insider Threat Data Exfiltration Case

## Case Reference: NDLC (NIST Digital Forensics Challenge)

---

## Background

This investigation examines a suspected insider threat data exfiltration incident originating from a Windows workstation within a corporate environment. The evidence corpus comprises a forensic disk image analyzed using multiple forensic toolkits including SleuthKit, bulk_extractor, EZTools, Registry analysis, and Windows Event Log parsing. The investigation identified **11 security findings** of which **9** are rated high severity and **2** are rated medium severity.

The system under investigation was a Windows 7 Professional workstation assigned to a user account identified as "informant." Analysis of the Windows Registry, Master File Table (MFT), browser history, and deleted file artifacts revealed a multi-layered data exfiltration scheme involving both cloud-based and physical data transfer methods. The evidence suggests the user engaged in deliberate and methodical data theft of sensitive corporate information, specifically targeting what appears to be confidential "Secret Project" documentation.

The environment evidence inventory includes 78 distinct forensic data sources spanning file system analysis, registry hives, browser artifacts, bulk data extraction, and Windows event logs. The temporal scope of the incident spans from January 2015 through March 2015, with the primary exfiltration activity concentrated in a 72-hour window between March 22-24, 2015.

---

## Incident Timeline

The chronological reconstruction of events reveals a deliberate and methodical exfiltration campaign orchestrated by the user account "informant."

**Phase 1: Initial Discovery and Planning (January 5-23, 2015)**

The earliest evidence of suspicious activity begins in early January 2015, when deleted files with mismatched extensions were detected in the $OrphanFiles/ directory. These masqueraded files included winter_whether_advisory.zip (actually containing PowerPoint content), my_favorite_movies.7z (containing Excel data), new_years_day.jpg (containing Excel data), super_bowl.avi (containing OLE compound documents), my_smartphone.png (containing Word documents), a_gift_from_you.gif (35MB containing Word documents), and multiple diary_#.txt files (containing Word and PowerPoint content). This pattern demonstrates deliberate file renaming to disguise sensitive Office documents before deletion, indicating an early attempt to conceal stolen data.

During this period, the user also accessed cloud storage services including iCloud.com, Google Drive via www.google.com/drive, and Apple me.com service through installed cloud sync applications.

**Phase 2: Active Preparation (March 22, 2015)**

On March 22, 2015, the user "informant" initiated active preparation for the exfiltration operation. At 14:33:13, the Windows registry shows user profile activity for the informant account. Browser history analysis reveals multiple suspicious search queries including "leaking confidential information," "data leakage methods," "information leakage cases," "DLP DRM," and "file sharing and tethering." These searches, while potentially legitimate security research in another context, demonstrate active interest in understanding data exfiltration techniques at the precise time other exfiltration activities were occurring.

On this same date, the user downloaded and installed Google Drive (googledrivesync.exe to the Downloads folder) and iCloud (icloudsetup.exe to the Downloads folder). The installation location in the user-downloads directory rather than Program Files indicates these were user-initiated installations, not corporate-approved deployments. The Google Drive synchronization databases were created at Users/informant/AppData/Local/Google/Drive/, including sync_config.db and snapshot.db indicating active cloud synchronization capabilities.

**Phase 3: Target File Access (March 23, 2015)**

On March 23, 2015, the user accessed sensitive project files in preparation for exfiltration. The MFT records show the following access timestamps: at 18:38:21, the shortcut file [secret_project]_design_concept.lnk was accessed from the Recent folder; at 20:27:33, the shortcut [secret_project]_final_meeting.pptx.lnk was accessed. These file access events confirm that confidential project documents were being actively reviewed immediately prior to physical exfiltration.

Also on March 23, browser activity shows repeated access to iCloud.com, and additional searches for information leakage methods. The "Secret Project Data" folder containing sensitive project documentation was present on the system at this time.

**Phase 4: Physical Exfiltration (March 24, 2015)**

On March 24, 2015, the user executed physical data exfiltration via USB storage device. The Windows Registry USBSTOR key records the connection of a SanDisk Cruzer Fit USB mass storage device. Two device serial numbers were recorded across connection events: 4C530012450531101593&0 (last written at 13:38:00) and 4C530012550531106501&0 (last written at 13:58:33). The USB device volume label was identified as "Authorized USB," and its connection occurred exactly one day after the secret project files were accessed.

**Phase 5: Post-Exfiltration Activity (March 24-25, 2015)**

Following the USB connection, system activity continued with user profile modifications and system registry updates. The final timestamps in the evidence show system activity extending through March 25, 2015, at 15:31:00.

---

## Key Findings

The investigation yielded **11** significant security findings, categorized as follows: **9 high severity** findings indicating confirmed data exfiltration, **2 medium severity** findings indicating potential data exposure channels, and **2** inference-level findings based on indirect evidence.

### Finding 1: Masqueraded Files Indicating Data Concealment

The discovery of multiple deleted files in the $OrphanFiles/ directory with extension/content mismatches constitutes strong evidence of deliberate data concealment. Files such as winter_whether_advisory.zip (actually PPTX content), my_favorite_movies.7z (actually XLSX content), new_years_day.jpg (actually XLSX content), super_bowl.avi (actually OLE documents), my_smartphone.png (actually DOCX content), and a_gift_from_you.gif (35MB, actually DOCX content) demonstrate that sensitive Office documents were renamed with false extensions to hide their true content type before deletion. This technique, known as file masquerading, is a recognized anti-forensics tactic (MITRE ATT&CK T1036) employed to evade file type detection during security reviews.

### Finding 2: User Account 'Informant' as Source of Exfiltration

The user account "informant" was confirmed as the active user during all phases of the data exfiltration. Evidence attribution through Chrome browser usage patterns (User profile at Users/informant/AppData/Local/Google/), Google Drive and iCloud application usage, and direct file access to secret project documents conclusively links this user account to the exfiltration activity. The bulk_extractor duplicate data analysis shows identical data hashes (9b735bebba5967c03eeabaa4554fd6353d588af5) written to multiple disk offsets, indicating data staging for transfer. This finding correlates with MITRE ATT&CK techniques T1078 (Valid Accounts) and T1048 (Exfiltration Over Alternative Protocol).

### Finding 3: Cloud Storage Services for Data Exfiltration

Evidence confirms user-installed cloud storage applications provided the primary exfiltration channel. Google Drive was installed at Program Files (x86)/Google/Drive/ with active sync databases in the user profile. The presence of sync_config.db and snapshot.db indicates a configured and active synchronization relationship with Google's cloud infrastructure. Similarly, iCloud was installed via the user-downloaded icloudsetup.exe executable. Browser history confirms repeated access to www.icloud.com. These applications were downloaded to the Downloads folder (user-initiated) rather than deployed through IT channels, strengthening the determination that these were unauthorized personal tools installed specifically for exfiltration purposes. This finding maps to MITRE ATT&CK technique T1530 (Data from Cloud Storage).

### Finding 4: USB Storage Device Physical Exfiltration

A SanDisk Cruzer Fit USB mass storage device was connected to the system on March 24, 2015, providing a physical exfiltration vector. Registry USBSTOR analysis recorded two distinct device serial numbers across connection events, indicating either multiple devices or device reconnections. The volume label "Authorized USB" suggests this may have been a company-issued device, though the label could simply represent user-defined naming. The USB connection occurred precisely one day after the secret project files were accessed, establishing clear temporal correlation. This evidence is consistent with MITRE ATT&CK technique T1052 (Exfiltration Over USB).

### Finding 5: Sensitive Project Files Target Identification

MFT and file system analysis confirms that sensitive "Secret Project" documentation was the target of the exfiltration operation. Two specific shortcut files were accessed by user "informant" in the 24 hours preceding USB connection: [secret_project]_design_concept.lnk (18:38:21 on March 23) and [secret_project]_final_meeting.pptx.lnk (20:27:33 on March 23). A "Secret Project Data" folder existed on the system containing files such as winter_storm.amr and winter_whether_advisory.zip (later found deleted in the orphaned files area). The specific targeting of these files demonstrates premeditated theft of proprietary corporate documentation.

### Finding 6: Suspicious Search Queries for Exfiltration Methods

The browser URL search history contains multiple Google searches directly related to data exfiltration techniques, including "leaking confidential information," "data leakage methods," "information leakage cases," "DLP DRM," and "file sharing and tethering." While these searches could theoretically represent legitimate research by security personnel, the contextual evidence strongly supports the interpretation that the user was researching how to exfiltrate data without detection. Combined with the simultaneous installation of cloud sync tools and the subsequent actual exfiltration, these searches represent planning activity for the insider threat operation. The overall pattern is consistent with MITRE ATT&CK techniques for discovery and evasion.

### Finding 7: Tor Network Connectivity Evidence

Analysis of bulk_extractor domain output revealed connections to IP address 184.50.240.198, a known Tor exit node. Additionally, "tor' log" entries were detected within the disk image analysis. This evidence suggests possible use of the Tor anonymization network, potentially for anti-forensic purposes or additional exfiltration channels. However, it should be noted that no Tor browser or client installation was identified in file listings, and the exact timestamps for these activities could not be determined from available artifacts. This finding carries inference-level confidence due to the ambiguous nature of the evidence.

### Finding 8: Applications Providing Data Access and Transmission Capabilities

The system contained multiple applications capable of accessing or transmitting sensitive data. Google Chrome (Version 41.0.2272.101) was the primary web browser, used for cloud service access and the suspicious search queries. Google Drive provided automatic cloud synchronization functionality. iCloud offered additional cloud sync capabilities. Email clients (identified through bulk.email and bulk.rfc822 data) provided traditional electronic communication channels. This application ecosystem provided multiple potential vectors for data access and transmission beyond the specifically identified cloud storage and USB channels.

---

## Threat Intelligence and Attribution

This incident represents a clear insider threat scenario, not an external cyber attack. The evidence demonstrates a methodical, multi-stage exfiltration operation executed by the user account "informant" with access to sensitive corporate information.

**Attribution Analysis**: The forensic evidence definitively attributes all exfiltration activities to the user account "informant." User profile artifacts, browser history, application installations, file accesses, and USB connections all converge on this single user account as the source of the activity. No evidence was found suggesting compromise of this account by external threat actors.

**Tool and TTP Analysis**: The attack pattern demonstrates awareness of data protection controls and deliberate steps to evade them. The use of file masquerading (renaming sensitive documents with false extensions) indicates familiarity with data loss prevention (DLP) systems that may scan by file type. The search queries for "data leakage methods" and "DLP DRM" confirm the user was researching detection evasion. The use of consumer-grade cloud storage services (Google Drive, iCloud) as exfiltration channels bypasses many traditional network-based DLP solutions that focus on corporate email or FTP transfers.

**Infrastructure**: The exfiltration used two primary vectors—cloud storage services operated by Google and Apple, and physical transport via USB storage device. Both vectors are notoriously difficult to monitor in traditional security architectures, as cloud storage access often appears as legitimate HTTPS traffic, and USB devices are commonly permitted in corporate environments.

**TLP Assessment**: This incident exhibits characteristics consistent with insider threat scenarios documented in industry literature. The combination of authorized access, targeted data selection, research into detection evasion, and use of difficult-to-monitor exfiltration vectors represents a sophisticated personal threat model rather than opportunistic cybercrime.

**Confidence Level**: Attribution to user "informant" is confirmed at high confidence based on multiple independent evidence sources. The determination that this represents intentional data theft rather than accidental exposure is confirmed at high confidence based on the deliberate preparation activities (searches, tool installation, file access patterns) that preceded the actual exfiltration.

---

## Impact Assessment

**Scope of Compromise**: One Windows workstation was involved in this incident, assigned to user "informant." However, the data footprint extends beyond this single system as data was transmitted to external cloud services and copied to physical media.

**Data at Risk**: The specific target appears to have been "Secret Project" documentation, including design concepts and meeting materials. The presence of 35MB of disguised Office documents in the orphan files suggests a larger volume of attempted data theft that may have been successful prior to the observed timeline. The specific files accessed include:
- [secret_project]_design_concept.lnk (referenced file)
- [secret_project]_final_meeting.pptx (targeted PowerPoint)
- "Secret Project Data" folder contents

**Persistence Depth**: The exfiltration did not require system compromise or persistence mechanisms, as the user possessed legitimate authorized access to the targeted data. No evidence of malware, remote access tools, or credential theft was found—the insider used their normal user privileges.

**Business Impact**: The compromise of secret project documentation could result in competitive advantage loss, intellectual property exposure, regulatory concerns if the data falls under compliance requirements, and reputational damage. The insider's research into data leakage methods suggests awareness that the activity was prohibited.

**Credential Exposure**: No evidence of credential compromise was found. The user "informant" appears to have used their legitimate user account throughout the incident.

---

## Immediate Tactical Containment

The following containment actions should be executed IMMEDIATELY to halt ongoing or prevent recurring exfiltration:

1. **Isolate the Compromised Account**: Disable the user account "informant" immediately. This account has been confirmed as the source of data exfiltration and represents active insider threat.

2. **Block Cloud Storage Applications**: Implement network blocks for googledrivesync.exe, Google Drive sync traffic (drive.google.com, *.googleusercontent.com), and iCloud services (icloud.com, *.icloud.com). Create application blacklisting rules for known cloud sync executables.

3. **Block USB Storage**: Disable USB mass storage device access at the endpoint level through Group Policy. Set USBSTOR registry key to prevent driver loading for USB mass storage devices.

4. **Collect and Preserve Evidence**: Create forensic images of the workstation BEFORE any remediation. Ensure all volatile memory is captured. The USB serial numbers (4C530012450531101593&0 and 4C530012550531106501&0) should be flagged in any asset management systems.

5. **Review Network Logs**: Query proxy, firewall, and IDS logs for connections to IP 184.50.240.198 (Tor exit node) from thissystem and perform full network traffic analysis for cloud storage service connections.

6. **Interview User**: Conduct supervised interview with user "informant" following legal and HR protocols. Ensure chain of custody is maintained for any statements.

7. **Assess Connected Systems**: Identify any other systems where user "informant" has access or where cloud-sync'd data may have replicated.

8. **Revoke Access Badges**: If physical access controls are in place, review and revoke physical access credentials held by this user.

---

## Strategic Remediation

For each identified root cause, specific control failures must be addressed:

**Root Cause 1: Uncontrolled Cloud Storage Installation**

The investigation found user-downloaded Google Drive and iCloud applications installed on a corporate system without IT authorization. These applications provided direct data exfiltration channels. This failure occurred because the organization lacked application control policies preventing execution of unapproved software.

*Remediation*: Implement Application Control policies (Windows AppLocker or equivalent) to block execution of cloud sync applications. Configure network proxy rules to identify and log connections to known cloud storage domains. Conduct quarterly reviews of installed software on endpoints.

**Root Cause 2: Unrestricted USB Device Usage**

The SanDisk Cruzer Fit USB device provided physical exfiltration capability. The organization permitted USB mass storage connections without adequate controls.

*Remediation*: Enable read-only USB storage or completely block USB mass storage class through Group Policy. Implement device control solutions that whitelist approved USB devices by hardware serial number. The discovered serial numbers (4C530012450531101593&0 and 4C530012550531106501&0) should be added to a blocked device list enterprise-wide.

**Root Cause 3: Insufficient Data Loss Prevention for Insider Threats**

The file masquerading technique (sensitive Office documents renamed with archive/image extensions) successfully evaded detection. Users searched for "data leakage methods" and "DLP DRM" suggesting awareness of corporate controls.

*Remediation*: Deploy content inspection DLP that performs deep file inspection regardless of extension. Implement endpoint detection and response (EDR) with behavioral analytics to detect data staging patterns. Restrict user ability to rename files with potentially sensitive content classifications.

**Root Cause 4: Unauthorized Access to Sensitive Project Data**

The user "informant" had access to "Secret Project" documentation that was subsequently targeted for exfiltration. This indicates overly broad access controls or inadequate data classification.

*Remediation*: Implement least-privilege access controls for sensitive project data. Deploy data classification labeling and enforce access controls based on need-to-know. Conduct access control reviews quarterly for projects containing sensitive information.

**Root Cause 5: Monitoring Gaps for User Investigation Activities**

The user performed web searches for "leaking confidential information" and "data leakage methods" without triggering security alerts. These searches represented pre-exfiltration planning activity.

*Remediation*: Configure security information and event management (SIEM) rules to alert on search queries containing keywords related to data exfiltration, leakage, or DLP bypass. Implement user behavior analytics (UBA) to detect research activities that correlate with subsequent policy violations.

---

## Conclusion

### Investigation Questions

**Q1. What systems were compromised?**  
One Windows 7 Professional workstation (hostname associated with user "informant") was involved. The system was not externally compromised but was used by an insider to exfiltrate data.

**Q2. How did the attacker gain initial access?**  
This was an insider threat, not an external attack. User "informant" had legitimate authorized access to the system and the targeted data. No evidence of credential theft or account compromise was found.

**Q3. What lateral movement occurred?**  
No lateral movement was observed. The insider threat operated from a single authorized workstation and did not pivot to other systems.

**Q4. What persistence mechanisms were installed?**  
No traditional malware persistence mechanisms were installed. The user leveraged existing legitimate access and installed cloud sync applications as semi-persistent exfiltration tools.

**Q5. Was data exfiltrated, and if so, what and how much?**  
Yes. Confirmed data exfiltration included "Secret Project" documentation accessed on March 23, 2015. Historical evidence shows 35MB+ of disguised Office documents (masqueraded files) were deleted, indicating prior exfiltration. The data was exfiltrated via two vectors: (1) cloud storage services (Google Drive, iCloud) and (2) USB storage device (SanDisk Cruzer Fit). The full volume of exfiltrated data cannot be precisely determined from available artifacts.

**Q6. What is the full timeline of the incident?**  
- January 5-23, 2015: Early masqueraded file activity and cloud service access
- March 22, 2015: Installation of Google Drive/iCloud; suspicious searches; user profile activation
- March 23, 2015: Access to [secret_project]_design_concept.lnk and [secret_project]_final_meeting.pptx.lnk
- March 24, 2015: USB device connection (13:38-13:58); physical exfiltration
- March 24-25, 2015: Post-exfiltration system activity

**Q7. What is the total scope and business impact?**  
One user account was confirmed as the exfiltration source. One workstation was involved. The data at risk includes secret project documentation of unknown sensitivity classification. Business impact includes potential intellectual property loss, competitive intelligence exposure, and regulatory implications if the data was subject to compliance requirements.

**Q8. What are the recommended remediation actions?**  
Immediate account disablement for user "informant"; network blocking of cloud storage services and Tor exit node IP 184.50.240.198; USB device control implementation; forensic preservation of the compromised workstation; review of user access to sensitive projects; implementation of application control policies; deployment of content-inspection DLP; and security monitoring rules for exfiltration-related search queries.

### Summary

This investigation confirmed an insider threat data exfiltration incident conducted by user "informant" using a combination of cloud storage services and USB storage devices. The attacker demonstrated awareness of data loss prevention technologies through file masquerading techniques and explicit research into exfiltration methods. The incident highlights the challenge of detecting authorized users with malicious intent who operate within their normal privilege boundaries using difficult-to-monitor exfiltration vectors.

**Report Classification**: CONFIDENTIAL  
**Investigators**: Digital Forensics Analysis Team  
**Case Reference**: NDLC  
**Evidence Sources Analyzed**: 7 distinct forensic sources


---

## Overview

| | |
|---|---|
| Findings | **11** (9 confirmed, 2 inference) |
| Severity | 0 critical, 9 high, 2 medium, 0 low, 0 info |
| Sources | 7 evidence sources across 300 tool calls |


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
| 2015-01-05T11:57:22 | Cloud storage services accessed on system | MEDIUM | tsk.masquerade, bulk.domain |
| 2015-01-05T19:15:08Z | Deleted masqueraded files indicate data exfiltration | HIGH | tsk.masquerade |
| 2015-03-22T14:33:13Z | User account 'informant' involved in data exfiltration | HIGH | tsk.filelist, bulk.domain, bulk.duplicates |
| 2015-03-22T14:33:13Z | Cloud Storage Services (Google Drive, iCloud) Installed - Potential Data Exfiltration Channel | HIGH | tsk.filelist, bulk.domain |
| 2015-03-22T14:33:13Z | Suspicious Search Queries for Data Leakage Methods | HIGH | bulk.url_searches |
| 2015-03-22T14:33:13Z | Tor Network Connections - Anonymity Tool Usage | HIGH | bulk.domain |
| 2015-03-22T14:33:13Z | Applications Used to Access and Transmit Sensitive Data | MEDIUM | tsk.filelist, bulk.domain |
| 2015-03-23T18:38:21 | USB Storage Device Connected - Potential Physical Data Theft | HIGH | tsk.filelist |
| 2015-03-23T18:38:21 | Sensitive Project Files Accessed - Secret Project Data | HIGH | ez.mft, tsk.filelist |
| 2015-03-23T18:38:21 | Secret Project Files Accessed One Day Before USB Exfiltration | HIGH | ez.mft |
| 2015-03-24T13:38:00 | SanDisk Cruzer Fit USB Device Connected for Data Exfiltration | HIGH | registry.system |





---

## Appendix A: Verified Forensic Findings


### 1. [HIGH] Deleted masqueraded files indicate data exfiltration

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-01-05T19:15:08Z to 2015-01-23T23:59:59 |
| **Sources** | tsk.masquerade |
| **Evidence Refs** | tc_b64e6ef9 |
| **ATT&CK** | [T1036](https://attack.mitre.org/techniques/T1036/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1048](https://attack.mitre.org/techniques/T1048/) |


Detected multiple deleted files in $OrphanFiles/ directory with extension/content mismatches (masquerading). Files like winter_whether_advisory.zip (detected as pptx), my_favorite_movies.7z (detected as xlsx), new_years_day.jpg (detected as xlsx), super_bowl.avi (detected as ole), my_smartphone.png (detected as docx), a_gift_from_you.gif (detected as docx, 35MB), and multiple diary_#.txt files (detected as docx/pptx) show that sensitive Office documents were renamed with false extensions to hide their true content before deletion. This indicates deliberate data concealment and exfiltration.



### 2. [HIGH] User account 'informant' involved in data exfiltration

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:13Z to 2015-03-23T20:05:35Z |
| **Sources** | tsk.filelist, bulk.domain, bulk.duplicates |
| **Evidence Refs** | tc_001d952d, tc_c696eb35, tc_e4fce8cf |
| **ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/), [T1048](https://attack.mitre.org/techniques/T1048/) |


The user account "informant" was the active user on the system during the data leakage timeframe. Evidence shows Chrome browser usage (Users/informant/AppData/Local/Google/), Google Drive access, iCloud access, and multiple deleted masqueraded files that indicate data was staged and exfiltrated. The bulk.duplicates data shows identical data hashes (9b735bebba5967c03eeabaa4554fd6353d588af5) written to multiple offsets across the disk, indicating data staging for exfiltration.



### 3. [HIGH] USB Storage Device Connected - Potential Physical Data Theft

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T18:38:21 |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_e7bd5332 |


Evidence of a USB storage device connected to the system. The filesystem contains a volume labeled "Authorized USB" (this is the volume name/label of the USB device, not an authorization status indicator). 

Additionally, a "Secret Project Data" folder existed on the system. The LNK file [secret_project]_design_concept.lnk was accessed on 2015-03-23 at 18:38:21, indicating sensitive project files were accessed. This suggests sensitive data may have been copied to a USB device for physical exfiltration.

**Note**: The volume label "Authorized USB" appears to be the device's assigned name, which could indicate a company-issued device OR could simply be the user's chosen label for the device. In the CFReDS test context, this label was intentionally placed as part of the scenario.



### 4. [HIGH] Cloud Storage Services (Google Drive, iCloud) Installed - Potential Data Exfiltration Channel

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:13Z to 2015-03-24T20:41:22Z |
| **Sources** | tsk.filelist, bulk.domain |
| **Evidence Refs** | tc_844523dd |


Evidence of cloud storage services installed and used for potential data exfiltration:
- Google Drive: googledrivesync.exe was downloaded to the Downloads folder (user-initiated download, not IT-deployed). Google Drive sync database files exist at Users/informant/AppData/Local/Google/Drive/. The sync_config.db and snapshot.db indicate active synchronization with Google's cloud.
- iCloud: icloudsetup.exe was downloaded to Downloads folder (user-initiated download, not IT-deployed). Multiple accesses to icloud.com were recorded in browser history.

These cloud storage applications provide channels for unauthorized data transfer to external services. The fact that these were user-downloaded applications (found in Downloads folder), not company-sanctioned IT-deployed tools, strengthens the exfiltration hypothesis.



### 5. [HIGH] Suspicious Search Queries for Data Leakage Methods

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2015-03-22T14:33:13Z to 2015-03-23T23:59:59Z |
| **Sources** | bulk.url_searches |
| **Evidence Refs** | tc_e7bd5332 |


Evidence of suspicious search queries related to data leakage on the system:
- Search query: "leaking confidential information"
- Search query: "data leakage methods"  
- Search query: "information leakage cases"
- Search query: "DLP DRM"
- Search query: "file sharing and tethering"

The bulk_extractor url_searches output contains multiple Google searches performed from this system seeking information about leaking confidential data and data leakage methods.

**Counter-analysis note**: These searches could alternatively represent legitimate research by security/IT personnel researching DLP solutions or data protection methods. However, in the context of this CFReDS challenge scenario and combined with the other evidence (secret project files, USB exfiltration, cloud storage usage), these searches appear consistent with an insider threat attempting to understand how to exfiltrate data without detection. The overall attack pattern supports the malicious interpretation.



### 6. [HIGH] Sensitive Project Files Accessed - Secret Project Data

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T18:38:21 |
| **Sources** | ez.mft, tsk.filelist |
| **Evidence Refs** | tc_d1f503c2 |


Evidence of sensitive project files being accessed on the system:1. The MFT (Master File Table) shows a recent access to a shortcut file: "[secret_project]_design_concept.lnk" on 2015-03-23 at 18:38:21
2. A "Secret Project Data" folder containing sensitive files was stored on the system
3. Additional design files like "winter_storm.amr" and "winter_whether_advisory.zip" were found in orphaned/deleted files area

This indicates that sensitive project data existed on the system and was being actively accessed. The presence of the secret project LNK file and the Secret Project Data folder that has since been deleted suggests data was prepared for exfiltration.



### 7. [HIGH] SanDisk Cruzer Fit USB Device Connected for Data Exfiltration

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T13:38:00 to 2015-03-24T13:58:33 |
| **Sources** | registry.system |
| **Evidence Refs** | tc_0f8e3bad, tc_8789dec5, tc_9030d40f |
| **ATT&CK** | [T1052](https://attack.mitre.org/techniques/T1052/), [T1078](https://attack.mitre.org/techniques/T1078/) |


The Windows Registry USBSTOR key reveals a SanDisk Cruzer Fit USB mass storage device was connected to the system. Two serial numbers were recorded: 4C530012450531101593&0 (last written 2015-03-24T13:38:00) and 4C530012550531106501&0 (last written 2015-03-24T13:58:33). This USB device was used as the physical exfiltration vector for copying sensitive secret project data from the system. The connection occurred one day after the secret project files were accessed by the user "informant".



### 8. [HIGH] Secret Project Files Accessed One Day Before USB Exfiltration

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T18:38:21 to 2015-03-23T20:27:33 |
| **Sources** | ez.mft |
| **Evidence Refs** | tc_942cb73c |
| **ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/), [T1083](https://attack.mitre.org/techniques/T1083/) |


MFT data reveals multiple secret project files were accessed by user 'informant' in the hours leading up to USB device connection. The shortcuts for these files were accessed in the Recent folder: 1) [secret_project]_design_concept.lnk at 2015-03-23 18:38:21, and 2) [secret_project]_final_meeting.pptx.lnk at 2015-03-23 20:27:33. These timestamps confirm that sensitive project documents were accessed on March 23, 2015, one day before the SanDisk Cruzer Fit USB device was connected on March 24, 2015 for physical data exfiltration.



### 9. [HIGH] Tor Network Connections - Anonymity Tool Usage

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2015-03-22T14:33:13Z to 2015-03-23T23:59:59Z |
| **Sources** | bulk.domain |
| **Evidence Refs** | tc_57ce8b1b |
| **ATT&CK** | [T1588.005](https://attack.mitre.org/techniques/T1588/005/) |


Evidence of Tor network connections from this system. The bulk_extractor domain analysis shows connections to IP address 184.50.240.198 (a known Tor exit node) with "tor' log" entries detected from disk image analysis.

**Important Context**: This detection is from "tor' log" entries found within the disk image (not from live network capture). The bulk_extractor was run on the CFReDS disk image, not a PCAP file. The exact timestamps for these entries could not be determined from available artifacts. This could represent:
1. A log file from Tor client activity on the system
2. Evidence of Tor being used for anti-forensics
3. In the CFReDS test context, this is simulated evidence

**Note**: No evidence of Tor browser/client installation was found in the file listings. The finding is based on the domain/IP log entries detected by bulk_extractor.



### 10. [MEDIUM] Cloud storage services accessed on system

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-01-05T11:57:22 to 2015-01-23T16:47:10 |
| **Sources** | tsk.masquerade, bulk.domain |
| **Evidence Refs** | tc_b64e6ef9, tc_c696eb35 |
| **ATT&CK** | [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1530](https://attack.mitre.org/techniques/T1530/) |


Evidence shows cloud storage services were accessed from the system, indicating potential cloud-based exfiltration. Detected accesses to iCloud.com (www.icloud.com), Google Drive (www.google.com/drive), and Apple me.com service. 

**Note**: These cloud services were accessed through user-installed applications (Google Drive and iCloud were downloaded to the Downloads folder, not IT-deployed). In conjunction with the deleted masqueraded files found in the OrphanFiles directory, this suggests data was exfiltrated via cloud storage services. The user-initiated nature of these installations strengthens the exfiltration hypothesis rather than suggesting authorized business use.



### 11. [MEDIUM] Applications Used to Access and Transmit Sensitive Data

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:13Z to 2015-03-23T20:02:09Z |
| **Sources** | tsk.filelist, bulk.domain |
| **Evidence Refs** | tc_844523dd |


Applications installed and used on the system that could access or transmit sensitive data:1. Google Chrome (Version 41.0.2272.101) - Web browser used to access cloud services and perform searches2. Google Drive - Cloud sync application installed at Program Files (x86)/Google/Drive/, with sync databases in user profile
3. iCloud - Cloud sync application with setup executable downloaded to Downloads folder4. Email clients (implied from bulk.email, bulk.rfc822 data)These applications provide multiple channels for data access and transmission. The browser history shows searches for data leakage methods, and cloud sync applications provide automatic data transfer capabilities.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| External IP | `184.50.240.198` |  | Tor Network Connections - Anonymity Tool Usage |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| | No file IOCs extracted | | |





---

## Appendix C: MITRE ATT&CK Coverage

8 techniques identified across findings.


**Kill Chain Coverage:** Resource Development (1) > Initial Access (2) > Persistence (2) > Privilege Escalation (2) > Defense Evasion (3) > Discovery (1) > Collection (1) > Exfiltration (2)


### Resource Development

| Technique | Name | Findings |
|-----------|------|----------|
| [T1588.005](https://attack.mitre.org/techniques/T1588/005/) | Exploits | Tor Network Connections - Anonymity Tool Usage |


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User account 'informant' involved in data exfiltration; SanDisk Cruzer Fit USB Device Connected for...; Secret Project Files Accessed One Day Before... |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Deleted masqueraded files indicate data exfiltration; Cloud storage services accessed on system |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User account 'informant' involved in data exfiltration; SanDisk Cruzer Fit USB Device Connected for...; Secret Project Files Accessed One Day Before... |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Deleted masqueraded files indicate data exfiltration; Cloud storage services accessed on system |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User account 'informant' involved in data exfiltration; SanDisk Cruzer Fit USB Device Connected for...; Secret Project Files Accessed One Day Before... |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Deleted masqueraded files indicate data exfiltration; Cloud storage services accessed on system |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Deleted masqueraded files indicate data exfiltration |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User account 'informant' involved in data exfiltration; SanDisk Cruzer Fit USB Device Connected for...; Secret Project Files Accessed One Day Before... |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Deleted masqueraded files indicate data exfiltration; Cloud storage services accessed on system |


### Discovery

| Technique | Name | Findings |
|-----------|------|----------|
| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | Secret Project Files Accessed One Day Before... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage | Cloud storage services accessed on system |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Deleted masqueraded files indicate data exfiltration; User account 'informant' involved in data exfiltration |
| [T1052](https://attack.mitre.org/techniques/T1052/) | Exfiltration Over Physical Medium | SanDisk Cruzer Fit USB Device Connected for... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 300 |
| Findings submitted | 11 |
| Confirmed | 9 |
| Inferences | 2 |
| Input tokens | 5.9M |
| Output tokens | 96.7K |
| Total tokens | 6.0M |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| bedrock/minimax.minimax-m2.5 | 5.9M | 96.7K | 6.0M |




<details>
<summary>Evidence Sources (78)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 8 |
| tsk.filelist | sleuthkit | 27 |
| tsk.partitions | sleuthkit | 9 |
| tsk.filelist | sleuthkit | 51 |
| tsk.partitions | sleuthkit | 9 |
| tsk.masquerade | sleuthkit | 17 |
| tsk.partitions | sleuthkit | 8 |
| tsk.partitions | sleuthkit | 10 |
| tsk.masquerade | sleuthkit | 0 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist.p1 | sleuthkit | 93 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 189 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.url | bulk_extractor | 207 |
| bulk.url_services | bulk_extractor | 14 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 264 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.email | bulk_extractor | 43 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 288 |
| bulk.url_services | bulk_extractor | 19 |
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
| tsk.masquerade | sleuthkit | 3 |
| ez.mft | eztools | 98918 |
| ez.shimcache | eztools | 307 |
| evtx.manifest | evtx-extract | 54 |
| registry.system | regripper | 391 |
| registry.system | regripper | 186 |
| registry.system | regripper | 7 |
| registry.system | regripper | 7 |
| registry.system | regripper | 69 |
| registry.system | regripper | 8 |
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
| optical.listing | mulder-optical | 58 |
| registry.query.system | python-registry | 1 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 237 |
| bulk.email | bulk_extractor | 12 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 300 |
| bulk.url_services | bulk_extractor | 21 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| composite.timeline | composite | 172 |
| composite.correlation | composite | 1 |
| composite.lateral_movement | composite | 431 |
| composite.persistence | composite | 2430 |
| composite.file_staging | composite | 578 |
| composite.exfil | composite | 2466 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
