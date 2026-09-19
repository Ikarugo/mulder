# Accuracy Report: NDLC (NIST CFReDS Data Leakage Case 2015) — bedrock/deepseek.v3.2 (release v1.5.2, 2026-09-19)

Mulder's autonomous findings, produced by the open-weight model `bedrock/deepseek.v3.2` (`--no-thinking`) on the **v1.5.2 release image** (git tag `v1.5.2` = main @ 70ea37f plus the per-image partition-table fix #228; UDF/ISO optical reader, file-masquerading detector and advisory coverage gate as in the v2 run), evaluated against the [published answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) for the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html), using the same 20 ground-truth items and the same standards as the Claude Opus baseline (`examples/ndlc/ACCURACY-REPORT.md`) and the previous DeepSeek V3.2 scorecards (pre-release runs of the same model on the same evidence, not published): a wrong detail (edition, date, timezone, device) is PARTIAL, mention without evidence is PARTIAL, and only claims the answer key contradicts or causal attributions the evidence does not support count as FALSE POSITIVE. Hedged inferences labelled as such are not counted; a claim carried unhedged into the narrative, IOC table or containment actions is.

Report scored: `ndlc.report.md` in this directory (17 findings: 9 confirmed, 8 inference; 6 high, 9 medium, 2 info; rc 0; 242 tool calls; 27 minutes, 19:53–20:20 UTC; 9.95M input / 61K output tokens; 0 compactions). **Image: v1.5.2.** The report's own footer counts 352 tool calls, 25 minutes and 9.7M / 56.4K tokens; the runner's figures are used here.

---

## Scorecard

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 0 | 0% |
| PARTIAL | 12 | 60% |
| MISSED | 8 | 40% |
| FALSE POSITIVE (within the 20 items) | 0 | 0% |

Five false positives were made on claims outside the 20-item grid (see False Positive Handling), for **5 false positives in total**.

**Effective accuracy: 0% full match, 60% detection rate (found at least related evidence), 25% false positive rate (5 contradicted claims / 20 items, the baseline's definition).**

---

## Ground Truth Comparison

| # | Ground Truth Item | Status | Agent's Finding |
|---|-------------------|--------|-----------------|
| 1 | Suspect identity: "Iaman Informant" (iaman.informant@nist.gov) | PARTIAL | The account is the actor of the account events and the address is now attached to it rather than filed as victim data (v2): "Informant account (iaman.informant@nist.gov.ost) password reset by SYSTEM"; finding 6 is titled "Coordinated Account Manipulation and Google Drive Exfiltration by NIST Informant". Attribution is then declined: "The email reference 'iaman.informant@nist.gov.ost' suggests potential connection to NIST, but the '.ost' extension indicates an Outlook offline storage file reference rather than confirmed live email account. This could represent placeholder configuration rather than confirmed NIST affiliation"; "attribution to a specific threat actor remains uncertain". The name "Iaman Informant" never appears and the "IAMAN CD" label is not connected to it. The same account is also cast as the initial-access vector (FP 2). |
| 2 | PC OS: Windows 7 Ultimate 64-bit, standalone WORKGROUP | PARTIAL | "The system is running Windows 7 Ultimate edition. Registry query confirms the ProductName value is 'Windows 7 Ultimate'. The InstallDate registry value shows a Unix timestamp of 1427034866 (which converts to March 22, 2015)". Edition correct for the first time in any open-weight run (v2 and the baseline said Professional) and the install date exact (Q3: 2015-03-22 14:34:26 GMT). No architecture, build, computer name or WORKGROUP: one of the item's three facts is stated. |
| 3 | USB Device 1: SanDisk Cruzer Fit, S/N 4C530012450531101593, exFAT, "Authorized USB" | MISSED | "removable storage media (rm1, rm2)" is the only mention. No vendor, model, serial, filesystem, volume label or connection time; the "Authorized USB" label and the "Secret Project Data" folder never appear. `tsk.filelist` for rm1 (27 lines) was indexed and not read; `tsk.masquerade` on rm1 returned 0 lines. Same as v2. |
| 4 | USB Device 2: SanDisk Cruzer Fit, S/N 4C530012550531106501, FAT32, "IAMAN $_@" | MISSED | rm2 appears only as the carrier of a carved number: "Credit card number 5627938946716605 found on rm2.E01 (bulk.ccn)"; "Payment card numbers were extracted from the rm2 disk image". The 17 disguised files that `tsk.masquerade` returned for rm2 are placed elsewhere: "Same masqueraded files found on PC orphan files and optical media" (finding 15); "The tsk.masquerade source detected 17 files" on "optical media (volume label: 'IAMAN CD')" (finding 12). No FAT32, size, label, serial or connection time (v2 had "FAT32 filesystem, 1GB" and scored PARTIAL). Ruled as the MiniMax v2 item 4: contents without the device is MISSED. |
| 5 | RM3: CD-ROM, UDF filesystem, formatted March 24, 2015 (16:53:17 UTC) | PARTIAL | "optical media labeled 'IAMAN CD'"; "Volume label 'IAMAN CD' with 9 VAT generations (write sessions)"; "Optical media write sessions in March 2015"; finding 12's window ends "2015-03-24T20:57:03Z". Medium, label, session count and the March 24 date are right; UDF is not named (VAT is UDF terminology), the descriptor timestamp (16:53:17) and the burner drive are absent. Same as v2. |
| 6 | Five Secret Project documents exfiltrated to USB | PARTIAL | None of the five filenames nor "Secret Project" appears. What the report has is the disguised copies with types and a size range: "File sizes ranging from 27KB to 35MB"; "Office documents up to 35MB in size" (35 MB is the 35,226,880-byte document); "'winter_whether_advisory.zip' (actual content: pptx), 'my_favorite_movies.7z' (actual content: xlsx), 'new_years_day.jpg' (actual content: xlsx), 'super_bowl.avi' (actual content: ole), 'my_favorite_cars.db' (actual content: ole)". The documents were found through their disguised copies, never named or traced to RM1; Q5: "definitive confirmation of successful transfer requires additional network forensic analysis". Same as v2. |
| 7 | File masquerading: documents renamed with false extensions on RM2 FAT32 | PARTIAL | Detected with true types: "'$OrphanFiles/design/winter_storm.amr' (ext=amr) actually contains OLE format content ... '$OrphanFiles/design/winter_whether_advisory.zip' (ext=zip) contains PPTX ... '$OrphanFiles/PRICIN~1/my_favorite_movies.7z' (ext=7z) contains XLSX ... '$OrphanFiles/PRICIN~1/new_years_day.jpg' (ext=jpg) contains XLSX ... '$OrphanFiles/progress/my_smartphone.png' (ext=png) contains DOCX ... '$OrphanFiles/TECHNI~1/diary_#1d.txt' (ext=txt) contains DOCX", plus super_bowl.avi and my_favorite_cars.db (OLE): eight of 17 named (v2: six). The count "17 files" is stated but attached to the disc (finding 12), and RM2 is never named as the location: the files are on "PC orphan files" and "optical media". No original-name mapping. Dated "December 2014 - January 2015: Systematic creation of Office documents ... with misleading file extensions" (FP 1), against finding 13's own "Files were deleted but show creation times in March 2015". |
| 8 | Anti-forensics tools: CCleaner and Eraser deployed | PARTIAL | "Presence of Eraser.exe secure deletion tool and CCleaner64.exe detected via ShimCache analysis"; "Eraser.exe secure deletion tool detected via ShimCache; CCleaner64.exe anti-forensics tool present". Both tools named with a source (v2: neither) but no version, date, install evidence or restore point (baseline: CCleaner 5.04, Eraser 6.2.0.2962, "Installed Eraser 6.2.0.2962" restore point). The ASP.NET service installed three minutes before that restore point is still reported as a backdoor rather than Eraser's .NET prerequisite (FP 3). |
| 9 | Search history reveals premeditation (leakage methods, anti-forensics) | PARTIAL | "Multiple Google searches for 'information leakage cases'"; "Search for 'how to leak a secret' suggesting research on data exfiltration methods"; "Search for 'how to delete data' indicating potential attempts to cover tracks"; "Access to security research materials including DEFCON website (defcon.org)"; "National Institute of Justice (NIJ) materials on digital forensics". One Q16 term matches exactly (v2 had four); none of the anti-forensics terms ("anti-forensic tools", "eraser", "ccleaner", "cd burning method", "security checkpoint cd-r"). Dated "Throughout the period" and 2014-12-01 (answer key: 2015-03-23 14:02–14:21 EDT). |
| 10 | Google Drive sync installed for cloud exfiltration | PARTIAL | "Drive.google.com access detected in bulk.url data"; "Credential sharing URLs: https://drive.google.com/sharing/share?...foreignService=googledrivesync&access_token=ya29..."; "OAuth relay URLs"; "Document sync URLs: https://docs.google.com/presentation?usp=drive_sync"; T1567.002; "Throughout March 2015: Evidence of Google Drive access". The client is inferred from URLs only: no googledrivesync.exe ShimCache entry, no install date, no sync folder. Same as v2. |
| 11 | iCloud setup downloaded (secondary cloud channel) | MISSED | iCloud does not appear anywhere. v2 had "iCloud Setup executables" (PARTIAL). |
| 12 | USB connection timestamps via EVTX System log | MISSED | No USB connection event of any kind. `registry.system` and `evtx.manifest` (54 lines) were indexed; no USBSTOR entry, no 20001/20003 event. Same as v2. |
| 13 | Exfiltration timeline: Feb 15 bulk copy (42-second window) | MISSED | No February activity; RM1's filesystem timeline is never examined. |
| 14 | Anti-forensics: CCleaner deployed but did not clean (launched and closed without action) | PARTIAL | "CCleaner64.exe anti-forensics tool present"; containment 2 "terminate any processes associated with anti-forensics tools including Eraser.exe (secure deletion tool) and CCleaner64.exe"; Root Cause 4 "failed to detect deployment and use of anti-forensics tools including secure deletion software and registry cleaning utilities". Deployment stated, effect never assessed: no claim that it destroyed artifacts (the baseline's false positive) and no observation that it did nothing. Half the item. |
| 15 | Systematic file deletion on RM2 FAT32 (Mar 24, 09:54-10:00) | PARTIAL | "Files were deleted but show creation times in March 2015"; "deletion timestamps in March 2015"; "File timestamps showing coordinated deletion patterns in March 2015"; finding 1's window ends "2015-03-24T10:00:18" and finding 9's "2015-03-24T09:59:27". Deletion recognised and placed in March; no window stated as such, no count of 17, no quick-format inference; "2222 total deleted files identified across systems" is `composite.recovery`, not RM2. Same as v2. |
| 16 | RM3 contains government documents matching Secret Project content | PARTIAL | Finding 15 enumerates the disc: "design/ - Contains winter_storm.amr (OLE) and winter_whether_advisory.zip (PPTX); pricing decision/ - Contains my_favorite_cars.db (OLE), my_favorite_movies.7z (XLSX), new_years_day.jpg (XLSX), super_bowl.avi (OLE); progress/ - Contains my_friends.svg, my_smartphone.png (DOCX), new_year_calendar.one; proposal/ - Contains a_gift_from_you.gif, landscape.png; technical review/ - Contains diary files #1d.txt (DOCX), #1p.txt (PPTX) ... #3p.txt (PPTX)". The fullest disc listing of any open-weight run, including the pricing-decision directory v2 lacked. Not matched to the five Secret Project documents; the Govdocs strings on the disc are read as "Government-related content including an OMB email address" (FP 4). |
| 17 | Files opened in RM2 (list all accessed files) | MISSED | No LNK, JumpList, ShellBag or RecentDocs evidence for `E:`; `winter_whether_advisory.zip` is named only as an orphan, not as opened. Same as v2. |
| 18 | Network drive directories traversed | MISSED | "No evidence of traditional network-based lateral movement was identified" (Q3). No mention of `10.11.11.128` or `secured_drive`; `composite.lateral_movement` (416 lines) indexed and unused. Same as v2. |
| 19 | Email communication with spy.conspirator@nist.gov | PARTIAL | "iaman.informant@nist.gov.ost" is surfaced and recognised as an Outlook offline store ("the '.ost' extension indicates an Outlook offline storage file reference"), this time as the suspect's rather than a target's. `spy.conspirator@nist.gov` is absent, the OST is not parsed (`bulk.rfc822`, 7,326 lines, indexed and unused), and the address is discounted as "placeholder configuration". Same standard as the baseline's PARTIAL. |
| 20 | FAT32 timezone offset (local time vs UTC) | MISSED | No timezone is stated and no timestamp discrepancy is observed. Same as v2. |

---

## Findings Beyond the Answer Key

| Finding | Assessment |
|---------|------------|
| "Windows 7 Ultimate", InstallDate 1427034866 (2015-03-22) | Legitimate; matches Q3. First open-weight run with the right edition. |
| admin11 / ITechTeam / temporary created 2015-03-22 15:51:54–15:53:11 and added to Administrators; informant password reset by SYSTEM at 14:33:54 | Legitimate observations (Q6: all created by the suspect during setup). The interpretation placed on them is FP 2. |
| ASP.NET State Service installed 2015-03-25 14:54:25 | Legitimate observation; it is the .NET Framework 4 install that precedes the "Installed Eraser 6.2.0.2962" restore point (Q47, 14:57:27Z) by three minutes. The report names Eraser and still reads the service as persistence (FP 3). |
| "IAMAN CD", 9 VAT generations, full directory tree with true file types | Legitimate; the best disc enumeration of any open-weight run. |
| Eraser.exe and CCleaner64.exe in ShimCache | Legitimate (items 8, 14); undated. |
| Google Drive sharing URL with `foreignService=googledrivesync` and an `access_token` | Legitimate; it is the sync client's OAuth traffic. "Google Drive integration suggests potential credential exposure" is a stretch, not counted. |
| Searches "how to leak a secret", "how to delete data"; DEFCON and NIJ site access | Not in the Q16 list as scored here; plausible `bulk.url` hits, unverified, not counted. |
| "2222 total deleted files identified across systems" | `composite.recovery` count; harmless. |
| "Same masqueraded files found on PC orphan files and optical media"; "17 files" on optical media | Incorrect medium: the 17-line `tsk.masquerade` output is rm2 (the PC was not scanned; the disc's run returned 3 lines). Detail error, covered under items 4 and 7, not counted. |
| Q3: "Data flowed from PC to removable media to optical media" | Unverified chain (the disc was formatted at 16:53 UTC, after the RM2 copy); not directly contradicted, not counted. |
| `Eric_P._Lauer@omb.eop.gov`, `FEA_CRM_v23_Final_Oct_2007.pdf`, `s53.pdf` as "Government Targeting" and Email IOC | Incorrect. Govdocs1 seed-document metadata (answer key footnote 1). See FP 4. |
| Credit card numbers on the PC and rm2 as "Payment Card Data Leakage" | Incorrect. `bulk.ccn` matches inside public Govdocs1 content; no payment data exists in the case. See FP 5. |
| Q5: "definitive confirmation of successful transfer requires additional network forensic analysis" | Wrong conclusion (Q58/Q59: e-mail, cloud, USB and CD-R), but a negative finding, not counted. |

---

## False Positive Handling

**Five false positives identified in post-verification.** None falls on a graded item; all five are stated at "confirmed" confidence or carried unhedged into the timeline, impact assessment, containment plan, root causes or IOC table. Findings 8, 9 and 17 hedge at finding level ("does not necessarily constitute unauthorized access", "patterns consistent with test/sample data"); the narrative, the lifecycle headers and finding 5 (confirmed) drop the hedges.

| # | Report claim | Contradicting answer-key statement |
|---|-------------|------------------------------------|
| 1 | Timeline "Phase 1: Data Collection and Organization (December 2014 - January 2015)": "Systematic creation of Office documents (DOCX, XLSX, PPTX) with misleading file extensions"; "January 5-23, 2015: File creation and modification activities with clear patterns of obfuscation"; "January 20, 2015: Multiple 'diary' files created"; finding 2 (confirmed) dated "2014-12-01T14:50:26 to 2015-01-23T16:47:10"; lifecycle "Defense Evasion / Anti-Forensics (2014-12-01 to 2015-01-05)"; Q6 "Data Collection and Organization (Dec 2014-Jan 2015)". | Q3: OS installed 2015-03-22 (a date the report itself states). Q22/Q25: RM2 first connected 2015-03-24 09:58. USN journal (Q55): the 22 renames happened on 2015-03-24; RM2's files were deleted 09:54–10:00 the same day. The December/January values are the documents' original modification times carried by the copy, read as the date of the masquerading. Same as v2 FP 1; finding 13's "creation times in March 2015" is the correct reading and is overruled by the narrative. |
| 2 | "Phase 3: Account Manipulation and System Access"; "coordinated privilege escalation activity"; Q2 "Initial access appears to have been facilitated through the informant@nist.gov.ost account, with a password reset performed by SYSTEM on March 22, 2015. This was followed by creation of additional administrative accounts (admin11, ITechTeam, temporary) suggesting privilege escalation"; Impact "User account manipulation indicates compromised administrative access"; containment 3 "Disable Compromised Accounts ... admin11 ... ITechTeam ... temporary ... Any account referencing iaman.informant@nist.gov.ost"; Root Cause 2; finding 6 "T1070: Indicator Removal (account manipulation to obscure original actor)". | Q3: Registered Owner `informant`; Q6: `informant` (RID 1000) created at OS install; Section 3: the suspect himself created admin11 / ITechTeam / temporary during setup on 2015-03-22 and had "sufficient authority" throughout. No account was compromised, no initial access occurred and no privilege escalation enabled anything. Findings 4 and 6 are labelled inference; Q2, the impact assessment, the containment plan and Root Cause 2 are not. Same as v2 FP 2. |
| 3 | "March 25, 2015, 14:54:25: Suspicious installation of ASP.NET State Service suggesting web application persistence mechanism"; Q4 "Persistence mechanisms identified include ... ASP.NET State Service installed on March 25, 2015 suggesting web application persistence"; Impact "System-level persistence mechanisms installed"; containment 6 "Examine and disable the ASP.NET State Service installed on March 25, 2015 14:54:25 as a potential persistence mechanism". | The answer key records no persistence mechanism (Q58/Q59 list the leakage methods exhaustively). The service is a component of the .NET Framework 4 installer that Eraser requires: the "Installed Eraser 6.2.0.2962" restore point (Q47) is at 14:57:27Z, three minutes after the service install. This run names Eraser (item 8) and still reports its footprint as a backdoor. Same as v2 FP 3. |
| 4 | Finding 8 (confirmed) "Unauthorized Access to Government Documents and Email Information"; finding 5 (confirmed) "Government document access: OMB email address Eric_P._Lauer@omb.eop.gov and whitehouse.gov documents"; "Government Targeting: Consistent focus on government documents, OMB materials, and .gov email addresses suggests either research interest or targeted collection"; Root Cause 5 "systematic collection of government-related documents and email addresses ... suggesting targeted collection"; Email IOC `eric_p._lauer@omb.eop.gov`; T1552, T1530. | Footnote 1: the seed documents are Govdocs1 files and carry their authors' metadata; `FEA_CRM_v23_Final_Oct_2007.pdf` and `s53.pdf` are public OMB documents used as filler. Nothing in the case involves collecting or targeting government communications. Finding 8's own body ("publicly available government policy documents ... does not necessarily constitute unauthorized access") is correct and is overruled by its title, finding 5, Root Cause 5 and the IOC table. Same class as v2 FP 4, now with one address instead of eight and the suspect's own address no longer listed as a target. |
| 5 | Lifecycle "Credential Access (2015-01-16): Payment Card Data Leakage on Removable Media"; finding 5 (confirmed) "PC Source System: Credit card numbers discovered in bulk.ccn (263 lines) from pc.E01 file"; "Credit card number 5627938946716605 found on rm2.E01"; Category 3 "PC to Removable Media Pathway: Credit card numbers and sensitive financial data on primary system"; Impact "Credit card numbers present, though some appear to be test/sample patterns"; finding 17 "Hundreds of credit card numbers were found ... suggest this system may have been used to collect or process payment card data". | The scenario contains no payment card data (Sections 1, 3; Q58/Q59; footnote 1: every seed file is a public Govdocs1 document). The strings are Luhn-valid digit runs inside those documents. Finding 9 (inference) correctly says the numbers "resemble test patterns", and the previous DeepSeek run (2026-09-18) labelled the same `bulk.ccn` output a probable false positive; this run carries them into a confirmed finding, the exfiltration pathway and the lifecycle header. Same class as the MiniMax v2 FP 2, at lower severity. |

The remaining material is either correct (edition and install date, the accounts and their times, the disc's label, sessions and directory tree, the eight disguised filenames with types, the two anti-forensics executables, the Drive sync URLs) or silence. The characteristic failure is unchanged from both previous runs: benign setup artifacts (account creation, a .NET service) and document metadata (old timestamps, embedded addresses, digit strings) are assembled into an intrusion narrative with initial access, privilege escalation, persistence and government targeting, while the actual case (one insider, named on the CD he burned, writing to a conspirator) stays at "attribution to a specific threat actor remains uncertain".

---

## Analysis of Misses and Errors

### What v1.5.2 changed (nothing visible in the extractor output)

The #228 fix scopes `tsk.partitions` lookups to the image being analysed and scans every partition in `detect_masquerading`. On this evidence set the masquerade line counts are the same as v2 (0 on rm1, 17 on rm2, 3 on rm3) and `optical.listing` is again 58 lines, so the model consumed the same extractor output as v2; the differences between the two reports are the model's path through it, not the tooling.

### What came back (items 8, 14)

CCleaner and Eraser, absent from v2, are back from `ez.shimcache`: "Presence of Eraser.exe secure deletion tool and CCleaner64.exe detected via ShimCache analysis". That moves items 8 and 14 from MISSED to PARTIAL. The report does not date either tool, does not connect Eraser to the March 25 restore point, and does not connect the ASP.NET service it flags as persistence to the Eraser install three minutes later, so the anti-forensics evidence and the persistence false positive sit side by side in the same report.

### What was lost (items 4, 11)

RM2 as a device and iCloud as a channel are gone. v2 had "removable media rm2 (FAT32 filesystem, 1GB)"; this run has rm2 only as the source of a carved credit-card number and attributes rm2's 17 disguised files to "PC orphan files" and the optical disc. iCloud, present in v2 as a downloaded executable, is not mentioned. Net effect on the grid: two items up, two down, 0 / 12 / 8 again.

### Timestamps still not sanity-checked (FP 1; items 7, 15)

The report states the install date (1427034866 = March 22, 2015) in finding 16 and builds "Phase 1: Data Collection and Organization (December 2014 - January 2015)" on RM2 file timestamps from before the OS, or the USB stick, existed. Finding 13 has the right reading ("Files were deleted but show creation times in March 2015"); the executive timeline and Q6 use the wrong one. Same root cause as v2 FP 1 and run 1's three pre-install dates.

### Insider case still narrated as an intrusion (FPs 2, 3, 4, 5; item 1)

The account-manipulation chain, the "compromised" accounts, the service backdoor and the "government targeting" are the v2 template unchanged, with the credit-card carve added as a fifth contradicted claim. The report gets as close to attribution as v2 did (the account is the actor; the address is the account's) and declines it on the grounds that ".ost" might be "placeholder configuration". The label it needed ("IAMAN CD") is quoted in the same report.

### Device identification and PC-side artifacts absent (items 3, 4, 12, 17, 18, 20)

Nothing has changed: no serials, vendors, labels or connection times for either stick; no USB event; no LNK, JumpList or ShellBag evidence; no share; no timezone. The 242 tool calls (search 72, get_raw_output 34, submit_finding 22, open_case 19, get_investigation_summary 14 per the report's histogram) went to the masquerade and optical outputs, `bulk.url` and `hayabusa.alerts`, not to the registry and event-log sources that carry these items.

---

## Notes: what changed since the v2 run

- **CD-R contents: shown.** The report identifies `rm3` as optical media with volume label "IAMAN CD" and "9 VAT generations (write sessions)", and finding 15 lists the disc's five directories with every disguised file and its true type, including the pricing-decision directory v2 did not have. It does not state the UDF format timestamp or the burner, and does not match the disc's files to the Secret Project documents. Items 5 and 16 stay PARTIAL with better evidence.
- **Masquerading finding: shown.** Eight of the 17 disguised files are named with true types (v2: six) and the count of 17 is stated, but attached to the disc rather than RM2, and the RM2 location is never named. No original-name mapping. Item 7 stays PARTIAL.
- **Score versus the v2 DeepSeek V3.2 run (0 FOUND / 12 PARTIAL / 8 MISSED / 0 FP in grid; 4 FP total; 0% full, 60% detection, 20% FP):** this run is 0 / 12 / 8 / 0 with 5 FP total, i.e. 0% full, 60% detection, 25% FP. Two items improved (8, 14 from MISSED to PARTIAL: both anti-forensics tools named), two regressed (4, 11 from PARTIAL to MISSED: RM2 unidentified, iCloud gone), sixteen are unchanged. The four v2 false positives recur in the same form and a fifth (payment-card data) is added. Cost fell from 11.4M to 10.0M tokens at the same 27-minute runtime; findings fell from 19 to 17.

---

## Comparison with Claude Opus baseline and the v2 DeepSeek V3.2 run

| Metric | Claude Opus (baseline) | DeepSeek V3.2 v2 (2026-09-19) | DeepSeek V3.2 v1.5.2 (2026-09-19) |
|--------|------------------------|-------------------------------|-----------------------------------|
| FOUND | 12 | 0 | 0 |
| PARTIAL | 6 | 12 | 12 |
| MISSED | 1 | 8 | 8 |
| FALSE POSITIVE (in 20-item grid) | 1 | 0 | 0 |
| False positives, total | 1 | 4 | 5 |
| Full-match rate | 60% | 0% | 0% |
| Detection rate (FOUND + PARTIAL) | 90% | 60% | 60% |
| False-positive rate (FP / 20) | 5% | 20% | 25% |
| Suspect attributed | Yes, 6 sources | No ("primary operator account") | No (account is the actor; ".ost" read as "placeholder configuration") |
| Case type identified | Insider threat | Privilege escalation + staging (wrong) | Initial access + privilege escalation + persistence (wrong) |
| Secret Project documents named | 5 of 5 | 0 (disguised copies with sizes only) | 0 (disguised copies with sizes only) |
| USB devices identified | Both, with serials | Neither (RM2 partition only) | Neither (RM2 named only as bulk.ccn source) |
| CD-R (RM3) analysed | Yes | Yes (label, UDF sessions, disguised files) | Yes (label, 9 VAT generations, full directory tree) |
| Masquerading detected | Yes (4 mappings) | Yes (6 files, no mappings, no count) | Yes (8 files, count 17 on wrong medium, no mappings) |
| CCleaner / Eraser | Both, with evidence | Neither | Both named from ShimCache, undated |
| Email correspondent identified | No | No | No (suspect's OST filename found) |
| Network drive identified | No | No | No |
| Timezone | UTC+1 (wrong) | Not stated | Not stated |
| Dates preceding OS install | 0 | 1 (Dec 2014–Jan 2015 "Phase 1") | 1 (Dec 2014–Jan 2015 "Phase 1") |
| Findings | 33 (29 confirmed / 4 inference) | 19 (16 confirmed / 3 inference) | 17 (9 confirmed / 8 inference) |
| Tool calls | 723 | 372 | 242 (report footer: 352) |
| Runtime | 1.7 h | 27 min | 27 min |
| Total tokens | 330.3K | 11.4M | 10.0M |

Per-item status, side by side:

| # | Item | Opus | DeepSeek v2 | DeepSeek v1.5.2 |
|---|------|------|-------------|-----------------|
| 1 | Suspect identity | FOUND | PARTIAL | PARTIAL |
| 2 | PC OS | PARTIAL | PARTIAL | PARTIAL |
| 3 | USB Device 1 | FOUND | MISSED | MISSED |
| 4 | USB Device 2 | FOUND | PARTIAL | MISSED |
| 5 | RM3 CD-ROM | PARTIAL | PARTIAL | PARTIAL |
| 6 | Five documents exfiltrated | FOUND | PARTIAL | PARTIAL |
| 7 | File masquerading | PARTIAL | PARTIAL | PARTIAL |
| 8 | CCleaner and Eraser | FOUND | MISSED | PARTIAL |
| 9 | Search history | FOUND | PARTIAL | PARTIAL |
| 10 | Google Drive | FOUND | PARTIAL | PARTIAL |
| 11 | iCloud | FOUND | PARTIAL | MISSED |
| 12 | USB EVTX timestamps | FOUND | MISSED | MISSED |
| 13 | Feb 15 bulk copy | FOUND | MISSED | MISSED |
| 14 | CCleaner did not clean | FALSE POSITIVE | MISSED | PARTIAL |
| 15 | RM2 systematic deletion | FOUND | PARTIAL | PARTIAL |
| 16 | RM3 content | PARTIAL | PARTIAL | PARTIAL |
| 17 | Files opened in RM2 | PARTIAL | MISSED | MISSED |
| 18 | Network drive traversal | MISSED | MISSED | MISSED |
| 19 | Email with spy.conspirator | PARTIAL | PARTIAL | PARTIAL |
| 20 | FAT32 timezone offset | PARTIAL | MISSED | MISSED |

The v1.5.2 run is the v2 run with two items swapped and one more false positive. It reads the same extractor output (the release changed nothing this evidence set exercises), recovers the anti-forensics tools v2 dropped, loses RM2 and iCloud, and reproduces all four v2 contradicted claims while adding the payment-card carve. The Opus baseline remains the only run that identified both USB devices, named the five documents, and attributed the case.
