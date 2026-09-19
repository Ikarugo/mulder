# Accuracy Report: NDLC (NIST CFReDS Data Leakage Case 2015) — bedrock/minimax.minimax-m2.5 (release v1.5.2, 2026-09-19)

Mulder's autonomous findings, produced by the open-weight model `bedrock/minimax.minimax-m2.5` (native reasoning) on the **v1.5.2 release image** (git tag `v1.5.2` = main @ 70ea37f plus the per-image partition-table fix #228; UDF/ISO optical reader, file-masquerading detector and advisory coverage gate as in the v2 run), evaluated against the [published answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) for the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html), using the same 20 ground-truth items and the same standards as the Claude Opus baseline (`examples/ndlc/ACCURACY-REPORT.md`) and the previous MiniMax M2.5 scorecards (pre-release runs of the same model on the same evidence, not published): a wrong detail (edition, date, timezone, device) is PARTIAL, mention without evidence is PARTIAL, and only claims the answer key contradicts or causal attributions the evidence does not support count as FALSE POSITIVE. Hedged inferences labelled as such are not counted; a claim carried unhedged into the narrative, IOC table or containment actions is.

Report scored: `ndlc.report.md` in this directory (13 findings: 7 confirmed, 6 inference; 3 high, 6 medium, 4 info; rc 0; 222 tool calls; 29 minutes, 19:53–20:22 UTC; 7.27M input / 123K output tokens; 0 compactions; 1 gate retry). **Image: v1.5.2.** The report's own footer counts 323 tool calls, 27 minutes and 7.1M / 116.9K tokens; the runner's figures are used here.

---

## Scorecard

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 1 | 5% |
| PARTIAL | 11 | 55% |
| MISSED | 8 | 40% |
| FALSE POSITIVE (within the 20 items) | 0 | 0% |

One false positive was made on a claim outside the 20-item grid (see False Positive Handling), for **1 false positive in total**.

**Effective accuracy: 5% full match, 60% detection rate (found at least related evidence), 5% false positive rate (1 contradicted claim / 20 items, the baseline's definition).**

---

## Ground Truth Comparison

| # | Ground Truth Item | Status | Agent's Finding |
|---|-------------------|--------|-----------------|
| 1 | Suspect identity: "Iaman Informant" (iaman.informant@nist.gov) | PARTIAL | The account is the actor and, for the first time in a MiniMax run, the address is the suspect's rather than carved victim data: "The activity is internally sourced and attributed to the user account 'informant.'"; "The presence of NIST email addresses (iaman.informant@nist.gov, informant@nist.gov) in the extracted data strongly suggests the user was a NIST employee or contractor with legitimate access to the workstation"; containment "disable the NIST user account 'informant'". The name "Iaman Informant" never appears, the "IAMAN $_@" and "IAMAN CD" labels quoted in the same report are not connected to it, and attribution is held at inference: "there is no direct process-level or USN journal evidence showing exactly who performed the USB copy operation". |
| 2 | PC OS: Windows 7 Ultimate 64-bit, standalone WORKGROUP | MISSED | "a Windows workstation at NIST"; containment "the workstation (IP or hostname to be determined from registry)". No version, edition, build, install date, computer name or workgroup; `registry.query.system` was indexed three times. Same as v2. |
| 3 | USB Device 1: SanDisk Cruzer Fit, S/N 4C530012450531101593, exFAT, "Authorized USB" | MISSED | RM1 is absent from the report: "The evidence set consists of a PC disk image, two removable media images (RM2 - USB drive, RM3 - optical CD)". The "Authorized USB" label and "Secret Project Data" folder v2 had are gone; rm1's `tsk.filelist` (27 lines) and `tsk.masquerade` (0 lines) were indexed and not read. Regressed from PARTIAL. (The v2 false positive that made RM1 the destination of the copy is gone with it.) |
| 4 | USB Device 2: SanDisk Cruzer Fit, S/N 4C530012550531106501, FAT32, "IAMAN $_@" | PARTIAL | "The use of USB removable media (the 'IAMAN $_@' device) as an exfiltration vector"; Q1 "RM2 USB drive labeled 'IAMAN $_@'"; finding 10 "Removable media (labeled 'IAMAN $_@') contains archive files"; containment "seize any removable media ... matching the 'IAMAN $_@' labeling observed on RM2". The volume label is correct, for the first time in any open-weight run (from `tsk.fsstat`, 40 lines, new in this run). No FAT32, no 1 GB partition, no vendor, model or serial, no 09:58 connection. Ruled as v2 item 3 (label only): PARTIAL. |
| 5 | RM3: CD-ROM, UDF filesystem, formatted March 24, 2015 (16:53:17 UTC) | PARTIAL | The disc is recognised for the first time in a MiniMax run: "RM3 - optical CD"; "write-once CD labeled 'IAMAN CD'"; "files were stored and deleted over 9 sessions"; RecentDocs "BD-RE Drive (D:) IAMAN CD"; "Files were deleted from CD during session -1 around 20:54-20:55 on March 24, 2015"; finding 9's window ends "2015-03-24T20:57:03Z". UDF is not named and the descriptor timestamp (16:53:17) is not stated; the date given instead is wrong: "The CD pre-dates the incident and was likely used over multiple sessions without detection" (the disc was formatted on 2015-03-24; see FP 1). |
| 6 | Five Secret Project documents exfiltrated to USB | PARTIAL | None of the five filenames appears and "Secret Project Data" is gone (v2 had the folder and one name via LNK). What the report has is byte-exact sizes on the disguised copies: "winter_storm.amr is 14,547,968 bytes on both media. winter_whether_advisory.zip is 16,381,123 bytes on both. my_favorite_movies.7z is 100,078 bytes on both" (two of the answer key's four document sizes). The documents were found on RM2 and RM3, never named or traced to RM1; Q5 "At minimum, 17 files with mislabeled extensions were copied from CD to USB". Same level as v2 on different evidence. |
| 7 | File masquerading: documents renamed with false extensions on RM2 FAT32 | FOUND | "17 deleted files were created on the USB removable media (RM2) located in the OrphanFiles directory. These files exhibited mislabeled extensions indicating intentional obfuscation: winter_whether_advisory.zip → actually PPTX (16,381,123 bytes); my_favorite_movies.7z → actually XLSX (100,078 bytes); new_years_day.jpg → actually XLSX; my_smartphone.png → actually DOCX; new_year_calendar.one → actually DOCX; a_gift_from_you.gif → actually DOCX; landscape.png → actually DOCX; diary_#1d.txt → actually DOCX; diary_#1p.txt → actually PPTX; diary_#2d.txt → actually DOCX; Plus 7 additional OLE files with mislabeled extensions"; "Mislabeled Extensions as Anti-Forensic Measure ... designed to evade content inspection and automated data loss prevention (DLP) systems". Count (17), medium (RM2), deleted state, date (March 24) and technique all match Q53/Q55; ten files typed (v2: four). Not stated: the FAT32 filesystem and any original-name mapping (the baseline had four). Same ruling as v2. |
| 8 | Anti-forensics tools: CCleaner and Eraser deployed | MISSED | Neither tool is mentioned; Q4: "No malware, scheduled tasks, or service installations were observed." `ez.shimcache` (307 lines) was indexed and not cited. Same as v2. |
| 9 | Search history reveals premeditation (leakage methods, anti-forensics) | MISSED | No search term of any kind is quoted (v2 at least had the truncated 'security+che'); `bulk.url_searches` (155 lines) was indexed twice and not used. |
| 10 | Google Drive sync installed for cloud exfiltration | PARTIAL | Installation and sync folder found and dated: "Google Drive installation at Program Files (x86)\Google\Drive, user data folders at \Users\informant\AppData\Local\Google\Drive and \Users\informant\Google Drive, language pack access, and a lockfile indicating active synchronization" on March 23 20:02–20:05 UTC; finding 4 (confirmed) "This represents cloud-based data exfiltration capability." Then withdrawn: "Google Drive Sync - Non-Factor ... thoroughly investigated and determined to be unrelated to the March 24 USB exfiltration"; finding 12 "Google Drive Sync Not Source of USB Business Documents". The narrow claim (Drive was not the source of the USB files) is true; the conclusion that Drive played no part contradicts Q58/Q59 (cloud is one of the four leakage methods) but is a negative finding, not counted. v2 had the ShimCache execution time and the exfiltration framing (FOUND). |
| 11 | iCloud setup downloaded (secondary cloud channel) | MISSED | iCloud does not appear. Regressed from FOUND. |
| 12 | USB connection timestamps via EVTX System log | PARTIAL | "The USB Mass Storage Driver (USBSTOR.SYS) was loaded and active on March 24, 2015 at 13:37:59, confirming removable media was connected to the system around the time of the data exfiltration. The registry USBSTOR key contained one subkey, indicating at least one USB mass storage device was connected." From `registry.system`, not the EVTX; one unattributed timestamp (13:37:59Z = 09:37:59 EDT, the answer key's 09:38 RM1 connection on March 24), and not the 09:58 RM2 connection the exfiltration needs. Same ruling as run 1's PARTIAL for the same event; v2 had nothing. |
| 13 | Exfiltration timeline: Feb 15 bulk copy (42-second window) | MISSED | No February activity; the timeline starts 2015-01-05 on document modification times. |
| 14 | Anti-forensics: CCleaner deployed but did not clean (launched and closed without action) | MISSED | CCleaner is not mentioned. |
| 15 | Systematic file deletion on RM2 FAT32 (Mar 24, 09:54-10:00) | PARTIAL | "The primary data exfiltration occurred on March 24, 2015, between 09:59:27 and 10:00:18 UTC. During this window, 17 deleted files were created on the USB removable media (RM2)"; finding 6 "files with creation timestamps between 09:59:27 and 10:00:18 on March 24, 2015". The window is now on the right device (v2 attached it to rm1) and the files are recognised as deleted, but the window is described as the copy, no deletion event is described, and the quick format (Q54) is not inferred. Same level as v2. |
| 16 | RM3 contains government documents matching Secret Project content | PARTIAL | The disc's listing is read for the first time in a MiniMax run: "The CD contains /design, /pricing decision, /progress, /proposal, and /technical review directories"; "deleted files from previous sessions reveal the full scope of data that was staged for potential exfiltration: design documents, pricing decisions, technical reviews, proposals, progress reports, and personal diary files"; "3 legitimate JPEG images (Koala.jpg, Penguins.jpg, Tulips.jpg) totaling approximately 2.1MB"; sizes matched file-for-file to the RM2 copies. Not matched to the five Secret Project documents ("appear to be corporate or government-sensitive materials based on their naming conventions"); the diary files, which the report itself types as DOCX/PPTX, are called "personal diary files". From MISSED. |
| 17 | Files opened in RM2 (list all accessed files) | PARTIAL | "RecentDocs entries for this user show access to: winter_whether_advisory.zip (20:44:18Z), BD-RE Drive (D:) IAMAN CD (21:01:14Z), and image files (Koala.jpg, Tulips.jpg, Penguins.jpg) from the CD. These files directly correspond to the data found on the USB removable media." The opened file is the Q26 file; the drive letter (`E:`) and the 10:01 open time are not given (20:44:18Z is the RecentDocs key's write time), and the other entries are the disc, not RM2. No LNK, JumpList or ShellBag evidence for `E:`. From MISSED. |
| 18 | Network drive directories traversed | PARTIAL | "references to IP address 10.11.11.128 labeled as 'SECURED_DRIVE' or 'secured_drive'"; "a private IP address (10.x.x.x range), suggesting a local network resource such as a network-attached storage (NAS) device"; "This finding may represent an alternative exfiltration vector that was considered or attempted but not confirmed as the primary method"; T1041. IP and share correct; no directory (v2 had `Common Data`), no date, no traversal, no files. v2's correct "legitimate corporate infrastructure" has become a hedged possible exfiltration target (inference, INFO; not counted). Q3 "No lateral movement was detected." |
| 19 | Email communication with spy.conspirator@nist.gov | PARTIAL | "NIST email addresses (iaman.informant@nist.gov, informant@nist.gov)", correctly the suspect's this time; "Microsoft Outlook (OUTLOOK.EXE) at 15:03:42" on March 22; "email archives" in the evidence inventory. `spy.conspirator@nist.gov` is absent, the OST is not named or parsed (`bulk.rfc822`, 7,326 lines, indexed twice and unused). Same standard as the baseline's PARTIAL. |
| 20 | FAT32 timezone offset (local time vs UTC) | MISSED | No timezone is stated. The report prints the offset without seeing it: "winter_storm.amr shows modified=2015-01-23T20:47:10Z on CD and mtime=2015-01-23 16:47:10 UTC on USB; winter_whether_advisory.zip shows modified=2014-12-16T16:10:26Z on CD and mtime=2014-12-16 12:10:26 UTC on USB" and calls these "File modification timestamps match". The four-hour gap is the FAT32 local-time (Eastern) versus UDF UTC discrepancy the item asks for. |

---

## Findings Beyond the Answer Key

| Finding | Assessment |
|---------|------------|
| RM2 volume label "IAMAN $_@" | Legitimate (Q23); first open-weight run to state it. |
| RM3: 9 sessions, 3 JPEGs currently present (~2.1 MB), deletion in "session -1" at 20:54–20:55 on March 24 | Legitimate; consistent with the disc's final state. |
| Byte-exact size matches between disc and RM2 copies (14,547,968; 16,381,123; 100,078) | Legitimate. The same numbers would have matched the Secret Project originals on RM1, which was never read. |
| RecentDocs: `winter_whether_advisory.zip`, "BD-RE Drive (D:) IAMAN CD", Koala/Tulips/Penguins | Legitimate; `D:` is the burner (Q35). |
| UserAssist: `xpsrchvw.exe` on March 25 15:24–15:28; admin11 and temporary active only on March 22 | Legitimate (Q6: accounts created during setup) and, unlike the DeepSeek runs, not read as a compromise. |
| Excel, Outlook, PowerPoint, Windows Mail on March 22 14:34–15:23 | Legitimate. |
| Google Drive install path, sync folder and lockfile, March 23 20:02Z | Legitimate (Q11 places the install at 19:56Z). |
| "This incident represents insider threat, not external attack"; no malware; Q4 "No persistence mechanisms were identified" | Correct case type, as in both previous runs. |
| "The registry USBSTOR key contained one subkey" | Technically the device-class key (both sticks are the same SanDisk Cruzer Fit model); the two serial subkeys beneath it were not read. Not counted. |
| "personal diary files with potentially sensitive content" as a data category | The `diary_*.txt` files are disguised technical-review documents (the report types them DOCX/PPTX itself). Detail, not counted. |
| 10.11.11.128 as "an alternative exfiltration vector that was considered or attempted"; T1041 | Hedged inference at INFO; not counted. |
| "Google Drive Sync - Non-Factor" | Negative finding contradicting Q58/Q59; not counted (see item 10). |
| "files were copied from CD (RM3) to USB (RM2), not directly from PC"; "The CD pre-dates the incident" | Incorrect. See FP 1. |

---

## False Positive Handling

**One false positive identified in post-verification.** It does not fall on a graded item; it is a confirmed HIGH finding, the title of the report's first lifecycle phase, and the basis of Q5, the strategic remediation and finding 12.

| # | Report claim | Contradicting answer-key statement |
|---|-------------|------------------------------------|
| 1 | Finding 3 (HIGH, confirmed) "CD (RM3) to USB (RM2) Data Staging Path Confirmed": "files were copied from CD (RM3) to USB (RM2), NOT directly from PC"; Key Findings "The investigation definitively established the data staging path: files were copied from the CD (RM3) to the USB drive (RM2), not directly from the PC hard drive"; "The deletion timeline on the CD shows files were deleted during session -1 around 20:54-20:55 on March 24, 2015, correlating with the USB file creation times (09:59:27-10:00:18 on March 24)"; Q5 "17 files with mislabeled extensions were copied from CD to USB on March 24, 2015"; Strategic Remediation "The CD pre-dates the incident and was likely used over multiple sessions without detection"; finding 9 "This CD was likely used as a data staging location before copying to other removable media". | Q34/Q35: RM3 was formatted (UDF) on 2015-03-24 at 16:53:17 UTC, i.e. after the 09:59–10:00 (Eastern) copy to RM2 it is said to have fed; the disc does not pre-date the incident and could not be the source of the USB files. Section 3 and Q55: the documents came from RM1 ("Authorized USB") to the PC on March 23 and 24, were renamed on the PC and copied to RM2, and were burned to the CD-R afterwards; the CD's own "session -1" deletion at 20:54 UTC is the last step of the day, not the source of the morning's copy. The identical sizes and directory names the finding cites are what two copies of the same files look like and say nothing about direction. This is the same class of error as v2 FP 1 (direction of copy inverted, then with RM1 as destination, now with RM3 as source), built this time on the disc listing the model read for the first time. |

The remaining material is either correct (the "IAMAN $_@" label, the 17 disguised files with types and sizes, the disc's label, sessions, directories and final JPEGs, the Drive install and sync folder, the USBSTOR service time, the RecentDocs entries, the network share, the insider framing, the absence of malware) or silence. The v2 false positives on Govdocs content (45 American Express cards, NASA phone numbers, OMB/LoC addresses as exfiltrated PII) are gone: `bulk.ccn` and `bulk.telephone` were not run this time, and no email address other than the suspect's is reported. No IOC table entries were produced.

---

## Analysis of Misses and Errors

### What v1.5.2 changed

The #228 fix scopes `tsk.partitions` lookups to the image being analysed and scans every partition in `detect_masquerading`. The masquerade line counts are the same as v2 (0 on rm1, 17 on rm2, 3 on rm3) and `optical.listing` is again 58 lines, so the masquerade and optical output the model saw is unchanged. What is new in this run's source table is `tsk.fsstat` (40 lines) and per-image `tsk.partitions` rows, and the report's one new device fact, the "IAMAN $_@" label, comes from there.

### The CD-R was read this time, and used to build the wrong chain (items 5, 16, 17; FP 1)

v2's outstanding gap was `optical.listing` indexed and unread; this run reads it, reports the label, the 9 sessions, the five directories, the three surviving JPEGs and the session-level deletion time, and matches the disc's files byte-for-byte to RM2's orphans. Items 5 and 16 move from MISSED to PARTIAL and the RecentDocs entry for the disc supports item 17. The same reading then produces the run's only false positive: because the disc's files are older (document mtimes) and the disc's deletion is later, the model concludes the CD was the source and "pre-dates the incident", without checking the disc's format timestamp or reading RM1, where the originals sit under their real names.

### What regressed (items 3, 10, 11)

RM1 is absent, and with it the "Authorized USB" label and the "Secret Project Data" folder that gave v2 items 3 and 6 their content. Google Drive and iCloud, both FOUND in v2 from the ShimCache execution times, are now a PARTIAL (install and sync folder, role denied) and a MISSED (not mentioned). The run made 222 tool calls against 343 in v2, and the report's histogram (search 73, open_case 24, get_raw_output 18, submit_finding 16, start_extraction_batch 14) shows the budget went to RM2, RM3 and the `informant` NTUSER hive, not to ShimCache or RM1.

### Anti-forensics and search history still absent (items 8, 9, 13, 14)

Neither CCleaner nor Eraser, no search term, no February copy: unchanged from v2. `ez.shimcache` and `bulk.url_searches` are in the source table and not in the report. Q4's "no ... service installations were observed" is wrong in detail (the ASP.NET service for Eraser was installed on March 25) but is a negative finding.

### Timezone offset printed and not seen (item 20)

Finding 3 quotes a UDF timestamp of 20:47:10Z and a FAT32 timestamp of 16:47:10 for the same file and calls them matching. The four-hour difference is Eastern Daylight Time; the report had the answer to item 20 in its own evidence and read past it.

### Email still not parsed (item 19)

The suspect's address is now correctly the suspect's, and Outlook use on March 22 is noted, but the OST is not named, `bulk.rfc822` is unused and `spy.conspirator@nist.gov` is absent.

---

## Notes: what changed since the v2 run

- **CD-R contents: shown.** The report identifies `rm3` as a "write-once CD labeled 'IAMAN CD'" with 9 sessions, lists its five directories and the three JPEGs currently present, dates the last deletion to March 24 20:54–20:55, and matches its deleted files by size to RM2's orphans. It does not state UDF, the format timestamp or the burner, says the disc "pre-dates the incident", and makes it the source of the USB copy (FP 1). Items 5 and 16 move from MISSED to PARTIAL.
- **Masquerading finding: shown.** "17 deleted files were created on the USB removable media (RM2)", ten named with true types and two with exact sizes, correctly called an anti-forensic measure against DLP inspection. No original-name mapping. Item 7 stays FOUND.
- **Score versus the v2 MiniMax M2.5 run (3 FOUND / 6 PARTIAL / 11 MISSED / 0 FP in grid; 3 FP total; 15% full, 45% detection, 15% FP):** this run is 1 / 11 / 8 / 0 with 1 FP total, i.e. 5% full, 60% detection, 5% FP. Five items improved (4, 5, 12, 16, 17 from MISSED to PARTIAL), three regressed (3 from PARTIAL to MISSED; 10 from FOUND to PARTIAL; 11 from FOUND to MISSED), twelve are unchanged. Detection rose on the disc and RM2 evidence; full matches fell because the two cloud items lost their ShimCache times; false positives fell from three to one because the Govdocs carves were not run and the RM1 inversion went away with RM1, leaving a new inversion (RM3 as source) in its place. Cost rose from 6.9M to 7.4M tokens at 29 minutes against 28.

---

## Comparison with Claude Opus baseline and the v2 MiniMax M2.5 run

| Metric | Claude Opus (baseline) | MiniMax M2.5 v2 (2026-09-19) | MiniMax M2.5 v1.5.2 (2026-09-19) |
|--------|------------------------|------------------------------|----------------------------------|
| FOUND | 12 | 3 | 1 |
| PARTIAL | 6 | 6 | 11 |
| MISSED | 1 | 11 | 8 |
| FALSE POSITIVE (in 20-item grid) | 1 | 0 | 0 |
| False positives, total | 1 | 3 | 1 |
| Full-match rate | 60% | 15% | 5% |
| Detection rate (FOUND + PARTIAL) | 90% | 45% | 60% |
| False-positive rate (FP / 20) | 5% | 15% | 5% |
| Suspect attributed | Yes, 6 sources | Account only (address seen, filed as victim data) | Account only (address correctly the suspect's; name not stated) |
| Case type identified | Insider threat | Insider threat (correct) | Insider threat (correct) |
| Secret Project documents named | 5 of 5 | 1 of 5 (LNK), folder on RM1 | 0 (disguised copies with exact sizes) |
| USB devices identified | Both, with serials | RM1 by label only; RM2 examined but unidentified | RM2 by label only ("IAMAN $_@"); RM1 absent |
| CD-R (RM3) analysed | Yes | No (called a USB device; `optical.listing` unread) | Yes (label, 9 sessions, directories, deletion time; wrongly made the source) |
| Masquerading detected | Yes (4 mappings) | Yes (17 files, 4 typed, no mappings) | Yes (17 files, 10 typed, 2 sized, no mappings) |
| CCleaner / Eraser | Both, with evidence | Neither | Neither |
| Email correspondent identified | No | No (suspect's address and OST filename found) | No (suspect's address found, attributed correctly) |
| Network drive identified | No | Yes (one directory, correctly assessed as corporate) | Yes (share only, hedged as possible exfiltration target) |
| Timezone | UTC+1 (wrong) | Not stated | Not stated (offset printed, unrecognised) |
| Dates preceding OS install | 0 | 0 | 0 as activity (Dec–Jan read as document mtimes), but the CD is said to "pre-date the incident" |
| Findings | 33 (29 confirmed / 4 inference) | 11 (11 confirmed / 0 inference) | 13 (7 confirmed / 6 inference) |
| Tool calls | 723 | 343 | 222 (report footer: 323) |
| Runtime | 1.7 h | 28 min | 29 min |
| Total tokens | 330.3K | 6.9M | 7.4M |

Per-item status, side by side:

| # | Item | Opus | MiniMax v2 | MiniMax v1.5.2 |
|---|------|------|------------|----------------|
| 1 | Suspect identity | FOUND | PARTIAL | PARTIAL |
| 2 | PC OS | PARTIAL | MISSED | MISSED |
| 3 | USB Device 1 | FOUND | PARTIAL | MISSED |
| 4 | USB Device 2 | FOUND | MISSED | PARTIAL |
| 5 | RM3 CD-ROM | PARTIAL | MISSED | PARTIAL |
| 6 | Five documents exfiltrated | FOUND | PARTIAL | PARTIAL |
| 7 | File masquerading | PARTIAL | FOUND | FOUND |
| 8 | CCleaner and Eraser | FOUND | MISSED | MISSED |
| 9 | Search history | FOUND | MISSED | MISSED |
| 10 | Google Drive | FOUND | FOUND | PARTIAL |
| 11 | iCloud | FOUND | FOUND | MISSED |
| 12 | USB EVTX timestamps | FOUND | MISSED | PARTIAL |
| 13 | Feb 15 bulk copy | FOUND | MISSED | MISSED |
| 14 | CCleaner did not clean | FALSE POSITIVE | MISSED | MISSED |
| 15 | RM2 systematic deletion | FOUND | PARTIAL | PARTIAL |
| 16 | RM3 content | PARTIAL | MISSED | PARTIAL |
| 17 | Files opened in RM2 | PARTIAL | MISSED | PARTIAL |
| 18 | Network drive traversal | MISSED | PARTIAL | PARTIAL |
| 19 | Email with spy.conspirator | PARTIAL | PARTIAL | PARTIAL |
| 20 | FAT32 timezone offset | PARTIAL | MISSED | MISSED |

The v1.5.2 run is the cleanest open-weight report so far on false positives (one, versus three to five in every other run) and the widest on detection (12 of 20 items touched), and it is the first MiniMax run to read the CD-R and name RM2. It pays with the cloud items, which lose their ShimCache times, and with RM1, which disappears entirely; and its one contradicted claim is a structural one, the direction of the copy, which it has now got wrong in two different ways across two runs. The Opus baseline remains the only run that identified both USB devices, named the five documents, and attributed the case.
