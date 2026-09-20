# Accuracy Report: NDLC (NIST CFReDS Data Leakage Case 2015) — bedrock/qwen.qwen3-235b-a22b-2507-v1:0 (release v1.5.2, run 2, 2026-09-19)

Mulder's autonomous findings, produced by the open-weight model `bedrock/qwen.qwen3-235b-a22b-2507-v1:0` (via LiteLLM, `--no-thinking`) on the **v1.5.2 release image** (git tag `v1.5.2` = main @ 70ea37f plus the per-image partition-table fix #228; UDF/ISO optical reader, file-masquerading detector and advisory coverage gate), evaluated against the [published answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) for the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html), using the same 20 ground-truth items and the same standards as the Claude Opus baseline (`examples/ndlc/ACCURACY-REPORT.md`), the Opus 4.6 v1.5.2 run (`examples/ndlc-v1.5.2/opus-4.6`) and run 1 of this model on the same image and settings (`examples/ndlc-v1.5.2/qwen3-235b-run1`): a wrong detail (edition, date, timezone, device) is PARTIAL, mention without evidence is PARTIAL, and only claims the answer key contradicts or causal attributions the evidence does not support count as FALSE POSITIVE. Hedged inferences labelled as such are not counted; a claim carried unhedged into the narrative, key findings, IOC table or containment actions is.

Report scored: `ndlc.report.md` (this directory) (3 findings delivered: 0 confirmed, 3 inference; 3 high; 19 evidence sources; rc 0; all gates passed; 33 minutes, 01:05–01:38 UTC; 2 turn-limit continuations; 13.5M input / 16.5K output tokens per the runner). **Image: v1.5.2.** **Run 2 of 3.** The report's own footer counts 205 tool calls, 31 minutes and 13.2M / 13.6K tokens; the audit log has 207 `tool_call` records; the runner's figures are used here. Harness notes from the run log: the catalog phase (4 turns, 3 tool calls) returned a JSON that registered **one** system, `cfreds_2015_data_leakage` (the four images' common filename prefix), where run 1 registered four (`_pc`, `_rm1`, `_rm2`, `_rm3_type3`); the orchestrator therefore planned "1 session(s) for 1 systems", ran one 13-task extraction plan for the whole case, and skipped the cross-system phase ("only 1 system(s) in catalog"). Of the 13 tasks, `run_bulk_extractor` failed on all three disk images ("Unknown bulk_extractor scanner(s): regex, tcpudp") and `run_fls` was first rejected three times ("unexpected parameter(s) 'output_path'") and resubmitted; no registry, MFT, EVTX, ShimCache, Amcache, Prefetch, ShellBags, USN, SRUM or browser-history parser was ever run. The 19 indexed sources are three `tsk.partitions`, three `tsk.filelist` (rm2 51 lines, rm1 27, PC 104,709) plus `tsk.filelist.p1` (93), three `tsk.masquerade` (rm2 **17** lines, rm1 0, PC 3: the first Qwen run in which the detector reached rm2), `optical.listing` (58), seven one-line `registry.query.*` values and `composite.correlation` (1). The analysis session paged the PC's 104,709-line `tsk.filelist` into context through 23 `get_raw_output` calls until the model's 262K context filled ("your prompt contains at least 229377 input tokens"), auto-compacted once, then issued the identical `search` (`["diary", "txt"]` in `tsk.filelist`) 20 times in a row (01:16:08–01:20:04). Both IOC tables are empty ("No network IOCs extracted", "No file IOCs extracted"). The tool histogram is get_raw_output (65), search (52), open_case (11), get_timeline (11), get_investigation_summary (7), query_registry_value (7).

---

## Scorecard

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 0 | 0% |
| PARTIAL | 5 | 25% |
| MISSED | 15 | 75% |
| FALSE POSITIVE (within the 20 items) | 0 | 0% |

One false positive was made on a claim outside the 20-item grid (see False Positive Handling), for **1 false positive in total**.

**Effective accuracy: 0% full match, 25% detection rate (found at least related evidence), 5% false positive rate (1 contradicted claim / 20 items, the baseline's definition).**

---

## Ground Truth Comparison

| # | Ground Truth Item | Status | Agent's Finding |
|---|-------------------|--------|-----------------|
| 1 | Suspect identity: "Iaman Informant" (iaman.informant@nist.gov) | MISSED | No name, address, account or resignation letter anywhere on the page. Threat Intelligence: "The evidence in this case does not provide sufficient information for attribution to a specific threat actor or group"; Impact: "The `Temporary Internet Files` finding suggests the same user account may have been used for general web browsing", the account never named. The run searched `Users/informant/AppData/Local/Microsoft/Windows/Temporary Internet Files` at 01:35:40 and wrote nothing of it down; `informant`, `Iaman` and `IAMAN` do not occur in the report. Run 1 had the account, the insider framing and the letter (PARTIAL); this is the first Qwen run with no attribution of any kind. |
| 2 | PC OS: Windows 7 Ultimate 64-bit, standalone WORKGROUP | PARTIAL | "The primary system runs Windows 7, as indicated by the filesystem structure and registry keys." Version only: no edition, architecture, build, computer name or workgroup. `Microsoft\Windows NT\CurrentVersion` was queried at 01:24:29 (`registry.query.software`, 1 line), where `ProductName` is "Windows 7 Ultimate" (Q3), and only "Windows 7" reached the page. The edition is absent rather than wrong (run 1: "Professional"); bare "Windows 7" is the PARTIAL floor. |
| 3 | USB Device 1: SanDisk Cruzer Fit, S/N 4C530012450531101593, exFAT, "Authorized USB" | MISSED | rm1 is one of "three potential source disk images (cfreds_2015_data_leakage_rm1.E01 to rm3_type3.E01)"; Q1 "The other systems (rm1, rm2, rm3) are the suspected source media, not compromised hosts." The word "USB" does not occur in the report ("removable storage devices" once, in Strategic Remediation). rm1's `tsk.partitions` (8 lines) and `tsk.filelist` (27) are indexed and never described; "RM#1" and "Secret Project Data" were searched at 01:35:03 and 01:34:58 and nothing was reported. No vendor, model, serial, filesystem, label or connection time. Same as run 1. |
| 4 | USB Device 2: SanDisk Cruzer Fit, S/N 4C530012550531106501, FAT32, "IAMAN $_@" | MISSED | rm2 is a "suspected source" image. Its 17-line `tsk.masquerade` output is the basis of two of the three findings, and the report places that content on the PC: finding 1 "Deleted files from the optical media were staged in the 'OrphanFiles' directory on the target system"; Key Findings "The `$OrphanFiles` directory on the primary system contained files that were originally copied from the optical media." No FAT32, no label, no serial, no size, no connection time; the device is never named as a device. Contents on the wrong device (FP 1): MISSED, the run 1 ruling for contents without the device. |
| 5 | RM3: CD-ROM, UDF filesystem, formatted March 24, 2015 (16:53:17 UTC) | PARTIAL | Background: "the filesystem listing of an optical media (CD) used for data transfer"; finding 1 "Optical media listing shows directories 'technical review', 'proposal', 'progress', etc., containing suspicious document files" (`optical.listing`, 58 lines, fetched six times); narrative "files from the `technical review` and `progress` directories on the optical disc. This included the file `tr/diary_#1d.txt` and `tr/diary_#1p.txt`" (the disc's abbreviated session directory, read correctly). Medium right and sourced. No filesystem ("UDF" never appears), no label ("IAMAN CD" never appears), no session count, no date of any kind, no burner, and the disc's role is inverted: it is the *source* the data came from in January 2015, not the last destination (FP 1). Run 1 had UDF, the label and nine sessions; this is the medium and the directory names. |
| 6 | Five Secret Project documents exfiltrated to USB | PARTIAL | None of the five is named and "Secret Project" does not occur. What the report has is the disguised copies with their detected types: finding 3 "design/winter_whether_advisory.zip (PPTX detected)", "design/winter_storm.amr (OLE detected)", "proposal/a_gift_from_you.gif (DOCX detected)", "proposal/landscape.png (DOCX detected)" (the disguised copies of four of the five, never mapped back), and Q5 "A significant volume of data, estimated at over 60 MB based on file sizes, was copied from the targeted system. The data includes documents from `technical review`, `proposal`, `progress`, `pricing decision`, and `design` directories, all of which were disguised with false file extensions." The DeepSeek and MiniMax v1.5.2 ruling for the same content (documents found through their disguised copies, never named or traced to RM1): PARTIAL. No sizes, no USB, and the direction of travel is inverted everywhere except Q5. |
| 7 | File masquerading: documents renamed with false extensions on RM2 FAT32 | PARTIAL | Technique detected and the set complete: finding 3 lists all 17 with detected types ("TECHNI~1/diary_#1d.txt (OLE detected) ... PRICIN~1/my_favorite_movies.7z (XLSX detected) ... progress/my_smartphone.png (DOCX detected) ... proposal/a_gift_from_you.gif (DOCX detected)"), "These findings confirm the active use of file extension masquerading to conceal sensitive documents"; Key Findings "Forensic analysis via `tsk.masquerade` confirmed that these files, despite their apparent extensions (e.g., `.txt`, `.amr`, `.gif`), were actually Microsoft Office documents, compressed archives, and other proprietary formats." `tsk.masquerade` returned 17 lines on rm2 for the first time in a Qwen run (run 1 never ran it there). But the medium is never RM2 or FAT32: the 17 are "Deleted files from the optical media ... staged in the 'OrphanFiles' directory on the target system"; no original-to-fake mapping; and the count is "14 files" in finding 1, "16 files" in Key Findings and 17 in finding 3. Technique and set on the wrong medium: PARTIAL, the DeepSeek run 1 ruling ("count on wrong medium"). The one item better than run 1 (MISSED). |
| 8 | Anti-forensics tools: CCleaner and Eraser deployed | MISSED | Neither name occurs. "Eraser" and "CCleaner" were searched in `tsk.filelist` at 01:34:38 and 01:34:40 and nothing was reported; no UserAssist, ShimCache or Amcache parser ran. Run 1 had Eraser to the second (PARTIAL). |
| 9 | Search history reveals premeditation (leakage methods, anti-forensics) | MISSED | No URL source exists: all three `run_bulk_extractor` jobs failed at submission ("Unknown bulk_extractor scanner(s): regex, tcpudp") and were not resubmitted, and no browser-history parser ran. The report's whole web-activity content is "A separate activity, focused on web browsing, took place in March 2015" and two Temporary Internet Files entries; no search term, no premeditation. Run 1 had the leakage-methods half paraphrased (PARTIAL). |
| 10 | Google Drive sync installed for cloud exfiltration | MISSED | Not mentioned. "googledrivesync.exe" was searched in `tsk.filelist` at 01:34:33 and not reported; Impact "there is no evidence of system compromise beyond the data copy operation". Run 1's best item (FOUND). |
| 11 | iCloud setup downloaded (secondary cloud channel) | MISSED | Not mentioned. "icloudsetup.exe" was searched at 01:34:34 and not reported. Run 1: FOUND. |
| 12 | USB connection timestamps via EVTX System log | MISSED | No EVTX parser ran, `USBSTOR` was never queried; no connection event of any kind. Same as run 1. |
| 13 | Exfiltration timeline: Feb 15 bulk copy (42-second window) | MISSED | No February. The report's transfer is "between January 5 and January 24, 2015", inbound from the disc (FP 1); Q6 "The main data transfer occurred between January 5 and January 23, 2015." rm1's filesystem is never examined. Same status as run 1. |
| 14 | Anti-forensics: CCleaner deployed but did not clean (launched and closed without action) | MISSED | CCleaner is not mentioned; nothing to grade. Same as run 1. |
| 15 | Systematic file deletion on RM2 FAT32 (Mar 24, 09:54–10:00) | MISSED | The 17 files are "Deleted files" in `$OrphanFiles`, but on "the target system", dated to January 2015 write events, with no deletion event, no window and no count as a deletion. The only deletion described as an event is `f[1].txt`, which "may have been deleted". The DeepSeek and MiniMax v1.5.2 PARTIALs each had a March 2015 deletion date; this has none, and run 1's disc-side "written and then deleted across sessions" is gone. Same status as run 1. |
| 16 | RM3 contains government documents matching Secret Project content | PARTIAL | Finding 1 "Optical media listing shows directories 'technical review', 'proposal', 'progress', etc., containing suspicious document files"; narrative names disc files by session path ("`tr/diary_#1d.txt`", "`my_favorite_cars.db`", "`winter_storm.amr` and `winter_whether_advisory.zip`" from "the `design` directory on the optical disc"); Impact "technical reviews, pricing decisions, progress reports, and design documents, all of which were successfully exfiltrated via the optical media". Directory and file names from the listing; nothing matched to the five documents, the three surviving JPEGs absent, and the disc's role inverted in the timeline (source) while right in Impact and Q5 (destination). Same level as run 1 (directory names only). |
| 17 | Files opened in RM2 (list all accessed files) | MISSED | No ShellBags, RecentDocs, LNK or JumpList evidence; no file is said to have been opened on any medium. Run 1 had `winter_whether_advisory.zip` opened from RecentDocs (PARTIAL). |
| 18 | Network drive directories traversed | MISSED | Q3 "There is no evidence of lateral movement within a network. The attack was isolated to a single host." No `10.11.11.128`, no `secured_drive`, no `V:`. Same as run 1. |
| 19 | Email communication with spy.conspirator@nist.gov | MISSED | No OST, no Outlook, no address of any kind; `run_bulk_extractor` failed so no `bulk.email` or `bulk.rfc822` exists. Same as run 1. |
| 20 | FAT32 timezone offset (local time vs UTC) | MISSED | `ControlSet001\Control\TimeZoneInformation` was queried at 01:23:45 (`registry.query.system`, 1 line) and never reported; no timezone is stated and no discrepancy is observed. Same as run 1. |

---

## Findings Beyond the Answer Key

| Finding | Assessment |
|---------|------------|
| Q3 "There is no evidence of lateral movement within a network"; Q4 "There is no evidence of any persistence mechanisms, such as backdoors, scheduled tasks, or registry run keys"; Threat Intelligence "the lack of sophisticated tools, unique indicators, malware, or persistent access mechanisms points towards a basic data theft operation rather than an advanced persistent threat (APT)" | Correct on all three (Q2, Q3, Q4). No intrusion subplot, no account-manipulation, phishing, payment-card or government-targeting claim: run 1's phishing initial access (its FP 1) does not recur. Silence on the suspect, not judgement. |
| Finding 2 (HIGH, inference) "Suspicious Deleted Document in Temporary Internet Files": "`f[1].txt` located in the temporary internet files directory contains content that suggests it is actually a Microsoft Word document ... Further investigation of the file is needed to confirm its content and origin"; narrative "makes it suspicious and a potential indicator of other web-based concealment activities" | One of the PC's three browser-cache mismatches (`tsk.masquerade`, 3 lines), the class run 1's finding 12 correctly dismissed as "browser cache artifacts"; here it is one of three HIGH findings. Hedged ("suggests", "potential", "needed to confirm") and carried into no containment; not counted. |
| Narrative "the file `ae5e07f2a2a2cf54d3a820290c281442[1].png` was accessed at 20:44:28 UTC. This file exhibits a masquerading characteristic similar to the staged data but in a different context"; "`AccountChooser[1].htm`, later identified as a gzip-compressed HTML file" | The other two browser-cache mismatches, correctly typed, presented as a "Phase 2" of the incident. Not claims about the case; not counted. |
| Q5 "estimated at over 60 MB based on file sizes" | The 17 disguised copies sum to about 104 MB; an estimate, not a claim about any file. Not counted (Opus v1.5.2's "135 megabytes" was the same class). |
| Finding 1 "name-extension mismatches for 14 files"; Key Findings "the 16 files copied from the `technical review` and `progress` directories"; finding 3's list of 17 | Three counts for one set; a consistency defect, noted under item 7. |
| Threat Intelligence "It is also a common technique taught in digital forensics exercises." | True of this evidence set. Not counted. |
| Strategic Remediation "Physical Access Control was Absent ... A technical control, such as Group Policy to disable CD/DVD writing, would have prevented the initial data staging and exfiltration" | Built on FP 1's inverted direction (the disc as the inbound medium); a consequence, not a separate claim. |
| Executive-summary "Attack Lifecycle: Initial Access / Deployment (2015-01-20): Data Staging and Concealment on Optical Media; Defense Evasion / Anti-Forensics (2015-01-20)" | Generated lifecycle labels on a January 2015 date that precedes the PC's OS installation (Q3, 2015-03-22); the date is FP 1's. Template artefact. |
| Seven `query_registry_value` calls indexed and unreported: four Office `Uninstall` GUIDs (`{90150000-001F-0409-1000-0000000FF1CE}` etc.), `TimeZoneInformation`, `Windows NT\CurrentVersion`, `Control\Windows` | Retrieved, not written down; scored under items 2 and 20. |
| Both IOC tables empty; no MITRE IDs on any finding (`mitre_attack_ids: []` on all three submissions) | Report-assembly gaps; not claims. |

---

## False Positive Handling

**One false positive identified in post-verification.** It falls on no graded item. The finding that carries it is labelled "inference", but the claim is stated unhedged in the timeline, Key Findings, Attack Lifecycle, Q1, Q2, Q6 and Strategic Remediation, which is the standard under which it is counted.

| # | Report claim | Contradicting answer-key statement |
|---|-------------|------------------------------------|
| 1 | Finding 1 (HIGH) "Data Staging and Concealment on Optical Media": "Deleted files from the optical media were staged in the 'OrphanFiles' directory on the target system, a known indicator of data staging from removable media"; timeline "**Phase 1: Optical Media Data Transfer (January 2015)**. The primary incident occurred between January 5 and January 24, 2015. Data was copied from an optical disc to the primary system's hard drive ... On the system, these files were copied to a directory named `$OrphanFiles` and retained their original names ... The `winter_storm.amr` file was written to the target system at 16:47:10 UTC" on January 23; Key Findings "The `$OrphanFiles` directory on the primary system contained files that were originally copied from the optical media"; Q1 "A single system, the primary disk image, was compromised through direct physical access. The other systems (rm1, rm2, rm3) are the suspected source media, not compromised hosts"; Q2 "The attacker gained initial access through physical access to the machine. This allowed them to insert an optical disc and copy data directly, bypassing network security controls"; Q6 "The main data transfer occurred between January 5 and January 23, 2015." | The direction, the device and the dates are all contradicted. Q3: the PC's OS was installed 2015-03-22 (14:34:26 GMT), so nothing was written to it in January 2015. Section 3 and Q33: the disc was burned from the PC on 2015-03-24 (`D:` "BD-RE Drive (D:) IAMAN CD", first mastered burn 15:47:47 EDT), the last step of PC → RM1 (Feb 15) → RM2 disguised (Mar 24) → CD, not the first. Q53/Q55: the 17 deleted orphan files with false extensions are on RM2's FAT32 volume, created 2015-03-24 09:59–10:00 local, not in the PC's `$OrphanFiles`; the `TECHNI~1/` and `PRICIN~1/` paths the report lists are RM2's FAT short names, and the 17-line `tsk.masquerade` source it cites is rm2's. The January dates are file timestamps carried by the two cited sources (the disguised copies keep their originals' times), read as write events; every one precedes the PC's existence and the key's earliest event. The report contradicts itself in the same document: Q5 "was copied from the targeted system" and Impact "successfully exfiltrated via the optical media" have the direction right. This is run 1's FP 2 (the CD burn reported as USB staging) in a new form: the same disc-and-orphans evidence, this time reported as an inbound copy onto the PC two months before the PC was built. |

**Not counted.** (a) `f[1].txt` as a "potential indicator of other web-based concealment activities": hedged, "Further investigation ... is needed". (b) "over 60 MB": an estimate. (c) The 14 / 16 / 17 count: a consistency defect under item 7. (d) "Windows 7" alone: scored under item 2. (e) Q3's "no evidence of lateral movement": item 18 is a miss, not a contradicted claim, as in run 1.

The remaining material is correct (the 17 disguised files with their true types, the disc's directory names and session paths, the two browser-cache mismatches correctly typed, no persistence, no lateral movement, no APT) or silence. This is the run 1 report with its two FOUND items, its Eraser timestamp, its account and its resignation letter removed, its one invented event (phishing) replaced by another (a January inbound copy from the disc), and the one thing it gained, the rm2 detector output, placed on the wrong device.

---

## Analysis of Misses and Errors

### One system in the catalog (every item)

The catalog phase's JSON named one system, `cfreds_2015_data_leakage`, the prefix the four `.E01` filenames share, instead of four. Everything downstream follows from that line: one extraction session instead of four, one 13-task plan and one 80-turn analysis budget for four images, and no cross-system phase ("Skipping cross-system phase: only 1 system(s) in catalog"). Run 1 ran four sessions with some 60 extractor calls (`run_registry_parser`, `run_mft_parser`, `run_evtx_parser`, `run_shimcache_parser`, `run_amcache_parser`, `run_prefetch_parser`, `parse_shellbags`, `parse_usn_journal`, `parse_srum`, `parse_browser_history`, `run_hayabusa`, `run_chainsaw`, six `run_bulk_extractor` ...); this run's plan was `run_optical_listing`, three `run_mmls`, three `run_fls`, three `run_bulk_extractor`, three `detect_masquerading`, and none of the parsers. The items that live in the registry, the MFT, the event log, the URL carve and the OST (1, 3, 4, 8–15, 17–20) had no source to be found in.

### The extraction plan that ran (items 9, 19; 8, 10, 11)

Three of the 13 tasks failed and were not retried: `run_bulk_extractor` was submitted with `scanners: ["email", "url", "regex", "tcpudp"]` on all three disk images and rejected at once ("Unknown bulk_extractor scanner(s): regex, tcpudp"), so there is no `bulk.url_searches`, `bulk.email` or `bulk.rfc822` in this run at all. `run_fls` was rejected three times for an `output_path` parameter and resubmitted without it. The model read "Results: 10/13 ok, 3 failed" and moved to analysis. The later `search` calls for `googledrivesync.exe`, `icloudsetup.exe`, `Eraser` and `CCleaner` (01:34:33–01:34:40) went to `tsk.filelist` and, whatever they returned, nothing was written down.

### Context spent on a file listing (items 2, 20; the three findings)

The analysis session's first 23 tool calls were `get_raw_output` against the PC's 104,709-line `tsk.filelist` in windows of 1 to 50 lines (`after_id` 8, 9, 13, 19 ... 290, 3010, 8149, 8160), until the request failed at 229,377 input tokens against a 262,144 context ("Context exhausted (detected in response)") and the runner auto-compacted. The continuation then ran the same `search` (`queries: ["diary", "txt"]`, `source: tsk.filelist`) twenty times between 01:16:08 and 01:20:04 before submitting finding 1 at 01:20:26. Seven `query_registry_value` calls followed (four Office `Uninstall` GUIDs, `TimeZoneInformation`, `Windows NT\CurrentVersion`, `Control\Windows`); of their values, "Windows 7" is the only one on the page. 6.7M of the run's 13.5M input tokens are this one 51-turn session.

### The detector reached RM2 and the report put it on the PC (items 4, 6, 7, 15, 16; FP 1)

`detect_masquerading` ran on rm2 for the first time in a Qwen run and returned the 17-line set that Opus, DeepSeek and MiniMax got on this image. The model enumerated all 17 with their true types, which is why item 7 is the one item better than run 1. It then had no device model to put them in: with one "system" in the case and rm1/rm2/rm3 described as "suspected source media", the `$OrphanFiles` directory became "the primary system", the FAT short names `TECHNI~1/` and `PRICIN~1/` went unrecognised, the files' own January timestamps became write events, and the disc, which the `optical.listing` showed holding the same names, became the medium they arrived on. The five directory names from the disc and the 17 files from rm2 are both on the page and are never recognised as the same set on two media, nor as the "Secret Project Data" tree the run searched for and did not report.

### The narrative phase (105 turns, 2 continuations)

The alternative-narrative phase's three sessions (36 + 36 + 20 turns) produced one `update_finding` (an `event_time_start` on finding 1) and a dry-run `deduplicate_findings`; the rest was `open_case`, `get_findings`, `get_investigation_summary` and 30 more `search` calls over `tsk.filelist` and `tsk.masquerade`, chiefly for `f[1].txt`. The two turn-limit continuations were spent confirming that the three findings had timestamps ("All non-negative findings now have precise timestamps added"), not adding a fourth. The report phase's 22 turns then wrote the narrative from three findings and two sources.

---

## Comparison with the Opus 4.6 v1.5.2 run and run 1

| Metric | Claude Opus 4.6 (v1.5.2) | Qwen3 235B 2507 (v1.5.2, run 1, `examples/ndlc-v1.5.2/qwen3-235b-run1`) | Qwen3 235B 2507 (v1.5.2, run 2, this directory) |
|--------|--------------------------|-----------------------------------------------------------------------------|--------------------------------------------------|
| FOUND | 9 | 2 | 0 |
| PARTIAL | 10 | 8 | 5 |
| MISSED | 0 | 10 | 15 |
| FALSE POSITIVE (in 20-item grid) | 1 | 0 | 0 |
| False positives, total | 2 | 2 | 1 |
| Full-match rate | 45% | 10% | 0% |
| Detection rate (FOUND + PARTIAL) | 95% | 50% | 25% |
| False-positive rate (FP / 20) | 10% | 10% | 5% |
| Suspect attributed | Yes, 7 sources | Insider attributed to `informant`; name only in the resignation-letter filename | No ("does not provide sufficient information for attribution"); account never named |
| Case type identified | Insider threat | Insider threat, with an invented phishing initial access | "basic data theft operation" via physical access, with an invented January inbound copy from the disc |
| Secret Project documents named | 5 of 5 with sizes | 1 of 5 (RecentDocs) | 0 of 5; four found under their disguised names with true types |
| USB devices identified | Neither by serial; labels and filesystems | Neither (rm1 "a removable flash drive", rm2 "a second data image") | Neither ("suspected source media"; "USB" absent) |
| CD-R (RM3) analysed | Yes (UDF, 9 sessions, 17 files by session, 37 extracted) | Yes (UDF, 9 sessions, "IAMAN CD", five directory names, three JPEGs; undated, unlinked) | Listing only ("optical media (CD)", directory names, session paths); no UDF, label, sessions or date; role inverted |
| Masquerading detected | Yes (17 files, 4 mappings) | No (detector never run on rm2; 3 browser-cache files on the PC) | Yes, 17 files with true types, no mappings, on the wrong medium |
| CCleaner / Eraser | Both, every timestamp exact | Eraser only, exact (15:12:28Z); CCleaner absent | Neither |
| Google Drive / iCloud | Both, FOUND | Both, FOUND, every timestamp exact | Neither |
| Email correspondent identified | Yes (contact entry) | No (nothing) | No (nothing) |
| Network drive identified | Yes (wrong first-access date) | No ("zero evidence of lateral movement") | No ("no evidence of lateral movement") |
| Timezone | Eastern stated; FAT offset not observed | Not stated | Not stated (`TimeZoneInformation` queried, unreported) |
| Dates preceding OS install | 0 | 0 | 1 (the January 5–24, 2015 "Optical Media Data Transfer") |
| Systems in catalog | 4 | 4 | 1 |
| Findings | 23 (19 confirmed / 4 inference) | 14 (12 / 2) | 3 (0 / 3) |
| Tool calls | 596 | 968 | 205 (207 in the audit log) |
| Runtime | 68 min | 86 min (12 turn-limit continuations) | 33 min (2 turn-limit continuations, 1 auto-compaction) |
| Total tokens | ~276K (37K uncached input + 239K output) | 58.5M (58.4M / 79K) | 13.5M (13.5M / 16.5K) |

Per-item status, side by side:

| # | Item | Opus 4.6 v1.5.2 | Qwen3 235B run 1 | Qwen3 235B run 2 | Run 2 vs run 1 |
|---|------|-----------------|------------------|------------------|----------------|
| 1 | Suspect identity | FOUND | PARTIAL | MISSED | worse (account and letter lost) |
| 2 | PC OS | PARTIAL | PARTIAL | PARTIAL | = (edition absent rather than wrong) |
| 3 | USB Device 1 | PARTIAL | MISSED | MISSED | = |
| 4 | USB Device 2 | PARTIAL | MISSED | MISSED | = |
| 5 | RM3 CD-ROM | PARTIAL | PARTIAL | PARTIAL | = (UDF, label and sessions lost; medium kept) |
| 6 | Five documents exfiltrated | FOUND | PARTIAL | PARTIAL | = (one name lost, four disguised copies typed) |
| 7 | File masquerading | FOUND | MISSED | PARTIAL | better (17 files typed; wrong medium) |
| 8 | CCleaner and Eraser | FOUND | PARTIAL | MISSED | worse |
| 9 | Search history | FOUND | PARTIAL | MISSED | worse |
| 10 | Google Drive | FOUND | FOUND | MISSED | worse |
| 11 | iCloud | FOUND | FOUND | MISSED | worse |
| 12 | USB EVTX timestamps | PARTIAL | MISSED | MISSED | = |
| 13 | Feb 15 bulk copy | FOUND | MISSED | MISSED | = |
| 14 | CCleaner did not clean | FALSE POSITIVE | MISSED | MISSED | = |
| 15 | RM2 systematic deletion | PARTIAL | MISSED | MISSED | = |
| 16 | RM3 content | FOUND | PARTIAL | PARTIAL | = (directory names, now with session paths) |
| 17 | Files opened in RM2 | PARTIAL | PARTIAL | MISSED | worse |
| 18 | Network drive traversal | PARTIAL | MISSED | MISSED | = |
| 19 | Email with spy.conspirator | PARTIAL | MISSED | MISSED | = |
| 20 | FAT32 timezone offset | PARTIAL | MISSED | MISSED | = |

Against run 1 this run is better on one item (7), worse on six (1, 8, 9, 10, 11, 17) and tied on thirteen; it detects five items to run 1's ten, with no full match where run 1 had two, and one false positive to run 1's two. Against Opus it is behind on fifteen items, level on five (2, 5, 6 by status only, 16 by status only, and 14, where Opus's false positive faces a miss), with half Opus's false-positive count. The difference from run 1 is not the model reading the evidence differently but the model seeing a quarter of it: the same settings produced a four-system catalog at 23:33 and a one-system catalog at 01:07, and the 13-task plan, the three failed carves, the unparsed registry and the skipped cross-system phase are all downstream of that one JSON. What the run did get, the rm2 detector output, it reported completely and on the wrong device.
