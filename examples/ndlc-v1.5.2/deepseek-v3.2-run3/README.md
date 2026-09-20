# NDLC on DeepSeek V3.2, run 3 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using the open-weight model `bedrock/deepseek.v3.2` on Amazon Bedrock through Mulder's LiteLLM proxy, run on the v1.5.2 release image with `--no-thinking`. The same evidence, prompts, tools and scoring rubric as the [Claude Opus 4.6 run](../opus-4.6-run1/) in this directory.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the Opus baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 0 | 0% |
| PARTIAL | 13 | 65% |
| MISSED | 7 | 35% |
| FALSE POSITIVE | 4 | 20% |

**0% full match, 65% detection rate, 20% false positive rate.** The highest detection of the three DeepSeek runs on this image; see [run 1](../deepseek-v3.2-run1/) and [run 2](../deepseek-v3.2-run2/).

## What the Model Concluded

- Narrated the case as a system compromise: "initial access" through the `informant` credentials with "privilege escalation" on March 22 and the `admin11`, `ITechTeam` and `temporary` accounts as persistence. Attribution was left between insider and external compromise, although "IAMAN CD" is tied to `iaman.informant@nist.gov` three times.
- Built a timeline that starts before the OS existed: research in October 2014, masqueraded documents created December 2014 to January 2015, Eraser installed January 12 and CCleaner March 13. All are carried file timestamps; the answer key has everything on March 22 to 25.
- Enumerated all 17 disguised files with true types and most sizes, and read the CD ("IAMAN CD", 9 burn sessions, three photos in the current session), but placed the disguised files on the PC and "on Optical Media" rather than on RM2's FAT32, and never named RM2 as a device.
- Named RM1 for the first time in a DeepSeek run ("Authorized USB" with the "Secret Project Data" folder) and one USB registry timestamp, but no serials, no OS edition, no timezone, no February copy, no network share, no iCloud, no email correspondent.
- Reported 263 "credit card numbers" as a PCI breach and OMB and Library of Congress addresses as "government data exposure", both from bulk_extractor hits inside the public sample documents, while concluding the case showed "exfiltration preparation rather than confirmed exfiltration". Those, the pre-install timeline and the account-manipulation kill chain are the four false positives.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 111 (50 disk, 61 other) |
| Total tool calls | 491 |
| Findings | 17 (0 critical, 5 high, 7 medium, 3 low, 2 info) |
| Confirmed / Inference | 7 / 10 |
| False positives | 4 |
| Runtime | 40 minutes |
| Model | bedrock/deepseek.v3.2 (`--no-thinking`) |
| Tokens | 14.0M input / 75K output (no prompt caching through the proxy) |
| Exit code | 0, one report-gate retry |
| Mulder | v1.5.2 |

## How It Was Run

```bash
docker run --privileged \
  -v /evidence:/evidence:ro -v cases:/home/mulder/.mulder/cases \
  -e AWS_REGION=us-west-2 \
  ghcr.io/calebevans/mulder:1.5.2 \
  mulder investigate /evidence ndlc --model bedrock/deepseek.v3.2 --no-thinking --show-cli-stderr
```

Bedrock credentials came from the EC2 instance role. See the [usage guide](../../../docs/usage-guide.md#using-non-anthropic-models-via-litellm) for the proxy configuration.

## Evidence Dataset

| Field | Value |
|-------|-------|
| **Source** | [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) |
| **Answer Key** | [Published NIST ground truth (55 pages)](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) |
| **Accuracy Report** | [ACCURACY-REPORT.md](ACCURACY-REPORT.md) |

### Evidence Files

| File | Type | Size |
|------|------|------|
| cfreds_2015_data_leakage_pc.E01-.E04 | PC disk image (EnCase, 4 parts) | 7.3 GB |
| cfreds_2015_data_leakage_rm1.E01 | USB RM1 (exFAT, "Authorized USB") | 75 MB |
| cfreds_2015_data_leakage_rm2.E01 | USB RM2 (FAT32, "IAMAN $_@") | 243 MB |
| cfreds_2015_data_leakage_rm3_type3.E01 | CD-R RM3 (UDF) | 90 MB |

## Files in This Directory

| File | Description |
|------|-------------|
| `ndlc.report.md` | Full investigation report (Markdown) |
| `ndlc.report.html` | Investigation report (HTML with navigation) |
| `ndlc.audit.jsonl` | Structured tool execution audit log (521 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (2,028 lines) |
| `mulder.log` | MCP server tool execution log (310 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
