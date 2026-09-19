# NDLC on DeepSeek V3.2, run 2 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using the open-weight model `bedrock/deepseek.v3.2` on Amazon Bedrock through Mulder's LiteLLM proxy, run on the v1.5.2 release image with `--no-thinking`. The same evidence, prompts, tools and scoring rubric as the [Claude Opus 4.6 run](../opus-4.6/) in this directory.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the Opus baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 0 | 0% |
| PARTIAL | 10 | 50% |
| MISSED | 10 | 50% |
| FALSE POSITIVE | 4 | 20% |

**0% full match, 50% detection rate, 20% false positive rate.** One of three DeepSeek runs on this image; see [run 1](../deepseek-v3.2-run1/) and [run 3](../deepseek-v3.2-run3/).

## What the Model Concluded

- Read the case as a privilege-escalation-to-USB kill chain: the `informant` account's SYSTEM password reset as "initial access", the `admin11`, `ITechTeam` and `temporary` accounts as persistence, those accounts used to reach the `10.11.11.128\secured_drive` share, and data moved by SanDisk Cruzer Fit USB "to avoid network monitoring". Attribution was left between insider abuse and external credential compromise.
- The first DeepSeek run to recover both USB serials with vendor, model and revision, the network share, and all five `[secret_project]` filenames, but it never tied a serial to an image, called RM1 FAT32, and gave no sizes or copy event for the documents.
- Placed the masquerading on RM2 for the first time ("16 deleted files with intentionally misleading file extensions", 11 named with true types, created around March 24) while the executive timeline still dates the masquerading to December 2014.
- Read the CD-R as a UDF disc labelled "IAMAN CD" with 9 sessions, the five project directories and the three cover photos, but did not match its files to the originals.
- Lost everything run 1 had from the PC's software side: no OS edition, no CCleaner or Eraser, no search history, no Google Drive or iCloud, no Outlook, no timezone. It acknowledged the sample-document origin of the "sensitive government documents" in four findings and then listed that explanation as a ruled-out hypothesis. The four false positives are the pre-install timeline, the account-manipulation kill chain, the government-data exposure and a carved credit-card number.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 128 (55 disk, 73 other) |
| Total tool calls | 353 |
| Findings | 12 (0 critical, 2 high, 6 medium, 1 low, 3 info), 1 hypothesis ruled out |
| Confirmed / Inference | 10 / 2 |
| False positives | 4 |
| Runtime | 36 minutes |
| Model | bedrock/deepseek.v3.2 (`--no-thinking`) |
| Tokens | 10.1M input / 63K output (no prompt caching through the proxy) |
| Exit code | 0, all quality gates passed |
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
| `ndlc.audit.jsonl` | Structured tool execution audit log (372 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (1,699 lines) |
| `mulder.log` | MCP server tool execution log (402 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
