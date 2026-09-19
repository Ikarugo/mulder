# NDLC on MiniMax M2.5, run 1 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using the open-weight model `bedrock/minimax.minimax-m2.5` on Amazon Bedrock through Mulder's LiteLLM proxy, run on the v1.5.2 release image with the model's native reasoning. The same evidence, prompts, tools and scoring rubric as the [Claude Opus 4.6 run](../opus-4.6/) in this directory.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the Opus baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 1 | 5% |
| PARTIAL | 11 | 55% |
| MISSED | 8 | 40% |
| FALSE POSITIVE | 1 | 5% |

**5% full match, 60% detection rate, 5% false positive rate.** One of three MiniMax runs on this image; see [run 2](../minimax-m2.5-run2/) (5% / 55% / 10%) and [run 3](../minimax-m2.5-run3/) (0% / 55% / 10%).

## What the Model Concluded

- Concluded an insider data-exfiltration case attributed to the user account `informant` (`iaman.informant@nist.gov`), with no malware, no external access and no persistence. Attribution was held at inference for lack of USN journal and process evidence.
- Identified 17 deleted Office documents with mislabeled extensions on the "IAMAN $_@" USB drive (RM2), created between 09:59:27 and 10:00:18 on 2015-03-24, and read the "IAMAN CD" (RM3) with the new UDF reader: 9 sessions, five project directories, byte-exact size matches to the RM2 files, and the last deletion at 20:54 on March 24. The first open-weight run to state the RM2 volume label.
- Concluded, wrongly, that the files were copied from the CD to the USB drive and that the CD pre-dates the incident. The disc was formatted after the USB copy. This is the single false positive. RM1 ("Authorized USB"), where the originals sit under their real names, was never examined.
- Found the Google Drive install and sync folder but ruled cloud storage a "non-factor"; noted the `\\10.11.11.128\secured_drive` share and a USBSTOR load at 13:37:59 on March 24; missed CCleaner, Eraser, the search history, iCloud, the email correspondent, the OS edition and the timezone.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 99 (58 disk, 41 other) |
| Total tool calls | 323 |
| Findings | 13 (0 critical, 3 high, 6 medium, 0 low, 4 info) |
| Confirmed / Inference | 7 / 6 |
| False positives | 1 |
| Runtime | 29 minutes |
| Model | bedrock/minimax.minimax-m2.5 (native reasoning) |
| Tokens | 7.27M input / 123K output (no prompt caching through the proxy) |
| Exit code | 0, one quality-gate retry |
| Mulder | v1.5.2 |

## How It Was Run

```bash
docker run --privileged \
  -v /evidence:/evidence:ro -v cases:/home/mulder/.mulder/cases \
  -e AWS_REGION=us-west-2 \
  -e MULDER_MODEL_MAX_OUTPUT_TOKENS=32768 \
  ghcr.io/calebevans/mulder:1.5.2 \
  mulder investigate /evidence ndlc --model bedrock/minimax.minimax-m2.5 --show-cli-stderr
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
| `ndlc.audit.jsonl` | Structured tool execution audit log (341 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (2,006 lines) |
| `mulder.log` | MCP server tool execution log (615 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
