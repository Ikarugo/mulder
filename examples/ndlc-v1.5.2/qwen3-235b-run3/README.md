# NDLC on Qwen3 235B, run 3 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using the open-weight model `bedrock/qwen.qwen3-235b-a22b-2507-v1:0` on Amazon Bedrock through Mulder's LiteLLM proxy, run on the v1.5.2 release image with `--no-thinking`. The same evidence, prompts, tools and scoring rubric as the [Claude Opus 4.6 run](../opus-4.6/) in this directory.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the Opus baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 0 | 0% |
| PARTIAL | 7 | 35% |
| MISSED | 13 | 65% |
| FALSE POSITIVE | 2 | 10% |

**0% full match, 35% detection rate, 10% false positive rate.** Like run 2, the catalog phase registered the four images as one system, so a single analyst held every image in one context window, exhausted it twice paging the PC file listing, and the cross-system phase was skipped. See [run 1](../qwen3-235b-run1/) and [run 2](../qwen3-235b-run2/).

## What the Model Concluded

- Framed the case correctly as a deliberate insider data theft via USB with no remote intrusion, lateral movement or persistence, but attributed it only to "the specific user account ('informant')": no name, email address, resignation letter, OS version or timezone.
- Read the USBSTOR key for the first time in a Qwen run: SanDisk Cruzer Fit, both serials, the March 24 last-write time and the "Authorized USB" volume with "Secret Project Data", but treated the two serials as one device with "different sessions", named no filesystem, and put the volume on D:, which is the CD burner.
- Ran the masquerade detector on RM2 and named ten of the 17 disguised files with their true types, without saying which medium they were on, how many there were, or which originals they hid.
- Placed the PC's local "Secret Project Data" browse on the USB stick and stretched the March 24 renames into a "December 2014 to March 2015" preparation window, two months before the OS was installed. Those are the two false positives.
- Nothing on the CD-R, Google Drive, iCloud, Eraser, CCleaner, the search history, the February copy, the network share or the email correspondent. Four findings, both IOC tables empty.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 90 (49 disk, 41 other) |
| Total tool calls | 374 |
| Findings | 4 (0 critical, 3 high, 0 medium, 0 low, 1 info) |
| Confirmed / Inference | 4 / 0 |
| False positives | 2 |
| Runtime | 37 minutes |
| Model | bedrock/qwen.qwen3-235b-a22b-2507-v1:0 (`--no-thinking`) |
| Tokens | 17.2M input / 33K output (no prompt caching through the proxy) |
| Exit code | 0, all quality gates passed, 1 turn-limit continuation, 2 context exhaustions |
| Mulder | v1.5.2 |

## How It Was Run

```bash
docker run --privileged \
  -v /evidence:/evidence:ro -v cases:/home/mulder/.mulder/cases \
  -e AWS_REGION=us-west-2 \
  ghcr.io/calebevans/mulder:1.5.2 \
  mulder investigate /evidence ndlc --model bedrock/qwen.qwen3-235b-a22b-2507-v1:0 --no-thinking --show-cli-stderr
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
| `ndlc.audit.jsonl` | Structured tool execution audit log (384 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (563 lines) |
| `mulder.log` | MCP server tool execution log (381 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
