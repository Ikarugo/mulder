# NDLC on Qwen3 235B, run 2 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using the open-weight model `bedrock/qwen.qwen3-235b-a22b-2507-v1:0` on Amazon Bedrock through Mulder's LiteLLM proxy, run on the v1.5.2 release image with `--no-thinking`. The same evidence, prompts, tools and scoring rubric as the [Claude Opus 4.6 run](../opus-4.6/) in this directory.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the Opus baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 0 | 0% |
| PARTIAL | 5 | 25% |
| MISSED | 15 | 75% |
| FALSE POSITIVE | 1 | 5% |

**0% full match, 25% detection rate, 5% false positive rate.** The catalog phase registered the four images as a single system, so a single 13-task extraction plan ran for the whole case, no registry, event-log or execution-artifact parser ever ran, and the cross-system phase was skipped. See [run 1](../qwen3-235b-run1/) and [run 3](../qwen3-235b-run3/).

## What the Model Concluded

- Framed the case as "a basic data theft operation rather than an advanced persistent threat" with no persistence, lateral movement or malware, which is correct, but named no suspect, account, email address or resignation letter.
- Enumerated all 17 disguised documents with their true types from the RM2 masquerade detector, the first Qwen run to reach it, but placed them in the PC's orphan files and never named RM2, FAT32, "Secret Project" or any original filename.
- Inverted the exfiltration: data "copied from an optical disc to the primary system's hard drive" in January 2015, two months before the PC's OS was installed, with the three removable media as "suspected source media". That is the run's one false positive.
- Nothing on Google Drive, iCloud, Eraser, CCleaner, the search history, USB devices, the network share, the email correspondent or the timezone. The catalog registered one system, no parsers ran, every bulk_extractor job failed on a bad scanner name, and the cross-system phase was skipped.
- Three findings, none confirmed, one of them a browser-cache file flagged high; both IOC tables empty.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 19 (10 disk, 9 other) |
| Total tool calls | 205 |
| Findings | 3 (0 critical, 3 high, 0 medium, 0 low, 0 info) |
| Confirmed / Inference | 0 / 3 |
| False positives | 1 |
| Runtime | 33 minutes |
| Model | bedrock/qwen.qwen3-235b-a22b-2507-v1:0 (`--no-thinking`) |
| Tokens | 13.5M input / 17K output (no prompt caching through the proxy) |
| Exit code | 0, all quality gates passed, 2 turn-limit continuations, 1 auto-compaction |
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
| `ndlc.audit.jsonl` | Structured tool execution audit log (210 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (334 lines) |
| `mulder.log` | MCP server tool execution log (364 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
