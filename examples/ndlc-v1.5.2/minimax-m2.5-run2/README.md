# NDLC on MiniMax M2.5, run 2 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using the open-weight model `bedrock/minimax.minimax-m2.5` on Amazon Bedrock through Mulder's LiteLLM proxy, run on the v1.5.2 release image with the model's native reasoning. The same evidence, prompts, tools and scoring rubric as the [Claude Opus 4.6 run](../opus-4.6/) in this directory.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the Opus baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 1 | 5% |
| PARTIAL | 10 | 50% |
| MISSED | 9 | 45% |
| FALSE POSITIVE | 2 | 10% |

**5% full match, 55% detection rate, 10% false positive rate.** The only MiniMax run on this image to score a full match on the masquerading item; see [run 1](../minimax-m2.5-run1/) and [run 3](../minimax-m2.5-run3/).

## What the Model Concluded

- Insider data theft by the `informant` account (`iaman.informant@nist.gov`), correctly framed as an insider threat with no malware, no external access and no lateral movement. The suspect's name is never stated, and the "IAMAN CD" label is read as a placeholder.
- Two USB sticks placed on the right images by label ("Authorized USB" on RM1 with the "Secret Project Data" folder; "IAMAN $_@" on RM2, FAT32) and all 17 disguised files on RM2 named with their true Office types, deleted, dated March 24. No serials, connection times or original-name mappings.
- A multi-session CD ("IAMAN CD", 9 sessions, both directory naming schemes, final burn on the evening of March 24) whose content is misread as exfiltrated OMB and Library of Congress material (the sample-document metadata), reported as the run's only critical finding with a recommendation to notify both agencies. That is one of the two false positives.
- An operational timeline built on file-modification dates that runs from late 2014 through "Eraser installed January 12" and "Google Drive installed February 19", all before the OS was installed on March 22. That pre-install timeline is the other false positive.
- Absent: the OS version, CCleaner, the search history, iCloud, the USB connection records, the February copy, the RM2 file opens, the network share, the email correspondent and the timezone. Five of these were retrieved during the run and never reached the report.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 245 (32 disk, 213 other) |
| Total tool calls | 315 |
| Findings | 10 (1 critical, 6 high, 2 medium, 0 low, 1 info) |
| Confirmed / Inference | 9 / 1 |
| False positives | 2 |
| Runtime | 31 minutes |
| Model | bedrock/minimax.minimax-m2.5 (native reasoning) |
| Tokens | 6.30M input / 110K output (no prompt caching through the proxy) |
| Exit code | 0, all quality gates passed |
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
| `ndlc.audit.jsonl` | Structured tool execution audit log (333 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (2,091 lines) |
| `mulder.log` | MCP server tool execution log (185 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
