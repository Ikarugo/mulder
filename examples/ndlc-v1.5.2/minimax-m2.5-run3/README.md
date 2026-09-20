# NDLC on MiniMax M2.5, run 3 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using the open-weight model `bedrock/minimax.minimax-m2.5` on Amazon Bedrock through Mulder's LiteLLM proxy, run on the v1.5.2 release image with the model's native reasoning. The same evidence, prompts, tools and scoring rubric as the [Claude Opus 4.6 run](../opus-4.6-run1/) in this directory.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the Opus baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 0 | 0% |
| PARTIAL | 11 | 55% |
| MISSED | 9 | 45% |
| FALSE POSITIVE | 2 | 10% |

**0% full match, 55% detection rate, 10% false positive rate.** The fastest of the three MiniMax runs on this image and the only one that never mentions the CD-R; see [run 1](../minimax-m2.5-run1/) and [run 2](../minimax-m2.5-run2/).

## What the Model Concluded

- Correctly framed the case as an insider threat by the `informant` account with no malware, credential theft or lateral movement, but never named Iaman Informant or any email address.
- Walked the USBSTOR key to both SanDisk Cruzer Fit serials with their March 24 last-write times and the "Authorized USB" label, the first MiniMax run to do so, then treated them as "either multiple devices or device reconnections" and never mapped either to an image.
- Detected the file-masquerading technique (six disguised Office documents typed from `tsk.masquerade`) but placed the files on "the system" instead of RM2 and dated the concealment to January 2015, before the OS was installed, from the documents' modification times. That January phase is one of the two false positives.
- Found the Google Drive and iCloud installs and five data-leakage search terms, all dated a day early. CCleaner, Eraser, the CD-R, the network share and the email correspondent are absent from the report, although Eraser and the disc's contents were seen during the run.
- Promoted a carved domain fragment to a "known Tor exit node" IOC (the address is Akamai's CDN) with two containment actions, after its own counter-analysis failed to find the IP in the evidence. That is the second false positive.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 78 (40 disk, 38 other) |
| Total tool calls | 300 |
| Findings | 11 (0 critical, 9 high, 2 medium, 0 low, 0 info) |
| Confirmed / Inference | 9 / 2 |
| False positives | 2 |
| Runtime | 19 minutes |
| Model | bedrock/minimax.minimax-m2.5 (native reasoning) |
| Tokens | 6.07M input / 103K output (no prompt caching through the proxy) |
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
| `ndlc.audit.jsonl` | Structured tool execution audit log (318 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (1,932 lines) |
| `mulder.log` | MCP server tool execution log (354 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
