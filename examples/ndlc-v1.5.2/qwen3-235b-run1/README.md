# NDLC on Qwen3 235B, run 1 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using the open-weight model `bedrock/qwen.qwen3-235b-a22b-2507-v1:0` on Amazon Bedrock through Mulder's LiteLLM proxy, run on the v1.5.2 release image with `--no-thinking`. The same evidence, prompts, tools and scoring rubric as the [Claude Opus 4.6 run](../opus-4.6/) in this directory.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the Opus baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 2 | 10% |
| PARTIAL | 8 | 40% |
| MISSED | 10 | 50% |
| FALSE POSITIVE | 2 | 10% |

**10% full match, 50% detection rate, 10% false positive rate.** The best of three Qwen3 235B runs on this image and the only one whose catalog registered four systems; see [run 2](../qwen3-235b-run2/) (0% / 25% / 5%) and [run 3](../qwen3-235b-run3/) (0% / 35% / 10%).

## What the Model Concluded

- Framed the case correctly as an insider data theft by the `informant` account before resignation, with no lateral movement, no persistence and none of the intrusion subplots other open-weight models produced. The suspect's name appears only inside the resignation-letter filename and the NIST email address never appears.
- Reconstructed the PC-side cloud and anti-forensics timeline to the second: the Google Drive installer downloaded and iCloud setup executed on March 23, Google Drive installed minutes later, Eraser run and Drive sync launched on March 25. Both full matches are here. CCleaner is never mentioned.
- Read the CD (UDF, nine sessions, "IAMAN CD", five deleted project directories, three sample photos) but never dated it or linked it to the documents, and never ran the masquerade detector on RM2, so no disguised file, no USB device, no RM2 deletion window and no serial appears in the report.
- Two false positives, both template-driven: the Google Drive download narrated as a phishing initial-access vector (no email exists in the evidence), and the CD burn reported as staging to "a USB drive (D:)" when D: is the burner.
- The most expensive open-weight run of the round: 86 minutes, 968 tool calls, 12 turn-limit continuations and 58M input tokens for 14 findings, 8 of them informational.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 100 (49 disk, 51 other) |
| Total tool calls | 968 |
| Findings | 14 (0 critical, 5 high, 1 medium, 0 low, 8 info) |
| Confirmed / Inference | 12 / 2 |
| False positives | 2 |
| Runtime | 86 minutes |
| Model | bedrock/qwen.qwen3-235b-a22b-2507-v1:0 (`--no-thinking`) |
| Tokens | 58.4M input / 79K output (no prompt caching through the proxy) |
| Exit code | 0, all quality gates passed, 12 turn-limit continuations |
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
| `ndlc.audit.jsonl` | Structured tool execution audit log (1,003 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (1,431 lines) |
| `mulder.log` | MCP server tool execution log (1,117 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
