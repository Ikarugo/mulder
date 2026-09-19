# NDLC on DeepSeek V3.2 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using the open-weight model `bedrock/deepseek.v3.2` on Amazon Bedrock through Mulder's LiteLLM proxy, run on the v1.5.2 release image with `--no-thinking`. The same evidence, prompts, tools and scoring rubric as the [Claude Opus 4.6 run](../opus-4.6/) in this directory.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the Opus baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 0 | 0% |
| PARTIAL | 12 | 60% |
| MISSED | 8 | 40% |
| FALSE POSITIVE | 5 | 25% |

**0% full match, 60% detection rate, 25% false positive rate.**

## What the Model Concluded

- Framed the case as a "coordinated data collection, concealment, and potential exfiltration" operation from December 2014 to March 2015 by an unattributed actor. It identified the `informant` account and the `iaman.informant@nist.gov.ost` mailbox but dismissed the address as a possible placeholder.
- Correctly identified Windows 7 Ultimate installed on 2015-03-22, read the "IAMAN CD" optical disc (9 write sessions, full directory tree of Office documents disguised as media, archive and text files) with the new UDF reader, and named Eraser and CCleaner from ShimCache.
- Narrated the insider case as an intrusion: the SYSTEM password reset and the `admin11`, `ITechTeam` and `temporary` accounts as initial access and privilege escalation, the ASP.NET State Service as persistence, OMB and whitehouse.gov strings from Govdocs sample documents as government targeting, and bulk_extractor credit-card hits as payment-card leakage. Those five claims are the false positives.
- Missed both USB devices' identities, RM1 entirely, the USB connection events, iCloud, the network share, the email correspondent and the timezone, and dated the file masquerading to December 2014 from document modification times.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 91 (46 disk, 45 other) |
| Total tool calls | 352 |
| Findings | 17 (0 critical, 6 high, 9 medium, 0 low, 2 info) |
| Confirmed / Inference | 9 / 8 |
| False positives | 5 |
| Runtime | 27 minutes |
| Model | bedrock/deepseek.v3.2 (`--no-thinking`) |
| Tokens | 9.95M input / 61K output (no prompt caching through the proxy) |
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
| `ndlc.audit.jsonl` | Structured tool execution audit log (376 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (1,642 lines) |
| `mulder.log` | MCP server tool execution log (707 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
