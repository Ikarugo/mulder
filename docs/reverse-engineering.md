# Static malware analysis with Mulder (`mulder reverse`)

Mulder can reverse-engineer a single sample **statically** and document
everything it claims. From one file it produces:

- a capability report where every statement cites the code that shows it
  (the `tool_call_id` of a decompilation or disassembly call);
- the IOCs recovered from the code (C2, URLs, IPs, registry keys, mutexes,
  paths, keys), exported as CSV next to the report;
- a MITRE ATT&CK mapping and an ATT&CK Navigator layer;
- a candidate YARA rule, **always marked as to be validated by a human**;
- for native executables, an **annotated Ghidra project** (functions
  renamed, `[mulder]` comments, bookmarks) that the analyst opens in the
  Ghidra GUI to check the work.

It is built for a CERT analyst who knows Ghidra's basics without being a
reverse engineer: Mulder prepares the ground and shows its evidence; the
analyst validates.

> **Static only.** The sample is never executed, emulated or debugged. No
> tool can run it, and no tool accepts a script or a shell command for the
> engine: agents only call typed MCP tools.

---

## Contents

1. [How it works](#1-how-it-works)
2. [Where to run it](#2-where-to-run-it)
3. [Installation](#3-installation)
4. [Confidential samples: local models](#4-confidential-samples-local-models)
5. [Autonomous analysis: `mulder reverse`](#5-autonomous-analysis-mulder-reverse)
6. [Interactive analysis: `mulder serve`](#6-interactive-analysis-mulder-serve)
7. [Checking the result in Ghidra](#7-checking-the-result-in-ghidra)
8. [Scripts (PowerShell, JavaScript, VBScript, batch, HTA)](#8-scripts)
9. [.NET assemblies](#9-net-assemblies)
10. [Limits](#10-limits)
11. [Cost](#11-cost)
12. [Reference](#12-reference)

---

## 1. How it works

The sample goes through five phases, each with a planner, an executor and
an analyst (the same machinery as `mulder investigate`), and a quality gate
between phases that retries the phase with precise instructions when its
output is not good enough:

| Phase | What happens | Gate |
|---|---|---|
| Triage | File type, packing, compiler; `triage_binary`, `run_capa`, `run_floss`, `run_detect_it_easy`, YARA; load into the disassembler. Scripts are read and decoded layer by layer here. | Triage and capa ran, type known, at least one finding |
| Mapping | Leads (suspicious imports, IOC-like strings, capa match locations, hot functions) lead to a prioritised list of functions, or to the statement that the sample is packed. | Disassembler loaded; functions prioritised or packed verdict |
| Deep analysis | Decompile the prioritised functions, rename and comment them in the project, extract configuration and IOCs, confirm or refute **every** capa capability in the code, propose a YARA rule. | Every capa capability decided; every capability finding cites decompiled or disassembled code |
| Counter-analysis | Try to prove the findings wrong: is the code reachable from an entry point? Library code? A benign use? | Audits ran; every high or critical finding challenged |
| Report | Narrative and final report, IOC export, ATT&CK layer. | Report written, IOCs exported, ATT&CK present, project path in the report |

Routes by sample type (detected from magic bytes, not the extension):

| Type | Route |
|---|---|
| PE, ELF, Mach-O (native) | all five phases (Ghidra, or radare2 with `--backend radare2`) |
| .NET assembly | all five phases with ILSpy when `ilspycmd` is installed; otherwise triage and report, with a warning |
| Script | triage (reading and decoding every layer), counter-analysis, report |
| Document, archive, unknown | triage and report |
| **Packed sample** | stops after mapping: the report says so plainly. Unpacking is out of scope. |

The disassembler never runs inside the MCP server: each sample gets a
child process (a JVM for Ghidra). If it crashes, runs out of memory or
hangs, that process is killed and the tool returns a clean error; the
analysed project stays on disk and reopens on the next call without being
analysed again.

## 2. Where to run it

**Run it in an isolated analysis VM** (no shared folders with your
workstation, no access to production networks, snapshots before each
sample), as for any malware handling. Mulder never executes the sample, but
the sample still sits on disk, the tools that parse it (Ghidra, radare2,
capa, FLOSS) have had parsing bugs, and a mistaken double-click is enough.

Everything the sample contains (strings, symbol names, decompiled code,
decoded layers) is **attacker-controlled data**. Every agent prompt says so
and tells the model to report instructions found in the sample (fake
analyst notes, "ignore previous instructions") as an anti-analysis
technique rather than follow them. Keep reading the report critically all
the same.

## 3. Installation

The Mulder Docker image already has capa, FLOSS, Detect-It-Easy, rabin2
and YARA. The disassemblers are optional; install at least one.

### Ghidra (recommended)

| Component | Version tested | Notes |
|---|---|---|
| Java | OpenJDK 21 | required by Ghidra 12 |
| Ghidra | 12.1.4 | unzip into `/opt/ghidra_12.1.4_PUBLIC` |
| pyghidra | 3.1.0 | the wheel ships with Ghidra |

```bash
sudo apt-get install -y openjdk-21-jdk
curl -LO https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip
sudo unzip -q ghidra_12.1.4_PUBLIC_20260921.zip -d /opt
pip install /opt/ghidra_12.1.4_PUBLIC/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl
# or: pip install 'mulder[reverse]'
```

Mulder finds Ghidra through `MULDER_GHIDRA_DIR`, then `GHIDRA_INSTALL_DIR`,
then the newest `/opt/ghidra_*_PUBLIC`.

### radare2 (alternative engine)

```bash
sudo apt-get install -y radare2
pip install r2pipe
r2pm -ci r2ghidra          # the decompiler; without it, decompile is refused
```

Without r2ghidra, `reverse_decompile` returns `binary_missing` rather than
quietly giving assembly instead. With the radare2 5.5 packaged by Ubuntu
24.04, `r2pm` cannot build r2ghidra; build tag 5.5.0 by hand
(`git clone --branch 5.5.0 https://github.com/radareorg/r2ghidra`), with
`libradare2-dev libpugixml-dev libxxhash-dev bison flex`, the pugixml
sources in `third-party/pugixml`, `#include <memory>` added to
`src/R2Scope.h`, then recompile the x86 SLEIGH files with the `sleighc` it
builds and copy the matching `.pspec`/`.cspec`/`.ldefs` into
`~/.local/share/radare2/plugins/r2ghidra_sleigh`. A recent radare2 from
upstream avoids all of this.

### ILSpy (.NET)

```bash
dotnet tool install -g ilspycmd      # needs a .NET SDK
```

Mulder finds it through `MULDER_ILSPYCMD`, then `ilspycmd` on `PATH`, then
`~/.dotnet/tools/ilspycmd`.

### Check

```bash
mulder reverse --help
python -c "from mulder.reverse import get_backend; print(get_backend('ghidra').check())"
# None means ready; otherwise the message says what is missing.
```

## 4. Confidential samples: local models

Nothing ties the analysis to one model provider. For a TLP:AMBER or
TLP:RED sample, route every role to a model you host, through the LiteLLM
proxy Mulder starts itself (see *Using Non-Anthropic Models via LiteLLM* in
the [usage guide](usage-guide.md)):

```bash
mulder reverse /samples/dropper.exe dropper-01 \
  --model ollama/qwen3-coder:30b --no-thinking
# or a custom proxy configuration:
mulder reverse /samples/dropper.exe dropper-01 --proxy-config litellm.yaml
```

With a local model, the sample's strings and code never leave the VM.
Expect a lower quality of analysis than with a frontier model, and check
the report more carefully. Mulder never submits samples or hashes to online
services (VirusTotal, sandboxes) by itself.

## 5. Autonomous analysis: `mulder reverse`

```bash
mulder reverse SAMPLE CASE_ID [options]

mulder reverse /samples/dropper.exe dropper-01 --effort high \
  --planner-model claude-opus-5-5 --analyst-model claude-opus-5-5 \
  --executor-model claude-haiku-4-5
```

| Option | Default | Role |
|---|---|---|
| `--backend` | `auto` | `auto` (ILSpy for .NET, Ghidra otherwise), `ghidra`, `radare2`, `ilspy` |
| `--effort` | `high` | effort of the agent sessions; the main cost lever |
| `--planner-model` / `--analyst-model` / `--executor-model` / `--model` / `--config` | | models per role, as for `mulder investigate` |
| `--proxy-config` | | LiteLLM configuration (local models) |
| `--db-dir` | `~/.mulder/cases` | where the case, report and projects are written |

One case holds one sample: reusing a case ID for another sample is refused.
Re-running the same case and sample resumes it (the analysed project is
reused). A `MULDER.md` next to the sample is read as a briefing (context,
questions to answer).

Outputs, in `--db-dir`:

| File | Content |
|---|---|
| `<case>.report.md` / `.report.html` | the report, with the reverse-engineering section |
| `<case>.iocs.csv` | IOCs from the findings |
| `<case>.navigator.json` | ATT&CK Navigator layer |
| `<case>.audit.jsonl` | every tool call, with the hash of its output |
| `<case>.phase_usage.json` | tokens used per phase and model |
| `reverse/<case>/<sha256[:16]>_<name>/ghidra/mulder.gpr` | the annotated Ghidra project |

The reverse-engineering section of the report gives the sample and its
hash, the project to open and every annotation, the functions studied and
why, each capa capability with its verdict (confirmed, refuted and why, or
**not verified**), the counter-analysis of each serious finding, decoded
script layers, and the candidate YARA rule.

## 6. Interactive analysis: `mulder serve`

The same tools work without the pipeline, from Claude Code or Claude
Desktop, for an analyst who wants to drive:

```json
{ "mcpServers": { "mulder": { "type": "stdio", "command": "mulder", "args": ["serve"] } } }
```

Typical session: `reverse_analyze(file_path)`, then `reverse_imports` and
`reverse_strings` for leads, `reverse_xrefs` to the functions that use
them, `reverse_decompile` on those, `reverse_annotate` as you understand
them, `reverse_call_path` to check reachability. Without an open case,
projects go under `reverse/_standalone/`; open a case (`scan_evidence` on
the sample) to index outputs and submit findings.

## 7. Checking the result in Ghidra

1. Ghidra > File > Open Project > the `mulder.gpr` named in the report.
2. Open the program. Functions the agent understood have names
   (`decode_config`, `install_run_key`...) and a plate comment starting
   with `[mulder]`.
3. Window > Bookmarks, category `mulder`: every place the agent touched.
4. Check each claim of the report against the code it cites.

Close the project in Ghidra before re-running Mulder on the same case:
Ghidra locks an open project (Mulder waits up to a minute for the lock).

**From radare2:** the report of a radare2 case (and the
`reverse_export_annotations` tool) writes `mulder_annotations_ghidra.py`
next to the project. Open the sample in your own Ghidra and run that
script from the Script Manager: it replays the renames, comments and
bookmarks.

## 8. Scripts

`reverse_read_script` reads PowerShell, JavaScript, VBScript, batch and
HTA files whatever their encoding (UTF-16 PowerShell included) and lists
the encoded blobs it sees as numbered *indicators*: `-EncodedCommand` in
any accepted spelling, character-code arrays, hex, base64.
`reverse_decode_layer` undoes one indicator in pure Python (base64, hex,
character codes, an XOR key you read in the script, zlib/DEFLATE/gzip
capped at 20 MB, UTF-16) and writes the result as a new layer file with its
lineage (`layers.json`). A layer is itself a script: read it, decode its
own blobs, and so on. No interpreter is ever started, not even in a
sandbox: a technique that needs run-time evaluation to reveal its payload
stays opaque (see limits).

## 9. .NET assemblies

Ghidra sees the CLR loader stub and IL bytes, not classes and methods.
With `ilspycmd` installed, `.NET` samples go to ILSpy automatically: the
assembly is decompiled once to a C# project (`csharp/`) and IL (`il/`), and
the same tools answer with methods named `Namespace.Type::Method` and
addresses `file.cs:line`. `reverse_disassemble` returns a method's IL;
`reverse_imports` lists P/Invoke declarations and referenced assemblies.
Cross-references and call paths come from the C# text and are marked
`approximate` (overloads and common names can over-match). An assembly
cannot be annotated in place: renames and comments are recorded in
`annotations.jsonl` and listed in the report.

## 10. Limits

- **Packed or encrypted samples** are detected and reported, then the
  pipeline stops. Unpack them yourself (in a sandbox, outside Mulder) and
  analyse the unpacked payload as a new sample.
- **Obfuscation:** control-flow flattening, opaque predicates, virtualised
  code (VMProtect, Themida) and API hashing make the decompiled code hard
  to read for the model as for a human; findings will be fewer and less
  certain. Strings decrypted at run time appear only if the decoder is
  found and its key read from the code.
- **Indirect calls** (vtables, callbacks, APIs resolved at run time) are
  invisible to static call paths: "no path from an entry point" is not
  proof of dead code.
- **Scripts** that only reveal their payload when evaluated (string
  building by execution, `Invoke-Expression` of computed values) are
  decoded only as far as their blobs can be undone statically.
- **.NET** cross-references are textual (see above); obfuscated assemblies
  (renamed members, encrypted strings) decompile poorly.
- **Library code:** statically linked libraries (CRT, OpenSSL, Go and Rust
  runtimes) make large binaries expensive; Ghidra's Function ID hides what
  it recognises, the rest is left to the counter-analysis.
- The **YARA rule** is a starting point: test it on the sample and on a
  clean corpus before deploying it.

## 11. Cost

Token use is logged per phase in `<case>.phase_usage.json`. Rough orders
of magnitude, to be confirmed on your samples: 200,000 to 500,000 tokens for
a small unpacked sample, 1 to 3 million for a large C++ or Go binary. The
tools keep costs down by hiding library functions, paginating every output
and making agents start from leads rather than decompile every function.
`--effort` weighs more than the model choice; keep a cheaper model for the
executor.

## 12. Reference

| Variable | Default | Role |
|---|---|---|
| `MULDER_GHIDRA_DIR` / `GHIDRA_INSTALL_DIR` | newest `/opt/ghidra_*_PUBLIC` | Ghidra install |
| `MULDER_GHIDRA_MAXMEM` | `4G` | JVM heap of each Ghidra worker |
| `MULDER_REVERSE_MAX_SESSIONS` | `2` | engine processes alive at once (least recently used idle one closed first) |
| `MULDER_REVERSE_BACKEND` | (auto) | engine for tool calls that do not name one |
| `MULDER_RADARE2` | `radare2` on `PATH` | radare2 binary |
| `MULDER_ILSPYCMD` | `ilspycmd` on `PATH` | ILSpy command-line tool |

Tools: see section 21 of the [tool manifest](tool-manifest.md). Error
types: `not_analyzed` (call `reverse_analyze` first), `binary_missing`
(engine or plugin not installed), `file_not_found`, `invalid_parameter`,
`not_found`, `timeout` (engine process killed; the next call reopens the
project), `backend_error`.
