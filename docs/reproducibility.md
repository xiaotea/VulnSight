# Reproducibility

## Environment

Offline scoring requires Python 3.10+ and its standard library only. Run commands
from the repository root. Full source analysis additionally uses the dependencies
in `requirements.txt` and `pyproject.toml`, an accessible LLM endpoint and the
language-specific source-analysis tools described in the main README.

The dependency files are not a historical environment lock. Exact SDK/provider
versions and any vLLM version for the archived experiments have not been established
from the retained records. Record these details when performing a new run.

## LLM configuration

The 20260904 manuscript reports `temperature=0.1`. Top-p and maximum output tokens
were not explicitly specified and followed backend defaults at invocation time.
The Python comparison uses DeepSeek-R1-0528, gemini-2.5-pro, and o3-2025-04-16.
The current interactive CLI selects `deepseek-v4-pro`; running that CLI is a new
experiment and does not recreate the paper's backend snapshots. It also sets
temperature to 0.1 and leaves top-p and maximum output tokens unspecified.

Retained response text does not independently establish every request setting.
Provider defaults can change; exact prompts, API versions and invocation dates are
needed for a fully specified model rerun. The release currently supports exact
rescoring of saved decisions.

## Dataset and ground truth

| Benchmark | CVEs | Version pairs | Additional scope |
| --- | ---: | ---: | --- |
| Python | 184 | 4,032 | 114 repositories |
| Java | 74 | 8,535 | 6,305 Maven releases |
| C/C++ | One qualitative case | Not a quantitative benchmark | NimBLE |

The public scoring labels are copied from the retained experiment labels, without
changing them to match model outputs. Python's three-column annotation table and
final decisions are included as `evaluation/python/annotation_records.csv`.
Final decisions were checked against all 4,032 evaluation labels. This table does
not contain reviewer identities, dates, or per-decision rationales; do not interpret
three columns alone as proof of independent review. Java labels come from the
VISION comparison's ground-truth file.

A complete ground-truth audit should expose vulnerability descriptions, fixing
patches, release histories, target-version source evidence and adjudication records.
Those complete evidence trails are not established by the compact label exports.

## Evaluation scripts

```sh
python scripts/reproduce_results.py --dataset python
python scripts/reproduce_results.py --dataset java
# Equivalent dataset-specific entry points:
python evaluation/python/evaluate.py
python evaluation/java/evaluate.py
```

These commands do not call an LLM or overwrite files. They report exact coverage,
confusion counts, pair metrics and CVE-macro metrics. See the
[scoring contract](../evaluation/README.md). Prediction and label keys must agree
exactly; missing responses fail validation.

## Raw outputs and provenance

The Git repository contains compact complete predictions. The 60,480 Python and
8,535 Java raw responses are intended for separate distribution as
`vulnsight-raw-outputs.zip`. The ZIP and its SHA-256 file are prepared locally under
ignored `artifacts/`. **No public release URL or DOI is recorded yet.** Publish the
archive as a release asset or on Zenodo and add its permanent link before announcing
complete raw-output availability. This documentation does not claim it is already
published.

Each prediction includes its raw source path and SHA-256. Extract the archive at
the repository root to restore those paths. The ZIP also contains the original
label files, annotation table and Java baseline JSON used by the export. Export
construction can then be repeated with:

```sh
python scripts/export_predictions.py
# Also rebuild the separate archive:
python scripts/export_predictions.py --archive
```

This command intentionally rewrites generated evaluation CSVs and provenance;
original experiment files remain intact. It requires the raw archive or equivalent
local source folders. `evaluation/provenance.json` records source hashes.

## C/C++ case and limitations

The [case package](../examples/c_cpp_case/CVE-2026-45813/README.md) separates the
description and patch inputs from the recorded output. It supplies no expected
target verdict in its description. The archived run reports a vulnerable target;
this is one observed result and does not establish general C/C++ performance.

The repository's older NimBLE source entries are Git links with stale local
worktree references. Use the explicit upstream refs in the new case's instructions
to obtain sources. Full benchmark source archives and a locked historical model
environment remain outside this release.
