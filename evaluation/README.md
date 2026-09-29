# Paper evaluation artifacts

The compact CSVs support offline rescoring of the 20260904 manuscript. No API key,
model download, or third-party Python dependency is needed for rescoring.

```sh
python scripts/reproduce_results.py --dataset python
python scripts/reproduce_results.py --dataset java
```

| Directory | Scope |
| --- | --- |
| [python](python/README.md) | 184 CVEs, 4,032 pairs, 15 model/configuration combinations, three recorded annotation columns |
| [java](java/README.md) | 74 CVEs, 8,535 pairs, 6,305 Maven releases; VulnSight and VISION |
| [cpp](cpp/README.md) | Qualitative C/C++ case only |

## CSV contract and scoring

Each prediction row contains `cve`, `repository` (Python) or `artifact` (Java),
`version`, `ground_truth`, and `prediction`. `YES` means vulnerable; `NO` means
non-vulnerable. Versions remain strings. The manifest defines the evaluation
population; predictions must match it exactly, including ground truth.

`source_file` identifies the original response inside the separate raw archive;
`source_sha256` permits byte-for-byte verification. VISION predictions originate
from one JSON file, so their rows share its source hash.

The evaluator reports TP/TN/FP/FN and pair-level metrics, plus CVE-macro accuracy,
positive/negative precision, recall and F1. Macro metrics are calculated separately
within each CVE and then averaged with equal weight. Zero denominators yield zero.
F1 is averaged after calculating it per CVE. Confidence is not used for classification.
Missing, invalid, duplicate or extra predictions fail validation rather than being
silently omitted. The released Python experiments have full coverage, so this
strict rule preserves the original script's scores on the released records.

`response_parser.py` preserves the original decision parser: ignore reasoning before
the last `</think>` and fenced code; use the last explicit YES/NO line; accept
`Therefore, YES/NO` only immediately before a confidence line if no explicit verdict
exists. The conversion does not infer predictions from ground truth.

See [reproducibility](../docs/reproducibility.md) for environment, provenance,
raw archive availability, and limits of a full model rerun.
