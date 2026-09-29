"""Offline binary evaluation with strict sample coverage (standard library only)."""
import csv
import json
from collections import defaultdict
from pathlib import Path


def read_rows(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError(f"Empty CSV: {path}")
    return rows


def index_rows(rows, identity):
    indexed = {}
    for row in rows:
        key = tuple(row[field] for field in ("cve", identity, "version"))
        if not all(key) or key in indexed:
            raise ValueError(f"Empty or duplicate sample: {key}")
        if row["ground_truth"] not in {"YES", "NO"}:
            raise ValueError(f"Invalid ground truth: {key}")
        indexed[key] = row
    return indexed


def binary_metrics(rows):
    tp = sum(r["ground_truth"] == "YES" and r["prediction"] == "YES" for r in rows)
    tn = sum(r["ground_truth"] == "NO" and r["prediction"] == "NO" for r in rows)
    fp = sum(r["ground_truth"] == "NO" and r["prediction"] == "YES" for r in rows)
    fn = sum(r["ground_truth"] == "YES" and r["prediction"] == "NO" for r in rows)
    def ratio(a, b):
        return a / b if b else 0.0
    return dict(tp=tp, tn=tn, fp=fp, fn=fn, accuracy=ratio(tp + tn, len(rows)),
                precision_positive=ratio(tp, tp + fp), recall_positive=ratio(tp, tp + fn),
                f1_positive=ratio(2 * tp, 2 * tp + fp + fn),
                precision_negative=ratio(tn, tn + fn), recall_negative=ratio(tn, tn + fp),
                f1_negative=ratio(2 * tn, 2 * tn + fp + fn))


def evaluate(manifest, predictions, identity):
    labels = index_rows(read_rows(manifest), identity)
    actual = index_rows(read_rows(predictions), identity)
    if labels.keys() != actual.keys():
        raise ValueError(f"Coverage mismatch: missing={len(labels.keys() - actual.keys())}, "
                         f"extra={len(actual.keys() - labels.keys())}")
    grouped = defaultdict(list)
    for key, row in actual.items():
        if row["ground_truth"] != labels[key]["ground_truth"]:
            raise ValueError(f"Ground truth mismatch: {key}")
        if row["prediction"] not in {"YES", "NO"}:
            raise ValueError(f"Missing or unparseable prediction: {key}")
        grouped[row["cve"]].append(row)
    per_cve = [binary_metrics(rows) for rows in grouped.values()]
    macro = {key: sum(row[key] for row in per_cve) / len(per_cve)
             for key in per_cve[0] if key not in {"tp", "tn", "fp", "fn"}}
    return dict(experiment=Path(predictions).stem, evaluated=len(actual), labeled=len(labels),
                cves=len(grouped), pair=binary_metrics(list(actual.values())), cve_macro=macro)


def run_dataset(dataset, prediction=None):
    base = Path(__file__).resolve().parent / dataset
    identity = "repository" if dataset == "python" else "artifact"
    manifest = base / ("python_manifest.csv" if dataset == "python" else "java_manifest.csv")
    paths = [Path(prediction)] if prediction else sorted((base / "predictions").glob("*.csv"))
    if not paths:
        raise ValueError(f"No predictions under {base}")
    results = [evaluate(manifest, path, identity) for path in paths]
    print(json.dumps(results, indent=2))
    return results
