#!/usr/bin/env python3
"""3-run consistency analysis (terminal only).

Filenames are now `<CVE>__<version>.txt`.  Verdicts are extracted with the same
`parse_answer` as calculate_accuracy.py.  Prints:

  1. per-run macro accuracy (mean of per-CVE accuracy),
  2. accuracy deviation across the three runs,
  3. complete agreement rate across the three runs,
  4. Fleiss' kappa (3 raters, 2 categories YES/NO),
  5. pairwise verdict agreement.
"""
import statistics
import sys
from collections import defaultdict
from pathlib import Path

DATA_DIR = Path(r"D:\Users\wyj20\Desktop\affected_version\code\Github_VulnSight\data")
EXPERIMENT_DIR = Path(r"D:\Users\wyj20\Desktop\affected_version\code\Github_VulnSight\llm_nondeterminism_3runs")
LABELS_PATH = DATA_DIR / "python_vuln_dataset_184_versions.csv"

sys.path.insert(0, str(DATA_DIR))
from calculate_accuracy import parse_answer, read_labels  # noqa: E402

RUNS = ["run1", "run2", "run3"]
DECISION_TO_LABEL = {"YES": "affected", "NO": "not_affected"}


def parse_name(stem):
    """'<CVE>__<version>' -> (cve, version)."""
    if "__" not in stem:
        return None
    cve, version = stem.split("__", 1)
    if not cve or not version:
        return None
    return cve, version


def load_run(run_dir):
    predictions = {}
    for path in sorted(run_dir.glob("*.txt")):
        parsed = parse_name(path.stem)
        if parsed is None:
            print(f"skip malformed filename: {path.name}")
            continue
        cve, version = parsed
        verdict = parse_answer(path.read_text(encoding="utf-8-sig"))
        predictions[(cve, version)] = verdict
    return predictions


def macro_accuracy(predictions, labels):
    """Same macro metric as calculate_accuracy.evaluate()."""
    by_cve = defaultdict(list)
    for (cve, version), (_, truth) in labels.items():
        decision = predictions.get((cve, version))
        predicted = DECISION_TO_LABEL.get(decision, "")
        by_cve[cve].append((decision is not None, predicted == truth))

    per_cve = []
    for cve, rows in sorted(by_cve.items()):
        usable = [correct for included, correct in rows if included]
        per_cve.append((len(usable), sum(usable)))

    evaluated = sum(n for n, _ in per_cve)
    accuracies = [c / n for n, c in per_cve if n]
    accuracy = statistics.mean(accuracies) if accuracies else float("nan")
    return accuracy, evaluated, len(labels)


def fleiss_kappa(table, categories):
    n = sum(table[0].values()) if table else 0
    N = len(table)

    p_bar = 0.0
    for row in table:
        p_bar += (sum(row[c] ** 2 for c in categories) - n) / (n * (n - 1))
    p_bar /= N

    p_e = 0.0
    for c in categories:
        p_j = sum(row[c] for row in table) / (N * n)
        p_e += p_j ** 2

    kappa = (p_bar - p_e) / (1 - p_e) if (1 - p_e) else float("nan")
    return kappa, p_bar, p_e


def main():
    labels = read_labels(LABELS_PATH)
    runs = {n: load_run(EXPERIMENT_DIR / n) for n in RUNS}
    common = set.intersection(*(set(p) for p in runs.values()))

    print("=" * 62)
    print("3-run consistency analysis")
    print(f"labels: {len(labels)}   common samples: {len(common)}")
    print("=" * 62)

    # ---- 1. per-run accuracy ---------------------------------------------- #
    print("\n[1] per-run macro accuracy")
    accs = {}
    for n in RUNS:
        acc, evaluated, labeled = macro_accuracy(runs[n], labels)
        accs[n] = acc
        print(f"    {n}: {acc:.6%}   (evaluated {evaluated}/{labeled})")

    # ---- 2. accuracy deviation --------------------------------------------- #
    vals = [accs[n] for n in RUNS]
    mean = statistics.mean(vals)
    stdev = statistics.stdev(vals) if len(vals) > 1 else 0.0
    print("\n[2] accuracy deviation")
    print(f"    mean    = {mean:.6%}")
    print(f"    stdev   = {stdev:.6%}")
    print(f"    min     = {min(vals):.6%}")
    print(f"    max     = {max(vals):.6%}")
    print(f"    max-min = {(max(vals) - min(vals)):.6%}")

    # ---- agreement over the common samples ---------------------------------- #
    categories = ["YES", "NO"]
    table = []
    agreement = {"all_yes": 0, "all_no": 0, "2yes_1no": 0, "1yes_2no": 0}
    unparseable = 0
    for key in sorted(common):
        triple = [runs[n].get(key) for n in RUNS]
        if any(v is None for v in triple):
            unparseable += 1
            continue
        yes = triple.count("YES")
        no = triple.count("NO")
        table.append({"YES": yes, "NO": no})
        if yes == 3:
            agreement["all_yes"] += 1
        elif no == 3:
            agreement["all_no"] += 1
        elif yes == 2:
            agreement["2yes_1no"] += 1
        else:
            agreement["1yes_2no"] += 1

    N = len(table)
    full = agreement["all_yes"] + agreement["all_no"]
    complete_rate = full / N if N else float("nan")

    # ---- 3. complete agreement rate ----------------------------------------- #
    print("\n[3] complete agreement rate (all 3 runs identical)")
    print(f"    all-YES  = {agreement['all_yes']}")
    print(f"    all-NO   = {agreement['all_no']}")
    print(f"    2YES/1NO = {agreement['2yes_1no']}")
    print(f"    1YES/2NO = {agreement['1yes_2no']}")
    if unparseable:
        print(f"    unparseable = {unparseable}")
    print(f"    complete agreement rate = {complete_rate:.6%}  ({full}/{N})")

    # ---- 4. Fleiss' kappa ---------------------------------------------------- #
    kappa, p_bar, p_e = fleiss_kappa(table, categories)
    print("\n[4] Fleiss' kappa (3 raters, 2 categories: YES/NO)")
    print(f"    P-bar = {p_bar:.6f}   P-e = {p_e:.6f}")
    print(f"    Fleiss' kappa = {kappa:.6f}")

    # ---- 5. pairwise agreement ---------------------------------------------- #
    print("\n[5] pairwise verdict agreement")
    for a, b in [("run1", "run2"), ("run1", "run3"), ("run2", "run3")]:
        agree = sum(1 for k in common if runs[a].get(k) == runs[b].get(k))
        print(f"    {a} vs {b}: {agree}/{len(common)} = {agree/len(common):.6%}")

    print("=" * 62)


if __name__ == "__main__":
    main()
