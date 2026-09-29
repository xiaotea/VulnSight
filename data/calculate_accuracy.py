import csv
import re
import statistics
from collections import defaultdict
from pathlib import Path

BASE = Path(__file__).resolve().parent
LABELS_PATH = BASE / "python_vuln_dataset_184_versions.csv"
OUTPUT_PATH = BASE / "accuracy_summary.csv"

DECISION_TO_LABEL = {"YES": "affected", "NO": "not_affected"}


def explicit_decisions(answer):
    """Every line that states a bare YES/NO verdict; last one wins."""
    text = answer.rsplit("</think>", 1)[-1].strip()
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    return [value.upper() for value in re.findall(
        r"(?im)^[ \t]*(?:(?:Line\s*1|Answer):[ \t]*)?(YES|NO)"
        r"(?:[ \t]*:[ \t]*CONFIDENCE[ \t]*:[ \t]*[01](?:\.\d+)?)?[.!]?[ \t]*$",
        text)]


def parse_answer(answer):
    """The verdict of one prediction, or None when it cannot be read safely.

    Only explicit decisions count; YES/NO mentioned inside explanatory prose is
    ignored.  A prose conclusion is accepted solely as 'Therefore, YES/NO'
    directly above a CONFIDENCE line.
    """
    if not isinstance(answer, str) or not answer.strip():
        return None
    matches = explicit_decisions(answer)
    if matches:
        return matches[-1]
    text = re.sub(r"```.*?```", "", answer.rsplit("</think>", 1)[-1], flags=re.S)
    matches = re.findall(
        r"(?im)^[ \t]*(?:\*[ \t]*)?Therefore,[ \t]*(YES|NO)[.!]?[ \t]*\r?\n"
        r"\s*CONFIDENCE[ \t]*:", text)
    return matches[-1].upper() if matches else None


def read_labels(path):
    """(cve, version) -> (repository, is_affected)."""
    labels = {}
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            cve, repo, version, label = (
                row[key].strip() for key in ("cve", "repository", "version", "is_affected"))
            if (cve, version) in labels or label not in {"affected", "not_affected"}:
                raise ValueError(f"Duplicate sample or invalid label: {row}")
            labels[(cve, version)] = (repo, label)
    if not labels:
        raise ValueError(f"Empty label file: {path}")
    return labels


def parse_name(stem):
    """'<CVE>_<owner-repo>_<tag>' -> (cve, repo, tag), or None if malformed.

    CVE identifiers and tags never contain '_', so the tag is the last field and
    the repository is everything between it and the CVE.
    """
    parts = stem.split("_")
    if len(parts) < 3:
        return None
    return parts[0], "_".join(parts[1:-1]), parts[-1]


def evaluate(group, labels):
    """Score one model config; returns (summary_row, issues)."""
    issues = []
    predictions = {}
    files = sorted(group.glob("*.txt"))

    for path in files:
        parsed = parse_name(path.stem)
        if parsed is None:
            issues.append((group.name, path.name, "malformed_filename"))
            continue
        cve, repo, tag = parsed
        entry = labels.get((cve, tag))
        if entry is None:
            issues.append((group.name, path.name, "sample_not_in_labels"))
            continue
        expected_repo = entry[0].replace("/", "-")
        if repo != expected_repo:
            issues.append((group.name, path.name, f"repository_mismatch: {repo} != {expected_repo}"))
        if (cve, tag) in predictions:
            issues.append((group.name, path.name, "duplicate_prediction_ignored"))
            continue

        text = path.read_text(encoding="utf-8-sig")
        decision = parse_answer(text)
        if decision is None:
            issues.append((group.name, path.name, "unparseable_answer"))
        elif len(set(explicit_decisions(text))) > 1:
            issues.append((group.name, path.name, "multiple_decisions_used_last"))
        predictions[(cve, tag)] = decision

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

    # 'accuracy' is the macro metric: mean of the per-CVE accuracies.  The extra
    # fields are console diagnostics only; the CSV exposes model and accuracy.
    row = dict(
        model=group.name,
        accuracy=statistics.mean(accuracies) if accuracies else "",
        evaluated=evaluated,
        labeled=len(labels),
        issue_records=len(issues),
    )
    return row, issues


def main():
    labels = read_labels(LABELS_PATH)
    groups = sorted(path for path in BASE.iterdir() if path.is_dir())
    if not groups:
        raise ValueError(f"No model directories under {BASE}")

    summaries, issues = [], []
    for group in groups:
        summary, group_issues = evaluate(group, labels)
        summaries.append(summary)
        issues.extend(group_issues)
        accuracy = summary["accuracy"]
        shown = f"{accuracy:.6%}" if accuracy != "" else "N/A"
        print(f"{group.name}: accuracy={shown} "
              f"evaluated={summary['evaluated']}/{summary['labeled']} "
              f"issues={summary['issue_records']}", flush=True)

    summaries.sort(key=lambda row: row["accuracy"] if row["accuracy"] != "" else -1,
                   reverse=True)
    with OUTPUT_PATH.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["model", "accuracy"],
                                extrasaction="ignore")
        writer.writeheader()
        writer.writerows(summaries)

    reasons = defaultdict(int)
    for _, _, reason in issues:
        reasons[reason.split(":")[0]] += 1
    print(f"\nwrote {OUTPUT_PATH.name} ({len(summaries)} rows)")
    if reasons:
        print("issue records: " + ", ".join(f"{k}={v}" for k, v in sorted(reasons.items())))
        for group, name, reason in issues[:20]:
            print(f"  {group}/{name}: {reason}")
        if len(issues) > 20:
            print(f"  ... {len(issues) - 20} more")


if __name__ == "__main__":
    main()
