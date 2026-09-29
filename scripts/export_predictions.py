"""Build compact evaluation records from the retained local experiment folders.

Run before publishing. Original inputs are never changed. --archive additionally
creates an ignored ZIP for separate release, with an adjacent SHA-256 checksum.
"""
import argparse
import csv
import hashlib
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "evaluation"))
from response_parser import parse_answer


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def source_fields(path):
    return dict(source_file=path.relative_to(ROOT).as_posix(), source_sha256=digest(path))


def decision(path):
    answer = parse_answer(path.read_text(encoding="utf-8-sig"))
    if answer is None:
        raise ValueError(f"Unparseable response: {path}")
    return answer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", action="store_true")
    args = parser.parse_args()
    output = ROOT / "evaluation"
    sources = []
    labels_path = ROOT / "data/python_vuln_dataset_184_versions.csv"
    labels = read_csv(labels_path)
    assert len(labels) == 4032 and len({r['cve'] for r in labels}) == 184
    manifest = [dict(cve=r['cve'], repository=r['repository'], version=r['version'],
                     ground_truth={'affected': 'YES', 'not_affected': 'NO'}[r['is_affected']])
                for r in labels]
    assert len({(r['cve'], r['repository'], r['version']) for r in manifest}) == len(manifest)
    write_csv(output / "python/python_manifest.csv", manifest)
    for name in ("python_vuln_dataset_184.csv", "python_vuln_dataset_184_versions.csv"):
        path = ROOT / "data" / name
        shutil.copyfile(path, output / "python" / name)
        sources.append(path)
    audit = ROOT / "dataset/python_vuln_dataset_184_versions_three_audits.csv"
    annotations = read_csv(audit)
    annotation_index = {(r['CVE'], r['name_version']): r['Final annotation'] for r in annotations}
    assert len(annotations) == len(annotation_index) == len(labels)
    assert all(annotation_index[(r['cve'], r['repository'] + '@' + r['version'])] == r['is_affected']
               for r in labels)
    shutil.copyfile(audit, output / "python/annotation_records.csv")
    sources.append(audit)
    raw_paths = []
    for model in ("DeepSeek-R1-0528", "gemini-2.5-pro", "o3-2025-04-16"):
        for setting in ("Full", "-VP", "-SP", "-PP", "-MSI"):
            group = ROOT / "data" / f"{model}_{setting}"
            rows, used = [], set()
            for row in manifest:
                path = group / (f"{row['cve']}_{row['repository'].replace('/', '-')}_{row['version']}.txt")
                rows.append(dict(row, prediction=decision(path), **source_fields(path)))
                used.add(path)
            assert used == set(group.glob('*.txt')), f"Unmatched outputs: {group}"
            raw_paths.extend(sorted(used))
            write_csv(output / "python/predictions" / f"{group.name}.csv", rows)
    java = ROOT / "VS_VISION"
    tasks = read_json(java / "download_success.json")
    truth = read_json(java / "trueresult.json")
    vision = read_json(java / "sortresults_original.json")
    vision_source = source_fields(java / "sortresults_original.json")
    sources.extend(java / n for n in ("download_success.json", "trueresult.json", "sortresults_original.json"))
    files = {}
    for path in (java / "VulnSight").glob("*.txt"):
        cve, artifact, version, suffix = path.stem.split('__')
        key = cve, artifact, version
        assert key not in files, f"Ambiguous filename: {key}"
        files[key] = path
    manifest, rows, baseline, used = [], [], [], set()
    for task in sorted(tasks, key=lambda t: (t['cve_id'], t['maven'], t['version'])):
        cve, artifact, version = task['cve_id'], task['maven'], task['version']
        def label(records):
            record = records[cve]
            assert (version in record['affected']) != (version in record['unaffected'])
            return 'YES' if version in record['affected'] else 'NO'
        row = dict(cve=cve, artifact=artifact, version=version, ground_truth=label(truth))
        manifest.append(row)
        key = cve, artifact.split(':')[1], re.sub(r'[^A-Za-z0-9._-]', '_', version)
        path = files[key]
        assert path not in used, f"Ambiguous sample mapping: {key}"
        used.add(path)
        rows.append(dict(row, prediction=decision(path), **source_fields(path)))
        baseline.append(dict(row, prediction=label(vision), **vision_source))
    assert len(manifest) == 8535 and len({r['cve'] for r in manifest}) == 74
    assert len({(r['artifact'], r['version']) for r in manifest}) == 6305
    assert used == set(files.values())
    raw_paths.extend(sorted(used))
    write_csv(output / "java/java_manifest.csv", manifest)
    write_csv(output / "java/predictions/VulnSight.csv", rows)
    write_csv(output / "java/predictions/VISION.csv", baseline)
    provenance = dict(sources=[source_fields(p) for p in sources],
                      parser=source_fields(output / 'response_parser.py'),
                      raw_output_files=len(raw_paths), archive_status="Prepared locally; not published")
    (output / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
    if args.archive:
        folder = ROOT / 'artifacts'
        folder.mkdir(exist_ok=True)
        archive = folder / 'vulnsight-raw-outputs.zip'
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as handle:
            for path in sorted(set(raw_paths + sources)):
                handle.write(path, path.relative_to(ROOT).as_posix())
        (folder / (archive.name + '.sha256')).write_text(digest(archive) + '  ' + archive.name + '\n', encoding='utf-8')
        print(f'Prepared {archive.name}: {archive.stat().st_size} bytes')
    print(f'Exported 15 Python experiments and 2 Java methods; {len(raw_paths)} raw outputs retained.')


if __name__ == '__main__':
    main()
