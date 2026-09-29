# Python evaluation

The benchmark contains 184 CVEs from 114 repositories and 4,032 vulnerability-version
pairs (1,640 vulnerable and 2,392 non-vulnerable).

- `python_vuln_dataset_184.csv`: original CVE-level metadata and patch references.
- `python_vuln_dataset_184_versions.csv`: original version labels.
- `python_manifest.csv`: normalized evaluation population with YES/NO labels.
- `annotation_records.csv`: original three annotation columns and final labels.
  All 4,032 final labels agree with the version manifest. Reviewer identities,
  timestamps, and independence of the three columns are not established by this file.
- `predictions/`: complete predictions for DeepSeek-R1-0528, gemini-2.5-pro, and
  o3-2025-04-16, each under Full, -VP, -SP, -PP and -MSI configurations.

The ablations remove VulnPattern, SafePattern, preprocessing, and multi-step
inference respectively. All 15 files contain 4,032 predictions; these are complete
experiment exports, not illustrative samples.

```sh
python evaluation/python/evaluate.py
python evaluation/python/evaluate.py --predictions evaluation/python/predictions/DeepSeek-R1-0528_Full.csv
```

The full configurations reproduce CVE-macro accuracies of 92.99%, 91.70%, and 92.22%.
Patch/description paths in the CVE metadata are source references; the complete
benchmark snapshots, patches and prompt histories are not bundled here. CSV
rescoring does not reconstruct the source-analysis runs or the paper's three-run
variability experiment.
