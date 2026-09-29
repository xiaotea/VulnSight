# Java evaluation

The Java evaluation uses 8,535 vulnerability-version pairs covering 74 CVEs and
6,305 distinct Maven component releases (artifact plus version).

- `java_manifest.csv`: `cve,artifact,version,ground_truth`.
- `predictions/VulnSight.csv`: full saved VulnSight results, with original filenames and hashes.
- `predictions/VISION.csv`: VISION baseline on exactly the same manifest.

```sh
python evaluation/java/evaluate.py
```

| Method | TP | TN | FP | FN | CVE-macro accuracy |
| --- | ---: | ---: | ---: | ---: | ---: |
| VulnSight | 2864 | 5244 | 250 | 177 | 0.964398493 |
| VISION | 2942 | 5121 | 373 | 99 | 0.910100213 |

The export uses the current `VS_VISION/download_success.json` population,
`trueresult.json` labels, `sortresults_original.json` baseline and `VulnSight/*.txt`
responses. It does not use the older 201-pair partial archive. See
[`provenance.json`](../provenance.json) for input hashes.

Maven coordinates remain intact in the CSV; sanitized response filenames are
matched uniquely and checked against the complete manifest. Complete Java source
snapshots and per-run API metadata are not included. Ground truth and VISION
outputs retain their upstream attribution and licensing; the code's MIT license
does not replace third-party terms.
