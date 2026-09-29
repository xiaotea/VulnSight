# Local raw experiment storage

Public benchmark labels, annotation records and compact predictions are maintained
under [`evaluation/`](../evaluation/README.md). Raw experiment directories and the
legacy scoring files remain local and are ignored by Git.

Use `python scripts/reproduce_results.py --dataset python` to score public CSVs.
Use `python scripts/export_predictions.py --archive` to rebuild the compact exports
and separate raw-output archive from retained local data. See
[`docs/reproducibility.md`](../docs/reproducibility.md) for availability and scope.
