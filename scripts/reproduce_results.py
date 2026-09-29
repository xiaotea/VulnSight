"""Rescore released predictions without LLM calls or file writes."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))
from metrics import run_dataset


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=("python", "java"), required=True)
    parser.add_argument("--predictions", type=Path, help="Score one CSV instead of all experiments")
    args = parser.parse_args()
    run_dataset(args.dataset, args.predictions)


if __name__ == "__main__":
    main()
