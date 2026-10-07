import argparse
import json
import os
import sys
from pathlib import Path

# Ensure project root is present in sys.path regardless of execution entry point
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.engine.pipeline import PipelineController


def main() -> None:
    parser = argparse.ArgumentParser(description="VaultSentry Static Analysis Engine")
    parser.add_argument("--file", required=True, help="Path to untrusted file for analysis")
    parser.add_argument("--output", required=False, help="Path to write the JSON report output")
    
    args = parser.parse_args()

    target_path = Path(args.file).resolve()
    if not target_path.exists():
        print(json.dumps({"status": "ERROR", "message": f"File not found: {args.file}"}))
        sys.exit(1)

    controller = PipelineController()
    report = controller.run_pipeline(str(target_path))

    report_json = json.dumps(report, indent=2)

    if args.output:
        out_path = Path(args.output).resolve()
        out_path.write_text(report_json, encoding="utf-8")
        print(f"[+] Scan completed. Report written to: {out_path}")
    else:
        # Output raw JSON to standard output for IPC consumption
        print(report_json)


if __name__ == "__main__":
    main()