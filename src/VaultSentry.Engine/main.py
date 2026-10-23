"""
VaultSentry Engine Entry Point
Executes PipelineController inside VQS and outputs pure JSON to stdout.
Redirects warnings and non-JSON output to prevent IPC parsing corruption.
"""

import sys
import os
import json
import warnings

# Suppress library warnings from corrupting the stdout JSON stream
warnings.filterwarnings("ignore")

# Force stdout/stderr encoding to UTF-8
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')


def main() -> None:
    if len(sys.argv) < 2:
        error_payload = {
            "status": "ERROR",
            "message": "Missing required file path argument.",
            "verdict": "ERROR",
            "risk_score": 0,
            "findings": []
        }
        print(json.dumps(error_payload))
        sys.exit(1)

    target_path = sys.argv[1]

    try:
        from pipeline import PipelineController
        controller = PipelineController()
        result = controller.run_pipeline(target_path)
        
        # Output strictly formatted JSON to stdout
        print(json.dumps(result, ensure_ascii=False))
        sys.exit(0)

    except Exception as ex:
        error_payload = {
            "status": "ERROR",
            "message": f"Engine Execution Exception: {str(ex)}",
            "verdict": "ERROR",
            "risk_score": 0,
            "findings": []
        }
        print(json.dumps(error_payload))
        sys.exit(1)


if __name__ == "__main__":
    main()