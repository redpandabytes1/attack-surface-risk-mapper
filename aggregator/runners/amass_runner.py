"""
Wrapper around Amass (https://github.com/owasp-amass/amass).
"""

import os
import subprocess
import tempfile
from typing import Any, Dict


def run(target: str) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "amass_output.txt")

        try:
            result = subprocess.run(
                [
                    "amass",
                    "enum",
                    "-passive",
                    "-d",
                    target,
                    "-o",
                    output_path,
                    "-timeout",
                    "5",
                ],
                capture_output=True,
                text=True,
                timeout=400,
                check=False,
            )
        except FileNotFoundError:
            return {
                "tool": "amass",
                "target": target,
                "subdomains": [],
                "errors": ["Amass executable was not found in PATH."],
            }
        except subprocess.TimeoutExpired:
            return {
                "tool": "amass",
                "target": target,
                "subdomains": [],
                "errors": ["Amass timed out after 400 seconds."],
            }

        subdomains = []
        errors = []

        if result.returncode != 0:
            errors.append(
                f"Amass exited with return code {result.returncode}."
            )

        if result.stderr.strip():
            errors.append(result.stderr.strip())

        if os.path.exists(output_path):
            with open(output_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()

                    if line:
                        subdomains.append(line)
        else:
            errors.append("Amass did not produce an output file.")

        return {
            "tool": "amass",
            "target": target,
            "subdomains": subdomains,
            "errors": errors,
        }
