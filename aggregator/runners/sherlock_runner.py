"""
Wrapper around Sherlock (https://github.com/sherlock-project/sherlock).
"""

import subprocess
from typing import Any, Dict


def run(target: str) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            [
                "sherlock",
                "--print-found",
                "--no-color",
                target,
                "--timeout",
                "60",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )

    except FileNotFoundError:
        return {
            "tool": "sherlock",
            "target": target,
            "found": [],
            "errors": ["Sherlock executable was not found in PATH."],
        }

    except subprocess.TimeoutExpired:
        return {
            "tool": "sherlock",
            "target": target,
            "found": [],
            "errors": ["Sherlock timed out after 600 seconds."],
        }

    found_sites = []

    for line in result.stdout.splitlines():
        line = line.strip()

        if line.startswith("[+]"):
            body = line[len("[+]"):].strip()

            if ":" in body:
                site_name, url = body.split(":", 1)

                found_sites.append(
                    {
                        "site": site_name.strip(),
                        "url": url.strip(),
                    }
                )

    return {
        "tool": "sherlock",
        "target": target,
        "found": found_sites,
        "errors": [],
    }
