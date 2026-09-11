"""
Wrapper around theHarvester (https://github.com/laramies/theHarvester).
"""

import json
import os
import subprocess
import tempfile
from typing import Any, Dict


def run(target: str) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmpdir:
        output_prefix = os.path.join(tmpdir, "th_report")

        subprocess.run(
            [
                "theHarvester",
                "-d", target,
                "-b", "crtsh,certspotter,commoncrawl",
                "-f", output_prefix,
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )

        json_path = output_prefix + ".json"
        hosts = []
        emails = []

        if os.path.exists(json_path):
            with open(json_path, "r") as f:
                data = json.load(f)
            hosts = data.get("hosts", [])
            emails = data.get("emails", [])

        return {
            "tool": "theharvester",
            "target": target,
            "hosts": hosts,
            "emails": emails,
            "errors": [],
        }
