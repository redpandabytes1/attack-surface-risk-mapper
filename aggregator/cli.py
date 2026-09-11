"""
Command-line entry point for the Attack-Surface Risk Mapper.
"""

import argparse
import sys

from aggregator.runners import (
    sherlock_runner,
    theharvester_runner,
    amass_runner,
)
from aggregator.report import builder


def build_arg_parser() -> argparse.ArgumentParser:
    """
    Build the command-line argument parser.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Run passive OSINT tools and produce one unified "
            "attack-surface report."
        )
    )

    parser.add_argument(
        "--username",
        help="Username to check with Sherlock",
    )

    parser.add_argument(
        "--domain",
        help="Domain to enumerate with theHarvester and Amass",
    )

    parser.add_argument(
        "--tools",
        default="sherlock,theharvester,amass",
        help=(
            "Comma-separated list of tools to run "
            "(default: sherlock,theharvester,amass)"
        ),
    )

    parser.add_argument(
        "--output",
        default="report.md",
        help="Path to write the unified Markdown report",
    )

    return parser


def main() -> int:
    """
    Parse arguments, run selected tools, build the unified report,
    and write it to disk.
    """
    parser = build_arg_parser()
    args = parser.parse_args()

    selected_tools = [
        tool.strip().lower()
        for tool in args.tools.split(",")
        if tool.strip()
    ]

    results = {}

    # ------------------------------------------------------------
    # Sherlock
    # ------------------------------------------------------------

    if "sherlock" in selected_tools:
        if not args.username:
            print(
                "Skipping sherlock: --username was not provided."
            )
        else:
            print(
                f"Running Sherlock for username: {args.username}"
            )

            results["sherlock"] = sherlock_runner.run(
                args.username
            )

    # ------------------------------------------------------------
    # theHarvester
    # ------------------------------------------------------------

    if "theharvester" in selected_tools:
        if not args.domain:
            print(
                "Skipping theHarvester: --domain was not provided."
            )
        else:
            print(
                f"Running theHarvester for domain: {args.domain}"
            )

            results["theharvester"] = (
                theharvester_runner.run(args.domain)
            )

    # ------------------------------------------------------------
    # Amass
    # ------------------------------------------------------------

    if "amass" in selected_tools:
        if not args.domain:
            print(
                "Skipping Amass: --domain was not provided."
            )
        else:
            print(
                f"Running Amass for domain: {args.domain}"
            )

            results["amass"] = amass_runner.run(
                args.domain
            )

    # ------------------------------------------------------------
    # No tools actually ran
    # ------------------------------------------------------------

    if not results:
        print(
            "No tools ran. Provide --username and/or --domain "
            "matching the selected tools."
        )
        return 1

    # ------------------------------------------------------------
    # Aggregate + score + report
    # ------------------------------------------------------------

    report = builder.generate_report(results)

    builder.write_report(
        report,
        args.output,
    )

    print(
        f"Report written to {args.output}"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
