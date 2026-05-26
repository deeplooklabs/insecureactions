import argparse
import sys

from .checkactions import check


def main():
    parser = argparse.ArgumentParser(
        prog="insecureactions",
        description=(
            "Scan GitHub Actions workflows for common security issues "
            "(script injection, pull_request_target abuse, self-hosted "
            "runner exposure, compromised actions, etc.)."
        ),
        epilog=(
            "Each TARGET can be:\n"
            "  org-or-user    scan every repo owned by that org or user\n"
            "  owner/repo     scan a single repository\n\n"
            "Examples:\n"
            "  insecureactions myorg\n"
            "  insecureactions myorg otheruser owner/specific-repo\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets",
        nargs="+",
        metavar="TARGET",
        help="One or more orgs, users, or owner/repo identifiers",
    )
    parser.add_argument(
        "--check-links",
        action="store_true",
        help="Also probe URLs found in workflows for hijack risk (slow)",
    )
    parser.add_argument(
        "--cve-2025-30066",
        action="store_true",
        dest="check_cve_tj",
        help=(
            "For workflows that use tj-actions/changed-files, list runs that "
            "executed during the CVE-2025-30066 exposure window "
            "(2025-03-14..2025-03-15) so you can audit logs for leaked secrets"
        ),
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=8,
        help="Concurrent repository scanners (default: 8)",
    )

    args = parser.parse_args()
    try:
        check(
            args.targets,
            check_links=args.check_links,
            check_cve_tj=args.check_cve_tj,
            workers=args.workers,
        )
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
