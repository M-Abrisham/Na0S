"""Na0S command-line interface.

Usage examples::

    na0s scan "Ignore all previous instructions"
    na0s scan -f suspicious.txt
    echo "some text" | na0s scan -
    na0s scan --jsonl batch.jsonl
    na0s version

Exit codes:
    0 = safe
    1 = malicious
    2 = blocked / error
    3 = usage error (bad arguments)
"""

import argparse
import csv
import io
import json
import sys

from na0s._version import __version__

EXIT_SAFE = 0
EXIT_MALICIOUS = 1
EXIT_BLOCKED = 2
EXIT_USAGE = 3


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="na0s",
        description="Na0S — Multi-layer prompt injection detector",
    )
    subparsers = parser.add_subparsers(dest="command")

    # --- na0s scan ---
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan text for prompt injection",
    )
    scan_parser.add_argument(
        "text",
        nargs="?",
        default=None,
        help='Inline text to scan, or "-" to read from stdin',
    )
    scan_parser.add_argument(
        "-f", "--file",
        default=None,
        help="Path to a file whose contents should be scanned",
    )
    scan_parser.add_argument(
        "--jsonl",
        default=None,
        help="Path to a JSONL file for batch scanning",
    )
    scan_parser.add_argument(
        "--output-format",
        choices=["json", "csv", "text"],
        default="json",
        help="Output format (default: json)",
    )
    scan_parser.add_argument(
        "--threshold",
        type=float,
        default=0.55,
        help="Decision threshold for the composite score (default: 0.55)",
    )

    # --- na0s version ---
    subparsers.add_parser(
        "version",
        help="Print the Na0S version",
    )

    return parser


def _format_text(result):
    """Format a ScanResult as human-readable text."""
    lines = [
        "Label: {}".format(result.label),
        "Risk Score: {}".format(result.risk_score),
        "Technique Tags: {}".format(", ".join(result.technique_tags) if result.technique_tags else "(none)"),
        "Rule Hits: {}".format(", ".join(result.rule_hits) if result.rule_hits else "(none)"),
        "Latency: {}ms".format(result.elapsed_ms),
    ]
    return "\n".join(lines)


def _format_csv(result):
    """Format a ScanResult as a single CSV line (with header)."""
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["label", "risk_score", "is_malicious", "technique_tags"])
    writer.writerow([
        result.label,
        result.risk_score,
        result.is_malicious,
        ",".join(result.technique_tags) if result.technique_tags else "",
    ])
    return buf.getvalue().rstrip("\n")


def _exit_code_for(result):
    """Return the appropriate exit code for a ScanResult."""
    if result.label == "blocked":
        return EXIT_BLOCKED
    if result.is_malicious:
        return EXIT_MALICIOUS
    return EXIT_SAFE


def _scan_single(text, threshold, output_format):
    """Scan a single piece of text. Returns the exit code."""
    from na0s.predict import scan

    try:
        result = scan(text, threshold=threshold)
    except Exception as exc:
        print("Error: {}".format(exc), file=sys.stderr)
        return EXIT_BLOCKED

    if output_format == "json":
        print(result.to_json(indent=2))
    elif output_format == "text":
        print(_format_text(result))
    elif output_format == "csv":
        print(_format_csv(result))

    return _exit_code_for(result)


def _scan_jsonl(jsonl_path, threshold):
    """Scan each line of a JSONL file. Returns the worst exit code seen."""
    from na0s.predict import scan

    worst_exit = EXIT_SAFE
    try:
        with open(jsonl_path, "r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    record = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    err = {"error": "Invalid JSON on line {}".format(line_no), "detail": str(exc)}
                    print(json.dumps(err))
                    worst_exit = max(worst_exit, EXIT_BLOCKED)
                    continue

                text = record.get("text", "")
                if not text:
                    err = {"error": "Missing 'text' field on line {}".format(line_no)}
                    print(json.dumps(err))
                    worst_exit = max(worst_exit, EXIT_BLOCKED)
                    continue

                try:
                    result = scan(text, threshold=threshold)
                    print(result.to_json())
                    worst_exit = max(worst_exit, _exit_code_for(result))
                except Exception as exc:
                    err = {"error": "Scan failed on line {}".format(line_no), "detail": str(exc)}
                    print(json.dumps(err))
                    worst_exit = max(worst_exit, EXIT_BLOCKED)

    except FileNotFoundError:
        print("Error: file not found: {}".format(jsonl_path), file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print("Error: {}".format(exc), file=sys.stderr)
        return EXIT_BLOCKED

    return worst_exit


def main(argv=None):
    """Entry point for the ``na0s`` CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    if args.command == "version":
        print("na0s {}".format(__version__))
        return EXIT_SAFE

    # --- scan command ---
    threshold = args.threshold
    output_format = args.output_format

    # JSONL batch mode
    if args.jsonl is not None:
        return _scan_jsonl(args.jsonl, threshold)

    # File mode
    if args.file is not None:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                text = fh.read()
        except FileNotFoundError:
            print("Error: file not found: {}".format(args.file), file=sys.stderr)
            return EXIT_USAGE
        except OSError as exc:
            print("Error: {}".format(exc), file=sys.stderr)
            return EXIT_BLOCKED
        return _scan_single(text, threshold, output_format)

    # Stdin mode
    if args.text == "-":
        text = sys.stdin.read()
        return _scan_single(text, threshold, output_format)

    # Inline text
    if args.text is not None:
        return _scan_single(args.text, threshold, output_format)

    # No input provided
    print("Error: provide text to scan, use -f FILE, --jsonl FILE, or - for stdin", file=sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
