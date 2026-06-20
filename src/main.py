import argparse
from parser import parse_log_file
from storage import save_events
from report import build_alerts, write_reports


def main(log_path="logs/security.log"):
    """
    Main workflow:

    1. Parse log file
    2. Save events to DB
    3. Build alerts
    4. Write CSV reports
    """
    # Parse log file
    events = parse_log_file(log_path)
    print(f"Parsed {len(events)} events from {log_path}")

    # Save to DB
    saved = save_events(events)
    print(f"Saved {saved} events to output/events.db")

    # Build alerts
    alerts = build_alerts(events)
    print(f"Generated {len(alerts)} alerts")

    # Write CSV reports
    write_reports(alerts)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Security events monitor: parse logs, store in DB, generate reports."
    )
    parser.add_argument(
        "log",
        nargs="?",
        default="logs/security.log",
        help="Path to the security log file (default: logs/security.log)",
    )

    args = parser.parse_args()
    main(args.log)