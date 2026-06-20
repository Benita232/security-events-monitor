import os
import pandas as pd
from storage import read_events


def build_alerts(events):
    """
    Build alert dictionaries from a list of event dictionaries.

    Alert example:
    - brute_force: more than 5 failed logins from the same IP
    """
    alerts = []

    # Count failed logins per IP
    failed_by_ip = {}
    for e in events:
        if e.get("event_type") == "failed_login" and e.get("ip_address"):
            ip = e["ip_address"]
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

    for ip, count in failed_by_ip.items():
        if count > 5:
            severity = "high" if count > 10 else "medium"
            alerts.append({
                "alert_type": "brute_force",
                "ip_address": ip,
                "username": None,
                "failed_count": count,
                "severity": severity,
                "message": f"More than 5 failed logins from {ip} ({count} total)",
            })

    # Optional: add more alert types here (invalid_user spikes, etc.)

    return alerts


def write_reports(alerts, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)

    alerts_path = os.path.join(output_dir, "alerts.csv")
    summary_path = os.path.join(output_dir, "summary.csv")

    if alerts:
        alerts_df = pd.DataFrame(alerts)
        alerts_df.to_csv(alerts_path, index=False, encoding="utf-8")
    else:
        pd.DataFrame(
            columns=["alert_type", "ip_address", "username", "failed_count", "severity", "message"]
        ).to_csv(alerts_path, index=False, encoding="utf-8")

    summary = {
        "total_alerts": len(alerts),
        "high_severity": sum(1 for a in alerts if a.get("severity") == "high"),
        "medium_severity": sum(1 for a in alerts if a.get("severity") == "medium"),
        "low_severity": sum(1 for a in alerts if a.get("severity") == "low"),
    }

    pd.DataFrame([summary]).to_csv(summary_path, index=False, encoding="utf-8")

    print(f"Alerts saved to {alerts_path}")
    print(f"Summary saved to {summary_path}")

    assert os.path.exists(alerts_path), f"alerts.csv not created at {alerts_path}"
    assert os.path.exists(summary_path), f"summary.csv not created at {summary_path}"


def generate_report(log_path=None):
    """
    Main report generation function:

    - If log_path is given:
        1. Parse log file
        2. Save events to DB
        3. Build alerts
        4. Write CSVs
    - If log_path is None:
        1. Read events from DB
        2. Build alerts
        3. Write CSVs
    """
    from parser import parse_log_file
    from storage import save_events

    events = []

    if log_path:
        # Parse log file
        events = parse_log_file(log_path)
        # Save to DB
        saved = save_events(events)
        print(f"Parsed {len(events)} events, saved {saved} to output/events.db")
    else:
        # Read from DB
        events = read_events()
        print(f"Read {len(events)} events from output/events.db")

    # Build alerts
    alerts = build_alerts(events)
    print(f"Generated {len(alerts)} alerts")

    # Write CSV reports
    write_reports(alerts)


if __name__ == "__main__":
    # Example: generate report from a log file
    # generate_report("logs/security.log")

    # Or just read from DB and generate report
    generate_report()