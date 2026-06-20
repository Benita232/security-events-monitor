import os
import pandas as pd

def write_reports(alerts, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)

    alerts_path = os.path.join(output_dir, "alerts.csv")
    summary_path = os.path.join(output_dir, "summary.csv")

    if alerts:
        alerts_df = pd.DataFrame(alerts)
        alerts_df.to_csv(alerts_path, index=False)
    else:
        pd.DataFrame(columns=["alert_type", "ip_address", "username", "failed_count", "severity", "message"]).to_csv(
            alerts_path, index=False
        )

    summary = {
        "total_alerts": len(alerts),
        "high_severity": sum(1 for a in alerts if a.get("severity") == "high"),
        "medium_severity": sum(1 for a in alerts if a.get("severity") == "medium"),
        "low_severity": sum(1 for a in alerts if a.get("severity") == "low"),
    }

    pd.DataFrame([summary]).to_csv(summary_path, index=False)

    print(f"Alerts saved to {alerts_path}")
    print(f"Summary saved to {summary_path}")


if __name__ == "__main__":
    sample_alerts = [
        {
            "alert_type": "brute_force",
            "ip_address": "192.168.1.10",
            "username": None,
            "failed_count": 6,
            "severity": "high",
            "message": "More than 5 failed logins from 192.168.1.10",
        }
    ]

    write_reports(sample_alerts)