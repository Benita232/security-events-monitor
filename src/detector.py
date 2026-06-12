from collections import defaultdict

def detect_suspicious_events(events, ip_threshold=5, username_threshold=3):
    alerts = []

    ip_counts = defaultdict(int)
    username_counts = defaultdict(int)

    for event in events:
        if event.get("event_type") == "failed_login":
            ip = event.get("ip_address")
            user = event.get("username")

            if ip:
                ip_counts[ip] += 1
            if user:
                username_counts[user] += 1

    for ip, count in ip_counts.items():
        if count > ip_threshold:
            alerts.append({
                "alert_type": "brute_force",
                "ip_address": ip,
                "failed_count": count,
                "severity": "high",
                "message": f"More than {ip_threshold} failed logins from {ip}"
            })

    for user, count in username_counts.items():
        if count > username_threshold:
            alerts.append({
                "alert_type": "username_targeting",
                "username": user,
                "failed_count": count,
                "severity": "medium",
                "message": f"More than {username_threshold} failed logins for {user}"
            })

    return alerts


if __name__ == "__main__":
    sample_events = [
        {"event_type": "failed_login", "ip_address": "192.168.1.10", "username": "admin"},
        {"event_type": "failed_login", "ip_address": "192.168.1.10", "username": "admin"},
        {"event_type": "failed_login", "ip_address": "192.168.1.10", "username": "admin"},
        {"event_type": "failed_login", "ip_address": "192.168.1.10", "username": "admin"},
        {"event_type": "failed_login", "ip_address": "192.168.1.10", "username": "admin"},
        {"event_type": "failed_login", "ip_address": "192.168.1.10", "username": "admin"},
    ]

    alerts = detect_suspicious_events(sample_events)
    print(f"Detected {len(alerts)} alerts")
    for alert in alerts:
        print(alert)