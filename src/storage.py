import sqlite3

def create_connection(db_path):
    return sqlite3.connect(db_path)

def create_table(conn):
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            host TEXT,
            service TEXT,
            pid TEXT,
            event_type TEXT,
            username TEXT,
            ip_address TEXT,
            result TEXT,
            raw_message TEXT
        )
    """)
    conn.commit()

def save_events(events, db_path="output/events.db"):
    conn = create_connection(db_path)
    create_table(conn)

    cursor = conn.cursor()

    insert_sql = """
        INSERT INTO events (
            timestamp, host, service, pid, event_type,
            username, ip_address, result, raw_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    count = 0
    for event in events:
        cursor.execute(insert_sql, (
            event.get("timestamp"),
            event.get("host"),
            event.get("service"),
            event.get("pid"),
            event.get("event_type"),
            event.get("username"),
            event.get("ip_address"),
            event.get("result"),
            event.get("raw_message")
        ))
        count += 1

    conn.commit()
    conn.close()
    return count


if __name__ == "__main__":
    sample_events = [
        {
            "timestamp": "Oct 15 10:30:45",
            "host": "server",
            "service": "sshd",
            "pid": "1234",
            "event_type": "failed_login",
            "username": "admin",
            "ip_address": "192.168.1.10",
            "result": "failed",
            "raw_message": "Failed password for admin from 192.168.1.10 port 22 ssh2"
        }
    ]

    saved = save_events(sample_events)
    print(f"Saved {saved} events")