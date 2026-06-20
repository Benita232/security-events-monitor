import os
import sqlite3


def init_db(db_path="output/events.db"):
    """
    Create the output directory and the SQLite database file.
    Create the events table if it does not exist.
    """
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            host TEXT NOT NULL,
            service TEXT NOT NULL,
            pid TEXT,
            event_type TEXT NOT NULL,
            username TEXT,
            ip_address TEXT,
            result TEXT,
            raw_message TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def save_events(events, db_path="output/events.db"):
    """
    Save a list of event dictionaries into the events table.

    Each event should have keys:
    - timestamp
    - host
    - service
    - pid (optional)
    - event_type
    - username (optional)
    - ip_address (optional)
    - result (optional)
    - raw_message

    Returns the number of events successfully saved.
    """
    # Ensure DB and table exist
    init_db(db_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    saved_count = 0

    for event in events:
        cursor.execute("""
            INSERT INTO events (
                timestamp,
                host,
                service,
                pid,
                event_type,
                username,
                ip_address,
                result,
                raw_message
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            event.get("timestamp"),
            event.get("host"),
            event.get("service"),
            event.get("pid"),
            event.get("event_type"),
            event.get("username"),
            event.get("ip_address"),
            event.get("result"),
            event.get("raw_message"),
        ))

        saved_count += 1

    conn.commit()
    conn.close()

    return saved_count


def read_events(db_path="output/events.db"):
    """
    Read all events from the database and return them as a list of dictionaries.
    """
    init_db(db_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM events")
    rows = cursor.fetchall()

    # Get column names
    columns = [col[0] for col in cursor.description]

    events = []
    for row in rows:
        event = dict(zip(columns, row))
        events.append(event)

    conn.close()
    return events


if __name__ == "__main__":
   
    test_event = {
        "timestamp": "Oct 15 10:30:45",
        "host": "server",
        "service": "sshd",
        "pid": "1234",
        "event_type": "failed_login",
        "username": "admin",
        "ip_address": "192.168.1.10",
        "result": "failed",
        "raw_message": "Failed password for admin from 192.168.1.10 port 22 ssh2",
    }

    saved = save_events([test_event])
    print(f"Saved {saved} event(s) to output/events.db")

    # Read and print them back
    events = read_events()
    print(f"Read {len(events)} event(s) from database:")
    for e in events:
        print(e)