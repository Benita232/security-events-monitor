import re


def parse_log_line(line):
    """
    Parse a single log line into an event dictionary.

    Expected format (SSH failed/login example):
        Oct 15 10:30:45 server sshd[1234]: Failed password for admin from 192.168.1.10 port 22 ssh2

    Returns a dict with:
        timestamp, host, service, pid, event_type, username, ip_address, result, raw_message
    Returns None if the line cannot be parsed.
    """
    line = line.strip()
    if not line:
        return None

    # Pattern for: timestamp host service[pid]: message
    pattern = r'^(\S+\s+\S+\s+\S+)\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)$'
    match = re.match(pattern, line)

    if not match:
        # Try a simpler pattern without pid
        pattern_simple = r'^(\S+\s+\S+\s+\S+)\s+(\S+)\s+(\S+):\s+(.*)$'
        match_simple = re.match(pattern_simple, line)
        if not match_simple:
            return None
        timestamp, host, service, message = match_simple.groups()
        pid = None
    else:
        timestamp, host, service, pid, message = match.groups()

    # Determine event type and extract username / ip
    event_type = "unknown"
    username = None
    ip_address = None
    result = "unknown"

    # Failed password
    if "Failed password" in message or "failure" in message.lower():
        event_type = "failed_login"
        result = "failed"

        # Example: "Failed password for admin from 192.168.1.10 port 22 ssh2"
        user_match = re.search(r'for\s+(\S+)\s+from\s+(\S+)', message)
        if user_match:
            username = user_match.group(1)
            ip_address = user_match.group(2)

    # Accepted password / successful login
    elif "Accepted password" in message or "success" in message.lower():
        event_type = "successful_login"
        result = "success"

        user_match = re.search(r'for\s+(\S+)\s+from\s+(\S+)', message)
        if user_match:
            username = user_match.group(1)
            ip_address = user_match.group(2)

    # Invalid user
    elif "Invalid user" in message:
        event_type = "invalid_user"
        result = "failed"
        user_match = re.search(r'Invalid user\s+(\S+)', message)
        if user_match:
            username = user_match.group(1)

        ip_match = re.search(r'from\s+(\S+)', message)
        if ip_match:
            ip_address = ip_match.group(2)

    # Connection closed
    elif "connection closed" in message.lower():
        event_type = "connection_closed"
        result = "closed"

    event = {
        "timestamp": timestamp,
        "host": host,
        "service": service,
        "pid": pid,
        "event_type": event_type,
        "username": username,
        "ip_address": ip_address,
        "result": result,
        "raw_message": message,
    }

    return event


def parse_log_file(log_path):
    """
    Parse a log file line by line and return a list of event dictionaries.
    """
    events = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            event = parse_log_line(line)
            if event:
                events.append(event)
    return events


if __name__ == "__main__":
    # Test with a sample log file
    test_log = """
Oct 15 10:30:45 server sshd[1234]: Failed password for admin from 192.168.1.10 port 22 ssh2
Oct 15 10:31:00 server sshd[1235]: Accepted password for user1 from 192.168.1.20 port 22 ssh2
Oct 15 10:32:10 server sshd[1236]: Invalid user hacker from 10.0.0.5 port 22
""".strip()

    # Parse test string as if it's a file in memory
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8", suffix=".log") as tmp:
        tmp.write(test_log)
        tmp_path = tmp.name

    events = parse_log_file(tmp_path)
    for e in events:
        print(e)