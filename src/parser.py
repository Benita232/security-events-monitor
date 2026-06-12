import re

def parse_auth_log_line(line):
    """
    Parse a single Linux auth log line into a dictionary.
    """
    pattern = r'(\w+\s+\d+\s+\d:\d:\d+)\s+(\S+)\s+(\S+)\s*\[(\d+)\]:\s*(.+)'
    match = re.match(pattern, line)

    if not match:
        return None

    timestamp, host, service, pid, message = match.groups()

    event_type = None
    username = None
    ip_address = None
    result = None

    if 'Failed password' in message:
        event_type = 'failed_login'
        result = 'failed'

        username_match = re.search(r'for (?:invalid user )?(\S+) from', message)
        ip_match = re.search(r'from (\S+) port', message)

        if username_match:
            username = username_match.group(1)
        if ip_match:
            ip_address = ip_match.group(1)

    elif 'Accepted password' in message:
        event_type = 'successful_login'
        result = 'success'

        username_match = re.search(r'for (\S+) from', message)
        ip_match = re.search(r'from (\S+) port', message)

        if username_match:
            username = username_match.group(1)
        if ip_match:
            ip_address = ip_match.group(1)

    elif 'sudo:' in message:
        event_type = 'sudo'
        result = 'sudo_command'

        username_match = re.search(r'(\S+):\s+sudo:', message)
        if username_match:
            username = username_match.group(1)

    if not event_type:
        return None

    return {
        'timestamp': timestamp,
        'host': host,
        'service': service,
        'pid': pid,
        'event_type': event_type,
        'username': username,
        'ip_address': ip_address,
        'result': result,
        'raw_message': message
    }


def parse_log_file(lines):
    """
    Parse a list of log lines and return a list of dictionaries.
    """
    events = []
    for line in lines:
        if not line:
            continue
        parsed = parse_auth_log_line(line)
        if parsed:
            events.append(parsed)
    return events


if __name__ == '__main__':
    test_lines = [
        'Oct 15 10:30:45 server sshd[1234]: Failed password for admin from 192.168.1.10 port 22 ssh2',
        'Oct 15 10:31:15 server sshd[1236]: Accepted password for alice from 192.168.1.20 port 22 ssh2',
        'Oct 15 10:32:00 server sudo[1237]: alice: sudo command executed'
    ]

    events = parse_log_file(test_lines)
    print(f"Parsed {len(events)} events")
    for event in events:
        print(event)
