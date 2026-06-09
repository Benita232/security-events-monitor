import re
from datetime import datetime

def parse_auth_log_line(line):
    """
    Parse a single Linux auth log line into a dictionary.
    Returns None if the line doesn't match expected format.
    """
    # Example log line:
    # Oct 15 10:30:45 server sshd[1234]: Failed password for user admin from 192.168.1.10 port 22 ssh2
    
    pattern = r'(\w+\s+\d+\s+\d:\d:\d+)\s+(\S+)\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.+)'
    match = re.match(pattern, line)
    
    if not match:
        return None
    
    timestamp_str, host, service, process, pid, message = match.groups()
    
    # Extract event type and details from message
    event_type = None
    username = None
    ip_address = None
    result = None
    
    # Failed password
    if 'Failed password' in message:
        event_type = 'failed_login'
        result = 'failed'
        username_match = re.search(r'for (\S+) from', message)
        ip_match = re.search(r'from (\S+) port', message)
        if username_match:
            username = username_match.group(1)
        if ip_match:
            ip_address = ip_match.group(1)
    
    # Accepted password
    elif 'Accepted password' in message:
        event_type = 'successful_login'
        result = 'success'
        username_match = re.search(r'for (\S+) from', message)
        ip_match = re.search(r'from (\S+) port', message)
        if username_match:
            username = username_match.group(1)
        if ip_match:
            ip_address = ip_match.group(1)
    
    # sudo usage
    elif 'sudo:' in message:
        event_type = 'sudo'
        result = 'sudo_command'
        username_match = re.search(r'(\S+):\s+sudo:', message)
        if username_match:
            username = username_match.group(1)
    
    if not event_type:
        return None
    
    return {
        'timestamp': timestamp_str,
        'host': host,
        'service': service,
        'pid': pid,
        'event_type': event_type,
        'username': username,
        'ip_address': ip_address,
        'result': result,
        'raw_message': message
    }

def parse_log_file(log_path):
    """
    Parse an entire log file and return a list of parsed events.
    """
    events = []
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parsed = parse_auth_log_line(line)
            if parsed:
                events.append(parsed)
    return events

if __name__ == '__main__':
    # Test with a sample log file
    test_events = parse_log_file('data/sample_auth.log')
    print(f"Parsed {len(test_events)} events")
    for event in test_events[:5]:
        print(event)