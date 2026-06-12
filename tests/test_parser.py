from src.parser import parse_auth_log_line

def test_parse_failed_login():
    """Test parsing a failed login line."""
    line = 'Oct 15 10:30:45 server sshd[1234]: Failed password for admin from 192.168.1.10 port 22 ssh2'
    result = parse_auth_log_line(line)
    
    assert result is not None, "Should parse the line"
    assert result['event_type'] == 'failed_login'
    assert result['username'] == 'admin'
    assert result['ip_address'] == '192.168.1.10'
    assert result['result'] == 'failed'
    assert result['service'] == 'sshd'
    assert result['host'] == 'server'

def test_parse_successful_login():
    """Test parsing a successful login line."""
    line = 'Oct 15 10:31:15 server sshd[1236]: Accepted password for alice from 192.168.1.20 port 22 ssh2'
    result = parse_auth_log_line(line)
    
    assert result is not None
    assert result['event_type'] == 'successful_login'
    assert result['username'] == 'alice'
    assert result['ip_address'] == '192.168.1.20'
    assert result['result'] == 'success'

def test_parse_sudo():
    """Test parsing a sudo line."""
    line = 'Oct 15 10:32:00 server sudo[1237]: alice: sudo command executed'
    result = parse_auth_log_line(line)
    
    assert result is not None
    assert result['event_type'] == 'sudo'
    assert result['username'] == 'alice'
    assert result['service'] == 'sudo'

def test_parse_invalid_line():
    """Test that invalid lines return None."""
    line = 'This is not a valid log line'
    result = parse_auth_log_line(line)
    
    assert result is None

def test_parse_empty_line():
    """Test that empty lines return None."""
    line = ''
    result = parse_auth_log_line(line)
    
    assert result is None

def test_parse_failed_login_with_invalid_user():
    """Test parsing failed login with invalid user prefix."""
    line = 'Oct 15 10:35:00 server sshd[1240]: Failed password for invalid user testuser from 10.0.0.5 port 22 ssh2'
    result = parse_auth_log_line(line)
    
    assert result is not None
    assert result['event_type'] == 'failed_login'
    assert result['username'] == 'invalid user testuser' or result['username'] == 'testuser'

if __name__ == '__main__':
    # Run tests manually
    print("Running test_parse_failed_login...")
    test_parse_failed_login()
    print("✓ Passed")
    
    print("Running test_parse_successful_login...")
    test_parse_successful_login()
    print("✓ Passed")
    
    print("Running test_parse_sudo...")
    test_parse_sudo()
    print("✓ Passed")
    
    print("Running test_parse_invalid_line...")
    test_parse_invalid_line()
    print("✓ Passed")
    
    print("Running test_parse_empty_line...")
    test_parse_empty_line()
    print("✓ Passed")
    
    print("Running test_parse_failed_login_with_invalid_user...")
    test_parse_failed_login_with_invalid_user()
    print("✓ Passed")
    
    print("\nAll tests passed!")