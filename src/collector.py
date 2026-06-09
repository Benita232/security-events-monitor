def read_log_file(log_path):
    """
    Read a log file and returns a list of lines.
    """

    lines = []

    try:
        with open(log_path, 'r', encoding='utf-8', errors= 'ignore') as f:
            for line in f:
                
                lines.append(line.strip())

    except FileNotFoundError:
        print(f"Error: File {log_path} not found")

    except Exception as e:
        print(f"Error reading file: {e}")

    return lines

if __name__ == '__main__':
    test_lines = read_log_file('data/sample_auth.log')
    print(test_lines)
