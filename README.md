# security-events-monitor
A Python-based Linux log analyzer that detects suspicious authentication events and generates security reports.


# Linux Security Events Monitoring Pipeline

A Python-based Linux log analyzer that detects suspicious authentication events and generates security reports.

## What this project does

This project reads Linux authentication logs, cleans and structures the data, stores it in a database, and detects suspicious activity such as:
- Failed login bursts
- Repeated access attempts
- Unusual sudo events

## Features (First Version)

- Parse Linux authentication logs
- Extract key fields (timestamp, username, IP, event type, result)
- Store events in SQLite
- Detect suspicious patterns
- Export reports to CSV

## Tech Stack

- Python 3
- `pandas` for data handling
- SQLite for storage
- `csv` for exports

## Folder Structure


security-events-monitor/
├── data/ # raw log files (not committed)
├── src/ # source code modules
├── output/ # generated reports (not committed)
├── tests/ # test files
├── .gitignore
├── README.md
├── requirements.txt
└── main.py


## Setup

1. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Add a sample Linux auth log file to `data/`.

4. Run the project:
   ```bash
   python main.py
   ```

## How to Test

1. Add a sample `auth.log` file to `data/`.
2. Run `python main.py`.
3. Check the output CSV in `output/`.

## Limitations

This is a student project using rule-based detection. It does not replace a full SIEM.

## Future Improvements

- Add real-time monitoring
- Add a dashboard UI
- Add email or Telegram alerts
- Add machine learning anomaly detection