# Log Triage

A simple python module to analyze NGINX/Apache access logs and report traffic statistics.

## Features
- Parses Combined Log Format access logs.
- Reports:
  - Top 20 Source IP addresses.
  - Top 20 User Agents.
  - Counts of 4xx (Client Error) and 5xx (Server Error) responses.

## Usage

Requirements: Python 3.11+

1. Clone the repository.
2. Run the analyzer against a log file:

```bash
python3 log_analyzer.py samples/access.log
```

## Testing

To run the unit tests:

```bash
python3 -m unittest discover tests
```

## License
MIT
