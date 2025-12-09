#!/usr/bin/env python3
import re
import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta

# Regex for Combined Log Format
LOG_PATTERN = re.compile(
    r'(?P<ip>[\d\.]+) - - \[(?P<date>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<size>\d+|-) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

class LogMetrics:
    def __init__(self):
        self.ip_counter = Counter()
        self.ua_counter = Counter()
        self.uri_counter = Counter()
        self.error_counts = {"4xx": 0, "5xx": 0}
        self.admin_ajax_count = 0
        self.total_requests = 0

    def update(self, data: Dict[str, str]):
        self.total_requests += 1
        self.ip_counter[data['ip']] += 1
        self.ua_counter[data['user_agent']] += 1
        
        # Extract URI from request line (e.g. "GET /foo HTTP/1.1" -> "/foo")
        request_parts = data['request'].split()
        if len(request_parts) > 1:
            uri = request_parts[1]
        else:
            uri = data['request']
        self.uri_counter[uri] += 1

        if 'admin-ajax.php' in uri:
            self.admin_ajax_count += 1

        status = int(data['status'])
        if 400 <= status < 500:
            self.error_counts["4xx"] += 1
        elif 500 <= status < 600:
            self.error_counts["5xx"] += 1

    def merge(self, other: 'LogMetrics'):
        self.total_requests += other.total_requests
        self.ip_counter += other.ip_counter
        self.ua_counter += other.ua_counter
        self.uri_counter += other.uri_counter
        self.error_counts["4xx"] += other.error_counts["4xx"]
        self.error_counts["5xx"] += other.error_counts["5xx"]
        self.admin_ajax_count += other.admin_ajax_count

def parse_log_line(line: str) -> Dict[str, str]:
    """Parses a single log line and returns a dictionary of fields, or None if no match."""
    match = LOG_PATTERN.match(line)
    if match:
        return match.groupdict()
    return None

def parse_log_date(date_str: str) -> Optional[datetime]:
    # Example format: 09/Dec/2025:11:00:00 -0600
    try:
        return datetime.strptime(date_str, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None

def analyze_file(filepath: Path) -> Dict[str, LogMetrics]:
    """Reads a log file and returns statistics grouped by date."""
    metrics_by_date: Dict[str, LogMetrics] = {}
    min_ts = None
    max_ts = None

    try:
        with filepath.open('r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                data = parse_log_line(line)
                if data:
                    ts = parse_log_date(data['date'])
                    if ts:
                        if min_ts is None or ts < min_ts:
                            min_ts = ts
                        if max_ts is None or ts > max_ts:
                            max_ts = ts
                        
                        date_key = ts.strftime("%Y-%m-%d")
                        if date_key not in metrics_by_date:
                            metrics_by_date[date_key] = LogMetrics()
                        metrics_by_date[date_key].update(data)

    except FileNotFoundError:
        print(f"Error: File not found - {filepath}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    if min_ts and max_ts and (max_ts - min_ts) < timedelta(hours=24):
        # Merge into a single summary if duration < 24h
        summary_metrics = LogMetrics()
        for m in metrics_by_date.values():
            summary_metrics.merge(m)
        return {"Summary": summary_metrics}
    
    return metrics_by_date

def print_metrics(title: str, metrics: LogMetrics):
    print(f"=== {title} ===")
    print(f"Total Requests: {metrics.total_requests}")
    print(f"Admin-ajax Requests: {metrics.admin_ajax_count}")
    print(f"4xx Errors: {metrics.error_counts['4xx']}")
    print(f"5xx Errors: {metrics.error_counts['5xx']}")
    print()

    print("--- Top 20 Source IPs ---")
    for ip, count in metrics.ip_counter.most_common(20):
        print(f"{count:<5} {ip}")
    print()

    print("--- Top 20 User Agents ---")
    for ua, count in metrics.ua_counter.most_common(20):
        print(f"{count:<5} {ua}")
    print()

    print("--- Top 20 URIs ---")
    for uri, count in metrics.uri_counter.most_common(20):
        print(f"{count:<5} {uri}")
    print()
    print("="*30 + "\n")


def print_report(results: Dict[str, LogMetrics]):
    """Prints the analysis report to stdout."""
    # Sort by date usually
    for date_key in sorted(results.keys()):
        print_metrics(date_key, results[date_key])

def main():
    parser = argparse.ArgumentParser(description="Analyze NGINX/Apache access logs.")
    parser.add_argument("logfile", type=Path, help="Path to the access log file")
    args = parser.parse_args()

    if not args.logfile.exists():
        print(f"Error: File {args.logfile} does not exist.")
        sys.exit(1)

    results = analyze_file(args.logfile)
    print_report(results)

if __name__ == "__main__":
    main()
