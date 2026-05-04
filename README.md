# SRE Log Analyzer

A Python-based local log analysis tool built for basic SRE and DevOps troubleshooting.

This tool scans server log files, counts log levels, detects repeated problems, finds suspicious keywords, calculates a severity score, and generates a clean report.

## Why This Project Exists

In real systems, logs can contain sensitive data like tokens, user IDs, IP addresses, internal paths, and service details.

Instead of uploading logs to an online tool, this project runs locally on your machine. That means private logs stay private while still getting a quick first-level analysis.

## Features

- Analyze any `.log` or `.txt` file
- Count log levels: `INFO`, `WARNING`, `ERROR`, `CRITICAL`
- Detect repeated errors
- Show top 5 repeated problems
- Detect suspicious keywords:
  - timeout
  - failed
  - denied
  - refused
  - crash
  - unavailable
  - exception
  - unauthorized
  - disconnect
- Generate a severity score
- Show risk status: `HEALTHY`, `LOW RISK`, `MEDIUM RISK`, `HIGH RISK`
- Generate `reports/report.txt`
- No internet required
- Logs stay local and are not uploaded anywhere

## Tech Stack

- Python
- File Handling
- Counter from Collections
- CLI-based workflow

## Folder Structure

```txt
sre-log-analyzer/
│
├── logs/
│   └── sample.log
│
├── reports/
│   └── .gitkeep
│
├── log_analyzer.py
├── README.md
└── .gitignore