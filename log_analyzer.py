from collections import Counter
from pathlib import Path
import sys

LOG_LEVELS = ["INFO", "WARNING", "ERROR", "CRITICAL"]

SUSPICIOUS_KEYWORDS = [
    "timeout",
    "failed",
    "denied",
    "refused",
    "crash",
    "crashed",
    "unavailable",
    "exception",
    "unauthorized",
    "disconnect",
]

DEFAULT_LOG_FILE = Path("logs/sample.log")
REPORT_FILE = Path("reports/report.txt")


def read_logs(file_path):
    if not file_path.exists():
        print(f"Log file not found: {file_path}")
        print("Usage: py log_analyzer.py logs/sample.log")
        return []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        return file.readlines()


def detect_log_level(line):
    for level in LOG_LEVELS:
        if f" {level} " in line:
            return level
    return None


def extract_message(line, level):
    if level and level in line:
        return line.split(level, 1)[1].strip()
    return line.strip()


def analyze_logs(lines):
    level_count = Counter()
    problem_messages = []
    suspicious_matches = Counter()

    for line in lines:
      clean_line = line.strip()
      lower_line = clean_line.lower()

      level = detect_log_level(clean_line)

      if level:
          level_count[level] += 1

          if level in ["ERROR", "CRITICAL"]:
              message = extract_message(clean_line, level)
              problem_messages.append(message)

      for keyword in SUSPICIOUS_KEYWORDS:
          if keyword in lower_line:
              suspicious_matches[keyword] += 1

    top_problems = Counter(problem_messages).most_common(5)
    return level_count, top_problems, suspicious_matches


def calculate_severity_score(level_count, suspicious_matches):
    score = 0

    score += level_count.get("INFO", 0) * 0
    score += level_count.get("WARNING", 0) * 2
    score += level_count.get("ERROR", 0) * 5
    score += level_count.get("CRITICAL", 0) * 10
    score += sum(suspicious_matches.values()) * 2

    if score >= 50:
        status = "HIGH RISK"
    elif score >= 20:
        status = "MEDIUM RISK"
    elif score > 0:
        status = "LOW RISK"
    else:
        status = "HEALTHY"

    return score, status


def generate_suggestions(top_problems, suspicious_matches):
    suggestions = []

    keyword_suggestions = {
        "timeout": "Check service response time, database latency, or network delay.",
        "failed": "Check failed dependency, service status, or incorrect configuration.",
        "denied": "Check permissions, access control, or authentication rules.",
        "refused": "Check if the target service/port is running and reachable.",
        "crash": "Check crash logs, memory usage, and recent code/config changes.",
        "crashed": "Check crash logs, memory usage, and recent code/config changes.",
        "unavailable": "Check service uptime, deployment health, or network connectivity.",
        "exception": "Check stack trace, input validation, and error handling.",
        "unauthorized": "Check authentication tokens, user permissions, or API keys.",
        "disconnect": "Check network stability and service connection handling.",
    }

    for keyword, count in suspicious_matches.most_common(5):
        suggestion = keyword_suggestions.get(keyword)
        if suggestion:
            suggestions.append(f"{keyword.upper()} detected {count} time(s): {suggestion}")

    if top_problems:
        most_common_problem, count = top_problems[0]
        suggestions.append(
            f"Most repeated problem: '{most_common_problem}' occurred {count} time(s). Start debugging here first."
        )

    if not suggestions:
        suggestions.append("No major suspicious patterns detected. Logs look clean based on current rules.")

    return suggestions


def generate_report(file_path, total_logs, level_count, top_problems, suspicious_matches):
    severity_score, severity_status = calculate_severity_score(
        level_count, suspicious_matches
    )
    suggestions = generate_suggestions(top_problems, suspicious_matches)

    report = []
    report.append("===== SRE Log Analyzer Report =====")
    report.append(f"Analyzed file: {file_path}")
    report.append(f"Total log lines: {total_logs}")
    report.append("")
    report.append("Severity:")
    report.append(f"Score: {severity_score}")
    report.append(f"Status: {severity_status}")
    report.append("")
    report.append("Log level summary:")

    for level in LOG_LEVELS:
        report.append(f"{level}: {level_count.get(level, 0)}")

    report.append("")
    report.append("Top 5 repeated problems:")

    if top_problems:
        for problem, count in top_problems:
            report.append(f"- {problem} — {count} time(s)")
    else:
        report.append("- No ERROR or CRITICAL problems found.")

    report.append("")
    report.append("Suspicious keyword detection:")

    if suspicious_matches:
        for keyword, count in suspicious_matches.most_common():
            report.append(f"- {keyword}: {count}")
    else:
        report.append("- No suspicious keywords found.")

    report.append("")
    report.append("Suggested checks:")

    for suggestion in suggestions:
        report.append(f"- {suggestion}")

    report.append("")
    report.append("Privacy note:")
    report.append(
        "This tool runs locally. Your log file is not uploaded anywhere, so sensitive logs stay on your machine."
    )

    return "\n".join(report)


def save_report(report):
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        file.write(report)


def main():
    if len(sys.argv) > 1:
        log_file = Path(sys.argv[1])
    else:
        log_file = DEFAULT_LOG_FILE

    lines = read_logs(log_file)

    if not lines:
        return

    level_count, top_problems, suspicious_matches = analyze_logs(lines)
    report = generate_report(
        log_file,
        len(lines),
        level_count,
        top_problems,
        suspicious_matches,
    )

    print(report)
    save_report(report)

    print(f"\nReport saved to: {REPORT_FILE}")
    print("Privacy: logs were analyzed locally and not uploaded anywhere.")


if __name__ == "__main__":
    main()