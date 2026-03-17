import re
import json
import argparse
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


def parse_auth_failures(log_file: str) -> pd.DataFrame:
    """
    Parse SSH authentication failure logs in formats like:

    Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; ... rhost=218.188.2.4
    Jun 15 02:04:59 combo sshd(pam_unix)[20882]: authentication failure; ... rhost=example.host user=root
    """
    pattern = re.compile(
        r'(?P<month>\w+)\s+'
        r'(?P<day>\d+)\s+'
        r'(?P<time>\d+:\d+:\d+)\s+'
        r'(?P<system>\S+)\s+'
        r'sshd\(pam_unix\)\[\d+\]:\s+'
        r'authentication failure;.*?'
        r'rhost=(?P<rhost>\S+)'
        r'(?:\s+user=(?P<user>\S+))?'
    )

    records = []

    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                row = match.groupdict()
                if row["user"] is None:
                    row["user"] = "unknown"
                records.append(row)

    df = pd.DataFrame(records)

    if not df.empty:
        df["timestamp"] = pd.to_datetime(
            "2025 " + df["month"] + " " + df["day"] + " " + df["time"],
            format="%Y %b %d %H:%M:%S",
            errors="coerce"
        )

    return df


def build_metrics(df: pd.DataFrame, threshold: int) -> dict:
    if df.empty:
        return {
            "summary": {
                "total_failures": 0,
                "unique_remote_hosts": 0,
                "unique_targeted_users": 0,
                "suspicious_hosts_count": 0,
                "time_range_start": None,
                "time_range_end": None,
            },
            "failures_by_host": pd.DataFrame(columns=["rhost", "failed_attempts"]),
            "failures_by_user": pd.DataFrame(columns=["user", "failed_attempts"]),
            "timeline": pd.DataFrame(columns=["time_bucket", "failed_attempts"]),
            "suspicious_hosts": pd.DataFrame(columns=["rhost", "failed_attempts"]),
        }

    failures_by_host = df["rhost"].value_counts().reset_index()
    failures_by_host.columns = ["rhost", "failed_attempts"]

    failures_by_user = df["user"].value_counts().reset_index()
    failures_by_user.columns = ["user", "failed_attempts"]

    timeline = (
        df.set_index("timestamp")
        .resample("1H")
        .size()
        .reset_index(name="failed_attempts")
    )
    timeline.columns = ["time_bucket", "failed_attempts"]

    suspicious_hosts = failures_by_host[
        failures_by_host["failed_attempts"] >= threshold
    ].copy()

    summary = {
        "total_failures": int(len(df)),
        "unique_remote_hosts": int(df["rhost"].nunique()),
        "unique_targeted_users": int(df["user"].nunique()),
        "suspicious_hosts_count": int(len(suspicious_hosts)),
        "time_range_start": str(df["timestamp"].min()) if df["timestamp"].notna().any() else None,
        "time_range_end": str(df["timestamp"].max()) if df["timestamp"].notna().any() else None,
    }

    return {
        "summary": summary,
        "failures_by_host": failures_by_host,
        "failures_by_user": failures_by_user,
        "timeline": timeline,
        "suspicious_hosts": suspicious_hosts,
    }


def ensure_output_dir(path: str) -> Path:
    output_dir = Path(path)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def create_failed_attempts_chart(failures_by_host: pd.DataFrame, output_dir: Path) -> Path | None:
    if failures_by_host.empty:
        return None

    chart_data = failures_by_host.head(10)

    plt.figure(figsize=(10, 6))
    plt.bar(chart_data["rhost"], chart_data["failed_attempts"])
    plt.title("Top Remote Hosts by Failed Authentication Attempts")
    plt.xlabel("Remote Host")
    plt.ylabel("Failed Attempts")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    output_file = output_dir / "failed_attempts_by_host.png"
    plt.savefig(output_file, dpi=150, bbox_inches="tight")
    plt.close()
    return output_file


def create_targeted_users_chart(failures_by_user: pd.DataFrame, output_dir: Path) -> Path | None:
    if failures_by_user.empty:
        return None

    chart_data = failures_by_user.head(10)

    plt.figure(figsize=(8, 5))
    plt.bar(chart_data["user"], chart_data["failed_attempts"])
    plt.title("Most Targeted Usernames")
    plt.xlabel("Username")
    plt.ylabel("Failed Attempts")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    output_file = output_dir / "targeted_users.png"
    plt.savefig(output_file, dpi=150, bbox_inches="tight")
    plt.close()
    return output_file


def create_attack_timeline_chart(timeline: pd.DataFrame, output_dir: Path) -> Path | None:
    if timeline.empty:
        return None

    plt.figure(figsize=(10, 5))
    plt.plot(timeline["time_bucket"], timeline["failed_attempts"])
    plt.title("SSH Authentication Failures Over Time")
    plt.xlabel("Time")
    plt.ylabel("Failed Attempts")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    output_file = output_dir / "attack_timeline.png"
    plt.savefig(output_file, dpi=150, bbox_inches="tight")
    plt.close()
    return output_file


def save_text_report(metrics: dict, output_dir: Path, threshold: int) -> Path:
    report_file = output_dir / "brute_force_report.txt"

    summary = metrics["summary"]
    failures_by_host = metrics["failures_by_host"]
    failures_by_user = metrics["failures_by_user"]
    suspicious_hosts = metrics["suspicious_hosts"]

    with open(report_file, "w", encoding="utf-8") as report:
        report.write("Brute Force Detection Dashboard Report\n")
        report.write("=" * 60 + "\n\n")

        report.write("1. Executive Summary\n")
        report.write("-" * 60 + "\n")
        report.write(f"Total authentication failures: {summary['total_failures']}\n")
        report.write(f"Unique remote hosts: {summary['unique_remote_hosts']}\n")
        report.write(f"Unique targeted users: {summary['unique_targeted_users']}\n")
        report.write(f"Suspicious hosts (threshold >= {threshold}): {summary['suspicious_hosts_count']}\n")
        report.write(f"Time range start: {summary['time_range_start']}\n")
        report.write(f"Time range end: {summary['time_range_end']}\n\n")

        report.write("2. Top Remote Hosts by Failed Attempts\n")
        report.write("-" * 60 + "\n")
        if failures_by_host.empty:
            report.write("No remote host data available.\n\n")
        else:
            report.write(failures_by_host.head(10).to_string(index=False))
            report.write("\n\n")

        report.write("3. Top Targeted Usernames\n")
        report.write("-" * 60 + "\n")
        if failures_by_user.empty:
            report.write("No username data available.\n\n")
        else:
            report.write(failures_by_user.head(10).to_string(index=False))
            report.write("\n\n")

        report.write("4. Suspicious Hosts\n")
        report.write("-" * 60 + "\n")
        if suspicious_hosts.empty:
            report.write("No suspicious hosts detected.\n\n")
        else:
            report.write(suspicious_hosts.to_string(index=False))
            report.write("\n\n")

        report.write("5. Analyst Notes\n")
        report.write("-" * 60 + "\n")
        if suspicious_hosts.empty:
            report.write(
                f"No host met the suspicious threshold of {threshold} failed attempts. "
                "This may indicate low-volume activity, distributed attempts, or a small sample size.\n"
            )
        else:
            top_host = failures_by_host.iloc[0]
            report.write(
                f"The most active remote host was {top_host['rhost']} "
                f"with {int(top_host['failed_attempts'])} failed attempts.\n"
            )
            report.write(
                "Repeated authentication failures from the same host may indicate "
                "brute-force or unauthorized access attempts.\n"
            )

    return report_file


def save_json_summary(metrics: dict, output_dir: Path) -> Path:
    output_file = output_dir / "summary.json"

    json_data = {
        "summary": metrics["summary"],
        "top_remote_hosts": metrics["failures_by_host"].head(10).to_dict(orient="records"),
        "top_targeted_users": metrics["failures_by_user"].head(10).to_dict(orient="records"),
        "suspicious_hosts": metrics["suspicious_hosts"].to_dict(orient="records"),
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=4)

    return output_file


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a brute-force detection dashboard from SSH authentication failure logs."
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Path to the SSH authentication log file"
    )
    parser.add_argument(
        "-o", "--output-dir",
        required=True,
        help="Directory where reports and charts will be saved"
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=3,
        help="Threshold for suspicious hosts (default: 3)"
    )

    args = parser.parse_args()

    output_dir = ensure_output_dir(args.output_dir)
    df = parse_auth_failures(args.input)
    metrics = build_metrics(df, args.threshold)

    failed_chart = create_failed_attempts_chart(metrics["failures_by_host"], output_dir)
    users_chart = create_targeted_users_chart(metrics["failures_by_user"], output_dir)
    timeline_chart = create_attack_timeline_chart(metrics["timeline"], output_dir)
    report_file = save_text_report(metrics, output_dir, args.threshold)
    json_file = save_json_summary(metrics, output_dir)

    print("Dashboard generation completed.")
    print(f"Parsed events: {metrics['summary']['total_failures']}")
    print(f"Suspicious hosts detected: {metrics['summary']['suspicious_hosts_count']}")
    print(f"Text report: {report_file}")
    print(f"JSON summary: {json_file}")

    if failed_chart:
        print(f"Chart saved: {failed_chart}")
    if users_chart:
        print(f"Chart saved: {users_chart}")
    if timeline_chart:
        print(f"Chart saved: {timeline_chart}")


if __name__ == "__main__":
    main()
