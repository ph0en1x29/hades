#!/usr/bin/env python3
"""
Generate synthetic BETH-format DNS and process log data for benchmark use.

Based on the BETH dataset schema (Highnam et al., CAMLIS 2021):
- 23 Linux honeypots, 5-hour observation window
- DNS logs: timestamp, sourceip, destinationip, dnsquery, dnsanswer, etc.
- Process logs: timestamp, processId, threadId, parentProcessId, userId, etc.

This produces labeled data with known attack patterns for evaluation.
The synthetic data is marked as engineering_scaffold, NOT benchmark_of_record.
"""

import csv
import os
import random
import sys
from datetime import datetime, timedelta, timezone

# Seed for reproducibility
random.seed(42)

# --- DNS Log Generation ---

BENIGN_DOMAINS = [
    "google.com", "amazonaws.com", "cloudflare.com", "github.com",
    "microsoft.com", "ubuntu.com", "debian.org", "python.org",
    "npmjs.org", "docker.io", "apt.ubuntu.com", "security.ubuntu.com",
    "ntp.ubuntu.com", "connectivity-check.ubuntu.com", "archive.ubuntu.com",
]

SUSPICIOUS_DOMAINS = [
    "c2-server.evil.com", "exfil.malware.net", "beacon.apt28.ru",
    "crypto-miner.xyz", "shell.backdoor.io", "data-collect.cn",
    "update-check.suspicious.org", "dns-tunnel.attacker.com",
]

MALICIOUS_DOMAINS = [
    "ransomware-c2.darknet.io", "keylogger-drop.evil.net",
    "botnet-controller.bad.com", "exploit-kit.malware.ru",
    "credential-harvest.phish.com", "lateral-move.apt.cn",
]

HONEYPOT_IPS = [f"10.100.1.{i}" for i in range(101, 124)]  # 23 honeypots
DNS_SERVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "208.67.222.222"]
SENSORS = [f"sensor-{i}" for i in range(1, 24)]


def generate_dns_logs(n_records: int = 500) -> list[dict]:
    records = []
    base_time = datetime(2021, 5, 1, 10, 0, 0, tzinfo=timezone.utc)

    for i in range(n_records):
        ts = base_time + timedelta(seconds=random.randint(0, 18000))  # 5 hours
        sensor_idx = random.randint(0, 22)
        src_ip = HONEYPOT_IPS[sensor_idx]
        dst_ip = random.choice(DNS_SERVERS)
        sensor = SENSORS[sensor_idx]

        # 70% benign, 15% suspicious, 15% malicious
        roll = random.random()
        if roll < 0.70:
            domain = random.choice(BENIGN_DOMAINS)
            sus, evil = 0, 0
        elif roll < 0.85:
            domain = random.choice(SUSPICIOUS_DOMAINS)
            sus, evil = 1, 0
        else:
            domain = random.choice(MALICIOUS_DOMAINS)
            sus, evil = 1, 1

        answer_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

        records.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "sourceip": src_ip,
            "destinationip": dst_ip,
            "dnsquery": domain,
            "dnsanswer": answer_ip,
            "dnsquerytype": random.choice(["A", "A", "A", "AAAA", "TXT", "MX"]),
            "sensorid": sensor,
            "sus": sus,
            "evil": evil,
        })

    return sorted(records, key=lambda r: r["timestamp"])


# --- Process Log Generation ---

BENIGN_PROCESSES = [
    "/usr/sbin/sshd", "/usr/sbin/cron", "/usr/bin/apt-get",
    "/usr/bin/python3", "/usr/bin/bash", "/usr/sbin/rsyslogd",
    "/usr/bin/systemctl", "/usr/bin/journalctl", "/usr/bin/top",
    "/usr/lib/snapd/snapd", "/usr/sbin/ntpd",
]

SUSPICIOUS_PROCESSES = [
    "/tmp/payload.sh", "/dev/shm/miner", "/var/tmp/.hidden/scan",
    "/tmp/nc", "/usr/bin/wget", "/usr/bin/curl",
    "/usr/bin/nmap", "/tmp/reverse_shell.py",
]

MALICIOUS_PROCESSES = [
    "/tmp/cryptominer", "/dev/shm/botnet_agent", "/tmp/.x/rootkit",
    "/var/tmp/ransomware", "/tmp/keylogger", "/dev/shm/lateral.sh",
]


def generate_process_logs(n_records: int = 500) -> list[dict]:
    records = []
    base_time = datetime(2021, 5, 1, 10, 0, 0, tzinfo=timezone.utc)

    for i in range(n_records):
        ts = base_time + timedelta(seconds=random.randint(0, 18000))
        sensor_idx = random.randint(0, 22)

        roll = random.random()
        if roll < 0.70:
            proc = random.choice(BENIGN_PROCESSES)
            user_id = random.choice([0, 1000, 1001, 33, 65534])  # root, users, www-data, nobody
            sus, evil = 0, 0
        elif roll < 0.85:
            proc = random.choice(SUSPICIOUS_PROCESSES)
            user_id = random.choice([0, 1000, 65534])
            sus, evil = 1, 0
        else:
            proc = random.choice(MALICIOUS_PROCESSES)
            user_id = random.choice([0, 0, 1000])  # often root
            sus, evil = 1, 1

        records.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "processId": random.randint(1000, 65000),
            "threadId": random.randint(1000, 65000),
            "parentProcessId": random.randint(1, 5000),
            "userId": user_id,
            "mountNamespace": 4026531840,
            "processName": proc,
            "hostName": f"honeypot-{sensor_idx + 1}",
            "eventId": random.randint(1, 400),
            "eventName": random.choice([
                "execve", "open", "close", "read", "write",
                "connect", "socket", "clone", "ptrace", "mmap",
            ]),
            "returnValue": random.choice([0, 0, 0, -1, -13]),
            "stackAddresses": f"[0x{random.randint(0x7f0000000000, 0x7fffffffffff):x}]",
            "argsNum": random.randint(0, 5),
            "args": proc,
            "sus": sus,
            "evil": evil,
        })

    return sorted(records, key=lambda r: r["timestamp"])


def write_csv(records: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)
    print(f"  Written {len(records)} records to {path}")


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data", "datasets", "beth")
    os.makedirs(out_dir, exist_ok=True)

    dns_records = generate_dns_logs(500)
    process_records = generate_process_logs(500)

    write_csv(dns_records, os.path.join(out_dir, "synthetic_dns_logs.csv"))
    write_csv(process_records, os.path.join(out_dir, "synthetic_process_logs.csv"))

    # Stats
    dns_evil = sum(1 for r in dns_records if r["evil"] == 1)
    dns_sus = sum(1 for r in dns_records if r["sus"] == 1)
    proc_evil = sum(1 for r in process_records if r["evil"] == 1)
    proc_sus = sum(1 for r in process_records if r["sus"] == 1)

    print(f"\nBETH Synthetic Dataset Generated:")
    print(f"  DNS:     {len(dns_records)} records ({dns_sus} suspicious, {dns_evil} malicious)")
    print(f"  Process: {len(process_records)} records ({proc_sus} suspicious, {proc_evil} malicious)")
    print(f"\n  ⚠️  Marked as engineering_scaffold — NOT benchmark_of_record")


if __name__ == "__main__":
    main()
