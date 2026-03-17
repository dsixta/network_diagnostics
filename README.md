# Network Diagnostics Tool

A Python tool for IT Help Desk technicians to diagnose network connectivity issues. Automates the "internet is down" investigation workflow — from local adapter checks to DNS, ping, traceroute, and port testing — and gives a plain-English diagnosis at the end.

## Features

- **Connectivity Check** — ICMP ping + TCP fallback against multiple reliable hosts
- **DNS Diagnostics** — compares system resolver vs. Google/Cloudflare/Quad9; detects DNS-vs-connectivity failures
- **Ping Test** — min/max/avg latency, packet loss %, and jitter statistics
- **Traceroute** — hop-by-hop path analysis, flags high-latency hops (>100ms)
- **Local Network Info** — IP, subnet, gateway, MAC address, DHCP lease info
- **Port Connectivity Test** — tests TCP reachability on specified ports (HTTP, HTTPS, RDP, SSH, etc.)
- **Speed Estimate** — rough bandwidth measurement via CDN download
- **Adapter Info** — all network interfaces with up/down status
- **Diagnosis Summary** — plain-English verdict: No Local Connectivity / No Gateway / ISP Issue / DNS Failure / All OK
- **Help Desk Report** — formatted output for ticket escalation

## Usage

```bash
# Quick core diagnostics
python network_diagnostics.py

# Full diagnostics (adds traceroute, speed test, adapter info)
python network_diagnostics.py --full

# Test a specific target
python network_diagnostics.py --target 192.168.1.1 --full

# Custom ping count and ports
python network_diagnostics.py --ping-count 20 --ports 80,443,22,3389

# Save report for ticket escalation
python network_diagnostics.py --full --output report.txt

# Plain text output (no color)
python network_diagnostics.py --no-color
```

## Diagnosis Logic

| Verdict | Meaning |
|---------|---------|
| No Local Connectivity | No valid IP — cable unplugged, Wi-Fi off, or DHCP failure |
| No Gateway Unreachable | IP assigned but no default gateway — router/switch issue |
| ISP / Upstream Issue | Local network fine but no internet — modem or ISP problem |
| DNS Failure | Internet reachable by IP but DNS completely broken (port 53 blocked?) |
| Local DNS Server Issue | System DNS fails but public DNS works — router DNS misconfigured |
| All Systems Operational | Everything passes — issue is with specific service, not your network |

## Installation

```bash
git clone https://github.com/dsixta/network_diagnostics.git
cd network_diagnostics

# Run immediately — no install needed
python network_diagnostics.py

# Optional: colored output on Windows
pip install colorama
```

## Requirements

- Python 3.8+
- Windows 10/11 (primary), Linux/Mac supported
- No required dependencies
- Optional: `colorama` for colored terminal output

## Skills Demonstrated

- Network troubleshooting methodology (OSI layer-by-layer diagnosis)
- DNS, ICMP, TCP/IP fundamentals (CompTIA Network+)
- Help Desk ticketing workflow
- Cross-platform Python with subprocess and socket
- Automated report generation
