#!/usr/bin/env python3
"""
Help Desk Network Diagnostics Tool
A comprehensive network diagnostics script for help desk technicians.
"""

import os
import sys
import socket
import struct
import time
import datetime
import platform
import subprocess
import threading
import ipaddress
import re
import json
from typing import Optional, List, Dict, Tuple, Any


# ──────────────────────────────────────────────
# Color
# ──────────────────────────────────────────────

class Color:
    """ANSI color codes for terminal output."""

    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

    @staticmethod
    def supports_color() -> bool:
        """Return True if the terminal supports ANSI color codes."""
        if platform.system() == "Windows":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                # Enable VIRTUAL_TERMINAL_PROCESSING
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                return True
            except Exception:
                return False
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    @classmethod
    def colorize(cls, text: str, *codes: str) -> str:
        """Wrap *text* with the given ANSI *codes* if color is supported."""
        if not cls.supports_color():
            return text
        prefix = "".join(codes)
        return f"{prefix}{text}{cls.RESET}"

    # Convenience helpers
    @classmethod
    def ok(cls, text: str) -> str:
        return cls.colorize(text, cls.GREEN, cls.BOLD)

    @classmethod
    def warn(cls, text: str) -> str:
        return cls.colorize(text, cls.YELLOW, cls.BOLD)

    @classmethod
    def err(cls, text: str) -> str:
        return cls.colorize(text, cls.RED, cls.BOLD)

    @classmethod
    def info(cls, text: str) -> str:
        return cls.colorize(text, cls.CYAN)

    @classmethod
    def header(cls, text: str) -> str:
        return cls.colorize(text, cls.BLUE, cls.BOLD)


# ──────────────────────────────────────────────
# ConnectivityChecker
# ──────────────────────────────────────────────

class ConnectivityChecker:
    """Check basic internet / gateway connectivity."""

    DEFAULT_HOSTS = [
        ("8.8.8.8",        53, "Google DNS"),
        ("1.1.1.1",        53, "Cloudflare DNS"),
        ("208.67.222.222", 53, "OpenDNS"),
        ("google.com",     80, "Google HTTP"),
    ]

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.results: List[Dict[str, Any]] = []

    def check_host(self, host: str, port: int, label: str) -> Dict[str, Any]:
        """Attempt a TCP connection to *host*:*port* and return a result dict."""
        start = time.time()
        success = False
        error = ""
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                success = True
        except OSError as exc:
            error = str(exc)
        elapsed = (time.time() - start) * 1000  # ms

        return {
            "label":      label,
            "host":       host,
            "port":       port,
            "success":    success,
            "latency_ms": round(elapsed, 2),
            "error":      error,
        }

    def run(self) -> List[Dict[str, Any]]:
        """Run all default connectivity checks and store results."""
        self.results = []
        for host, port, label in self.DEFAULT_HOSTS:
            result = self.check_host(host, port, label)
            self.results.append(result)
        return self.results

    def print_results(self) -> None:
        print(Color.header("\n=== Connectivity Check ==="))
        for r in self.results:
            status = Color.ok("PASS") if r["success"] else Color.err("FAIL")
            latency = f"{r['latency_ms']} ms" if r["success"] else r["error"]
            print(f"  [{status}] {r['label']} ({r['host']}:{r['port']}) — {latency}")

    @property
    def has_internet(self) -> bool:
        return any(r["success"] for r in self.results)


# ──────────────────────────────────────────────
# DnsDiagnostics
# ──────────────────────────────────────────────

class DnsDiagnostics:
    """Resolve a set of hostnames and report timing / failures."""

    DEFAULT_HOSTS = [
        "google.com",
        "microsoft.com",
        "github.com",
        "cloudflare.com",
    ]

    def __init__(self, hosts: Optional[List[str]] = None, timeout: float = 5.0):
        self.hosts = hosts or self.DEFAULT_HOSTS
        self.timeout = timeout
        self.results: List[Dict[str, Any]] = []

    def resolve(self, hostname: str) -> Dict[str, Any]:
        start = time.time()
        try:
            addrs = socket.getaddrinfo(hostname, None)
            ips = list({a[4][0] for a in addrs})
            elapsed = (time.time() - start) * 1000
            return {"hostname": hostname, "success": True,
                    "ips": ips, "latency_ms": round(elapsed, 2), "error": ""}
        except socket.gaierror as exc:
            elapsed = (time.time() - start) * 1000
            return {"hostname": hostname, "success": False,
                    "ips": [], "latency_ms": round(elapsed, 2), "error": str(exc)}

    def run(self) -> List[Dict[str, Any]]:
        self.results = [self.resolve(h) for h in self.hosts]
        return self.results

    def print_results(self) -> None:
        print(Color.header("\n=== DNS Diagnostics ==="))
        for r in self.results:
            if r["success"]:
                ips = ", ".join(r["ips"][:3])
                print(f"  [{Color.ok('OK')}] {r['hostname']} -> {ips} ({r['latency_ms']} ms)")
            else:
                print(f"  [{Color.err('FAIL')}] {r['hostname']} — {r['error']}")


# ──────────────────────────────────────────────
# Traceroute
# ──────────────────────────────────────────────

class Traceroute:
    """Run a traceroute (uses OS command) and parse the output."""

    def __init__(self, target: str = "8.8.8.8", max_hops: int = 30, timeout: int = 3):
        self.target = target
        self.max_hops = max_hops
        self.timeout = timeout
        self.raw_output = ""
        self.hops: List[str] = []

    def _build_command(self) -> List[str]:
        system = platform.system()
        if system == "Windows":
            return ["tracert", "-h", str(self.max_hops), "-w",
                    str(self.timeout * 1000), self.target]
        else:
            return ["traceroute", "-m", str(self.max_hops), "-w",
                    str(self.timeout), self.target]

    def run(self) -> List[str]:
        cmd = self._build_command()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.max_hops * (self.timeout + 2),
            )
            self.raw_output = proc.stdout + proc.stderr
        except FileNotFoundError:
            self.raw_output = "traceroute/tracert command not found."
        except subprocess.TimeoutExpired:
            self.raw_output = "Traceroute timed out."
        except Exception as exc:
            self.raw_output = f"Error: {exc}"

        self.hops = [line for line in self.raw_output.splitlines() if line.strip()]
        return self.hops

    def print_results(self) -> None:
        print(Color.header(f"\n=== Traceroute to {self.target} ==="))
        if self.hops:
            for line in self.hops:
                print(f"  {line}")
        else:
            print(Color.warn("  No output captured."))


# ──────────────────────────────────────────────
# PingTest
# ──────────────────────────────────────────────

class PingTest:
    """Ping a host using the OS ping command and parse statistics."""

    def __init__(self, target: str = "8.8.8.8", count: int = 4):
        self.target = target
        self.count = count
        self.raw_output = ""
        self.stats: Dict[str, Any] = {}

    def _build_command(self) -> List[str]:
        system = platform.system()
        if system == "Windows":
            return ["ping", "-n", str(self.count), self.target]
        else:
            return ["ping", "-c", str(self.count), self.target]

    def run(self) -> Dict[str, Any]:
        cmd = self._build_command()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.count * 5 + 5,
            )
            self.raw_output = proc.stdout + proc.stderr
        except FileNotFoundError:
            self.raw_output = "ping command not found."
        except subprocess.TimeoutExpired:
            self.raw_output = "Ping timed out."
        except Exception as exc:
            self.raw_output = f"Error: {exc}"

        self.stats = self._parse()
        return self.stats

    def _parse(self) -> Dict[str, Any]:
        stats: Dict[str, Any] = {
            "target":       self.target,
            "packets_sent": self.count,
            "packets_recv": 0,
            "packet_loss":  100.0,
            "min_ms":       None,
            "avg_ms":       None,
            "max_ms":       None,
            "raw":          self.raw_output,
        }

        # Windows: "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
        m = re.search(r"Sent\s*=\s*(\d+).*?Received\s*=\s*(\d+).*?Lost\s*=\s*(\d+)",
                      self.raw_output, re.IGNORECASE)
        if m:
            stats["packets_sent"] = int(m.group(1))
            stats["packets_recv"] = int(m.group(2))
            lost = int(m.group(3))
            stats["packet_loss"] = round(lost / max(stats["packets_sent"], 1) * 100, 1)

        # Linux/macOS: "3 packets transmitted, 3 received, 0% packet loss"
        m2 = re.search(r"(\d+) packets transmitted,\s*(\d+) received", self.raw_output)
        elif m2:
            stats["packets_sent"] = int(m2.group(1))
            stats["packets_recv"] = int(m2.group(2))
            lost = stats["packets_sent"] - stats["packets_recv"]
            stats["packet_loss"] = round(lost / max(stats["packets_sent"], 1) * 100, 1)

        # Windows RTT: "Minimum = 10ms, Maximum = 20ms, Average = 15ms"
        m3 = re.search(
            r"Minimum\s*=\s*([\d.]+)ms.*?Maximum\s*=\s*([\d.]+)ms.*?Average\s*=\s*([\d.]+)ms",
            self.raw_output, re.IGNORECASE)
        if m3:
            stats["min_ms"] = float(m3.group(1))
            stats["max_ms"] = float(m3.group(2))
            stats["avg_ms"] = float(m3.group(3))

        # Linux RTT: "rtt min/avg/max/mdev = 10.1/15.2/20.3/... ms"
        m4 = re.search(r"rtt min/avg/max.*?=\s*([\d.]+)/([\d.]+)/([\d.]+)", self.raw_output)
        if m4:
            stats["min_ms"] = float(m4.group(1))
            stats["avg_ms"] = float(m4.group(2))
            stats["max_ms"] = float(m4.group(3))

        return stats

    def print_results(self) -> None:
        s = self.stats
        print(Color.header(f"\n=== Ping Test ({self.target}) ==="))
        loss = s.get("packet_loss", 100)
        loss_str = f"{loss}% loss"
        if loss == 0:
            loss_colored = Color.ok(loss_str)
        elif loss < 20:
            loss_colored = Color.warn(loss_str)
        else:
            loss_colored = Color.err(loss_str)

        print(f"  Sent: {s['packets_sent']}  Received: {s['packets_recv']}  {loss_colored}")
        if s["avg_ms"] is not None:
            print(f"  RTT  min/avg/max: {s['min_ms']}/{s['avg_ms']}/{s['max_ms']} ms")


# ──────────────────────────────────────────────
# LocalNetworkInfo
# ──────────────────────────────────────────────

class LocalNetworkInfo:
    """Collect local IP addresses, default gateway, and subnet info."""

    def __init__(self):
        self.info: Dict[str, Any] = {}

    def _get_default_gateway(self) -> str:
        system = platform.system()
        try:
            if system == "Windows":
                out = subprocess.check_output(
                    ["ipconfig"], text=True, stderr=subprocess.DEVNULL
                )
                m = re.search(r"Default Gateway[.\s]+:\s*([\d.]+)", out)
                if m:
                    return m.group(1)
            else:
                out = subprocess.check_output(
                    ["ip", "route"], text=True, stderr=subprocess.DEVNULL
                )
                m = re.search(r"default via ([\d.]+)", out)
                if m:
                    return m.group(1)
        except Exception:
            pass
        return "Unknown"

    def _get_local_ips(self) -> List[str]:
        ips = []
        try:
            hostname = socket.gethostname()
            addrs = socket.getaddrinfo(hostname, None)
            for a in addrs:
                ip = a[4][0]
                if not ip.startswith("127.") and ip != "::1":
                    ips.append(ip)
        except Exception:
            pass
        # fallback
        if not ips:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ips.append(s.getsockname()[0])
                s.close()
            except Exception:
                pass
        return list(set(ips))

    def _get_public_ip(self) -> str:
        """Best-effort public IP via a simple HTTP request."""
        try:
            import urllib.request
            with urllib.request.urlopen("https://api.ipify.org", timeout=5) as resp:
                return resp.read().decode().strip()
        except Exception:
            return "Unavailable"

    def run(self) -> Dict[str, Any]:
        self.info = {
            "hostname":        socket.gethostname(),
            "local_ips":       self._get_local_ips(),
            "default_gateway": self._get_default_gateway(),
            "public_ip":       self._get_public_ip(),
            "platform":        platform.platform(),
        }
        return self.info

    def print_results(self) -> None:
        print(Color.header("\n=== Local Network Info ==="))
        i = self.info
        print(f"  Hostname:        {i.get('hostname', 'N/A')}")
        print(f"  Local IPs:       {', '.join(i.get('local_ips', []))}")
        print(f"  Default Gateway: {i.get('default_gateway', 'N/A')}")
        print(f"  Public IP:       {i.get('public_ip', 'N/A')}")
        print(f"  Platform:        {i.get('platform', 'N/A')}")


# ──────────────────────────────────────────────
# PortTester
# ──────────────────────────────────────────────

class PortTester:
    """Test TCP connectivity to a list of (host, port) pairs."""

    COMMON_PORTS: List[Tuple[str, int, str]] = [
        ("google.com",     80,  "HTTP"),
        ("google.com",    443,  "HTTPS"),
        ("smtp.gmail.com", 587, "SMTP/TLS"),
        ("8.8.8.8",        53,  "DNS"),
    ]

    def __init__(self,
                 targets: Optional[List[Tuple[str, int, str]]] = None,
                 timeout: float = 3.0):
        self.targets = targets or self.COMMON_PORTS
        self.timeout = timeout
        self.results: List[Dict[str, Any]] = []

    def test_port(self, host: str, port: int, label: str) -> Dict[str, Any]:
        start = time.time()
        success = False
        error = ""
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                success = True
        except OSError as exc:
            error = str(exc)
        elapsed = (time.time() - start) * 1000
        return {
            "label":      label,
            "host":       host,
            "port":       port,
            "success":    success,
            "latency_ms": round(elapsed, 2),
            "error":      error,
        }

    def run(self) -> List[Dict[str, Any]]:
        self.results = [self.test_port(h, p, l) for h, p, l in self.targets]
        return self.results

    def print_results(self) -> None:
        print(Color.header("\n=== Port Connectivity Tests ==="))
        for r in self.results:
            status = Color.ok("OPEN") if r["success"] else Color.err("BLOCKED")
            detail = f"{r['latency_ms']} ms" if r["success"] else r["error"]
            print(f"  [{status}] {r['label']} {r['host']}:{r['port']} — {detail}")


# ──────────────────────────────────────────────
# SpeedEstimate
# ──────────────────────────────────────────────

class SpeedEstimate:
    """Estimate download throughput by downloading a small test file."""

    TEST_URLS = [
        "http://speed.cloudflare.com/__down?bytes=1000000",
        "http://ipv4.download.thinkbroadband.com/1MB.zip",
    ]

    def __init__(self, url: Optional[str] = None, timeout: int = 15):
        self.url = url or self.TEST_URLS[0]
        self.timeout = timeout
        self.result: Dict[str, Any] = {}

    def run(self) -> Dict[str, Any]:
        import urllib.request
        start = time.time()
        bytes_received = 0
        error = ""
        try:
            req = urllib.request.Request(
                self.url,
                headers={"User-Agent": "NetworkDiagnosticsTool/1.0"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                chunk_size = 65536
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    bytes_received += len(chunk)
        except Exception as exc:
            error = str(exc)

        elapsed = max(time.time() - start, 0.001)
        mbps = (bytes_received * 8) / (elapsed * 1_000_000)

        self.result = {
            "url":            self.url,
            "bytes_received": bytes_received,
            "elapsed_s":      round(elapsed, 2),
            "mbps":           round(mbps, 2),
            "error":          error,
        }
        return self.result

    def print_results(self) -> None:
        r = self.result
        print(Color.header("\n=== Speed Estimate ==="))
        if r.get("error") and r.get("bytes_received", 0) == 0:
            print(f"  {Color.err('Error')}: {r['error']}")
            return
        mb = round(r["bytes_received"] / 1_000_000, 2)
        print(f"  Downloaded:  {mb} MB in {r['elapsed_s']} s")
        speed = r["mbps"]
        if speed >= 10:
            colored = Color.ok(f"{speed} Mbps")
        elif speed >= 1:
            colored = Color.warn(f"{speed} Mbps")
        else:
            colored = Color.err(f"{speed} Mbps")
        print(f"  Est. speed:  {colored}")


# ──────────────────────────────────────────────
# AdapterInfo
# ──────────────────────────────────────────────

class AdapterInfo:
    """Retrieve network adapter / interface information from the OS."""

    def __init__(self):
        self.adapters: List[Dict[str, Any]] = []
        self.raw_output = ""

    def _run_windows(self) -> None:
        try:
            out = subprocess.check_output(
                ["ipconfig", "/all"], text=True, stderr=subprocess.DEVNULL
            )
            self.raw_output = out
            self._parse_windows(out)
        except Exception as exc:
            self.raw_output = f"Error: {exc}"

    def _parse_windows(self, text: str) -> None:
        blocks = re.split(r"\r?\n\r?\n", text)
        for block in blocks:
            if not block.strip():
                continue
            name_m = re.match(r"^([^\r\n:]+):", block.strip())
            if not name_m:
                continue
            name = name_m.group(1).strip()
            ip4 = re.findall(r"IPv4 Address[.\s]+:\s*([\d.]+)", block)
            ip6 = re.findall(r"IPv6 Address[.\s]+:\s*([^\s]+)", block)
            mac = re.findall(r"Physical Address[.\s]+:\s*([0-9A-Fa-f-]{17})", block)
            gw  = re.findall(r"Default Gateway[.\s]+:\s*([\d.]+)", block)
            dns = re.findall(r"DNS Servers[.\s]+:\s*([\d.]+)", block)
            self.adapters.append({
                "name":    name,
                "ipv4":    ip4,
                "ipv6":    ip6,
                "mac":     mac[0] if mac else "",
                "gateway": gw[0] if gw else "",
                "dns":     dns,
            })

    def _run_unix(self) -> None:
        try:
            out = subprocess.check_output(
                ["ip", "addr"], text=True, stderr=subprocess.DEVNULL
            )
            self.raw_output = out
            self._parse_ip_addr(out)
        except Exception:
            try:
                out = subprocess.check_output(
                    ["ifconfig"], text=True, stderr=subprocess.DEVNULL
                )
                self.raw_output = out
                self.adapters.append({"name": "see raw", "raw": out})
            except Exception as exc:
                self.raw_output = f"Error: {exc}"

    def _parse_ip_addr(self, text: str) -> None:
        blocks = re.split(r"\n(?=\d+:)", text)
        for block in blocks:
            m = re.match(r"\d+:\s+(\S+):", block)
            if not m:
                continue
            name = m.group(1)
            ip4 = re.findall(r"inet\s+([\d./]+)", block)
            ip6 = re.findall(r"inet6\s+([^\s]+)", block)
            mac = re.findall(r"link/ether\s+([0-9a-fA-F:]{17})", block)
            self.adapters.append({
                "name":    name,
                "ipv4":    ip4,
                "ipv6":    ip6,
                "mac":     mac[0] if mac else "",
                "gateway": "",
                "dns":     [],
            })

    def run(self) -> List[Dict[str, Any]]:
        if platform.system() == "Windows":
            self._run_windows()
        else:
            self._run_unix()
        return self.adapters

    def print_results(self) -> None:
        print(Color.header("\n=== Network Adapter Info ==="))
        if not self.adapters:
            print(Color.warn("  No adapter info retrieved."))
            return
        for a in self.adapters:
            name = a.get("name", "Unknown")
            ip4  = ", ".join(a.get("ipv4", [])) or "—"
            mac  = a.get("mac", "—")
            print(f"  {Color.info(name)}")
            print(f"    IPv4: {ip4}   MAC: {mac}")


# ──────────────────────────────────────────────
# DiagnosisSummary
# ──────────────────────────────────────────────

class DiagnosisSummary:
    """Aggregate results and produce a human-readable diagnosis."""

    def __init__(self):
        self.issues: List[str] = []
        self.suggestions: List[str] = []
        self.ok_items: List[str] = []

    def analyse(self,
                connectivity: ConnectivityChecker,
                dns: DnsDiagnostics,
                ping: PingTest,
                ports: PortTester,
                speed: SpeedEstimate) -> None:

        # Connectivity
        if connectivity.has_internet:
            self.ok_items.append("Basic internet connectivity (TCP) is working.")
        else:
            self.issues.append("No internet connectivity detected.")
            self.suggestions.append(
                "Check physical/Wi-Fi connection. Restart modem/router. "
                "Verify IP configuration (ipconfig /all)."
            )

        # DNS
        failed_dns = [r["hostname"] for r in dns.results if not r["success"]]
        if failed_dns:
            self.issues.append(f"DNS resolution failed for: {', '.join(failed_dns)}")
            self.suggestions.append(
                "Try alternative DNS servers (8.8.8.8 or 1.1.1.1). "
                "Flush DNS cache: ipconfig /flushdns (Windows) or "
                "sudo systemd-resolve --flush-caches (Linux)."
            )
        else:
            self.ok_items.append("DNS resolution working for all tested hosts.")

        # Ping / packet loss
        loss = ping.stats.get("packet_loss", 100)
        if loss == 0:
            self.ok_items.append("No packet loss detected.")
        elif loss < 20:
            self.issues.append(f"Minor packet loss ({loss}%) — possible network congestion.")
            self.suggestions.append("Monitor during peak hours; check for interference on Wi-Fi.")
        else:
            self.issues.append(f"High packet loss ({loss}%) — unstable connection.")
            self.suggestions.append(
                "Check cable integrity / Wi-Fi signal strength. "
                "Contact ISP if problem persists."
            )

        # Ports
        blocked = [r for r in ports.results if not r["success"]]
        if blocked:
            labels = ", ".join(r["label"] for r in blocked)
            self.issues.append(f"Blocked ports: {labels}")
            self.suggestions.append(
                "Check firewall rules (Windows Firewall / iptables). "
                "Verify ISP is not blocking these ports."
            )
        else:
            self.ok_items.append("All tested ports are accessible.")

        # Speed
        mbps = speed.result.get("mbps", 0)
        if speed.result.get("error") and speed.result.get("bytes_received", 0) == 0:
            self.issues.append("Speed test failed — could not download test file.")
        elif mbps < 1:
            self.issues.append(f"Very low download speed ({mbps} Mbps).")
            self.suggestions.append(
                "Run a full speed test (speedtest.net). "
                "Check for background downloads or QoS throttling."
            )
        elif mbps < 10:
            self.issues.append(f"Below-average download speed ({mbps} Mbps).")
        else:
            self.ok_items.append(f"Download speed estimate looks reasonable ({mbps} Mbps).")

    def print_results(self) -> None:
        print(Color.header("\n=== Diagnosis Summary ==="))
        for item in self.ok_items:
            print(f"  {Color.ok('[OK]')} {item}")
        for issue in self.issues:
            print(f"  {Color.err('[ISSUE]')} {issue}")
        if self.suggestions:
            print(Color.header("\n  Suggestions:"))
            for i, s in enumerate(self.suggestions, 1):
                print(f"  {i}. {s}")


# ──────────────────────────────────────────────
# ReportGenerator
# ──────────────────────────────────────────────

class ReportGenerator:
    """Save the full diagnostic results to a JSON and/or text file."""

    def __init__(self, output_dir: str = "."):
        self.output_dir = output_dir
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    def _json_path(self) -> str:
        return os.path.join(self.output_dir, f"net_diag_{self.timestamp}.json")

    def _txt_path(self) -> str:
        return os.path.join(self.output_dir, f"net_diag_{self.timestamp}.txt")

    def save_json(self, data: Dict[str, Any]) -> str:
        path = self._json_path()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def save_text(self, text: str) -> str:
        path = self._txt_path()
        with open(path, "w", encoding="utf-8") as f:
            # Strip ANSI codes for plain-text report
            clean = re.sub(r"\033\[[0-9;]*m", "", text)
            f.write(clean)
        return path

    def build_data(self,
                   local_info: LocalNetworkInfo,
                   connectivity: ConnectivityChecker,
                   dns: DnsDiagnostics,
                   ping: PingTest,
                   ports: PortTester,
                   speed: SpeedEstimate,
                   adapters: AdapterInfo,
                   summary: DiagnosisSummary) -> Dict[str, Any]:
        return {
            "timestamp":    self.timestamp,
            "local_info":   local_info.info,
            "connectivity": connectivity.results,
            "dns":          dns.results,
            "ping":         ping.stats,
            "ports":        ports.results,
            "speed":        speed.result,
            "adapters":     adapters.adapters,
            "issues":       summary.issues,
            "suggestions":  summary.suggestions,
            "ok_items":     summary.ok_items,
        }


# ──────────────────────────────────────────────
# _TeeOutput
# ──────────────────────────────────────────────

class _TeeOutput:
    """Duplicate stdout writes to an in-memory buffer for report generation."""

    def __init__(self, original):
        self._original = original
        self._buffer: List[str] = []

    def write(self, data: str) -> int:
        self._buffer.append(data)
        return self._original.write(data)

    def flush(self) -> None:
        self._original.flush()

    def getvalue(self) -> str:
        return "".join(self._buffer)

    def __getattr__(self, name: str):
        return getattr(self._original, name)


# ──────────────────────────────────────────────
# NetworkDiagnostics  (main orchestrator)
# ──────────────────────────────────────────────

class NetworkDiagnostics:
    """Orchestrate all diagnostic modules and produce a consolidated report."""

    BANNER = r"""
  _   _      _   ____  _
 | \ | | ___| |_|  _ \(_) __ _  __ _
 |  \| |/ _ \ __| | | | |/ _` |/ _` |
 | |\  |  __/ |_| |_| | | (_| | (_| |
 |_| \_|\___|\__|____/|_|\__,_|\__, |
  Help Desk Diagnostics Tool    |___/
"""

    def __init__(self,
                 ping_target: str = "8.8.8.8",
                 traceroute_target: str = "8.8.8.8",
                 run_traceroute: bool = False,
                 run_speed: bool = True,
                 save_report: bool = True,
                 report_dir: str = "."):
        self.ping_target       = ping_target
        self.traceroute_target = traceroute_target
        self.run_traceroute    = run_traceroute
        self.run_speed         = run_speed
        self.save_report       = save_report
        self.report_dir        = report_dir

        # Sub-modules
        self.local_info   = LocalNetworkInfo()
        self.connectivity = ConnectivityChecker()
        self.dns          = DnsDiagnostics()
        self.ping         = PingTest(target=self.ping_target)
        self.traceroute   = Traceroute(target=self.traceroute_target)
        self.ports        = PortTester()
        self.speed        = SpeedEstimate()
        self.adapters     = AdapterInfo()
        self.summary      = DiagnosisSummary()
        self.reporter     = ReportGenerator(output_dir=self.report_dir)

    def run(self) -> None:
        tee = _TeeOutput(sys.stdout)
        sys.stdout = tee  # type: ignore[assignment]

        try:
            self._run_inner()
        finally:
            sys.stdout = tee._original

        captured = tee.getvalue()

        if self.save_report:
            data = self.reporter.build_data(
                self.local_info, self.connectivity, self.dns,
                self.ping, self.ports, self.speed, self.adapters, self.summary,
            )
            json_path = self.reporter.save_json(data)
            txt_path  = self.reporter.save_text(captured)
            print(Color.info(f"\nReports saved:\n  JSON: {json_path}\n  Text: {txt_path}"))

    def _run_inner(self) -> None:
        print(Color.header(self.BANNER))
        print(Color.info(f"Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
        print(Color.info(f"Host:    {socket.gethostname()}"))
        print(Color.info(f"OS:      {platform.platform()}"))

        # 1. Adapter info
        print(Color.info("\n[1/8] Gathering adapter info..."))
        self.adapters.run()
        self.adapters.print_results()

        # 2. Local network info
        print(Color.info("\n[2/8] Gathering local network info..."))
        self.local_info.run()
        self.local_info.print_results()

        # 3. Connectivity check
        print(Color.info("\n[3/8] Checking internet connectivity..."))
        self.connectivity.run()
        self.connectivity.print_results()

        # 4. DNS diagnostics
        print(Color.info("\n[4/8] Testing DNS resolution..."))
        self.dns.run()
        self.dns.print_results()

        # 5. Ping test
        print(Color.info(f"\n[5/8] Pinging {self.ping_target}..."))
        self.ping.run()
        self.ping.print_results()

        # 6. Port tests
        print(Color.info("\n[6/8] Testing common ports..."))
        self.ports.run()
        self.ports.print_results()

        # 7. Speed estimate
        if self.run_speed:
            print(Color.info("\n[7/8] Estimating download speed (may take ~15 s)..."))
            self.speed.run()
            self.speed.print_results()
        else:
            print(Color.warn("\n[7/8] Speed estimate skipped."))
            self.speed.result = {"mbps": 0, "error": "skipped", "bytes_received": 0}

        # 8. Traceroute
        if self.run_traceroute:
            print(Color.info(f"\n[8/8] Running traceroute to {self.traceroute_target}..."))
            self.traceroute.run()
            self.traceroute.print_results()
        else:
            print(Color.warn("\n[8/8] Traceroute skipped (use --traceroute to enable)."))

        # Summary
        self.summary.analyse(
            self.connectivity, self.dns, self.ping, self.ports, self.speed
        )
        self.summary.print_results()

        print(Color.info(f"\nFinished: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def _parse_args():
    import argparse
    parser = argparse.ArgumentParser(
        description="Help Desk Network Diagnostics Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--ping-target",       default="8.8.8.8",
                        help="Host to ping")
    parser.add_argument("--traceroute-target", default="8.8.8.8",
                        help="Host for traceroute")
    parser.add_argument("--traceroute",        action="store_true",
                        help="Run traceroute (disabled by default)")
    parser.add_argument("--no-speed",          action="store_true",
                        help="Skip the speed estimate test")
    parser.add_argument("--no-report",         action="store_true",
                        help="Do not save reports to disk")
    parser.add_argument("--report-dir",        default=".",
                        help="Directory to save reports")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    tool = NetworkDiagnostics(
        ping_target       = args.ping_target,
        traceroute_target = args.traceroute_target,
        run_traceroute    = args.traceroute,
        run_speed         = not args.no_speed,
        save_report       = not args.no_report,
        report_dir        = args.report_dir,
    )
    tool.run()
