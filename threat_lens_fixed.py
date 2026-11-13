import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import subprocess
import platform
import threading
import json
import ipaddress
import shutil
from datetime import datetime

try:
    import nmap
except ImportError:
    nmap = None


class VulnerabilityAssessmentTool:
    """Threat Lens - local/authorized network vulnerability assessment GUI."""

    def __init__(self, root):
        self.root = root
        self.root.title("Threat Lens - Network Vulnerability Assessment Tool")
        self.root.geometry("1400x850")
        self.root.minsize(1100, 700)
        self.root.configure(bg="#0f172a")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.local_ip = self.get_local_ip()
        self.detected_subnet = self.detect_subnet(self.local_ip)

        self.scan_results = []
        self.active_hosts = []
        self.inactive_hosts = []
        self.mac_cache = {}
        self.scanning = False

        self.local_ip_var = tk.StringVar(value=self.local_ip)
        self.subnet_var = tk.StringVar(value=self.detected_subnet)
        self.active_count_var = tk.StringVar(value="0")
        self.inactive_count_var = tk.StringVar(value="0")
        self.vulnerable_count_var = tk.StringVar(value="0")
        self.critical_count_var = tk.StringVar(value="0")
        self.status_var = tk.StringVar(value="Ready")

        self.create_styles()
        self.create_gui()
        self.check_nmap()

    def create_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Treeview",
            background="#172033",
            foreground="#e5e7eb",
            fieldbackground="#172033",
            rowheight=30,
            font=("Arial", 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#26344d",
            foreground="white",
            font=("Arial", 10, "bold"),
        )
        style.map(
            "Treeview",
            background=[("selected", "#2563eb")],
            foreground=[("selected", "white")],
        )
        style.configure("TNotebook", background="#0f172a", borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background="#1e293b",
            foreground="white",
            padding=(18, 9),
            font=("Arial", 10, "bold"),
        )

    def create_gui(self):
        header = tk.Frame(self.root, bg="#172033", height=80)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header, text="THREAT LENS", bg="#172033", fg="#60a5fa",
            font=("Arial", 25, "bold")
        ).pack(side="left", padx=25)

        tk.Label(
            header, text="Network Vulnerability Assessment Tool",
            bg="#172033", fg="#94a3b8", font=("Arial", 11)
        ).pack(side="left")

        control = tk.Frame(self.root, bg="#0f172a")
        control.pack(fill="x", padx=20, pady=15)

        tk.Label(
            control, text="Local IP", bg="#0f172a", fg="white",
            font=("Arial", 10, "bold")
        ).grid(row=0, column=0, padx=5)

        self.local_ip_entry = tk.Entry(
            control, textvariable=self.local_ip_var, width=18,
            bg="#172033", fg="white", insertbackground="white",
            relief="flat", font=("Arial", 10)
        )
        self.local_ip_entry.grid(row=0, column=1, padx=5, ipady=7)

        tk.Label(
            control, text="Subnet", bg="#0f172a", fg="white",
            font=("Arial", 10, "bold")
        ).grid(row=0, column=2, padx=5)

        self.subnet_entry = tk.Entry(
            control, textvariable=self.subnet_var, width=25,
            bg="#172033", fg="white", insertbackground="white",
            relief="flat", font=("Arial", 10)
        )
        self.subnet_entry.grid(row=0, column=3, padx=5, ipady=7)

        self.detect_button = tk.Button(
            control, text="DETECT NETWORK", command=self.detect_network_button,
            bg="#374151", fg="white", activebackground="#4b5563",
            relief="flat", font=("Arial", 9, "bold"), padx=15, pady=8
        )
        self.detect_button.grid(row=0, column=4, padx=5)

        self.scan_button = tk.Button(
            control, text="START SCAN", command=self.start_scan,
            bg="#2563eb", fg="white", activebackground="#1d4ed8",
            relief="flat", font=("Arial", 9, "bold"), padx=25, pady=8
        )
        self.scan_button.grid(row=0, column=5, padx=5)

        self.clear_button = tk.Button(
            control, text="CLEAR", command=self.clear_results,
            bg="#475569", fg="white", activebackground="#64748b",
            relief="flat", font=("Arial", 9, "bold"), padx=20, pady=8
        )
        self.clear_button.grid(row=0, column=6, padx=5)

        stats = tk.Frame(self.root, bg="#0f172a")
        stats.pack(fill="x", padx=20)

        self.create_stat_card(stats, "ACTIVE SYSTEMS", self.active_count_var, "#22c55e")
        self.create_stat_card(stats, "INACTIVE SYSTEMS", self.inactive_count_var, "#94a3b8")
        self.create_stat_card(stats, "VULNERABLE", self.vulnerable_count_var, "#f59e0b")
        self.create_stat_card(stats, "CRITICAL", self.critical_count_var, "#ef4444")

        host_frame = tk.Frame(self.root, bg="#0f172a")
        host_frame.pack(fill="both", expand=True, padx=20, pady=15)

        tk.Label(
            host_frame, text="DISCOVERED SYSTEMS", bg="#0f172a", fg="white",
            font=("Arial", 12, "bold")
        ).pack(anchor="w", pady=(0, 8))

        table_frame = tk.Frame(host_frame, bg="#172033")
        table_frame.pack(fill="both", expand=True)

        columns = ("status", "ip", "hostname", "mac", "os", "ports", "risk")
        self.host_tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", selectmode="browse"
        )

        headings = {
            "status": "STATUS", "ip": "IP ADDRESS", "hostname": "HOSTNAME",
            "mac": "MAC ADDRESS", "os": "OPERATING SYSTEM",
            "ports": "OPEN PORTS", "risk": "RISK"
        }
        widths = {
            "status": 110, "ip": 150, "hostname": 190, "mac": 170,
            "os": 250, "ports": 220, "risk": 100
        }

        for column in columns:
            self.host_tree.heading(column, text=headings[column])
            self.host_tree.column(column, width=widths[column], anchor="center")

        scrollbar = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.host_tree.yview
        )
        self.host_tree.configure(yscrollcommand=scrollbar.set)
        self.host_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.host_tree.bind("<Double-1>", self.double_click_host)
        self.host_tree.tag_configure("active", foreground="#22c55e")
        self.host_tree.tag_configure("inactive", foreground="#94a3b8")
        self.host_tree.tag_configure("critical", foreground="#ef4444")
        self.host_tree.tag_configure("high", foreground="#f97316")
        self.host_tree.tag_configure("medium", foreground="#f59e0b")

        tk.Label(
            host_frame,
            text="Double-click an ACTIVE system to view its complete vulnerability assessment.",
            bg="#0f172a", fg="#94a3b8", font=("Arial", 9)
        ).pack(anchor="w", pady=6)

        bottom = tk.Frame(self.root, bg="#172033", height=45)
        bottom.pack(fill="x")
        bottom.pack_propagate(False)

        tk.Label(
            bottom, textvariable=self.status_var, bg="#172033",
            fg="#cbd5e1", anchor="w"
        ).pack(side="left", padx=15)

        tk.Button(
            bottom, text="EXPORT JSON", command=self.export_json,
            bg="#374151", fg="white", relief="flat",
            font=("Arial", 9, "bold"), padx=15
        ).pack(side="right", padx=10, pady=7)

        tk.Button(
            bottom, text="LOCAL FIREWALL", command=self.show_firewall,
            bg="#374151", fg="white", relief="flat",
            font=("Arial", 9, "bold"), padx=15
        ).pack(side="right", padx=5, pady=7)

        tk.Button(
            bottom, text="LOCAL HOTFIX", command=self.show_hotfix,
            bg="#374151", fg="white", relief="flat",
            font=("Arial", 9, "bold"), padx=15
        ).pack(side="right", padx=5, pady=7)

    def create_stat_card(self, parent, title, variable, color):
        frame = tk.Frame(parent, bg="#172033", height=85)
        frame.pack(side="left", fill="both", expand=True, padx=5)
        frame.pack_propagate(False)

        tk.Label(
            frame, text=title, bg="#172033", fg="#94a3b8",
            font=("Arial", 9, "bold")
        ).pack(anchor="w", padx=15, pady=(10, 0))

        tk.Label(
            frame, textvariable=variable, bg="#172033", fg=color,
            font=("Arial", 23, "bold")
        ).pack(anchor="w", padx=15)

    def get_local_ip(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        except OSError:
            try:
                return socket.gethostbyname(socket.gethostname())
            except OSError:
                return "127.0.0.1"
        finally:
            sock.close()

    def detect_subnet(self, ip):
        try:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        except ValueError:
            return "192.168.1.0/24"

    def detect_network_button(self):
        self.local_ip = self.get_local_ip()
        self.detected_subnet = self.detect_subnet(self.local_ip)
        self.local_ip_var.set(self.local_ip)
        self.subnet_var.set(self.detected_subnet)
        self.status_var.set(
            f"Local IP: {self.local_ip} | Subnet: {self.detected_subnet}"
        )

    def check_nmap(self):
        if nmap is None:
            self.status_var.set("python-nmap is not installed.")
            return
        if shutil.which("nmap") is None:
            self.status_var.set(
                "python-nmap is installed, but the Nmap executable was not found."
            )
            return
        try:
            scanner = nmap.PortScanner()
            version = scanner.nmap_version()
            import os
            privilege_note = ""
            if platform.system() == "Linux" and hasattr(os, "geteuid") and os.geteuid() != 0:
                privilege_note = " | Tip: run with sudo for OS detection"
            self.status_var.set(f"Nmap detected: {version[0]}.{version[1]}{privilege_note}")
        except Exception as exc:
            self.status_var.set(f"Nmap check failed: {exc}")

    def validate_subnet(self, subnet):
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            return network.version == 4
        except ValueError:
            return False

    def start_scan(self):
        if self.scanning:
            return

        if nmap is None:
            messagebox.showerror(
                "Missing Module",
                "Install the Python module first:\n\npip install python-nmap"
            )
            return

        if shutil.which("nmap") is None:
            messagebox.showerror(
                "Nmap Not Found",
                "Install Nmap and make sure nmap.exe is available in PATH."
            )
            return

        subnet = self.subnet_var.get().strip()
        if not self.validate_subnet(subnet):
            messagebox.showerror(
                "Invalid Subnet",
                "Enter a valid IPv4 subnet.\n\nExample:\n192.168.1.0/24"
            )
            return

        network = ipaddress.ip_network(subnet, strict=False)
        if network.num_addresses > 1024:
            messagebox.showerror(
                "Network Too Large",
                "For this GUI version, use an IPv4 subnet with at most 1024 addresses."
            )
            return

        self.clear_table_only()
        self.scan_results = []
        self.active_hosts = []
        self.inactive_hosts = []
        self.mac_cache = {}
        self.active_count_var.set("0")
        self.inactive_count_var.set("0")
        self.vulnerable_count_var.set("0")
        self.critical_count_var.set("0")

        self.scanning = True
        self.scan_button.config(state="disabled")
        self.detect_button.config(state="disabled")
        self.clear_button.config(state="disabled")
        self.status_var.set(f"Starting scan: {subnet}")

        threading.Thread(
            target=self.scan_network, args=(subnet,), daemon=True
        ).start()

    def scan_network(self, subnet):
        """Discover hosts, cache LAN MAC addresses, then assess active hosts."""
        try:
            self.mac_cache = {}
            network = ipaddress.ip_network(subnet, strict=False)
            all_ips = [str(ip) for ip in network.hosts()]

            self.ui_status(f"Discovering systems in {subnet}...")

            discovery = nmap.PortScanner()
            # ARP discovery is useful for devices on the same local LAN.
            discovery.scan(hosts=subnet, arguments="-sn -PR")

            active_ips = []
            for host_ip in discovery.all_hosts():
                if discovery[host_ip].state() == "up":
                    active_ips.append(host_ip)
                    addresses = discovery[host_ip].get("addresses", {})
                    mac = addresses.get("mac")
                    if mac:
                        self.mac_cache[host_ip] = mac

            active_ips.sort(key=ipaddress.ip_address)
            active_set = set(active_ips)
            inactive_ips = [ip for ip in all_ips if ip not in active_set]

            self.active_hosts = active_ips
            self.inactive_hosts = inactive_ips
            self.ui_set_counts(len(active_ips), len(inactive_ips))

            total = len(active_ips)
            for index, ip in enumerate(active_ips, start=1):
                self.ui_status(f"Detailed scanning {ip} ({index}/{total})")
                result = self.scan_active_host(ip)
                self.scan_results.append(result)
                self.root.after(0, self.insert_host_row, result)

            for ip in inactive_ips:
                inactive_result = {
                    "ip": ip,
                    "hostname": "-",
                    "mac": "-",
                    "status": "Inactive",
                    "os": "-",
                    "ports": [],
                    "vulnerabilities": [],
                    "risk": "-",
                    "scan_time": self.now(),
                }
                self.scan_results.append(inactive_result)
                self.root.after(0, self.insert_host_row, inactive_result)

            self.root.after(0, self.scan_finished)

        except Exception as exc:
            self.root.after(0, self.scan_failed, str(exc))

    def scan_active_host(self, ip):
        """Run service, OS and vulnerability checks against one active host."""
        result = {
            "ip": ip,
            "hostname": "Unknown",
            "mac": self.mac_cache.get(ip, "Unknown"),
            "status": "Active",
            "os": "Not detected",
            "ports": [],
            "vulnerabilities": [],
            "risk": "Low",
            "scan_time": self.now(),
        }

        try:
            result["hostname"] = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass

        try:
            scanner = nmap.PortScanner()
            # On Linux, run the app with sudo so Nmap can perform -O fingerprinting.
            arguments = (
                "-sV -O --osscan-guess -Pn --open "
                "--version-light --script vuln"
            )
            scanner.scan(hosts=ip, arguments=arguments)

            if ip in scanner.all_hosts():
                host = scanner[ip]
                addresses = host.get("addresses", {})

                # Prefer the MAC learned during the initial ARP discovery.
                detected_mac = addresses.get("mac")
                if detected_mac:
                    result["mac"] = detected_mac

                os_matches = host.get("osmatch", [])
                if os_matches:
                    best_match = os_matches[0]
                    os_name = best_match.get("name", "Not detected")
                    accuracy = best_match.get("accuracy")
                    result["os"] = (
                        f"{os_name} (confidence: {accuracy}%)"
                        if accuracy else os_name
                    )

                for protocol in host.all_protocols():
                    for port in sorted(host[protocol].keys()):
                        port_data = host[protocol][port]
                        result["ports"].append({
                            "port": int(port),
                            "protocol": protocol,
                            "state": port_data.get("state", "unknown"),
                            "service": port_data.get("name", "unknown"),
                            "product": port_data.get("product", ""),
                            "version": port_data.get("version", ""),
                            "cpe": port_data.get("cpe", ""),
                            "scripts": port_data.get("script", {}),
                        })

        except Exception as exc:
            result["error"] = str(exc)

        if result["mac"] == "Unknown":
            result["mac_note"] = (
                "MAC unavailable: the target may not be on the local LAN, "
                "or it did not answer ARP discovery."
            )

        if result["os"] == "Not detected":
            import os
            if platform.system() == "Linux" and hasattr(os, "geteuid") and os.geteuid() != 0:
                result["os_note"] = (
                    "OS detection may require root privileges. Run the application with sudo."
                )
            else:
                result["os_note"] = (
                    "Nmap could not obtain a reliable OS fingerprint. The host may filter "
                    "probes or may not have enough detectable open/closed ports."
                )

        self.perform_vulnerability_assessment(result)
        result["risk"] = self.calculate_risk(result)
        return result

    def perform_vulnerability_assessment(self, result):
        """
        Assess each discovered service.

        This combines:
        1. Port/service exposure rules.
        2. Version-specific checks for a small set of well-known legacy/risky versions.
        3. Nmap NSE `vuln` script findings when Nmap returns them.

        Nmap version detection alone cannot prove that a product is vulnerable.
        For production use, confirm the detected version against the vendor advisory
        or a current CVE database before treating a finding as confirmed.
        """
        for item in result.get("ports", []):
            port = item["port"]
            service = item.get("service", "").lower()
            product = item.get("product", "")
            version = item.get("version", "")
            fingerprint = " ".join(
                x for x in (product, version, service) if x
            ).strip()

            item["fingerprint"] = fingerprint

            # Exposure/service-level findings.
            if port == 21:
                self.add_vulnerability(
                    result, "FTP service exposed", port, "Medium",
                    f"FTP detected: {fingerprint or 'unknown FTP implementation'}.",
                    "Disable FTP if it is not required. Prefer SFTP/FTPS and restrict access with firewall rules."
                )
            elif port == 23:
                self.add_vulnerability(
                    result, "Telnet service exposed", port, "Critical",
                    f"Telnet detected: {fingerprint or 'unknown implementation'}. Telnet does not provide secure transport by default.",
                    "Disable Telnet and migrate to SSH or another encrypted remote-management protocol."
                )
            elif port == 445:
                self.add_vulnerability(
                    result, "SMB service exposed", port, "High",
                    f"SMB is reachable on port 445: {fingerprint or 'unknown SMB implementation'}.",
                    "Restrict SMB to trusted hosts, disable unnecessary file sharing, disable SMBv1, and apply current security updates."
                )
            elif port == 3389:
                self.add_vulnerability(
                    result, "Remote Desktop exposed", port, "High",
                    f"RDP is reachable: {fingerprint or 'unknown RDP implementation'}.",
                    "Restrict RDP to trusted networks/VPN, require strong authentication/MFA where supported, and keep the host fully patched."
                )
            elif port == 5900:
                self.add_vulnerability(
                    result, "VNC service exposed", port, "High",
                    f"VNC is reachable: {fingerprint or 'unknown VNC implementation'}.",
                    "Restrict VNC to trusted networks and use secure tunneling/VPN. Upgrade to a supported VNC release."
                )
            elif port in (80, 8080):
                self.add_vulnerability(
                    result, "HTTP service detected", port, "Low",
                    f"Web service detected: {fingerprint or 'unknown HTTP implementation'}.",
                    "Use HTTPS/TLS for credentials or sensitive data. Review the application and web-server version against current vendor security advisories."
                )
            elif port == 139:
                self.add_vulnerability(
                    result, "NetBIOS/SMB legacy service exposed", port, "High",
                    f"Legacy Windows file-sharing service is reachable: {fingerprint or 'unknown implementation'}.",
                    "Disable NetBIOS/legacy SMB where unnecessary and restrict file-sharing traffic with firewall rules."
                )
            elif port == 25:
                self.add_vulnerability(
                    result, "SMTP service exposed", port, "Medium",
                    f"SMTP detected: {fingerprint or 'unknown SMTP implementation'}.",
                    "Restrict SMTP to its intended role, prevent unauthorized relay, and require TLS/authentication where appropriate."
                )
            elif port == 110:
                self.add_vulnerability(
                    result, "POP3 service exposed", port, "Medium",
                    f"POP3 detected: {fingerprint or 'unknown POP3 implementation'}.",
                    "Disable plain POP3 or require POP3 over TLS and restrict access to trusted networks."
                )
            elif port == 143:
                self.add_vulnerability(
                    result, "IMAP service exposed", port, "Medium",
                    f"IMAP detected: {fingerprint or 'unknown IMAP implementation'}.",
                    "Require IMAPS/TLS, enforce strong authentication, and restrict access where possible."
                )

            # Version-specific checks. These are deliberately conservative.
            self.assess_service_version(result, item)

            # Findings returned by Nmap NSE vulnerability scripts.
            self.process_nmap_vulnerability_scripts(result, item)

    def assess_service_version(self, result, item):
        """Add conservative findings for recognizable legacy/high-risk versions."""
        port = item.get("port")
        product = (item.get("product") or "").lower()
        version = (item.get("version") or "").lower()
        service = (item.get("service") or "").lower()
        text = f"{product} {version} {service}"

        if not version:
            return

        # These are upgrade/advisory signals, not proof of a CVE.
        legacy_rules = [
            (
                "Apache HTTP Server 2.2.x detected",
                ("apache httpd" in text or "apache" in text) and "2.2." in text,
                "High",
                "Apache HTTP Server 2.2.x is a legacy branch and should not be used for a modern production deployment.",
                f"Upgrade {item.get('product') or 'Apache HTTP Server'} to a currently supported release and verify all vendor security advisories for the detected version {item.get('version')}."
            ),
            (
                "OpenSSL 1.0.x detected",
                "openssl" in text and any(v in text for v in ("1.0.0", "1.0.1", "1.0.2")),
                "High",
                "An OpenSSL 1.0.x library version was detected and should be treated as legacy.",
                f"Upgrade the application/OS cryptographic libraries to a supported OpenSSL release and retest TLS configuration. Confirm the exact build against vendor advisories."
            ),
            (
                "Apache HTTP Server 2.4.49/2.4.50 requires immediate review",
                ("apache httpd" in text or "apache" in text) and ("2.4.49" in text or "2.4.50" in text),
                "Critical",
                "Apache HTTP Server 2.4.49 and 2.4.50 are historically associated with serious security issues and require immediate version review.",
                f"Upgrade Apache immediately to a vendor-supported patched release and verify the exact installed build against the vendor security advisory/CVE records."
            ),
            (
                "SMB legacy protocol requires review",
                port in (139, 445) and ("smbv1" in text or "microsoft-ds" in text and "1." in text),
                "High",
                "The detected SMB information suggests a legacy SMB configuration may be present.",
                "Disable SMBv1 if it is not required, restrict SMB to trusted hosts, and apply current Windows security updates."
            ),
        ]

        for title, matched, risk, description, remediation in legacy_rules:
            if matched:
                self.add_vulnerability(
                    result, title, port, risk,
                    f"Detected product/version: {item.get('product') or 'Unknown'} {item.get('version') or 'Unknown'}. {description}",
                    remediation
                )

    def process_nmap_vulnerability_scripts(self, result, item):
        scripts = item.get("scripts") or {}
        if not scripts:
            return

        for script_id, output in scripts.items():
            text = str(output).strip()
            if not text:
                continue

            low = text.lower()
            # Nmap vuln scripts can return informational output as well as findings.
            # We only elevate output that appears to describe a vulnerability/exposure.
            finding_words = (
                "vulnerable", "vulnerability", "cve-", "exploit",
                "state: vulnerable", "is likely vulnerable", "dos",
                "security risk", "weak", "insecure"
            )
            if not any(word in low for word in finding_words):
                continue

            if any(word in low for word in ("critical", "remote code execution", "rce")):
                risk = "Critical"
            elif any(word in low for word in ("high", "arbitrary code", "authentication bypass")):
                risk = "High"
            elif any(word in low for word in ("medium", "weak", "dos")):
                risk = "Medium"
            else:
                risk = "Low"

            title = f"Nmap vulnerability check: {script_id}"
            description = (
                f"Nmap NSE script reported a security-related result for "
                f"{item.get('product') or item.get('service') or 'unknown service'} "
                f"version {item.get('version') or 'unknown'} on port {item.get('port')}.\n\n"
                f"Nmap output:\n{text}"
            )
            remediation = (
                f"Review the exact detected version ({item.get('version') or 'unknown'}) against the "
                "vendor security advisory/CVE referenced by the Nmap result. Upgrade to the latest "
                "supported security release, disable the affected service if unnecessary, and restrict "
                "network access until remediation is verified."
            )

            self.add_vulnerability(
                result, title, item.get("port"), risk, description, remediation
            )

    @staticmethod
    def add_vulnerability(result, title, port, risk, description, remediation):
        result["vulnerabilities"].append({
            "title": title,
            "port": port,
            "risk": risk,
            "description": description,
            "remediation": remediation,
        })

    def calculate_risk(self, result):
        risks = [v.get("risk", "Low") for v in result.get("vulnerabilities", [])]
        if "Critical" in risks:
            return "Critical"
        if "High" in risks:
            return "High"
        if "Medium" in risks:
            return "Medium"
        return "Low"

    def insert_host_row(self, result):
        iid = result["ip"]
        if self.host_tree.exists(iid):
            self.host_tree.delete(iid)

        if result["status"] == "Inactive":
            self.host_tree.insert(
                "", "end", iid=iid,
                values=("● INACTIVE", result["ip"], "-", "-", "-", "-", "-"),
                tags=("inactive",)
            )
            return

        ports = result.get("ports", [])
        port_text = ", ".join(str(item["port"]) for item in ports) or "None"
        risk = result.get("risk", "Low")
        tag = {
            "Critical": "critical",
            "High": "high",
            "Medium": "medium",
        }.get(risk, "active")

        self.host_tree.insert(
            "", "end", iid=iid,
            values=(
                "● ACTIVE", result["ip"], result["hostname"], result["mac"],
                result["os"], port_text, risk
            ),
            tags=(tag,)
        )

    def double_click_host(self, _event=None):
        selected = self.host_tree.selection()
        if not selected:
            return

        ip = selected[0]
        result = next(
            (item for item in self.scan_results if item["ip"] == ip), None
        )
        if result is None:
            return

        if result["status"] == "Inactive":
            messagebox.showinfo(
                "Inactive System",
                f"IP Address: {ip}\n\n"
                "This system was not detected as active during discovery.\n\n"
                "Detailed assessment is not available."
            )
            return

        self.show_active_details(result)

    def show_active_details(self, result):
        window = tk.Toplevel(self.root)
        window.title(f"Host Assessment - {result['ip']}")
        window.geometry("950x700")
        window.configure(bg="#0f172a")

        header = tk.Frame(window, bg="#172033", height=70)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header, text=f"HOST: {result['ip']}",
            bg="#172033", fg="#60a5fa", font=("Arial", 18, "bold")
        ).pack(side="left", padx=20, pady=15)

        tk.Label(
            header, text=f"RISK: {result['risk']}",
            bg="#172033", fg=self.get_risk_color(result["risk"]),
            font=("Arial", 12, "bold")
        ).pack(side="right", padx=20)

        notebook = ttk.Notebook(window)
        notebook.pack(fill="both", expand=True, padx=15, pady=15)

        general = tk.Frame(notebook, bg="#101827")
        notebook.add(general, text=" General ")

        general_text = tk.Text(
            general, bg="#172033", fg="#e5e7eb",
            insertbackground="white", font=("Consolas", 11), relief="flat"
        )
        general_text.pack(fill="both", expand=True, padx=10, pady=10)
        general_text.insert(
            "1.0",
            f"""============================================================
HOST INFORMATION
============================================================

IP Address       : {result['ip']}
Hostname         : {result['hostname']}
MAC Address      : {result['mac']}
Status           : {result['status']}
Operating System : {result['os']}
Risk Level       : {result['risk']}
Scan Time        : {result['scan_time']}
"""
        )
        if result.get("error"):
            general_text.insert(tk.END, f"\nScanner note/error:\n{result['error']}\n")
        general_text.config(state="disabled")

        ports_frame = tk.Frame(notebook, bg="#101827")
        notebook.add(ports_frame, text=" Ports & Services ")

        port_columns = ("port", "protocol", "state", "service", "product", "version")
        port_tree = ttk.Treeview(
            ports_frame, columns=port_columns, show="headings"
        )
        for column in port_columns:
            port_tree.heading(column, text=column.upper())

        for column, width in {
            "port": 80, "protocol": 100, "state": 100,
            "service": 150, "product": 220, "version": 180
        }.items():
            port_tree.column(column, width=width)

        port_tree.pack(fill="both", expand=True, padx=10, pady=10)

        for item in result.get("ports", []):
            port_tree.insert(
                "", "end",
                values=(
                    item["port"], item["protocol"], item["state"],
                    item["service"], item["product"], item["version"]
                )
            )

        vuln_frame = tk.Frame(notebook, bg="#101827")
        notebook.add(vuln_frame, text=" Vulnerabilities ")

        vuln_text = tk.Text(
            vuln_frame, bg="#172033", fg="#e5e7eb",
            insertbackground="white", font=("Consolas", 10),
            relief="flat", wrap="word"
        )
        vuln_text.pack(fill="both", expand=True, padx=10, pady=10)

        vulnerabilities = result.get("vulnerabilities", [])
        if not vulnerabilities:
            vuln_text.insert("1.0", "No rule-based vulnerability findings.\n")
        else:
            for index, vuln in enumerate(vulnerabilities, start=1):
                vuln_text.insert(
                    tk.END,
                    f"""============================================================
VULNERABILITY #{index}
============================================================

Title : {vuln['title']}
Port  : {vuln['port']}
Risk  : {vuln['risk']}

Description:
{vuln['description']}

Remediation:
{vuln['remediation']}

"""
                )
        vuln_text.config(state="disabled")

        version_frame = tk.Frame(notebook, bg="#101827")
        notebook.add(version_frame, text=" Version & Actions ")

        version_text = tk.Text(
            version_frame, bg="#172033", fg="#e5e7eb",
            insertbackground="white", font=("Consolas", 10),
            relief="flat", wrap="word"
        )
        version_text.pack(fill="both", expand=True, padx=10, pady=10)

        if not result.get("ports"):
            version_text.insert(
                "1.0",
                "No open TCP services with a detected service version were returned by Nmap.\n"
                "A version cannot be assessed when Nmap cannot fingerprint the service.\n"
            )
        else:
            for item in result.get("ports", []):
                service_name = item.get("service") or "unknown"
                product_name = item.get("product") or "unknown"
                version_name = item.get("version") or "not detected"
                cpe = item.get("cpe") or "not detected"

                version_text.insert(
                    tk.END,
                    "============================================================\n"
                    f"PORT {item.get('port')}/{item.get('protocol', 'tcp')}\n"
                    "============================================================\n"
                    f"Service       : {service_name}\n"
                    f"Product       : {product_name}\n"
                    f"Version       : {version_name}\n"
                    f"CPE           : {cpe}\n"
                )

                related = [
                    v for v in vulnerabilities
                    if v.get("port") == item.get("port")
                ]
                if related:
                    version_text.insert(tk.END, "\nAssociated findings and recommended actions:\n")
                    for number, vuln in enumerate(related, start=1):
                        version_text.insert(
                            tk.END,
                            f"\n{number}. [{vuln.get('risk', 'Low')}] {vuln.get('title', 'Finding')}\n"
                            f"   Finding : {vuln.get('description', '')}\n"
                            f"   ACTION  : {vuln.get('remediation', '')}\n"
                        )
                else:
                    version_text.insert(
                        tk.END,
                        "\nAssessment: No rule-based or Nmap NSE vulnerability finding was returned for this service/version.\n"
                        "ACTION: Confirm the exact version against the vendor security advisory/CVE database and keep the service patched.\n"
                    )
                version_text.insert(tk.END, "\n")

        version_text.config(state="disabled")

        remediation_frame = tk.Frame(notebook, bg="#101827")
        notebook.add(remediation_frame, text=" Remediation ")

        remediation_text = tk.Text(
            remediation_frame, bg="#172033", fg="#e5e7eb",
            font=("Consolas", 10), relief="flat", wrap="word"
        )
        remediation_text.pack(fill="both", expand=True, padx=10, pady=10)

        if vulnerabilities:
            for index, vuln in enumerate(vulnerabilities, start=1):
                remediation_text.insert(
                    tk.END,
                    f"{index}. {vuln['title']}\n"
                    f"   Risk  : {vuln['risk']}\n"
                    f"   Action: {vuln['remediation']}\n\n"
                )
        else:
            remediation_text.insert(
                tk.END, "No remediation actions are currently required."
            )
        remediation_text.config(state="disabled")

        tk.Button(
            window, text="CLOSE", command=window.destroy,
            bg="#2563eb", fg="white", relief="flat",
            font=("Arial", 10, "bold"), padx=25, pady=8
        ).pack(pady=(0, 15))

    def get_risk_color(self, risk):
        return {
            "Critical": "#ef4444",
            "High": "#f97316",
            "Medium": "#f59e0b",
            "Low": "#22c55e",
        }.get(risk, "#94a3b8")

    def scan_finished(self):
        self.scanning = False
        self.scan_button.config(state="normal")
        self.detect_button.config(state="normal")
        self.clear_button.config(state="normal")

        vulnerable = sum(
            1 for result in self.scan_results
            if result["status"] == "Active"
            and result.get("risk") in ("Medium", "High", "Critical")
        )
        critical = sum(
            1 for result in self.scan_results
            if result["status"] == "Active"
            and result.get("risk") == "Critical"
        )

        self.vulnerable_count_var.set(str(vulnerable))
        self.critical_count_var.set(str(critical))
        self.status_var.set("Scan completed successfully.")

        messagebox.showinfo(
            "Scan Complete",
            "Network assessment completed.\n\n"
            f"Active systems: {self.active_count_var.get()}\n"
            f"Inactive systems: {self.inactive_count_var.get()}\n"
            f"Vulnerable systems: {self.vulnerable_count_var.get()}\n"
            f"Critical systems: {self.critical_count_var.get()}"
        )

    def scan_failed(self, error):
        self.scanning = False
        self.scan_button.config(state="normal")
        self.detect_button.config(state="normal")
        self.clear_button.config(state="normal")
        self.status_var.set("Scan failed.")
        messagebox.showerror("Scan Error", error)

    def clear_table_only(self):
        for item in self.host_tree.get_children():
            self.host_tree.delete(item)

    def clear_results(self):
        if self.scanning:
            messagebox.showwarning(
                "Scan Running", "Please wait for the current scan to finish."
            )
            return

        self.clear_table_only()
        self.scan_results = []
        self.active_hosts = []
        self.inactive_hosts = []
        self.active_count_var.set("0")
        self.inactive_count_var.set("0")
        self.vulnerable_count_var.set("0")
        self.critical_count_var.set("0")
        self.status_var.set("Ready")

    def show_firewall(self):
        system = platform.system()
        output = ""

        try:
            if system == "Windows":
                command = [
                    "powershell", "-NoProfile", "-Command",
                    "Get-NetFirewallProfile | "
                    "Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction | "
                    "Format-List"
                ]
                output = subprocess.check_output(
                    command, text=True, stderr=subprocess.STDOUT
                )
            elif system == "Linux":
                if shutil.which("ufw"):
                    output = subprocess.check_output(
                        ["ufw", "status", "verbose"],
                        text=True, stderr=subprocess.STDOUT
                    )
                elif shutil.which("firewall-cmd"):
                    output = subprocess.check_output(
                        ["firewall-cmd", "--state"],
                        text=True, stderr=subprocess.STDOUT
                    )
                else:
                    output = "UFW/firewalld was not found."
            else:
                output = "Firewall information is not implemented for this OS."
        except Exception as exc:
            output = f"Unable to retrieve firewall status.\n\n{exc}"

        self.show_output_window("Local Firewall Status", output)

    def show_hotfix(self):
        system = platform.system()
        output = ""

        try:
            if system == "Windows":
                command = [
                    "powershell", "-NoProfile", "-Command",
                    "Get-HotFix | Sort-Object InstalledOn -Descending | "
                    "Select -First 20 HotFixID,InstalledOn,Description | "
                    "Format-Table -AutoSize"
                ]
                output = subprocess.check_output(
                    command, text=True, stderr=subprocess.STDOUT
                )
            elif system == "Linux":
                command = [
                    "bash", "-c",
                    "uname -a; echo ''; "
                    "echo 'Recent package updates:'; "
                    "grep ' upgrade ' /var/log/dpkg.log 2>/dev/null | tail -20"
                ]
                output = subprocess.check_output(
                    command, text=True, stderr=subprocess.STDOUT
                )
            else:
                output = "Update information is not implemented for this OS."
        except Exception as exc:
            output = f"Unable to retrieve update information.\n\n{exc}"

        self.show_output_window("Local Hotfix / Update Information", output)

    def show_output_window(self, title, output):
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("850x550")
        window.configure(bg="#0f172a")

        text = tk.Text(
            window, bg="#172033", fg="#e5e7eb",
            font=("Consolas", 10), wrap="none"
        )
        text.pack(fill="both", expand=True, padx=10, pady=10)
        text.insert("1.0", output)
        text.config(state="disabled")

        tk.Button(
            window, text="CLOSE", command=window.destroy,
            bg="#2563eb", fg="white", relief="flat",
            font=("Arial", 10, "bold"), padx=20, pady=7
        ).pack(pady=(0, 10))

    def export_json(self):
        if not self.scan_results:
            messagebox.showwarning("No Results", "Run a scan first.")
            return

        filename = filedialog.asksaveasfilename(
            title="Save Assessment Report",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        if not filename:
            return

        report = {
            "application": "Threat Lens",
            "report_type": "Network Vulnerability Assessment",
            "local_ip": self.local_ip_var.get(),
            "subnet": self.subnet_var.get(),
            "scan_time": self.now(),
            "statistics": {
                "active": int(self.active_count_var.get()),
                "inactive": int(self.inactive_count_var.get()),
                "vulnerable": int(self.vulnerable_count_var.get()),
                "critical": int(self.critical_count_var.get()),
            },
            "hosts": self.scan_results,
        }

        try:
            with open(filename, "w", encoding="utf-8") as file:
                json.dump(report, file, indent=4)
            messagebox.showinfo(
                "Export Complete",
                f"Report saved successfully:\n\n{filename}"
            )
        except OSError as exc:
            messagebox.showerror("Export Error", str(exc))

    def ui_status(self, text):
        self.root.after(0, self.status_var.set, text)

    def ui_set_counts(self, active, inactive):
        self.root.after(0, self.active_count_var.set, str(active))
        self.root.after(0, self.inactive_count_var.set, str(inactive))

    @staticmethod
    def now():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def on_close(self):
        if self.scanning:
            if not messagebox.askyesno(
                "Scan Running",
                "A scan is still running. Close the application anyway?"
            ):
                return
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityAssessmentTool(root)
    root.mainloop()

