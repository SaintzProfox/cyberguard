"""
CyberGuard Security Scanner Service
Performs port scanning, SSL validation, HTTP header checks, DNS lookups
"""
import asyncio
import socket
import ssl
import subprocess
import json
import logging
from datetime import datetime, timezone
from typing import Optional
import httpx
import dns.resolver

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Core security scanning engine."""

    def __init__(self, target_domain: str = None, target_ip: str = None):
        self.domain = target_domain
        self.ip = target_ip
        self.results = []

    async def run_full_scan(self) -> dict:
        """Run complete security scan suite."""
        findings = []

        # Run all checks concurrently where possible
        tasks = []
        if self.domain:
            tasks.extend([
                self._check_ssl_certificate(),
                self._check_http_headers(),
                self._check_dns_records(),
                self._whois_lookup(),
            ])

        target = self.ip or self.domain
        if target:
            tasks.append(self._port_scan(target))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Scanner error: {result}")
                continue
            if isinstance(result, list):
                findings.extend(result)

        risk_score = self._calculate_risk_score(findings)

        return {
            "findings": findings,
            "risk_score": risk_score,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

    def _calculate_risk_score(self, findings: list) -> float:
        """Calculate overall risk score 0-100."""
        if not findings:
            return 0.0

        weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 0}
        total = sum(weights.get(f["severity"], 0) for f in findings)
        max_possible = len(findings) * 10
        return round(min(100.0, (total / max(max_possible, 1)) * 100), 2)

    async def _check_ssl_certificate(self) -> list:
        """Check SSL/TLS certificate validity and configuration."""
        findings = []
        if not self.domain:
            return findings

        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=self.domain,
            )
            conn.settimeout(10)
            conn.connect((self.domain, 443))
            cert = conn.getpeercert()
            conn.close()

            # Check expiry
            import datetime as dt
            expire_date_str = cert.get("notAfter", "")
            if expire_date_str:
                expire_date = dt.datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
                days_until_expiry = (expire_date - dt.datetime.utcnow()).days

                if days_until_expiry < 0:
                    findings.append({
                        "category": "ssl",
                        "title": "SSL Certificate Expired",
                        "description": f"The SSL certificate expired {abs(days_until_expiry)} days ago.",
                        "severity": "CRITICAL",
                        "details": {"expiry_date": expire_date_str, "days": days_until_expiry},
                        "remediation": "Renew the SSL certificate immediately. Use Let's Encrypt for free certificates.",
                    })
                elif days_until_expiry < 14:
                    findings.append({
                        "category": "ssl",
                        "title": "SSL Certificate Expiring Soon",
                        "description": f"SSL certificate expires in {days_until_expiry} days.",
                        "severity": "HIGH",
                        "details": {"expiry_date": expire_date_str, "days": days_until_expiry},
                        "remediation": "Renew the SSL certificate before it expires to avoid service disruption.",
                    })
                elif days_until_expiry < 30:
                    findings.append({
                        "category": "ssl",
                        "title": "SSL Certificate Expiring",
                        "description": f"SSL certificate expires in {days_until_expiry} days.",
                        "severity": "MEDIUM",
                        "details": {"expiry_date": expire_date_str, "days": days_until_expiry},
                        "remediation": "Plan SSL certificate renewal in the next 2 weeks.",
                    })
                else:
                    findings.append({
                        "category": "ssl",
                        "title": "SSL Certificate Valid",
                        "description": f"SSL certificate is valid for {days_until_expiry} more days.",
                        "severity": "INFO",
                        "details": {"expiry_date": expire_date_str, "days": days_until_expiry},
                        "remediation": None,
                    })

            # Check TLS version
            protocol = conn.version() if hasattr(conn, 'version') else "Unknown"

        except ssl.SSLError as e:
            findings.append({
                "category": "ssl",
                "title": "SSL Configuration Error",
                "description": f"SSL connection failed: {str(e)}",
                "severity": "CRITICAL",
                "details": {"error": str(e)},
                "remediation": "Review and fix the SSL/TLS configuration. Ensure valid certificate is installed.",
            })
        except ConnectionRefusedError:
            findings.append({
                "category": "ssl",
                "title": "HTTPS Not Available",
                "description": "Port 443 is not accessible. HTTPS may not be enabled.",
                "severity": "HIGH",
                "details": {},
                "remediation": "Enable HTTPS on your web server and obtain an SSL certificate.",
            })
        except Exception as e:
            logger.warning(f"SSL check error for {self.domain}: {e}")

        return findings

    async def _check_http_headers(self) -> list:
        """Check security-related HTTP response headers."""
        findings = []
        if not self.domain:
            return findings

        security_headers = {
            "strict-transport-security": {
                "severity": "HIGH",
                "description": "Missing HSTS header. Browsers won't enforce HTTPS connections.",
                "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            },
            "content-security-policy": {
                "severity": "MEDIUM",
                "description": "Missing Content-Security-Policy header. XSS attacks are easier to execute.",
                "remediation": "Add a Content-Security-Policy header to prevent XSS attacks.",
            },
            "x-frame-options": {
                "severity": "MEDIUM",
                "description": "Missing X-Frame-Options header. Clickjacking attacks are possible.",
                "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
            },
            "x-content-type-options": {
                "severity": "LOW",
                "description": "Missing X-Content-Type-Options header.",
                "remediation": "Add: X-Content-Type-Options: nosniff",
            },
            "referrer-policy": {
                "severity": "LOW",
                "description": "Missing Referrer-Policy header.",
                "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
            },
            "permissions-policy": {
                "severity": "LOW",
                "description": "Missing Permissions-Policy header.",
                "remediation": "Add a Permissions-Policy header to control browser feature access.",
            },
        }

        try:
            async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
                response = await client.get(f"https://{self.domain}")
                headers = {k.lower(): v for k, v in response.headers.items()}

                # Check server header - info disclosure
                if "server" in headers:
                    server = headers["server"]
                    if any(v in server.lower() for v in ["apache/", "nginx/", "iis/"]):
                        findings.append({
                            "category": "headers",
                            "title": "Server Version Disclosure",
                            "description": f"Server header reveals version information: {server}",
                            "severity": "LOW",
                            "details": {"server": server},
                            "remediation": "Configure your server to hide version information in the Server header.",
                        })

                # Check x-powered-by
                if "x-powered-by" in headers:
                    findings.append({
                        "category": "headers",
                        "title": "Technology Stack Disclosure",
                        "description": f"X-Powered-By header reveals technology: {headers['x-powered-by']}",
                        "severity": "LOW",
                        "details": {"value": headers["x-powered-by"]},
                        "remediation": "Remove the X-Powered-By header from server configuration.",
                    })

                # Check missing security headers
                for header, info in security_headers.items():
                    if header not in headers:
                        findings.append({
                            "category": "headers",
                            "title": f"Missing Security Header: {header.replace('-', ' ').title()}",
                            "description": info["description"],
                            "severity": info["severity"],
                            "details": {"missing_header": header},
                            "remediation": info["remediation"],
                        })
                    else:
                        findings.append({
                            "category": "headers",
                            "title": f"Security Header Present: {header.replace('-', ' ').title()}",
                            "description": f"Header {header} is correctly configured.",
                            "severity": "INFO",
                            "details": {"header": header, "value": headers[header][:100]},
                            "remediation": None,
                        })

        except Exception as e:
            logger.warning(f"HTTP header check error for {self.domain}: {e}")

        return findings

    async def _check_dns_records(self) -> list:
        """Check DNS records for security issues."""
        findings = []
        if not self.domain:
            return findings

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10

            # Check SPF record
            try:
                txt_records = resolver.resolve(self.domain, "TXT")
                spf_found = any("v=spf1" in str(r) for r in txt_records)
                dmarc_found = False

                if not spf_found:
                    findings.append({
                        "category": "dns",
                        "title": "Missing SPF Record",
                        "description": "No SPF record found. Email spoofing is possible.",
                        "severity": "MEDIUM",
                        "details": {},
                        "remediation": "Add an SPF TXT record: v=spf1 include:_spf.yourmailprovider.com ~all",
                    })
                else:
                    findings.append({
                        "category": "dns",
                        "title": "SPF Record Present",
                        "description": "SPF record is configured for email authentication.",
                        "severity": "INFO",
                        "details": {},
                        "remediation": None,
                    })
            except Exception:
                pass

            # Check DMARC
            try:
                dmarc_records = resolver.resolve(f"_dmarc.{self.domain}", "TXT")
                findings.append({
                    "category": "dns",
                    "title": "DMARC Record Present",
                    "description": "DMARC record is configured for email security.",
                    "severity": "INFO",
                    "details": {},
                    "remediation": None,
                })
            except Exception:
                findings.append({
                    "category": "dns",
                    "title": "Missing DMARC Record",
                    "description": "No DMARC record found. Email phishing using your domain is easier.",
                    "severity": "MEDIUM",
                    "details": {},
                    "remediation": "Add a DMARC TXT record at _dmarc.yourdomain.com",
                })

            # Check MX records
            try:
                mx_records = resolver.resolve(self.domain, "MX")
                findings.append({
                    "category": "dns",
                    "title": "MX Records Configured",
                    "description": f"Found {len(list(mx_records))} MX record(s).",
                    "severity": "INFO",
                    "details": {},
                    "remediation": None,
                })
            except Exception:
                pass

        except Exception as e:
            logger.warning(f"DNS check error for {self.domain}: {e}")

        return findings

    async def _whois_lookup(self) -> list:
        """Perform WHOIS lookup for domain information."""
        findings = []
        if not self.domain:
            return findings

        try:
            import whois
            w = whois.whois(self.domain)
            expiry = w.expiration_date

            if expiry:
                if isinstance(expiry, list):
                    expiry = expiry[0]

                import datetime as dt
                days_until_expiry = (expiry - dt.datetime.utcnow()).days

                if days_until_expiry < 30:
                    findings.append({
                        "category": "dns",
                        "title": "Domain Expiring Soon",
                        "description": f"Domain expires in {days_until_expiry} days.",
                        "severity": "HIGH" if days_until_expiry < 14 else "MEDIUM",
                        "details": {"expiry_date": str(expiry), "days": days_until_expiry},
                        "remediation": "Renew your domain registration immediately to prevent domain expiry.",
                    })
                else:
                    findings.append({
                        "category": "dns",
                        "title": "Domain Registration Valid",
                        "description": f"Domain is registered and valid for {days_until_expiry} more days.",
                        "severity": "INFO",
                        "details": {"expiry_date": str(expiry), "days": days_until_expiry},
                        "remediation": None,
                    })
        except Exception as e:
            logger.warning(f"WHOIS lookup error for {self.domain}: {e}")

        return findings

    async def _port_scan(self, target: str) -> list:
        """Perform basic port scan using nmap."""
        findings = []

        common_ports = "21,22,23,25,80,443,3306,3389,5432,6379,8080,8443,27017"

        dangerous_ports = {
            21: ("FTP", "HIGH", "FTP transmits data in plaintext. Use SFTP or FTPS instead."),
            23: ("Telnet", "CRITICAL", "Telnet is insecure. Use SSH instead immediately."),
            3389: ("RDP", "HIGH", "RDP exposed to internet is high risk. Restrict access with firewall rules."),
            27017: ("MongoDB", "CRITICAL", "MongoDB is publicly accessible. Restrict with firewall."),
            6379: ("Redis", "CRITICAL", "Redis is publicly accessible. This allows full data access."),
            3306: ("MySQL", "HIGH", "MySQL is publicly accessible. Restrict with firewall rules."),
            5432: ("PostgreSQL", "HIGH", "PostgreSQL is publicly accessible. Restrict with firewall rules."),
        }

        safe_ports = {
            80: ("HTTP", "INFO", "HTTP traffic should redirect to HTTPS."),
            443: ("HTTPS", "INFO", "HTTPS is correctly enabled."),
            22: ("SSH", "LOW", "SSH is open. Ensure key-based auth only and restrict IPs if possible."),
        }

        try:
            cmd = ["nmap", "-p", common_ports, "--open", "-T4", "--host-timeout", "30s", target]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
            output = stdout.decode()

            open_ports = []
            for line in output.split("\n"):
                if "/tcp" in line and "open" in line:
                    port_num = int(line.split("/")[0].strip())
                    open_ports.append(port_num)

                    if port_num in dangerous_ports:
                        service, severity, remediation = dangerous_ports[port_num]
                        findings.append({
                            "category": "port_scan",
                            "title": f"Dangerous Port Open: {port_num} ({service})",
                            "description": f"Port {port_num} ({service}) is publicly accessible.",
                            "severity": severity,
                            "details": {"port": port_num, "service": service},
                            "remediation": remediation,
                        })
                    elif port_num in safe_ports:
                        service, severity, remediation = safe_ports[port_num]
                        findings.append({
                            "category": "port_scan",
                            "title": f"Port Open: {port_num} ({service})",
                            "description": f"Port {port_num} ({service}) is accessible.",
                            "severity": severity,
                            "details": {"port": port_num, "service": service},
                            "remediation": remediation,
                        })
                    else:
                        findings.append({
                            "category": "port_scan",
                            "title": f"Unexpected Port Open: {port_num}",
                            "description": f"Port {port_num} is open and may be unnecessary.",
                            "severity": "MEDIUM",
                            "details": {"port": port_num},
                            "remediation": "Review if this port needs to be publicly accessible. Close it if not needed.",
                        })

            if not open_ports:
                findings.append({
                    "category": "port_scan",
                    "title": "No Unexpected Open Ports",
                    "description": "Only expected ports are open.",
                    "severity": "INFO",
                    "details": {"checked_ports": common_ports},
                    "remediation": None,
                })

        except asyncio.TimeoutError:
            logger.warning(f"Port scan timed out for {target}")
        except FileNotFoundError:
            logger.warning("nmap not installed, skipping port scan")
            findings.append({
                "category": "port_scan",
                "title": "Port Scan Skipped",
                "description": "nmap tool not available. Port scan was skipped.",
                "severity": "INFO",
                "details": {},
                "remediation": "Install nmap to enable port scanning.",
            })
        except Exception as e:
            logger.error(f"Port scan error for {target}: {e}")

        return findings
