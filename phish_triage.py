#!/usr/bin/env python3
"""
SOAR Phishing Triage Automation
Local .eml analysis engine and threat intelligence enrichment.

Analyzes raw .eml files for:
- Authentication results (SPF, DKIM, DMARC)
- Sender and header alignment (From vs. Reply-To / Return-Path)
- Suspicious attachments (hashes, risky file extensions, archives)
- Embedded URLs and IP-based links (with defanging)
- Urgency and credential harvesting indicators
- Optional Threat Intelligence Enrichment (VirusTotal, AbuseIPDB, URLScan)
"""

import os
import sys
import re
import json
import glob
import email
import hashlib
import argparse
from email import policy
from email.parser import BytesParser
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# Optional external requests and dotenv for enrichment
try:
    import requests
except ImportError:
    requests = None

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# -----------------------------------------------------------------------------
# Defanging Utilities
# -----------------------------------------------------------------------------

def defang_url(url: str) -> str:
    """Defang URL to prevent accidental clicks (e.g. hxxps://bad[.]com)."""
    if not url:
        return ""
    defanged = re.sub(r"^http://", "hxxp://", url, flags=re.IGNORECASE)
    defanged = re.sub(r"^https://", "hxxps://", defanged, flags=re.IGNORECASE)
    defanged = defanged.replace(".", "[.]")
    return defanged


def defang_ip(ip: str) -> str:
    """Defang IP address (e.g. 192[.]168[.]1[.]1)."""
    if not ip:
        return ""
    return ip.replace(".", "[.]")


# -----------------------------------------------------------------------------
# Parser & Feature Extractor
# -----------------------------------------------------------------------------

class EmailTriageAnalyzer:
    RISKY_EXTENSIONS_CRITICAL = {
        ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".cpl",
        ".msi", ".jar", ".iso", ".img", ".wsf", ".lnk"
    }

    RISKY_EXTENSIONS_SUSPICIOUS = {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".docm", ".xlsm", ".pptm"
    }

    SUSPICIOUS_TLDS = {
        ".xyz", ".top", ".click", ".buzz", ".club", ".country", ".kim", ".work",
        ".support", ".gq", ".cf", ".tk", ".ml", ".ga"
    }

    CREDENTIAL_KEYWORDS = [
        "login", "signin", "sign-in", "password", "credential", "verify",
        "update-account", "account-alert", "secure-account", "owa", "webmail",
        "office365", "auth", "expiry", "expired"
    ]

    URGENT_KEYWORDS = [
        "urgent", "immediate action", "action required", "within 24 hours",
        "account suspended", "unauthorized access", "wire transfer",
        "remit payment", "overdue invoice", "final notice", "payroll"
    ]

    def __init__(self, eml_bytes: bytes, filename: str = ""):
        self.raw_bytes = eml_bytes
        self.filename = filename
        self.msg = BytesParser(policy=policy.default).parsebytes(eml_bytes)
        self.extracted = {}
        self.triage_result = {}

    def extract_all(self) -> dict:
        """Extract headers, authentication, body, URLs, and attachments."""
        headers = self._extract_headers()
        auth = self._extract_auth_results(headers)
        body_text, body_html = self._extract_bodies()
        urls = self._extract_urls(body_text, body_html)
        attachments = self._extract_attachments()

        self.extracted = {
            "file": self.filename,
            "headers": headers,
            "authentication": auth,
            "urls": urls,
            "attachments": attachments,
            "body_snippet": body_text[:500] if body_text else body_html[:500]
        }
        return self.extracted

    def _extract_headers(self) -> dict:
        headers = {}
        for key in ["Subject", "From", "To", "Cc", "Reply-To", "Return-Path", "Date", "Message-ID"]:
            headers[key] = str(self.msg.get(key, "") or "").strip()

        # Extract From Display and Email
        from_raw = headers.get("From", "")
        from_match = re.search(r"<([^>]+)>", from_raw)
        if from_match:
            from_email = from_match.group(1).lower().strip()
            from_display = from_raw[:from_match.start()].strip(' "\'')
        else:
            from_email = from_raw.lower().strip()
            from_display = ""

        # Reply-To email
        reply_raw = headers.get("Reply-To", "")
        reply_match = re.search(r"<([^>]+)>", reply_raw)
        reply_email = (reply_match.group(1) if reply_match else reply_raw).lower().strip()

        # Return-Path email
        ret_raw = headers.get("Return-Path", "")
        ret_match = re.search(r"<([^>]+)>", ret_raw)
        ret_email = (ret_match.group(1) if ret_match else ret_raw).lower().strip()

        headers["from_display"] = from_display
        headers["from_email"] = from_email
        headers["from_domain"] = from_email.split("@")[-1] if "@" in from_email else ""
        headers["reply_to_email"] = reply_email
        headers["reply_to_domain"] = reply_email.split("@")[-1] if "@" in reply_email else ""
        headers["return_path_email"] = ret_email
        headers["return_path_domain"] = ret_email.split("@")[-1] if "@" in ret_email else ""

        # Extract originating IPs from Received headers
        received_list = self.msg.get_all("Received", [])
        received_ips = []
        for rec in received_list:
            ip_matches = re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", rec)
            received_ips.extend(ip_matches)
        headers["received_ips"] = list(dict.fromkeys(received_ips))  # deduplicate preserving order
        headers["originating_ip"] = received_ips[-1] if received_ips else ""

        # All authentication headers
        headers["auth_results_raw"] = self.msg.get("Authentication-Results", "")
        headers["received_spf_raw"] = self.msg.get("Received-SPF", "")

        return headers

    def _extract_auth_results(self, headers: dict) -> dict:
        auth_raw = f"{headers.get('auth_results_raw', '')} {headers.get('received_spf_raw', '')}".lower()

        # Default statuses
        spf_status = "none"
        dkim_status = "none"
        dmarc_status = "none"

        # SPF matching
        spf_m = re.search(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)", auth_raw)
        if not spf_m:
            spf_m = re.search(r"\breceived-spf:\s*(pass|fail|softfail|neutral|none|temperror|permerror)", auth_raw)
        if spf_m:
            spf_status = spf_m.group(1)

        # DKIM matching
        dkim_m = re.search(r"\bdkim=(pass|fail|none|temperror|permerror)", auth_raw)
        if dkim_m:
            dkim_status = dkim_m.group(1)

        # DMARC matching
        dmarc_m = re.search(r"\bdmarc=(pass|fail|none|bestguesspass)", auth_raw)
        if dmarc_m:
            dmarc_status = dmarc_m.group(1)

        return {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status
        }

    def _extract_bodies(self) -> tuple[str, str]:
        body_text = ""
        body_html = ""

        if self.msg.is_multipart():
            for part in self.msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get("Content-Disposition", "")).lower()
                if "attachment" in cdispo:
                    continue
                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    charset = part.get_content_charset() or "utf-8"
                    decoded = payload.decode(charset, errors="replace")
                    if ctype == "text/plain":
                        body_text += "\n" + decoded
                    elif ctype == "text/html":
                        body_html += "\n" + decoded
                except Exception:
                    pass
        else:
            ctype = self.msg.get_content_type()
            try:
                payload = self.msg.get_payload(decode=True)
                if payload:
                    charset = self.msg.get_content_charset() or "utf-8"
                    decoded = payload.decode(charset, errors="replace")
                    if ctype == "text/html":
                        body_html = decoded
                    else:
                        body_text = decoded
            except Exception:
                pass

        return body_text.strip(), body_html.strip()

    def _extract_urls(self, text: str, html: str) -> list[dict]:
        combined = f"{text}\n{html}"
        # Match href in HTML
        href_urls = re.findall(r'href=[\'"]?([^\'" >]+)', html, flags=re.IGNORECASE)
        # Match standalone URLs in text
        regex_urls = re.findall(r'(https?://[^\s<>"\')]+)', combined, flags=re.IGNORECASE)

        raw_urls = list(dict.fromkeys(href_urls + regex_urls))
        results = []

        ip_url_pattern = re.compile(r"^https?://(\d{1,3}(?:\.\d{1,3}){3})")

        for u in raw_urls:
            # Clean trailing punctuation
            u = u.rstrip(".,;)>'\"]")
            if not u.startswith(("http://", "https://")):
                continue

            parsed = urlparse(u)
            hostname = (parsed.hostname or "").lower()
            is_ip = bool(ip_url_pattern.match(u))

            tld = ("." + hostname.split(".")[-1]) if "." in hostname and not is_ip else ""
            has_credential_keyword = any(k in u.lower() for k in self.CREDENTIAL_KEYWORDS)

            results.append({
                "url": u,
                "defanged_url": defang_url(u),
                "hostname": hostname,
                "defanged_hostname": defang_ip(hostname) if is_ip else hostname.replace(".", "[.]"),
                "is_ip_url": is_ip,
                "tld": tld,
                "is_suspicious_tld": tld in self.SUSPICIOUS_TLDS,
                "has_credential_keyword": has_credential_keyword
            })

        return results

    def _extract_attachments(self) -> list[dict]:
        attachments = []
        for part in self.msg.walk():
            filename = part.get_filename()
            cdispo = str(part.get("Content-Disposition", "")).lower()
            if not filename and "attachment" not in cdispo:
                continue

            payload = part.get_payload(decode=True)
            if payload is None:
                continue

            clean_filename = filename or "unnamed_attachment"
            ext = os.path.splitext(clean_filename)[1].lower()
            sha256 = hashlib.sha256(payload).hexdigest()
            md5 = hashlib.md5(payload).hexdigest()

            is_critical = ext in self.RISKY_EXTENSIONS_CRITICAL
            is_suspicious = ext in self.RISKY_EXTENSIONS_SUSPICIOUS
            is_double_ext = len(clean_filename.split(".")) > 2

            attachments.append({
                "filename": clean_filename,
                "extension": ext,
                "size_bytes": len(payload),
                "content_type": part.get_content_type(),
                "sha256": sha256,
                "md5": md5,
                "is_critical_risk": is_critical,
                "is_suspicious_archive": is_suspicious,
                "is_double_extension": is_double_ext
            })
        return attachments

    # -------------------------------------------------------------------------
    # Heuristic Triage Scoring Engine
    # -------------------------------------------------------------------------

    def evaluate_verdict(self) -> dict:
        """
        Evaluate extracted indicators and assign an objective risk score,
        verdict (malicious, suspicious, likely_benign), and explanation flags.
        """
        if not self.extracted:
            self.extract_all()

        headers = self.extracted["headers"]
        auth = self.extracted["authentication"]
        urls = self.extracted["urls"]
        attachments = self.extracted["attachments"]
        body_snippet = self.extracted["body_snippet"].lower()
        subject = headers.get("Subject", "").lower()

        score = 0
        reasons = []

        # 1. Authentication Checks
        if auth["spf"] == "fail":
            score += 35
            reasons.append("spf_fail")
        elif auth["spf"] == "softfail":
            score += 20
            reasons.append("spf_softfail")

        if auth["dkim"] == "fail":
            score += 25
            reasons.append("dkim_fail")

        if auth["dmarc"] == "fail":
            score += 35
            reasons.append("dmarc_fail")

        # 2. Sender / Reply-To / Return-Path Alignment
        from_domain = headers.get("from_domain", "")
        reply_domain = headers.get("reply_to_domain", "")
        return_domain = headers.get("return_path_domain", "")

        if reply_domain and from_domain and reply_domain != from_domain:
            score += 25
            reasons.append(f"sender_reply_to_mismatch ({from_domain} vs {reply_domain})")

        if return_domain and from_domain and return_domain != from_domain:
            score += 20
            reasons.append(f"sender_return_path_mismatch ({from_domain} vs {return_domain})")

        # 3. Attachment Risk Checks
        for att in attachments:
            if att["is_critical_risk"]:
                score += 50
                reasons.append(f"executable_attachment ({att['filename']})")
            elif att["is_suspicious_archive"]:
                score += 25
                reasons.append(f"suspicious_archive_attachment ({att['filename']})")

            if att["is_double_extension"]:
                score += 30
                reasons.append(f"double_extension_attachment ({att['filename']})")

        # 4. URL & Link Analysis
        for u in urls:
            if u["is_ip_url"]:
                score += 40
                reasons.append(f"ip_based_url ({u['defanged_url']})")
            if u["is_suspicious_tld"]:
                score += 15
                reasons.append(f"suspicious_tld ({u['tld']})")
            if u["has_credential_keyword"]:
                score += 15
                reasons.append(f"credential_harvest_url_pattern ({u['defanged_url']})")

        # 5. Urgency / Phishing Keywords in Subject or Body
        for kw in self.URGENT_KEYWORDS:
            if kw in subject or kw in body_snippet:
                score += 10
                reasons.append(f"urgent_lure_keyword ({kw})")
                break

        # Deduplicate reasons
        reasons = list(dict.fromkeys(reasons))

        # 6. Final Verdict Determination
        # Baseline threshold logic
        if score >= 50 or "executable_attachment" in " ".join(reasons):
            verdict = "malicious"
        elif score >= 25 or ("suspicious_archive_attachment" in " ".join(reasons) and ("spf_softfail" in reasons or "sender_return_path_mismatch" in " ".join(reasons))):
            verdict = "suspicious"
        else:
            verdict = "likely_benign"

        self.triage_result = {
            "file": self.filename,
            "subject": headers.get("Subject", ""),
            "sender": headers.get("From", ""),
            "verdict": verdict,
            "risk_score": score,
            "reasons": reasons,
            "extracted": self.extracted,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        return self.triage_result


# -----------------------------------------------------------------------------
# Threat Intelligence Enrichment Engine (VirusTotal, AbuseIPDB, URLScan)
# -----------------------------------------------------------------------------

class ThreatIntelligenceEnricher:
    def __init__(self, vt_key: str = None, abuse_key: str = None, urlscan_key: str = None):
        self.vt_key = vt_key or os.getenv("VT_API_KEY", "").strip()
        self.abuse_key = abuse_key or os.getenv("ABUSEIPDB_API_KEY", "").strip()
        self.urlscan_key = urlscan_key or os.getenv("URLSCAN_API_KEY", "").strip()

    def enrich(self, triage_result: dict) -> dict:
        """Run enrichment against VirusTotal, AbuseIPDB, and URLScan if keys exist."""
        enrichment = {
            "virustotal": [],
            "abuseipdb": [],
            "urlscan": []
        }

        if not requests:
            enrichment["status"] = "skipped_requests_module_not_installed"
            return enrichment

        extracted = triage_result.get("extracted", {})

        # 1. VirusTotal Lookups for Attachments (Hashes)
        if self.vt_key:
            for att in extracted.get("attachments", []):
                sha256 = att["sha256"]
                vt_res = self._query_virustotal_hash(sha256)
                vt_res["target"] = att["filename"]
                vt_res["sha256"] = sha256
                enrichment["virustotal"].append(vt_res)
        else:
            enrichment["virustotal"].append({"status": "skipped_no_api_key"})

        # 2. AbuseIPDB Lookups for IPs
        if self.abuse_key:
            ips_to_check = set()
            origin_ip = extracted.get("headers", {}).get("originating_ip")
            if origin_ip:
                ips_to_check.add(origin_ip)
            for u in extracted.get("urls", []):
                if u["is_ip_url"]:
                    ips_to_check.add(u["hostname"])

            for ip in ips_to_check:
                # Skip private RFC 1918 IPs
                if self._is_private_ip(ip):
                    continue
                abuse_res = self._query_abuseipdb(ip)
                abuse_res["ip"] = ip
                enrichment["abuseipdb"].append(abuse_res)
        else:
            enrichment["abuseipdb"].append({"status": "skipped_no_api_key"})

        # 3. URLScan.io Scan for URLs (Always with visibility: private)
        if self.urlscan_key:
            for u in extracted.get("urls", [])[:3]:  # limit to top 3 URLs
                url_str = u["url"]
                if self._is_private_ip(u["hostname"]):
                    continue
                scan_res = self._submit_urlscan(url_str)
                scan_res["url"] = u["defanged_url"]
                enrichment["urlscan"].append(scan_res)
        else:
            enrichment["urlscan"].append({"status": "skipped_no_api_key"})

        return enrichment

    def _query_virustotal_hash(self, file_hash: str) -> dict:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.vt_key}
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "status": "found",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                }
            elif r.status_code == 404:
                return {"status": "not_found", "malicious": 0, "message": "Hash not previously observed on VT"}
            elif r.status_code == 429:
                return {"status": "rate_limited", "error": "VirusTotal quota exceeded (HTTP 429)"}
            else:
                return {"status": "error", "http_code": r.status_code}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _query_abuseipdb(self, ip: str) -> dict:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuse_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        try:
            r = requests.get(url, headers=headers, params=params, timeout=10)
            if r.status_code == 200:
                data = r.json().get("data", {})
                return {
                    "status": "success",
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode", "unknown"),
                    "isp": data.get("isp", "unknown")
                }
            elif r.status_code == 429:
                return {"status": "rate_limited", "error": "AbuseIPDB quota exceeded"}
            else:
                return {"status": "error", "http_code": r.status_code}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _submit_urlscan(self, target_url: str) -> dict:
        url = "https://urlscan.io/api/v1/scan/"
        headers = {"API-Key": self.urlscan_key, "Content-Type": "application/json"}
        # IMPORTANT: Always set visibility to private to protect user/corporate privacy
        payload = {"url": target_url, "visibility": "private"}
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=10)
            if r.status_code == 200:
                data = r.json()
                return {
                    "status": "submitted",
                    "scan_id": data.get("uuid"),
                    "result_url": data.get("result"),
                    "visibility": "private"
                }
            elif r.status_code == 429:
                return {"status": "rate_limited", "error": "URLScan rate limited"}
            else:
                return {"status": "error", "http_code": r.status_code}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        if not ip:
            return False
        # Basic check for RFC 1918 / loopback / link-local
        if ip.startswith(("10.", "127.", "192.168.", "169.254.")):
            return True
        if re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", ip):
            return True
        return False


# -----------------------------------------------------------------------------
# Report Exporters (JSON & Markdown)
# -----------------------------------------------------------------------------

def generate_markdown_report(result: dict, enrichment: dict = None) -> str:
    """Generate professional analyst Markdown report."""
    base_name = os.path.basename(result["file"])
    headers = result.get("extracted", {}).get("headers", {})
    auth = result.get("extracted", {}).get("authentication", {})
    urls = result.get("extracted", {}).get("urls", [])
    attachments = result.get("extracted", {}).get("attachments", [])
    verdict = result["verdict"].upper()

    verdict_badge = {
        "MALICIOUS": "🔴 **MALICIOUS**",
        "SUSPICIOUS": "🟡 **SUSPICIOUS**",
        "LIKELY_BENIGN": "🟢 **LIKELY BENIGN**"
    }.get(verdict, verdict)

    md = []
    md.append(f"# Phishing Triage Report: `{base_name}`")
    md.append(f"\n- **Generated At**: {result.get('timestamp')}")
    md.append(f"- **Verdict**: {verdict_badge}")
    md.append(f"- **Risk Score**: `{result.get('risk_score')}`")
    md.append(f"- **Subject**: `{headers.get('Subject', 'None')}`")
    md.append(f"- **Sender**: `{headers.get('From', 'None')}`")
    md.append(f"- **Reply-To**: `{headers.get('reply_to_email') or 'None'}`")
    md.append(f"- **Return-Path**: `{headers.get('return_path_email') or 'None'}`")

    md.append("\n## Key Triage Triggers")
    reasons = result.get("reasons", [])
    if reasons:
        for r in reasons:
            md.append(f"- ⚠️ {r}")
    else:
        md.append("- No high-risk triggers detected.")

    md.append("\n## Authentication Breakdown")
    md.append("| Check | Status | Evaluation |")
    md.append("|---|---|---|")
    md.append(f"| **SPF** | `{auth.get('spf', 'none')}` | {'❌ Fail' if auth.get('spf') in ['fail', 'softfail'] else '✅ Valid'} |")
    md.append(f"| **DKIM** | `{auth.get('dkim', 'none')}` | {'❌ Fail' if auth.get('dkim') == 'fail' else ('⚠️ None' if auth.get('dkim') == 'none' else '✅ Valid')} |")
    md.append(f"| **DMARC** | `{auth.get('dmarc', 'none')}` | {'❌ Fail' if auth.get('dmarc') == 'fail' else ('⚠️ None' if auth.get('dmarc') == 'none' else '✅ Valid')} |")

    md.append("\n## Attachments")
    if attachments:
        md.append("| Filename | Extension | Size (Bytes) | SHA256 (Defanged) | Risk Level |")
        md.append("|---|---|---:|---|---|")
        for att in attachments:
            risk_label = "🔴 Critical" if att["is_critical_risk"] else ("🟡 Suspicious" if att["is_suspicious_archive"] else "🟢 Low")
            md.append(f"| `{att['filename']}` | `{att['extension']}` | {att['size_bytes']} | `{att['sha256'][:16]}...` | {risk_label} |")
    else:
        md.append("*No attachments present in email.*")

    md.append("\n## Extracted URLs (Defanged)")
    if urls:
        md.append("| Defanged Target | IP URL? | Credential Keyword? | Risk TLD? |")
        md.append("|---|:---:|:---:|:---:|")
        for u in urls:
            md.append(f"| `{u['defanged_url']}` | {'⚠️ Yes' if u['is_ip_url'] else 'No'} | {'⚠️ Yes' if u['has_credential_keyword'] else 'No'} | {'⚠️ Yes' if u['is_suspicious_tld'] else 'No'} |")
    else:
        md.append("*No URLs extracted from email body.*")

    if enrichment:
        md.append("\n## Threat Intelligence Enrichment")
        # VirusTotal
        vt_entries = enrichment.get("virustotal", [])
        if vt_entries and vt_entries[0].get("status") != "skipped_no_api_key":
            md.append("### VirusTotal Results")
            for vt in vt_entries:
                if vt.get("status") == "found":
                    md.append(f"- **{vt.get('target')}**: 🔴 {vt.get('malicious')}/{vt.get('malicious') + vt.get('harmless', 0)} security vendors flagged as malicious")
                else:
                    md.append(f"- **{vt.get('target', 'Target')}**: {vt.get('status')} ({vt.get('message', 'No detections')})")

        # AbuseIPDB
        abuse_entries = enrichment.get("abuseipdb", [])
        if abuse_entries and abuse_entries[0].get("status") != "skipped_no_api_key":
            md.append("### AbuseIPDB Results")
            for ab in abuse_entries:
                if ab.get("status") == "success":
                    md.append(f"- **IP {defang_ip(ab.get('ip'))}**: Confidence Score `{ab.get('abuse_confidence_score')}%` ({ab.get('total_reports')} reports)")

    md.append("\n---")
    md.append("*Automated report generated by SOAR Phishing Triage Engine.*")
    return "\n".join(md)


# -----------------------------------------------------------------------------
# Main Execution CLI
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SOAR Phishing Triage Automation: Local .eml triage and enrichment tool."
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="Path(s) or wildcard pattern(s) to .eml sample files (e.g. samples/*.eml)"
    )
    parser.add_argument(
        "-o", "--output-dir",
        default="reports",
        help="Directory to save JSON and Markdown reports (default: reports)"
    )
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Perform online Threat Intelligence lookups (VirusTotal, AbuseIPDB, URLScan)"
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Export only JSON reports"
    )
    parser.add_argument(
        "--markdown-only",
        action="store_true",
        help="Export only Markdown reports"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    # Expand glob patterns (ensures cross-platform Windows/Linux compatibility)
    target_files = []
    for item in args.inputs:
        matched = glob.glob(item)
        if matched:
            target_files.extend(matched)
        elif os.path.isfile(item):
            target_files.append(item)

    # Remove duplicates preserving order
    target_files = list(dict.fromkeys(target_files))

    if not target_files:
        print(f"[!] No valid .eml files found matching input patterns: {args.inputs}")
        sys.exit(1)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    enricher = ThreatIntelligenceEnricher() if args.enrich else None

    summary_list = []

    print("\n" + "=" * 70)
    print(" SOAR Phishing Triage Engine")
    print("=" * 70)
    print(f"[*] Processing {len(target_files)} sample(s)...")
    print(f"[*] Report output directory: {out_dir.resolve()}")
    if args.enrich:
        print("[*] Threat Intel Enrichment: ENABLED (VT, AbuseIPDB, URLScan)")
    else:
        print("[*] Threat Intel Enrichment: DISABLED (Offline heuristic mode)")
    print("-" * 70)

    for file_path in target_files:
        p = Path(file_path)
        try:
            with open(p, "rb") as f:
                content = f.read()
        except Exception as e:
            print(f"[-] Error reading {file_path}: {e}")
            continue

        analyzer = EmailTriageAnalyzer(content, filename=str(p))
        result = analyzer.evaluate_verdict()

        enrichment_data = {}
        if enricher:
            enrichment_data = enricher.enrich(result)
            result["enrichment"] = enrichment_data

        summary_list.append(result)

        # Verdict display badge
        verdict = result["verdict"]
        badge = {
            "malicious": "[MALICIOUS]",
            "suspicious": "[SUSPICIOUS]",
            "likely_benign": "[LIKELY_BENIGN]"
        }.get(verdict, f"[{verdict.upper()}]")

        print(f"-> {p.name:<38} | Verdict: {badge:<16} | Score: {result['risk_score']:<3}")
        if result["reasons"]:
            print(f"   Triggers: {', '.join(result['reasons'])}")

        # Save individual reports
        base_stem = p.stem
        if not args.markdown_only:
            json_file = out_dir / f"{base_stem}.json"
            with open(json_file, "w", encoding="utf-8") as jf:
                json.dump(result, jf, indent=2)

        if not args.json_only:
            md_file = out_dir / f"{base_stem}.md"
            md_content = generate_markdown_report(result, enrichment_data)
            with open(md_file, "w", encoding="utf-8") as mf:
                mf.write(md_content)

    # Save summary report
    summary_path_json = out_dir / "triage_summary.json"
    with open(summary_path_json, "w", encoding="utf-8") as sf:
        json.dump(summary_list, sf, indent=2)

    summary_path_md = out_dir / "triage_summary.md"
    with open(summary_path_md, "w", encoding="utf-8") as smf:
        smf.write("# SOAR Phishing Triage Batch Summary\n\n")
        smf.write(f"- **Execution Time**: {datetime.now(timezone.utc).isoformat()}\n")
        smf.write(f"- **Total Samples Analyzed**: {len(summary_list)}\n\n")
        smf.write("| Sample File | Verdict | Risk Score | Key Reasons |\n")
        smf.write("|---|---|---:|---|\n")
        for s in summary_list:
            reasons_str = "; ".join(s.get("reasons", [])) or "None"
            smf.write(f"| `{os.path.basename(s['file'])}` | **{s['verdict'].upper()}** | {s['risk_score']} | {reasons_str} |\n")

    print("-" * 70)
    print(f"[+] Triage complete. Summary written to {summary_path_md}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
