import os
import json
import socket
import ipaddress
import threading
import re
from datetime import datetime, timezone

import requests
import dns.resolver
import dns.reversename
import whois
import urllib.parse
import ssl
import socket as _socket

from flask import Blueprint, request, jsonify
from auth import require_auth
from extensions import limiter

tools_bp = Blueprint("tools", __name__)

ABUSEIPDB_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY  = os.getenv("VIRUSTOTAL_API_KEY", "")
IPINFO_TOKEN    = os.getenv("IPINFO_TOKEN", "")

REQUEST_TIMEOUT = 8

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def _is_valid_domain(value: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value))

def _is_valid_hash(value: str) -> bool:
    return bool(re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", value))

def _fetch(url, headers=None, params=None, timeout=REQUEST_TIMEOUT):
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=timeout)
        if resp.status_code == 404:
            return None, "not_found"
        if resp.status_code == 401:
            return None, "invalid_api_key"
        if resp.status_code == 429:
            return None, "rate_limited"
        resp.raise_for_status()
        return resp.json(), None
    except requests.exceptions.Timeout:
        return None, "timeout"
    except requests.exceptions.ConnectionError:
        return None, "connection_error"
    except Exception as e:
        return None, str(e)


# ─────────────────────────────────────────────
# Tool 1 — IP Intelligence
# ─────────────────────────────────────────────

def _lookup_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {"available": False, "reason": "API key not configured"}
    data, err = _fetch(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
    )
    if err:
        return {"available": False, "reason": err}
    d = data.get("data", {})
    return {
        "available": True,
        "abuse_score": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "last_reported": d.get("lastReportedAt"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "domain": d.get("domain"),
        "is_tor": d.get("isTor"),
        "is_whitelisted": d.get("isWhitelisted"),
        "usage_type": d.get("usageType"),
    }

def _lookup_virustotal_ip(ip: str) -> dict:
    if not VIRUSTOTAL_KEY:
        return {"available": False, "reason": "API key not configured"}
    data, err = _fetch(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": VIRUSTOTAL_KEY},
    )
    if err:
        return {"available": False, "reason": err}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "available": True,
        "malicious_votes": stats.get("malicious", 0),
        "suspicious_votes": stats.get("suspicious", 0),
        "harmless_votes": stats.get("harmless", 0),
        "undetected_votes": stats.get("undetected", 0),
        "country": attrs.get("country"),
        "asn": attrs.get("asn"),
        "as_owner": attrs.get("as_owner"),
        "reputation": attrs.get("reputation"),
        "network": attrs.get("network"),
    }

def _lookup_ipinfo(ip: str) -> dict:
    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": IPINFO_TOKEN} if IPINFO_TOKEN else {}
    data, err = _fetch(url, params=params)
    if err:
        return {"available": False, "reason": err}
    return {
        "available": True,
        "hostname":  data.get("hostname"),
        "city":      data.get("city"),
        "region":    data.get("region"),
        "country":   data.get("country"),
        "org":       data.get("org"),
        "timezone":  data.get("timezone"),
        "loc":       data.get("loc"),
    }


@tools_bp.route("/tools/ip-lookup", methods=["POST"])
@require_auth
@limiter.limit("30 per minute")
def ip_lookup():
    body = request.get_json(silent=True) or {}
    ip = (body.get("ip") or "").strip()

    if not ip:
        return jsonify({"error": "missing_ip"}), 400
    if not _is_valid_ip(ip):
        return jsonify({"error": "invalid_ip"}), 400

    results = {}

    def run(name, fn):
        try:
            results[name] = fn(ip)
        except Exception as e:
            results[name] = {"available": False, "reason": str(e)}

    threads = [
        threading.Thread(target=run, args=("abuseipdb",  _lookup_abuseipdb)),
        threading.Thread(target=run, args=("virustotal", _lookup_virustotal_ip)),
        threading.Thread(target=run, args=("ipinfo",     _lookup_ipinfo)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=REQUEST_TIMEOUT + 2)

    abuse_score  = (results.get("abuseipdb")  or {}).get("abuse_score")  or 0
    vt_malicious = (results.get("virustotal") or {}).get("malicious_votes") or 0

    if abuse_score >= 80 or vt_malicious >= 5:
        verdict = "malicious"
    elif abuse_score >= 25 or vt_malicious >= 1:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return jsonify({
        "ip": ip,
        "verdict": verdict,
        "sources": results,
        "queried_at": datetime.now(timezone.utc).isoformat(),
    }), 200


# ─────────────────────────────────────────────
# Tool 2 — DNS Lookup
# ─────────────────────────────────────────────

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

def _resolve_records(domain: str) -> dict:
    records = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 4

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [r.to_text() for r in answers]
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            records[rtype] = None
        except Exception:
            records[rtype] = []

    try:
        a_records = records.get("A") or []
        if a_records:
            rev_name = dns.reversename.from_address(a_records[0])
            ptr = resolver.resolve(rev_name, "PTR")
            records["PTR"] = [r.to_text() for r in ptr]
        else:
            records["PTR"] = []
    except Exception:
        records["PTR"] = []

    return records


@tools_bp.route("/tools/dns-lookup", methods=["POST"])
@require_auth
@limiter.limit("30 per minute")
def dns_lookup():
    body = request.get_json(silent=True) or {}
    target = (body.get("domain") or body.get("ip") or "").strip().lower()
    if not target:
        return jsonify({"error": "missing_target"}), 400

    if _is_valid_ip(target):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 4
            resolver.lifetime = 4
            rev_name = dns.reversename.from_address(target)
            ptr = resolver.resolve(rev_name, "PTR")
            return jsonify({
                "target": target,
                "type": "reverse",
                "records": {"PTR": [r.to_text() for r in ptr]},
                "queried_at": datetime.now(timezone.utc).isoformat(),
            }), 200
        except Exception as e:
            return jsonify({
                "target": target,
                "type": "reverse",
                "records": {"PTR": []},
                "error": str(e),
            }), 200

    if not _is_valid_domain(target):
        return jsonify({"error": "invalid_domain"}), 400

    records = _resolve_records(target)
    return jsonify({
        "target": target,
        "type": "forward",
        "records": records,
        "queried_at": datetime.now(timezone.utc).isoformat(),
    }), 200


# ─────────────────────────────────────────────
# Tool 3 — WHOIS
# ─────────────────────────────────────────────

def _safe_whois_field(value):
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


@tools_bp.route("/tools/whois", methods=["POST"])
@require_auth
@limiter.limit("20 per minute")
def whois_lookup():
    body = request.get_json(silent=True) or {}
    target = (body.get("domain") or body.get("ip") or "").strip().lower()

    if not target:
        return jsonify({"error": "missing_target"}), 400
    if not (_is_valid_domain(target) or _is_valid_ip(target)):
        return jsonify({"error": "invalid_target"}), 400

    try:
        w = whois.whois(target)
        result = {
            "domain_name":     _safe_whois_field(w.domain_name),
            "registrar":       _safe_whois_field(w.registrar),
            "creation_date":   _safe_whois_field(w.creation_date),
            "expiration_date": _safe_whois_field(w.expiration_date),
            "updated_date":    _safe_whois_field(w.updated_date),
            "name_servers":    [str(ns) for ns in (w.name_servers or [])],
            "status":          w.status if isinstance(w.status, list) else [w.status] if w.status else [],
            "emails":          w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
            "org":             _safe_whois_field(w.org),
            "country":         _safe_whois_field(w.country),
            "dnssec":          _safe_whois_field(w.dnssec),
        }
        return jsonify({
            "target": target,
            "result": result,
            "queried_at": datetime.now(timezone.utc).isoformat(),
        }), 200
    except Exception as e:
        return jsonify({"error": "whois_failed", "detail": str(e)}), 500


# ─────────────────────────────────────────────
# Tool 4 — Hash Lookup
# ─────────────────────────────────────────────

@tools_bp.route("/tools/hash-lookup", methods=["POST"])
@require_auth
@limiter.limit("20 per minute")
def hash_lookup():
    body = request.get_json(silent=True) or {}
    file_hash = (body.get("hash") or "").strip().lower()

    if not file_hash:
        return jsonify({"error": "missing_hash"}), 400
    if not _is_valid_hash(file_hash):
        return jsonify({"error": "invalid_hash",
                        "detail": "Must be MD5 (32), SHA1 (40), or SHA256 (64) hex"}), 400
    if not VIRUSTOTAL_KEY:
        return jsonify({"error": "api_key_not_configured",
                        "detail": "VIRUSTOTAL_API_KEY is not set"}), 503

    data, err = _fetch(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"x-apikey": VIRUSTOTAL_KEY},
    )
    if err == "not_found":
        return jsonify({"hash": file_hash, "found": False,
                        "message": "Hash not found in VirusTotal database"}), 200
    if err:
        return jsonify({"error": err}), 502

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    analysis_results = attrs.get("last_analysis_results", {})
    detections = [
        {"vendor": vendor, "result": info.get("result"), "category": info.get("category")}
        for vendor, info in analysis_results.items()
        if info.get("category") in ("malicious", "suspicious")
    ]

    if malicious >= 5:
        verdict = "malicious"
    elif malicious >= 1 or suspicious >= 3:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return jsonify({
        "hash":       file_hash,
        "found":      True,
        "verdict":    verdict,
        "stats":      stats,
        "detections": detections[:20],
        "file_name":  attrs.get("meaningful_name"),
        "file_type":  attrs.get("type_description"),
        "file_size":  attrs.get("size"),
        "first_seen": attrs.get("first_submission_date"),
        "last_seen":  attrs.get("last_analysis_date"),
        "tags":       attrs.get("tags", []),
        "queried_at": datetime.now(timezone.utc).isoformat(),
    }), 200

# ─────────────────────────────────────────────
# Tool 5 — URL Scanner
# ─────────────────────────────────────────────

def _expand_url(url: str) -> dict:
    """Follow redirects and return the final URL and redirect chain."""
    try:
        import requests
        session = requests.Session()
        session.max_redirects = 10
        resp = session.head(url, allow_redirects=True, timeout=8, verify=False)
        chain = [r.url for r in resp.history] + [resp.url]
        return {
            "final_url": resp.url,
            "redirect_chain": chain,
            "redirect_count": len(resp.history),
            "status_code": resp.status_code,
        }
    except Exception as e:
        return {"error": str(e)}


def _check_google_safe_browsing(url: str) -> dict:
    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
    if not gsb_key:
        return {"available": False, "reason": "GOOGLE_SAFE_BROWSING_KEY not configured"}
    try:
        payload = {
            "client": {"clientId": "intellicloud", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}",
            json=payload, timeout=8
        )
        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])
        return {
            "available": True,
            "safe": len(matches) == 0,
            "threats": [m.get("threatType") for m in matches],
        }
    except Exception as e:
        return {"available": False, "reason": str(e)}


def _check_typosquatting(url: str) -> list[str]:
    """Check if domain looks like a typosquat of a popular domain."""
    popular = [
        "google", "facebook", "microsoft", "apple", "amazon", "paypal",
        "netflix", "twitter", "instagram", "linkedin", "github", "dropbox",
        "chase", "bankofamerica", "wellsfargo", "gmail", "outlook", "yahoo",
    ]
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        base = domain.split(".")[0]
        warnings = []
        for brand in popular:
            if brand in base and base != brand:
                warnings.append(f"Domain '{domain}' may be typosquatting '{brand}.com'")
            elif _levenshtein(base, brand) <= 2 and base != brand:
                warnings.append(f"Domain '{domain}' is very similar to '{brand}.com' (possible typosquat)")
        return warnings
    except Exception:
        return []


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for c1 in s1:
        curr = [0] * (len(s2) + 1)
        curr[0] = prev[0] + 1
        for i, c2 in enumerate(s2):
            curr[i + 1] = min(prev[i] + (c1 != c2), curr[i] + 1, prev[i + 1] + 1)
        prev = curr
    return prev[-1]


@tools_bp.route("/tools/url-scan", methods=["POST"])
@require_auth
@limiter.limit("20 per minute")
def url_scan():
    body = request.get_json(silent=True) or {}
    url = (body.get("url") or "").strip()

    if not url:
        return jsonify({"error": "missing_url"}), 400

    # Ensure it has a scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        urllib.parse.urlparse(url)
    except Exception:
        return jsonify({"error": "invalid_url"}), 400

    # Run checks in parallel
    results = {}

    def run(name, fn, *args):
        try:
            results[name] = fn(*args)
        except Exception as e:
            results[name] = {"error": str(e)}

    threads = [
        threading.Thread(target=run, args=("redirect",       _expand_url,              url)),
        threading.Thread(target=run, args=("safe_browsing",  _check_google_safe_browsing, url)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    typo_warnings = _check_typosquatting(url)

    # Derive verdict
    gsb = results.get("safe_browsing", {})
    redirect = results.get("redirect", {})
    is_malicious = gsb.get("available") and not gsb.get("safe", True)
    redirect_count = redirect.get("redirect_count", 0)

    if is_malicious:
        verdict = "malicious"
    elif redirect_count > 3 or typo_warnings:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return jsonify({
        "url": url,
        "verdict": verdict,
        "redirect": redirect,
        "safe_browsing": gsb,
        "typosquat_warnings": typo_warnings,
        "queried_at": datetime.now(timezone.utc).isoformat(),
    }), 200


# ─────────────────────────────────────────────
# Tool 6 — CVE / Vulnerability Search
# ─────────────────────────────────────────────

@tools_bp.route("/tools/cve-search", methods=["GET"])
@require_auth
@limiter.limit("20 per minute")
def cve_search():
    query   = (request.args.get("q") or "").strip()
    cve_id  = (request.args.get("cve_id") or "").strip().upper()

    if not query and not cve_id:
        return jsonify({"error": "missing_query",
                        "detail": "Provide ?q=keyword or ?cve_id=CVE-YYYY-NNNNN"}), 400

    try:
        if cve_id:
            # Direct CVE lookup
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        else:
            # Keyword search — limit to 10 results
            encoded = urllib.parse.quote(query)
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded}&resultsPerPage=10"

        resp = requests.get(url, timeout=10,
                            headers={"User-Agent": "IntelliCloud/1.0"})

        if resp.status_code == 404:
            return jsonify({"results": [], "total": 0}), 200

        resp.raise_for_status()
        data = resp.json()

        items = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id_val = cve.get("id", "")

            # Get English description
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # Get CVSS score
            score = None
            severity = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    score    = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity") or metric_list[0].get("baseSeverity")
                    break

            # Get references
            refs = [r.get("url") for r in cve.get("references", [])[:3] if r.get("url")]

            published = cve.get("published", "")[:10]
            modified  = cve.get("lastModified", "")[:10]

            items.append({
                "cve_id":      cve_id_val,
                "description": desc,
                "cvss_score":  score,
                "severity":    severity,
                "published":   published,
                "modified":    modified,
                "references":  refs,
            })

        return jsonify({
            "results":     items,
            "total":       data.get("totalResults", len(items)),
            "queried_at":  datetime.now(timezone.utc).isoformat(),
        }), 200

    except requests.exceptions.Timeout:
        return jsonify({"error": "NVD API timed out. Try again."}), 504
    except Exception as e:
        return jsonify({"error": "cve_search_failed", "detail": str(e)}), 500


# ─────────────────────────────────────────────
# Tool 7 — SSL/TLS Certificate Inspector
# ─────────────────────────────────────────────

@tools_bp.route("/tools/ssl-inspect", methods=["POST"])
@require_auth
@limiter.limit("20 per minute")
def ssl_inspect():
    body = request.get_json(silent=True) or {}
    host = (body.get("host") or body.get("domain") or "").strip().lower()

    # Strip protocol if included
    host = host.replace("https://", "").replace("http://", "").split("/")[0]

    if not host:
        return jsonify({"error": "missing_host"}), 400
    if not _is_valid_domain(host) and not _is_valid_ip(host):
        return jsonify({"error": "invalid_host"}), 400

    port = int(body.get("port", 443))

    try:
        context = ssl.create_default_context()
        with _socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

        # Parse subject
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))

        # Parse SANs
        sans = []
        for san_type, san_value in cert.get("subjectAltName", []):
            sans.append(f"{san_type}:{san_value}")

        # Parse dates
        not_before = cert.get("notBefore", "")
        not_after  = cert.get("notAfter", "")

        # Check expiry
        from datetime import datetime as dt
        expired = False
        days_remaining = None
        try:
            expiry_dt = dt.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            now_dt    = dt.utcnow()
            expired   = expiry_dt < now_dt
            days_remaining = (expiry_dt - now_dt).days
        except Exception:
            pass

        # Weak cipher detection
        cipher_name    = cipher[0] if cipher else ""
        cipher_bits    = cipher[2] if cipher and len(cipher) > 2 else None
        weak_ciphers   = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]
        is_weak_cipher = any(w in cipher_name.upper() for w in weak_ciphers)
        is_weak_bits   = cipher_bits and cipher_bits < 128

        # Overall grade
        if expired:
            grade = "F"
        elif is_weak_cipher or is_weak_bits:
            grade = "C"
        elif protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            grade = "B"
        elif days_remaining and days_remaining < 30:
            grade = "B"
        else:
            grade = "A"

        return jsonify({
            "host":           host,
            "port":           port,
            "grade":          grade,
            "expired":        expired,
            "days_remaining": days_remaining,
            "protocol":       protocol,
            "cipher":         cipher_name,
            "cipher_bits":    cipher_bits,
            "is_weak_cipher": is_weak_cipher,
            "subject": {
                "common_name":   subject.get("commonName"),
                "org":           subject.get("organizationName"),
                "country":       subject.get("countryName"),
            },
            "issuer": {
                "common_name":   issuer.get("commonName"),
                "org":           issuer.get("organizationName"),
                "country":       issuer.get("countryName"),
            },
            "valid_from":   not_before,
            "valid_until":  not_after,
            "sans":         sans[:10],
            "serial_number": cert.get("serialNumber"),
            "queried_at":   datetime.now(timezone.utc).isoformat(),
        }), 200

    except ssl.SSLCertVerificationError as e:
        return jsonify({
            "host": host, "grade": "F",
            "error": "certificate_verification_failed",
            "detail": str(e),
        }), 200
    except ConnectionRefusedError:
        return jsonify({"error": "connection_refused", "detail": f"Port {port} is closed on {host}"}), 200
    except _socket.timeout:
        return jsonify({"error": "timeout", "detail": f"Connection to {host}:{port} timed out"}), 200
    except Exception as e:
        return jsonify({"error": "ssl_inspect_failed", "detail": str(e)}), 500