import streamlit as st
import requests
import json
import hashlib
import re
import ipaddress
import time
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
from urllib.parse import urlparse, quote
import base64

# ─────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────
st.set_page_config(
    page_title="IOC Intelligence Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────
# CUSTOM CSS — Dark Tactical Theme
# ─────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Rajdhani:wght@400;500;600;700&display=swap');

:root {
    --bg-primary: #0a0d14;
    --bg-secondary: #0f1420;
    --bg-card: #131824;
    --bg-card-hover: #1a2035;
    --accent-green: #00ff88;
    --accent-red: #ff3366;
    --accent-orange: #ff8c42;
    --accent-yellow: #ffd700;
    --accent-blue: #4dabf7;
    --accent-purple: #c084fc;
    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --text-muted: #4a5568;
    --border: #1e2d40;
    --border-accent: #00ff8820;
}

html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
    background-color: var(--bg-primary);
    color: var(--text-primary);
}

.stApp {
    background: linear-gradient(135deg, #0a0d14 0%, #0d1220 50%, #0a0f1a 100%);
}

/* Header */
.main-header {
    background: linear-gradient(90deg, #0f1420, #131824, #0f1420);
    border: 1px solid var(--border);
    border-left: 4px solid var(--accent-green);
    padding: 20px 28px;
    border-radius: 8px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
}
.main-header::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent-green), transparent);
}
.main-header h1 {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.8rem;
    font-weight: 700;
    color: var(--accent-green);
    margin: 0;
    letter-spacing: 2px;
    text-shadow: 0 0 20px #00ff8840;
}
.main-header p {
    color: var(--text-secondary);
    margin: 6px 0 0;
    font-size: 0.95rem;
    letter-spacing: 1px;
}

/* Cards */
.result-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin: 12px 0;
    transition: border-color 0.2s;
}
.result-card:hover { border-color: var(--accent-blue); }
.result-card.danger { border-left: 3px solid var(--accent-red); }
.result-card.warning { border-left: 3px solid var(--accent-orange); }
.result-card.safe { border-left: 3px solid var(--accent-green); }
.result-card.info { border-left: 3px solid var(--accent-blue); }

.card-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    letter-spacing: 2px;
    color: var(--text-secondary);
    text-transform: uppercase;
    margin-bottom: 8px;
}

/* Score badges */
.score-badge {
    display: inline-block;
    padding: 4px 14px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700;
    font-size: 0.85rem;
    letter-spacing: 1px;
}
.score-critical { background: #ff336620; color: var(--accent-red); border: 1px solid #ff336640; }
.score-high { background: #ff8c4220; color: var(--accent-orange); border: 1px solid #ff8c4240; }
.score-medium { background: #ffd70020; color: var(--accent-yellow); border: 1px solid #ffd70040; }
.score-low { background: #00ff8820; color: var(--accent-green); border: 1px solid #00ff8840; }
.score-clean { background: #4dabf720; color: var(--accent-blue); border: 1px solid #4dabf740; }

/* Stat boxes */
.stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }
.stat-box {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 14px;
    text-align: center;
}
.stat-number {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.8rem;
    font-weight: 700;
    color: var(--accent-green);
    display: block;
}
.stat-label { color: var(--text-secondary); font-size: 0.8rem; letter-spacing: 1px; }

/* Tag */
.tag {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 3px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    margin: 2px;
}
.tag-malware { background: #ff336615; color: #ff6b8a; border: 1px solid #ff336630; }
.tag-phishing { background: #ff8c4215; color: #ffab6e; border: 1px solid #ff8c4230; }
.tag-spam { background: #ffd70015; color: #ffe066; border: 1px solid #ffd70030; }
.tag-generic { background: #4dabf715; color: #74c0fc; border: 1px solid #4dabf730; }
.tag-apt { background: #c084fc15; color: #d8a4ff; border: 1px solid #c084fc30; }

/* IOC type indicator */
.ioc-type-badge {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    letter-spacing: 2px;
    padding: 3px 10px;
    border-radius: 3px;
    background: #00ff8810;
    color: var(--accent-green);
    border: 1px solid #00ff8830;
    display: inline-block;
    margin-bottom: 12px;
}

/* KV row */
.kv-row {
    display: flex;
    justify-content: space-between;
    padding: 6px 0;
    border-bottom: 1px solid var(--border);
    font-size: 0.9rem;
}
.kv-row:last-child { border-bottom: none; }
.kv-key { color: var(--text-secondary); font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; }
.kv-val { color: var(--text-primary); font-weight: 500; }

/* Sidebar */
section[data-testid="stSidebar"] {
    background: var(--bg-secondary) !important;
    border-right: 1px solid var(--border) !important;
}
section[data-testid="stSidebar"] * { color: var(--text-primary); }

/* Input */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    color: var(--text-primary) !important;
    font-family: 'JetBrains Mono', monospace !important;
    border-radius: 6px !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
    border-color: var(--accent-green) !important;
    box-shadow: 0 0 0 2px #00ff8820 !important;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, #00ff8820, #00cc6a20) !important;
    border: 1px solid var(--accent-green) !important;
    color: var(--accent-green) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-weight: 600 !important;
    letter-spacing: 2px !important;
    border-radius: 6px !important;
    padding: 8px 20px !important;
    transition: all 0.2s !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #00ff8830, #00cc6a30) !important;
    box-shadow: 0 0 16px #00ff8830 !important;
}

/* Expander */
.streamlit-expanderHeader {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
    color: var(--text-secondary) !important;
    font-size: 0.85rem !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    background: var(--bg-secondary) !important;
    border-bottom: 1px solid var(--border) !important;
    gap: 4px;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    color: var(--text-secondary) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.8rem !important;
    letter-spacing: 1px !important;
    border: none !important;
    padding: 8px 16px !important;
}
.stTabs [aria-selected="true"] {
    color: var(--accent-green) !important;
    border-bottom: 2px solid var(--accent-green) !important;
}

/* Alert boxes */
.stAlert { border-radius: 6px !important; border: 1px solid var(--border) !important; }

/* Spinner */
.stSpinner > div { border-top-color: var(--accent-green) !important; }

/* Progress */
.stProgress > div > div { background: var(--accent-green) !important; }

/* History item */
.history-item {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 16px;
    margin: 6px 0;
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    gap: 12px;
}
.history-item:hover { border-color: var(--accent-blue); background: var(--bg-card-hover); }

/* Separator */
.section-sep {
    border: none;
    border-top: 1px solid var(--border);
    margin: 20px 0;
}

/* Verdict bar */
.verdict-bar {
    background: var(--bg-secondary);
    border-radius: 8px;
    padding: 20px 24px;
    border: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 20px;
    margin: 16px 0;
}

/* Source pill */
.source-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 0.78rem;
    font-family: 'JetBrains Mono', monospace;
    border: 1px solid;
    margin: 3px;
}
.source-ok { background: #00ff8810; color: var(--accent-green); border-color: #00ff8830; }
.source-err { background: #ff336610; color: var(--accent-red); border-color: #ff336630; }
.source-skip { background: #94a3b815; color: var(--text-secondary); border-color: #94a3b830; }

/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent-green); }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────
# HELPERS — IOC DETECTION
# ─────────────────────────────────────────

def detect_ioc_type(value: str) -> str:
    value = value.strip()
    # MD5
    if re.fullmatch(r'[a-fA-F0-9]{32}', value): return "MD5"
    # SHA1
    if re.fullmatch(r'[a-fA-F0-9]{40}', value): return "SHA1"
    # SHA256
    if re.fullmatch(r'[a-fA-F0-9]{64}', value): return "SHA256"
    # SHA512
    if re.fullmatch(r'[a-fA-F0-9]{128}', value): return "SHA512"
    # IP
    try:
        ipaddress.ip_address(value)
        return "IPv4" if '.' in value else "IPv6"
    except ValueError:
        pass
    # URL
    if re.match(r'https?://', value, re.IGNORECASE):
        return "URL"
    # CIDR
    try:
        ipaddress.ip_network(value, strict=False)
        return "CIDR"
    except ValueError:
        pass
    # Domain
    if re.fullmatch(r'(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}', value):
        return "Domain"
    # Email
    if re.fullmatch(r'[^@]+@[^@]+\.[^@]+', value):
        return "Email"
    return "Unknown"

def get_api_key(name: str) -> str | None:
    try:
        key = st.secrets["api_keys"].get(name, "")
        if key and not key.startswith("YOUR_"):
            return key
    except Exception:
        pass
    return None

# ─────────────────────────────────────────
# API INTEGRATIONS
# ─────────────────────────────────────────

def query_virustotal(ioc: str, ioc_type: str) -> dict:
    api_key = get_api_key("virustotal")
    if not api_key:
        return {"error": "API key not configured", "source": "VirusTotal"}

    headers = {"x-apikey": api_key, "Accept": "application/json"}
    base = "https://www.virustotal.com/api/v3"

    try:
        if ioc_type in ("MD5", "SHA1", "SHA256", "SHA512"):
            url = f"{base}/files/{ioc}"
        elif ioc_type in ("IPv4", "IPv6"):
            url = f"{base}/ip_addresses/{ioc}"
        elif ioc_type == "Domain":
            url = f"{base}/domains/{ioc}"
        elif ioc_type == "URL":
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
            url = f"{base}/urls/{url_id}"
        else:
            return {"error": "Unsupported IOC type", "source": "VirusTotal"}

        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            d = r.json().get("data", {}).get("attributes", {})
            stats = d.get("last_analysis_stats", {})
            total = sum(stats.values()) or 1
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            return {
                "source": "VirusTotal",
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "total_engines": total,
                "detection_rate": round((malicious + suspicious) / total * 100, 1),
                "reputation": d.get("reputation", "N/A"),
                "tags": d.get("tags", []),
                "categories": d.get("categories", {}),
                "country": d.get("country", ""),
                "asn": d.get("asn", ""),
                "as_owner": d.get("as_owner", ""),
                "last_analysis_date": d.get("last_analysis_date", ""),
                "names": d.get("names", [])[:5],
                "raw_stats": stats,
                "threat_label": d.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
            }
        elif r.status_code == 404:
            return {"source": "VirusTotal", "error": "IOC not found in database", "malicious": 0}
        else:
            return {"source": "VirusTotal", "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


def query_abuseipdb(ip: str) -> dict:
    api_key = get_api_key("abuseipdb")
    if not api_key:
        return {"error": "API key not configured", "source": "AbuseIPDB"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=15,
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {
                "source": "AbuseIPDB",
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "num_distinct_users": d.get("numDistinctUsers", 0),
                "country": d.get("countryCode", ""),
                "isp": d.get("isp", ""),
                "domain": d.get("domain", ""),
                "is_public": d.get("isPublic", True),
                "is_tor": d.get("isTor", False),
                "last_reported": d.get("lastReportedAt", ""),
                "usage_type": d.get("usageType", ""),
                "hostnames": d.get("hostnames", [])[:3],
            }
        return {"source": "AbuseIPDB", "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "AbuseIPDB", "error": str(e)}


def query_shodan(ioc: str, ioc_type: str) -> dict:
    api_key = get_api_key("shodan")
    if not api_key:
        return {"error": "API key not configured", "source": "Shodan"}
    try:
        if ioc_type in ("IPv4", "IPv6"):
            r = requests.get(f"https://api.shodan.io/shodan/host/{ioc}?key={api_key}", timeout=15)
            if r.status_code == 200:
                d = r.json()
                ports = sorted(list(set(d.get("ports", []))))
                vulns = list(d.get("vulns", {}).keys())
                return {
                    "source": "Shodan",
                    "org": d.get("org", ""),
                    "isp": d.get("isp", ""),
                    "os": d.get("os", ""),
                    "country": d.get("country_name", ""),
                    "city": d.get("city", ""),
                    "ports": ports[:20],
                    "vulns": vulns[:10],
                    "hostnames": d.get("hostnames", [])[:5],
                    "tags": d.get("tags", []),
                    "last_update": d.get("last_update", ""),
                    "domains": d.get("domains", [])[:5],
                }
            return {"source": "Shodan", "error": f"HTTP {r.status_code}"}
        return {"source": "Shodan", "error": "Only available for IP addresses"}
    except Exception as e:
        return {"source": "Shodan", "error": str(e)}


def query_otx(ioc: str, ioc_type: str) -> dict:
    api_key = get_api_key("otx")
    if not api_key:
        return {"error": "API key not configured", "source": "OTX AlienVault"}
    headers = {"X-OTX-API-KEY": api_key}
    base = "https://otx.alienvault.com/api/v1/indicators"

    type_map = {
        "IPv4": "IPv4", "IPv6": "IPv6",
        "Domain": "domain", "URL": "url",
        "MD5": "file", "SHA1": "file", "SHA256": "file", "SHA512": "file",
    }
    otx_type = type_map.get(ioc_type, "")
    if not otx_type:
        return {"source": "OTX AlienVault", "error": "Unsupported IOC type"}

    try:
        endpoint = f"{base}/{otx_type}/{ioc}/general"
        r = requests.get(endpoint, headers=headers, timeout=15)
        if r.status_code == 200:
            d = r.json()
            pulses = d.get("pulse_info", {})
            return {
                "source": "OTX AlienVault",
                "pulse_count": pulses.get("count", 0),
                "pulses": [p.get("name", "") for p in pulses.get("pulses", [])[:5]],
                "tags": list(set(t for p in pulses.get("pulses", []) for t in p.get("tags", [])))[:10],
                "malware_families": list(set(
                    m.get("display_name", "") for p in pulses.get("pulses", [])
                    for m in p.get("malware_families", [])
                ))[:5],
                "adversaries": list(set(
                    a for p in pulses.get("pulses", []) for a in p.get("adversary", []) if a
                ))[:5],
                "reputation": d.get("reputation", 0),
                "asn": d.get("asn", ""),
                "country": d.get("country_name", ""),
                "city": d.get("city", ""),
            }
        return {"source": "OTX AlienVault", "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "OTX AlienVault", "error": str(e)}


def query_urlscan(url_or_domain: str, ioc_type: str) -> dict:
    api_key = get_api_key("urlscan")
    if not api_key:
        return {"error": "API key not configured", "source": "URLScan.io"}
    if ioc_type not in ("URL", "Domain"):
        return {"source": "URLScan.io", "error": "Only for URL/Domain IOCs"}
    try:
        # Search existing scans
        q = url_or_domain if ioc_type == "Domain" else f'page.url:"{url_or_domain}"'
        r = requests.get(
            "https://urlscan.io/api/v1/search/",
            headers={"API-Key": api_key, "Content-Type": "application/json"},
            params={"q": q, "size": 5},
            timeout=15,
        )
        if r.status_code == 200:
            results = r.json().get("results", [])
            if not results:
                return {"source": "URLScan.io", "info": "No existing scans found", "results": []}
            parsed = []
            for res in results[:3]:
                page = res.get("page", {})
                verdicts = res.get("verdicts", {})
                parsed.append({
                    "url": page.get("url", ""),
                    "domain": page.get("domain", ""),
                    "ip": page.get("ip", ""),
                    "country": page.get("country", ""),
                    "server": page.get("server", ""),
                    "malicious": verdicts.get("overall", {}).get("malicious", False),
                    "score": verdicts.get("overall", {}).get("score", 0),
                    "categories": verdicts.get("overall", {}).get("categories", []),
                    "scan_id": res.get("_id", ""),
                    "screenshot": res.get("screenshot", ""),
                })
            return {"source": "URLScan.io", "results": parsed, "total": r.json().get("total", 0)}
        return {"source": "URLScan.io", "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "URLScan.io", "error": str(e)}


def query_greynoise(ip: str) -> dict:
    api_key = get_api_key("greynoise")
    if not api_key:
        return {"error": "API key not configured", "source": "GreyNoise"}
    try:
        r = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": api_key},
            timeout=15,
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "source": "GreyNoise",
                "noise": d.get("noise", False),
                "riot": d.get("riot", False),
                "classification": d.get("classification", ""),
                "name": d.get("name", ""),
                "link": d.get("link", ""),
                "last_seen": d.get("last_seen", ""),
                "message": d.get("message", ""),
            }
        elif r.status_code == 404:
            return {"source": "GreyNoise", "classification": "unknown", "noise": False, "message": "IP not in GreyNoise dataset"}
        return {"source": "GreyNoise", "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "GreyNoise", "error": str(e)}


def query_ipinfo(ip: str) -> dict:
    api_key = get_api_key("ipinfo")
    token_param = f"?token={api_key}" if api_key else ""
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json{token_param}", timeout=10)
        if r.status_code == 200:
            d = r.json()
            return {
                "source": "IPInfo",
                "org": d.get("org", ""),
                "city": d.get("city", ""),
                "region": d.get("region", ""),
                "country": d.get("country", ""),
                "timezone": d.get("timezone", ""),
                "loc": d.get("loc", ""),
                "hostname": d.get("hostname", ""),
                "bogon": d.get("bogon", False),
            }
        return {"source": "IPInfo", "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "IPInfo", "error": str(e)}


# ─────────────────────────────────────────
# THREAT SCORING ENGINE
# ─────────────────────────────────────────

def calculate_threat_score(results: dict) -> tuple[int, str, str]:
    """Returns (score 0-100, level, color)"""
    score = 0
    weights = []

    vt = results.get("virustotal", {})
    if not vt.get("error"):
        det = vt.get("detection_rate", 0)
        mal = vt.get("malicious", 0)
        if mal > 10:    score += 40
        elif mal > 5:   score += 30
        elif mal > 0:   score += 20
        weights.append(1)

    abuse = results.get("abuseipdb", {})
    if not abuse.get("error"):
        sc = abuse.get("abuse_score", 0)
        score += int(sc * 0.3)
        weights.append(1)

    otx = results.get("otx", {})
    if not otx.get("error"):
        pc = otx.get("pulse_count", 0)
        if pc > 20:   score += 25
        elif pc > 5:  score += 15
        elif pc > 0:  score += 8

    gn = results.get("greynoise", {})
    if not gn.get("error"):
        cls = gn.get("classification", "")
        if cls == "malicious": score += 25
        elif cls == "benign": score = max(0, score - 10)

    urlscan = results.get("urlscan", {})
    if not urlscan.get("error") and urlscan.get("results"):
        if any(r.get("malicious") for r in urlscan.get("results", [])):
            score += 20

    score = min(100, score)
    if score >= 75: return score, "CRITICAL", "#ff3366"
    if score >= 50: return score, "HIGH", "#ff8c42"
    if score >= 25: return score, "MEDIUM", "#ffd700"
    if score >= 5:  return score, "LOW", "#4dabf7"
    return score, "CLEAN", "#00ff88"


# ─────────────────────────────────────────
# BULK QUERY ORCHESTRATOR
# ─────────────────────────────────────────

def run_all_checks(ioc: str, ioc_type: str) -> dict:
    results = {}
    results["virustotal"] = query_virustotal(ioc, ioc_type)

    if ioc_type in ("IPv4", "IPv6"):
        results["abuseipdb"] = query_abuseipdb(ioc)
        results["shodan"]    = query_shodan(ioc, ioc_type)
        results["greynoise"] = query_greynoise(ioc)
        results["ipinfo"]    = query_ipinfo(ioc)

    results["otx"] = query_otx(ioc, ioc_type)

    if ioc_type in ("URL", "Domain"):
        results["urlscan"] = query_urlscan(ioc, ioc_type)

    return results


# ─────────────────────────────────────────
# RENDER HELPERS
# ─────────────────────────────────────────

def render_score_gauge(score: int, level: str, color: str):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": f"<b>{level}</b>", "font": {"size": 16, "color": color, "family": "JetBrains Mono"}},
        number={"font": {"size": 36, "color": color, "family": "JetBrains Mono"}, "suffix": "/100"},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#1e2d40", "tickfont": {"color": "#94a3b8"}},
            "bar": {"color": color, "thickness": 0.3},
            "bgcolor": "#0f1420",
            "borderwidth": 1,
            "bordercolor": "#1e2d40",
            "steps": [
                {"range": [0, 5], "color": "#00ff8815"},
                {"range": [5, 25], "color": "#4dabf715"},
                {"range": [25, 50], "color": "#ffd70015"},
                {"range": [50, 75], "color": "#ff8c4215"},
                {"range": [75, 100], "color": "#ff336615"},
            ],
            "threshold": {"line": {"color": color, "width": 3}, "thickness": 0.8, "value": score}
        }
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#e2e8f0"},
        height=220,
        margin={"t": 40, "b": 10, "l": 20, "r": 20},
    )
    return fig


def render_detection_donut(vt: dict):
    if vt.get("error") or "malicious" not in vt:
        return None
    labels = ["Malicious", "Suspicious", "Harmless", "Undetected"]
    values = [
        vt.get("malicious", 0),
        vt.get("suspicious", 0),
        vt.get("harmless", 0),
        vt.get("undetected", 0),
    ]
    colors = ["#ff3366", "#ff8c42", "#00ff88", "#4dabf7"]
    fig = go.Figure(go.Pie(
        labels=labels, values=values,
        hole=0.65,
        marker={"colors": colors, "line": {"color": "#0a0d14", "width": 2}},
        textfont={"family": "JetBrains Mono", "size": 11, "color": "#e2e8f0"},
        hovertemplate="%{label}: %{value}<extra></extra>",
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=True,
        legend={"font": {"color": "#94a3b8", "family": "JetBrains Mono", "size": 11},
                "bgcolor": "rgba(0,0,0,0)"},
        height=220,
        margin={"t": 10, "b": 10, "l": 10, "r": 10},
        annotations=[{
            "text": f"<b>{vt.get('malicious',0)+vt.get('suspicious',0)}</b><br><span style='font-size:10px'>detections</span>",
            "x": 0.5, "y": 0.5, "font": {"size": 14, "color": "#e2e8f0", "family": "JetBrains Mono"},
            "showarrow": False,
        }],
    )
    return fig


def source_pill(name: str, result: dict) -> str:
    if "error" in result:
        return f'<span class="source-pill source-err">✗ {name}</span>'
    return f'<span class="source-pill source-ok">✓ {name}</span>'


def render_vt_result(vt: dict):
    if vt.get("error"):
        st.warning(f"VirusTotal: {vt['error']}")
        return

    st.markdown(f"""
    <div class="result-card {'danger' if vt.get('malicious',0)>0 else 'safe'}">
        <div class="card-title">🔬 VIRUSTOTAL ANALYSIS</div>
        <div class="kv-row"><span class="kv-key">Detection Rate</span><span class="kv-val">{vt.get('detection_rate',0)}% ({vt.get('malicious',0)+vt.get('suspicious',0)}/{vt.get('total_engines',0)} engines)</span></div>
        <div class="kv-row"><span class="kv-key">Malicious</span><span class="kv-val" style="color:#ff3366">{vt.get('malicious',0)}</span></div>
        <div class="kv-row"><span class="kv-key">Suspicious</span><span class="kv-val" style="color:#ff8c42">{vt.get('suspicious',0)}</span></div>
        <div class="kv-row"><span class="kv-key">Harmless</span><span class="kv-val" style="color:#00ff88">{vt.get('harmless',0)}</span></div>
        <div class="kv-row"><span class="kv-key">Reputation Score</span><span class="kv-val">{vt.get('reputation','N/A')}</span></div>
        <div class="kv-row"><span class="kv-key">ASN</span><span class="kv-val">{vt.get('asn','')} {vt.get('as_owner','')}</span></div>
        <div class="kv-row"><span class="kv-key">Country</span><span class="kv-val">{vt.get('country','')}</span></div>
        <div class="kv-row"><span class="kv-key">Threat Label</span><span class="kv-val" style="color:#c084fc">{vt.get('threat_label','')}</span></div>
    </div>
    """, unsafe_allow_html=True)

    tags = vt.get("tags", [])
    if tags:
        tag_html = " ".join(f'<span class="tag tag-generic">{t}</span>' for t in tags)
        st.markdown(f"<div style='margin-top:8px'>{tag_html}</div>", unsafe_allow_html=True)


def render_abuseipdb_result(d: dict):
    if d.get("error"):
        st.warning(f"AbuseIPDB: {d['error']}")
        return
    score = d.get("abuse_score", 0)
    color = "#ff3366" if score > 70 else "#ff8c42" if score > 30 else "#00ff88"
    st.markdown(f"""
    <div class="result-card {'danger' if score>70 else 'warning' if score>30 else 'safe'}">
        <div class="card-title">🚨 ABUSEIPDB</div>
        <div class="kv-row"><span class="kv-key">Abuse Confidence</span><span class="kv-val" style="color:{color};font-size:1.2rem;font-weight:700">{score}%</span></div>
        <div class="kv-row"><span class="kv-key">Total Reports</span><span class="kv-val">{d.get('total_reports',0)}</span></div>
        <div class="kv-row"><span class="kv-key">Distinct Reporters</span><span class="kv-val">{d.get('num_distinct_users',0)}</span></div>
        <div class="kv-row"><span class="kv-key">ISP</span><span class="kv-val">{d.get('isp','')}</span></div>
        <div class="kv-row"><span class="kv-key">Country</span><span class="kv-val">{d.get('country','')}</span></div>
        <div class="kv-row"><span class="kv-key">Usage Type</span><span class="kv-val">{d.get('usage_type','')}</span></div>
        <div class="kv-row"><span class="kv-key">Tor Exit Node</span><span class="kv-val" style="color:{'#ff3366' if d.get('is_tor') else '#00ff88'}">{'YES ⚠️' if d.get('is_tor') else 'No'}</span></div>
        <div class="kv-row"><span class="kv-key">Last Reported</span><span class="kv-val">{d.get('last_reported','')[:19] if d.get('last_reported') else ''}</span></div>
    </div>
    """, unsafe_allow_html=True)


def render_shodan_result(d: dict):
    if d.get("error"):
        st.warning(f"Shodan: {d['error']}")
        return
    ports = d.get("ports", [])
    vulns = d.get("vulns", [])
    st.markdown(f"""
    <div class="result-card {'danger' if vulns else 'info'}">
        <div class="card-title">🌐 SHODAN EXPOSURE</div>
        <div class="kv-row"><span class="kv-key">Organization</span><span class="kv-val">{d.get('org','')}</span></div>
        <div class="kv-row"><span class="kv-key">ISP</span><span class="kv-val">{d.get('isp','')}</span></div>
        <div class="kv-row"><span class="kv-key">OS</span><span class="kv-val">{d.get('os') or 'Unknown'}</span></div>
        <div class="kv-row"><span class="kv-key">Location</span><span class="kv-val">{d.get('city','')}, {d.get('country','')}</span></div>
        <div class="kv-row"><span class="kv-key">Open Ports</span><span class="kv-val">{', '.join(str(p) for p in ports) if ports else 'None detected'}</span></div>
        <div class="kv-row"><span class="kv-key">CVEs Detected</span><span class="kv-val" style="color:{'#ff3366' if vulns else '#00ff88'}">{len(vulns)} {'⚠️' if vulns else '✓'}</span></div>
    </div>
    """, unsafe_allow_html=True)
    if vulns:
        vuln_html = " ".join(f'<span class="tag tag-malware">{v}</span>' for v in vulns)
        st.markdown(f"**CVEs:** {vuln_html}", unsafe_allow_html=True)


def render_otx_result(d: dict):
    if d.get("error"):
        st.warning(f"OTX: {d['error']}")
        return
    pulse_count = d.get("pulse_count", 0)
    st.markdown(f"""
    <div class="result-card {'danger' if pulse_count>10 else 'warning' if pulse_count>0 else 'safe'}">
        <div class="card-title">👁️ OTX ALIENVAULT THREAT INTEL</div>
        <div class="kv-row"><span class="kv-key">Pulse Count</span><span class="kv-val" style="color:{'#ff3366' if pulse_count>10 else '#ff8c42' if pulse_count>0 else '#00ff88'};font-size:1.2rem;font-weight:700">{pulse_count}</span></div>
        <div class="kv-row"><span class="kv-key">Country</span><span class="kv-val">{d.get('country','')}</span></div>
        <div class="kv-row"><span class="kv-key">ASN</span><span class="kv-val">{d.get('asn','')}</span></div>
    </div>
    """, unsafe_allow_html=True)

    adversaries = d.get("adversaries", [])
    if adversaries:
        adv_html = " ".join(f'<span class="tag tag-apt">{a}</span>' for a in adversaries)
        st.markdown(f"**Threat Actors:** {adv_html}", unsafe_allow_html=True)

    mal_families = d.get("malware_families", [])
    if mal_families:
        mf_html = " ".join(f'<span class="tag tag-malware">{m}</span>' for m in mal_families)
        st.markdown(f"**Malware Families:** {mf_html}", unsafe_allow_html=True)

    pulses = d.get("pulses", [])
    if pulses:
        with st.expander(f"📋 Related Pulses ({pulse_count})", expanded=False):
            for p in pulses:
                st.markdown(f"- {p}")


def render_greynoise_result(d: dict):
    if d.get("error"):
        st.warning(f"GreyNoise: {d['error']}")
        return
    cls = d.get("classification", "unknown")
    is_noise = d.get("noise", False)
    is_riot = d.get("riot", False)
    color_map = {"malicious": "#ff3366", "benign": "#00ff88", "unknown": "#94a3b8"}
    color = color_map.get(cls, "#94a3b8")
    st.markdown(f"""
    <div class="result-card {'danger' if cls=='malicious' else 'safe' if cls=='benign' else 'info'}">
        <div class="card-title">🔊 GREYNOISE</div>
        <div class="kv-row"><span class="kv-key">Classification</span><span class="kv-val" style="color:{color};font-weight:700;text-transform:uppercase">{cls}</span></div>
        <div class="kv-row"><span class="kv-key">Internet Noise</span><span class="kv-val">{'Yes — benign scanner/crawler' if is_noise else 'No'}</span></div>
        <div class="kv-row"><span class="kv-key">RIOT (Known Good)</span><span class="kv-val" style="color:{'#00ff88' if is_riot else '#94a3b8'}">{'Yes' if is_riot else 'No'}</span></div>
        <div class="kv-row"><span class="kv-key">Name</span><span class="kv-val">{d.get('name','')}</span></div>
        <div class="kv-row"><span class="kv-key">Last Seen</span><span class="kv-val">{d.get('last_seen','')}</span></div>
        <div class="kv-row"><span class="kv-key">Note</span><span class="kv-val">{d.get('message','')}</span></div>
    </div>
    """, unsafe_allow_html=True)


def render_urlscan_result(d: dict):
    if d.get("error"):
        st.warning(f"URLScan: {d['error']}")
        return
    if d.get("info"):
        st.info(f"URLScan.io: {d['info']}")
        return
    results = d.get("results", [])
    for res in results:
        mal = res.get("malicious", False)
        st.markdown(f"""
        <div class="result-card {'danger' if mal else 'info'}">
            <div class="card-title">🌍 URLSCAN.IO SCAN RESULT</div>
            <div class="kv-row"><span class="kv-key">Verdict</span><span class="kv-val" style="color:{'#ff3366' if mal else '#00ff88'};font-weight:700">{'MALICIOUS ⚠️' if mal else 'CLEAN ✓'}</span></div>
            <div class="kv-row"><span class="kv-key">Domain</span><span class="kv-val">{res.get('domain','')}</span></div>
            <div class="kv-row"><span class="kv-key">IP</span><span class="kv-val">{res.get('ip','')}</span></div>
            <div class="kv-row"><span class="kv-key">Country</span><span class="kv-val">{res.get('country','')}</span></div>
            <div class="kv-row"><span class="kv-key">Server</span><span class="kv-val">{res.get('server','')}</span></div>
            <div class="kv-row"><span class="kv-key">Score</span><span class="kv-val">{res.get('score',0)}</span></div>
        </div>
        """, unsafe_allow_html=True)
        scan_id = res.get("scan_id")
        if scan_id:
            st.markdown(f"[🔗 View full scan report](https://urlscan.io/result/{scan_id}/)", unsafe_allow_html=False)


def render_ipinfo_result(d: dict):
    if d.get("error"):
        return
    st.markdown(f"""
    <div class="result-card info">
        <div class="card-title">📍 IP GEOLOCATION (IPInfo)</div>
        <div class="kv-row"><span class="kv-key">Organization</span><span class="kv-val">{d.get('org','')}</span></div>
        <div class="kv-row"><span class="kv-key">Location</span><span class="kv-val">{d.get('city','')}, {d.get('region','')}, {d.get('country','')}</span></div>
        <div class="kv-row"><span class="kv-key">Timezone</span><span class="kv-val">{d.get('timezone','')}</span></div>
        <div class="kv-row"><span class="kv-key">Hostname</span><span class="kv-val">{d.get('hostname','')}</span></div>
        <div class="kv-row"><span class="kv-key">Bogon IP</span><span class="kv-val">{'Yes' if d.get('bogon') else 'No'}</span></div>
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────
# SESSION STATE INIT
# ─────────────────────────────────────────

if "history" not in st.session_state:
    st.session_state.history = []
if "last_results" not in st.session_state:
    st.session_state.last_results = None
if "last_ioc" not in st.session_state:
    st.session_state.last_ioc = ""
if "last_type" not in st.session_state:
    st.session_state.last_type = ""
if "bulk_results" not in st.session_state:
    st.session_state.bulk_results = []


# ─────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style='padding:16px 0 8px;'>
        <div style='font-family:JetBrains Mono;font-size:0.65rem;letter-spacing:3px;color:#94a3b8;margin-bottom:8px;'>NAVIGATION</div>
    </div>
    """, unsafe_allow_html=True)

    page = st.radio(
        "Page",
        ["🔍 Single IOC Check", "📦 Bulk IOC Check", "📜 History", "⚙️ API Configuration"],
        label_visibility="collapsed"
    )

    st.markdown("<hr style='border-color:#1e2d40;margin:16px 0;'>", unsafe_allow_html=True)

    # API Status
    st.markdown("""
    <div style='font-family:JetBrains Mono;font-size:0.65rem;letter-spacing:3px;color:#94a3b8;margin-bottom:10px;'>API STATUS</div>
    """, unsafe_allow_html=True)

    apis = {
        "VirusTotal": "virustotal",
        "AbuseIPDB": "abuseipdb",
        "Shodan": "shodan",
        "OTX": "otx",
        "URLScan": "urlscan",
        "GreyNoise": "greynoise",
        "IPInfo": "ipinfo",
    }
    for name, key in apis.items():
        k = get_api_key(key)
        dot = "🟢" if k else "🔴"
        st.markdown(f"""
        <div style='display:flex;justify-content:space-between;align-items:center;padding:4px 0;font-family:JetBrains Mono;font-size:0.8rem;'>
            <span style='color:#94a3b8;'>{name}</span>
            <span>{dot}</span>
        </div>""", unsafe_allow_html=True)

    st.markdown("<hr style='border-color:#1e2d40;margin:16px 0;'>", unsafe_allow_html=True)

    # Quick stats
    if st.session_state.history:
        st.markdown("""
        <div style='font-family:JetBrains Mono;font-size:0.65rem;letter-spacing:3px;color:#94a3b8;margin-bottom:10px;'>SESSION STATS</div>
        """, unsafe_allow_html=True)
        total = len(st.session_state.history)
        threats = sum(1 for h in st.session_state.history if h.get("level") in ("CRITICAL","HIGH"))
        st.markdown(f"""
        <div style='font-family:JetBrains Mono;font-size:0.85rem;'>
            <div style='padding:4px 0;'><span style='color:#94a3b8'>Total Checked:</span> <span style='color:#e2e8f0'>{total}</span></div>
            <div style='padding:4px 0;'><span style='color:#94a3b8'>Threats Found:</span> <span style='color:#ff3366'>{threats}</span></div>
        </div>
        """, unsafe_allow_html=True)

    if st.button("🗑️ Clear History", use_container_width=True):
        st.session_state.history = []
        st.session_state.last_results = None
        st.rerun()


# ─────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────

st.markdown("""
<div class="main-header">
    <h1>🛡️ IOC INTELLIGENCE HUB</h1>
    <p>Multi-source Indicator of Compromise Analysis Platform · Powered by VirusTotal · AbuseIPDB · Shodan · OTX · URLScan · GreyNoise</p>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────
# PAGE: SINGLE IOC
# ─────────────────────────────────────────

if page == "🔍 Single IOC Check":

    col_input, col_btn = st.columns([5, 1])
    with col_input:
        ioc_input = st.text_input(
            "Enter IOC",
            placeholder="IP Address · Domain · URL · MD5 · SHA1 · SHA256 · Email",
            label_visibility="collapsed",
        )
    with col_btn:
        check_btn = st.button("⚡ ANALYZE", use_container_width=True)

    if ioc_input:
        detected = detect_ioc_type(ioc_input.strip())
        st.markdown(f'<div class="ioc-type-badge">DETECTED TYPE: {detected}</div>', unsafe_allow_html=True)

    if check_btn and ioc_input:
        ioc = ioc_input.strip()
        ioc_type = detect_ioc_type(ioc)

        if ioc_type == "Unknown":
            st.error("❌ Could not detect IOC type. Please verify your input.")
        else:
            with st.spinner("🔍 Querying threat intelligence sources..."):
                results = run_all_checks(ioc, ioc_type)
                score, level, color = calculate_threat_score(results)

                # Save to history
                st.session_state.history.append({
                    "ioc": ioc,
                    "type": ioc_type,
                    "score": score,
                    "level": level,
                    "color": color,
                    "results": results,
                    "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                })
                st.session_state.last_results = results
                st.session_state.last_ioc = ioc
                st.session_state.last_type = ioc_type

    # Show results
    if st.session_state.last_results:
        results = st.session_state.last_results
        ioc = st.session_state.last_ioc
        ioc_type = st.session_state.last_type
        score, level, color = calculate_threat_score(results)

        # Verdict bar + charts
        c1, c2, c3 = st.columns([1.2, 1, 2])

        with c1:
            st.plotly_chart(render_score_gauge(score, level, color), use_container_width=True, config={"displayModeBar": False})

        with c2:
            donut = render_detection_donut(results.get("virustotal", {}))
            if donut:
                st.plotly_chart(donut, use_container_width=True, config={"displayModeBar": False})

        with c3:
            vt = results.get("virustotal", {})
            abuse = results.get("abuseipdb", {})
            otx = results.get("otx", {})
            gn = results.get("greynoise", {})

            # Source status pills
            pills = ""
            pills += source_pill("VirusTotal", vt)
            if ioc_type in ("IPv4","IPv6"):
                pills += source_pill("AbuseIPDB", abuse)
                pills += source_pill("Shodan", results.get("shodan",{"error":"skip"}))
                pills += source_pill("GreyNoise", gn)
                pills += source_pill("IPInfo", results.get("ipinfo",{"error":"skip"}))
            pills += source_pill("OTX", otx)
            if ioc_type in ("URL","Domain"):
                pills += source_pill("URLScan", results.get("urlscan",{"error":"skip"}))

            st.markdown(f"""
            <div class="result-card" style="height:180px;overflow:auto;">
                <div class="card-title">IOC SUMMARY</div>
                <div class="kv-row"><span class="kv-key">IOC</span><span class="kv-val" style="font-family:'JetBrains Mono';font-size:0.85rem;word-break:break-all">{ioc}</span></div>
                <div class="kv-row"><span class="kv-key">Type</span><span class="kv-val">{ioc_type}</span></div>
                <div class="kv-row"><span class="kv-key">Threat Level</span><span class="kv-val" style="color:{color};font-weight:700">{level}</span></div>
                <div style="margin-top:10px">{pills}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<hr class='section-sep'>", unsafe_allow_html=True)

        # Tabs for each source
        tabs = ["🔬 VirusTotal", "👁️ OTX"]
        if ioc_type in ("IPv4","IPv6"):
            tabs += ["🚨 AbuseIPDB", "🌐 Shodan", "🔊 GreyNoise", "📍 IPInfo"]
        if ioc_type in ("URL","Domain"):
            tabs += ["🌍 URLScan"]
        tabs += ["📄 Raw JSON"]

        tab_objs = st.tabs(tabs)
        tab_idx = 0

        with tab_objs[tab_idx]: render_vt_result(results.get("virustotal", {}))
        tab_idx += 1
        with tab_objs[tab_idx]: render_otx_result(results.get("otx", {}))
        tab_idx += 1

        if ioc_type in ("IPv4","IPv6"):
            with tab_objs[tab_idx]: render_abuseipdb_result(results.get("abuseipdb", {}))
            tab_idx += 1
            with tab_objs[tab_idx]: render_shodan_result(results.get("shodan", {}))
            tab_idx += 1
            with tab_objs[tab_idx]: render_greynoise_result(results.get("greynoise", {}))
            tab_idx += 1
            with tab_objs[tab_idx]: render_ipinfo_result(results.get("ipinfo", {}))
            tab_idx += 1

        if ioc_type in ("URL","Domain"):
            with tab_objs[tab_idx]: render_urlscan_result(results.get("urlscan", {}))
            tab_idx += 1

        with tab_objs[tab_idx]:
            st.code(json.dumps(results, indent=2, default=str), language="json")


# ─────────────────────────────────────────
# PAGE: BULK IOC
# ─────────────────────────────────────────

elif page == "📦 Bulk IOC Check":
    st.markdown("""
    <div class="result-card info">
        <div class="card-title">📦 BULK IOC ANALYSIS</div>
        <p style="color:#94a3b8;font-size:0.9rem;margin:0">Enter one IOC per line. Mixed types supported (IP, Domain, Hash, URL).</p>
    </div>
    """, unsafe_allow_html=True)

    bulk_input = st.text_area(
        "IOC List",
        height=200,
        placeholder="8.8.8.8\nmalware.example.com\nhttps://phishing.site/page\nd41d8cd98f00b204e9800998ecf8427e",
        label_visibility="collapsed",
    )

    col_run, col_dl = st.columns([2, 1])
    with col_run:
        run_bulk = st.button("⚡ RUN BULK ANALYSIS", use_container_width=True)

    if run_bulk and bulk_input:
        ioc_list = [line.strip() for line in bulk_input.splitlines() if line.strip()]
        st.session_state.bulk_results = []

        progress = st.progress(0)
        status_txt = st.empty()

        for i, ioc in enumerate(ioc_list):
            ioc_type = detect_ioc_type(ioc)
            status_txt.markdown(f"<span style='font-family:JetBrains Mono;color:#94a3b8;font-size:0.85rem'>Checking {i+1}/{len(ioc_list)}: {ioc}</span>", unsafe_allow_html=True)
            results = run_all_checks(ioc, ioc_type)
            score, level, color = calculate_threat_score(results)

            row = {
                "IOC": ioc,
                "Type": ioc_type,
                "Threat Level": level,
                "Score": score,
                "VT Malicious": results.get("virustotal",{}).get("malicious","N/A"),
                "VT Det. Rate": f"{results.get('virustotal',{}).get('detection_rate','N/A')}%",
                "Abuse Score": results.get("abuseipdb",{}).get("abuse_score","N/A"),
                "OTX Pulses": results.get("otx",{}).get("pulse_count","N/A"),
                "GN Class.": results.get("greynoise",{}).get("classification","N/A"),
                "Country": results.get("virustotal",{}).get("country","") or results.get("abuseipdb",{}).get("country",""),
            }
            st.session_state.bulk_results.append(row)

            # Add to history too
            st.session_state.history.append({
                "ioc": ioc, "type": ioc_type, "score": score, "level": level,
                "color": color, "results": results, "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

            progress.progress((i + 1) / len(ioc_list))
            time.sleep(0.3)  # Rate limit courtesy

        status_txt.empty()
        progress.empty()

    if st.session_state.bulk_results:
        df = pd.DataFrame(st.session_state.bulk_results)

        # Summary bar chart
        level_counts = df["Threat Level"].value_counts().reset_index()
        level_counts.columns = ["Level", "Count"]
        color_map = {"CRITICAL": "#ff3366", "HIGH": "#ff8c42", "MEDIUM": "#ffd700", "LOW": "#4dabf7", "CLEAN": "#00ff88"}
        fig = px.bar(
            level_counts, x="Level", y="Count",
            color="Level",
            color_discrete_map=color_map,
            title="Threat Level Distribution",
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font={"color": "#e2e8f0", "family": "JetBrains Mono"},
            title_font={"color": "#94a3b8", "size": 13},
            showlegend=False, height=250,
            margin={"t": 40, "b": 10, "l": 10, "r": 10},
        )
        fig.update_xaxes(gridcolor="#1e2d40", linecolor="#1e2d40")
        fig.update_yaxes(gridcolor="#1e2d40", linecolor="#1e2d40")
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        # Styled table
        def style_level(val):
            colors = {"CRITICAL": "#ff3366", "HIGH": "#ff8c42", "MEDIUM": "#ffd700", "LOW": "#4dabf7", "CLEAN": "#00ff88"}
            c = colors.get(val, "#94a3b8")
            return f"color: {c}; font-weight: bold; font-family: JetBrains Mono;"

        styled = df.style.applymap(style_level, subset=["Threat Level"])
        st.dataframe(styled, use_container_width=True, hide_index=True)

        # Download CSV
        csv = df.to_csv(index=False)
        st.download_button(
            "📥 Download CSV Report",
            data=csv,
            file_name=f"ioc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )


# ─────────────────────────────────────────
# PAGE: HISTORY
# ─────────────────────────────────────────

elif page == "📜 History":
    st.markdown("""
    <div class="result-card info">
        <div class="card-title">📜 INVESTIGATION HISTORY</div>
    </div>
    """, unsafe_allow_html=True)

    if not st.session_state.history:
        st.info("No IOC checks performed yet in this session.")
    else:
        for i, h in enumerate(reversed(st.session_state.history)):
            color = h.get("color", "#94a3b8")
            st.markdown(f"""
            <div class="history-item">
                <span style="font-family:JetBrains Mono;font-size:0.7rem;color:#94a3b8;min-width:70px">{h.get('type','')}</span>
                <span style="font-family:JetBrains Mono;font-size:0.9rem;flex:1;word-break:break-all">{h.get('ioc','')}</span>
                <span style="color:{color};font-family:JetBrains Mono;font-size:0.8rem;font-weight:700;min-width:80px;text-align:right">{h.get('level','')} ({h.get('score',0)})</span>
                <span style="color:#4a5568;font-family:JetBrains Mono;font-size:0.75rem;min-width:120px;text-align:right">{h.get('ts','')}</span>
            </div>
            """, unsafe_allow_html=True)


# ─────────────────────────────────────────
# PAGE: API CONFIGURATION
# ─────────────────────────────────────────

elif page == "⚙️ API Configuration":
    st.markdown("""
    <div class="result-card info">
        <div class="card-title">⚙️ API CONFIGURATION GUIDE</div>
        <p style="color:#94a3b8;font-size:0.9rem;margin:8px 0 0">API keys are loaded from Streamlit Secrets — tidak perlu input setiap sesi.</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    ### Cara Setup API Keys

    Buat file `.streamlit/secrets.toml` di root folder project kamu dengan format berikut:
    """)

    st.code("""[api_keys]
virustotal    = "PASTE_YOUR_KEY_HERE"
abuseipdb     = "PASTE_YOUR_KEY_HERE"
shodan        = "PASTE_YOUR_KEY_HERE"
otx           = "PASTE_YOUR_KEY_HERE"
urlscan       = "PASTE_YOUR_KEY_HERE"
greynoise     = "PASTE_YOUR_KEY_HERE"
ipinfo        = "PASTE_YOUR_KEY_HERE"
""", language="toml")

    st.markdown("""<hr class='section-sep'>""", unsafe_allow_html=True)

    api_info = [
        ("🔬 VirusTotal", "virustotal", "https://www.virustotal.com/gui/my-apikey", "Free: 4 req/min, 500/day · Premium tersedia", "Hash, IP, Domain, URL"),
        ("🚨 AbuseIPDB", "abuseipdb", "https://www.abuseipdb.com/account/api", "Free: 1,000 req/day · Basic tier gratis", "IP Address only"),
        ("🌐 Shodan", "shodan", "https://account.shodan.io/", "Free: 1 req/sec · Developer $49/mo", "IP Address only"),
        ("👁️ OTX AlienVault", "otx", "https://otx.alienvault.com/api/", "Free tier tersedia (rate limited)", "IP, Domain, URL, Hash"),
        ("🌍 URLScan.io", "urlscan", "https://urlscan.io/user/apikey", "Free: 100 scans/hr · search unlimited", "URL, Domain only"),
        ("🔊 GreyNoise", "greynoise", "https://www.greynoise.io/account/api-keys", "Community tier gratis", "IP Address only"),
        ("📍 IPInfo", "ipinfo", "https://ipinfo.io/account/token", "Free: 50K req/month", "IP Address only"),
    ]

    for name, key, url, pricing, covers in api_info:
        configured = get_api_key(key)
        status = "🟢 CONFIGURED" if configured else "🔴 NOT SET"
        st.markdown(f"""
        <div class="result-card">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;">
                <div>
                    <div style="font-size:1rem;font-weight:600;margin-bottom:4px">{name}</div>
                    <div class="kv-row"><span class="kv-key">Covers</span><span class="kv-val">{covers}</span></div>
                    <div class="kv-row"><span class="kv-key">Pricing</span><span class="kv-val" style="font-size:0.85rem">{pricing}</span></div>
                    <div class="kv-row"><span class="kv-key">Get Key</span><span class="kv-val"><a href="{url}" target="_blank" style="color:#4dabf7">{url}</a></span></div>
                </div>
                <div style="font-family:JetBrains Mono;font-size:0.8rem;padding:6px 12px;border-radius:4px;background:{'#00ff8810' if configured else '#ff336610'};color:{'#00ff88' if configured else '#ff3366'};border:1px solid {'#00ff8830' if configured else '#ff336630'};white-space:nowrap">{status}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""<hr class='section-sep'>""", unsafe_allow_html=True)
    st.markdown("""
    ### ⚠️ Security Note

    > **Jangan pernah** commit file `secrets.toml` ke Git repository.
    > Tambahkan `.streamlit/secrets.toml` ke `.gitignore` kamu.

    Jika deploy ke **Streamlit Cloud**, masukkan API keys melalui:
    `App Settings → Secrets → Paste isi secrets.toml`
    """)

    st.code("# .gitignore\n.streamlit/secrets.toml\n*.toml", language="gitignore")
