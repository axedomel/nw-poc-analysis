#!/usr/bin/env python3
"""
NetWitness NDR v12.5 — PoC Traffic Analysis
Generates a dynamic HTML report with qualitative and quantitative traffic analysis.

╔══════════════════════════════════════════════════════════════════════╗
║  LAB ENVIRONMENT — 192.168.1.112 (Network Hybrid)                    ║
╠══════════════════════════════════════════════════════════════════════╣
║  Host 192.168.1.112 is a Network Hybrid — Decoder + Concentrator     ║
║  on one box. Port map (HTTPS, self-signed cert):                     ║
║                                                                      ║
║    50104  →  Packet/Log DECODER SDK      (/sdk, /decoder)            ║
║    50105  →  CONCENTRATOR SDK            (/sdk, /concentrator,       ║
║                                           /index, /database)         ║
║    50106  →  NwAppliance (mgmt agent)    (/appliance, /services)     ║
║                                           — NO /sdk here!            ║
║                                                                      ║
║  Message bus (AMQP):   192.168.1.111:5671                            ║
║  Credentials:          admin / netwitness                            ║
║                                                                      ║
║  NOTE: Port 50106 may be described as "access to the hybrid" — it's  ║
║  the management agent, NOT a data service. For data queries use      ║
║  50105 (Concentrator — indexed meta) or 50104 (Decoder —             ║
║  payload/client).                                                    ║
╚══════════════════════════════════════════════════════════════════════╝

Usage (for lab 192.168.1.112):
  python3 nw_poc_analysis_en.py \\
    --concentrator 192.168.1.112 --concentrator-port 50105 \\
    --decoder      192.168.1.112 --decoder-port      50104 \\
    --user admin --password 'netwitness' \\
    --hours 168 \\
    --output /home/sysadmin/Uploads/nw_report.html

Usage (generic template):
  python3 nw_poc_analysis_en.py \\
    --concentrator <IP> --concentrator-port 50105 \\
    --decoder      <IP> --decoder-port      50104 \\
    --user admin --password '<PASS>' \\
    --hours 24 \\
    --output report.html

╔══════════════════════════════════════════════════════════════════════╗
║  NW 12 SDK API — QUIRKS (confirmed on this lab)                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  1. Field parameter:  fieldName=X   (NOT value=X — returns HTTP 500) ║
║  2. Response XML:                                                    ║
║       <results><field count="N" type="svc">VALUE</field></results>   ║
║     (not <count value="X">N</count>, not <value count="N">X</value>) ║
║  3. where= with time:  time=1700000000-1700086400  (unix timestamps) ║
║     ISO form with apostrophes ('2026-...Z'-'...') → 400 rule syntax. ║
║  4. Compound where:  time=A-B && service=443 && analysis.session='x' ║
║  5. Non-indexed meta keys → 500 'non-indexed meta key: X'.           ║
║     _get() swallows this → empty result (no crash).                  ║
╚══════════════════════════════════════════════════════════════════════╝

Quick manual check (curl) that a port is really the Concentrator:
  curl -sk -u admin:netwitness https://192.168.1.112:50105/ | grep -o '/concentrator'
  # → should return '/concentrator'
  # For Decoder analogously: https://.../50104/ → '/decoder'

Requirements:
  pip install requests --break-system-packages
"""

import argparse
import json
import sys
import time
import warnings
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("ERROR: pip install requests --break-system-packages")
    sys.exit(1)

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────
# NW SDK CLIENT
# ─────────────────────────────────────────────

class NWClient:
    def __init__(self, host, port, user, password, timeout=60):
        self.base = f"https://{host}:{port}"
        self.auth = (user, password)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.auth = self.auth

    def _get(self, params):
        try:
            r = self.session.get(
                f"{self.base}/sdk",
                params=params,
                timeout=self.timeout
            )
            r.raise_for_status()
            return r.text
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.Timeout:
            return None
        except Exception:
            return None

    def values(self, field, where=None, size=25):
        """Fetch top N values for a given field (msg=values)."""
        params = {
            "msg": "values",
            "fieldName": field,
            "size": size,
            "flags": 0,
            "id1": 0,
            "id2": 0,
        }
        if where:
            params["where"] = where
        raw = self._get(params)
        return self._parse_values(raw, field)

    def count(self, where=None):
        """Fetch total session count."""
        params = {
            "msg": "values",
            "fieldName": "service",
            "size": 1,
            "flags": 0,
            "id1": 0,
            "id2": 0,
        }
        if where:
            params["where"] = where
        raw = self._get(params)
        if not raw:
            return None
        try:
            root = ET.fromstring(raw)
            # Look for total attribute or sum counts
            total = root.get("total") or root.get("count")
            if total:
                return int(total)
            counts = root.findall(".//count")
            return sum(int(c.get("count", c.text or 0)) for c in counts)
        except Exception:
            return None

    def _parse_values(self, raw, field):
        """Parse msg=values XML → list of (value, count)."""
        if not raw:
            return []
        try:
            root = ET.fromstring(raw)
            results = []
            # NW 12 format: <results><field count="N" ...>VALUE</field></results>
            for field_el in root.findall(".//field"):
                val = (field_el.text or "").strip()
                try:
                    cnt = int(field_el.get("count", 0))
                except (TypeError, ValueError):
                    cnt = 0
                if val:
                    results.append((val, cnt))
            # Legacy format 1: <counts><count value="X">N</count></counts>
            if not results:
                for count_el in root.findall(".//count"):
                    val = count_el.get("value", "")
                    try:
                        cnt = int(count_el.text or 0)
                    except (TypeError, ValueError):
                        cnt = 0
                    if val:
                        results.append((val, cnt))
            # Legacy format 2: <value count="N">X</value>
            if not results:
                for val_el in root.findall(".//value"):
                    val = val_el.text or ""
                    try:
                        cnt = int(val_el.get("count", 0))
                    except (TypeError, ValueError):
                        cnt = 0
                    if val:
                        results.append((val, cnt))
            results.sort(key=lambda x: x[1], reverse=True)
            return results
        except ET.ParseError:
            # Fallback: try plain-text parsing
            lines = []
            for line in raw.strip().splitlines():
                parts = line.strip().split("\t")
                if len(parts) == 2:
                    try:
                        lines.append((parts[0], int(parts[1])))
                    except ValueError:
                        pass
            return sorted(lines, key=lambda x: x[1], reverse=True)

    def ping(self):
        """Check if the endpoint is reachable."""
        params = {"msg": "values", "fieldName": "service", "size": 1,
                  "flags": 0, "id1": 0, "id2": 0}
        raw = self._get(params)
        return raw is not None


# ─────────────────────────────────────────────
# ANALYSIS
# ─────────────────────────────────────────────

def build_time_where(hours):
    """Build the time where-clause for SDK (unix timestamps)."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    return f"time={int(start.timestamp())}-{int(now.timestamp())}"

def run_analysis(conc, dec, hours):
    """Run the full analysis. Returns a dict with results."""
    tw = build_time_where(hours)
    data = {
        "meta": {
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hours": hours,
            "concentrator": conc.base,
            "decoder": dec.base if dec else "N/A",
            "time_range": tw
        },
        "sections": {}
    }

    def fetch(client, field, where=tw, size=25, label=""):
        print(f"  [{label or field}]...", end=" ", flush=True)
        t0 = time.time()
        result = client.values(field, where=where, size=size)
        elapsed = time.time() - t0
        print(f"{'OK' if result else 'NONE'} ({elapsed:.1f}s, {len(result)} rows)")
        return result

    print("\n[CONCENTRATOR — Quantitative analysis]")

    # 1. Protocol distribution
    data["sections"]["protocols"] = {
        "title": "Protocol distribution (service)",
        "desc": "Dominant protocols in traffic. service=0 = traffic unidentified by parsers.",
        "data": fetch(conc, "service", size=30, label="protocols")
    }

    # 2. Top source IPs
    data["sections"]["top_src"] = {
        "title": "Top source IPs (ip.src)",
        "desc": "Hosts generating the most network traffic — candidates for analysis and filtering.",
        "data": fetch(conc, "ip.src", size=20, label="top src IP")
    }

    # 3. Top destination IPs
    data["sections"]["top_dst"] = {
        "title": "Top destination IPs (ip.dst)",
        "desc": "Most common destinations. External IPs worth checking against threat intel.",
        "data": fetch(conc, "ip.dst", size=20, label="top dst IP")
    }

    # 4. Top hostnames (alias.host)
    data["sections"]["top_host"] = {
        "title": "Top hostnames (alias.host)",
        "desc": "Domains the traffic hits. Useful to identify streaming, update, CDN.",
        "data": fetch(conc, "alias.host", size=25, label="top hostnames")
    }

    # 5. Traffic direction
    data["sections"]["direction"] = {
        "title": "Traffic direction (direction)",
        "desc": "inbound=from outside, outbound=to outside, lateral=internal East-West. Requires traffic_flow.lua.",
        "data": fetch(conc, "direction", size=10, label="direction")
    }

    # 6. Session analysis
    data["sections"]["session_analysis"] = {
        "title": "Session characteristics (analysis.session)",
        "desc": "Values from session_analysis.lua. Key ones: potential beacon, high transmitted outbound, long connection.",
        "data": fetch(conc, "analysis.session", size=34, label="session analysis")
    }

    # 7. HTTP service analysis
    data["sections"]["http_analysis"] = {
        "title": "HTTP characteristics (analysis.service)",
        "desc": "HTTP anomalies: no user-agent, direct to IP, post no get. Requires HTTP_lua advanced()=true.",
        "data": fetch(conc, "analysis.service", size=30, label="analysis.service")
    }

    # 8. Unknown traffic — top ports
    data["sections"]["unknown_ports"] = {
        "title": "Unidentified destination ports (service=0)",
        "desc": "Traffic where the parser could not identify the protocol. Blind spot — no meta beyond IP and port.",
        "data": fetch(conc, "tcp.dstport",
                      where=f"{tw} && service=0", size=20,
                      label="unknown tcp.dstport")
    }

    # 9. TLS encryption
    data["sections"]["tls"] = {
        "title": "TLS versions (analysis.service)",
        "desc": "TLS 1.0/1.1 = vulnerable, should be eliminated. TLS 1.3 = gold standard.",
        "data": fetch(conc, "analysis.service",
                      where=f"{tw} && service=443",
                      size=15, label="TLS versions")
    }

    # 10. IOC/BOC/EOC tags
    data["sections"]["boc"] = {
        "title": "Behaviors of Compromise (boc)",
        "desc": "Active AR rules that produced BOC tags. What the system has already detected.",
        "data": fetch(conc, "boc", size=30, label="boc tags")
    }

    data["sections"]["ioc"] = {
        "title": "Indicators of Compromise (ioc)",
        "desc": "Active AR rules that produced IOC tags — higher priority than BOC.",
        "data": fetch(conc, "ioc", size=20, label="ioc tags")
    }

    data["sections"]["eoc"] = {
        "title": "Enablers of Compromise (eoc)",
        "desc": "EOC tags — behaviors that enable attacks (telnet, cleartext, default creds).",
        "data": fetch(conc, "eoc", size=20, label="eoc tags")
    }

    # 11. Session sizes
    data["sections"]["session_sizes"] = {
        "title": "Session size distribution",
        "desc": "Many 0-5k sessions = noise, NTP, DNS, beaconing. Many 100k+ = backup, streaming, exfil.",
        "data": [
            (tag, len(fetch(conc, "service",
                            where=f"{tw} && analysis.session='{tag}'",
                            size=1, label=f"size {tag}")))
            for tag in [
                "session size 0-5k",
                "session size 5-10k",
                "session size 10-50k",
                "session size 50-100k",
                "session size 100-250k"
            ]
        ]
    }

    # 12. Threat intelligence
    data["sections"]["threat_cat"] = {
        "title": "Threat categories (threat.category)",
        "desc": "Categories from threat intelligence feeds. Empty = no feed loaded.",
        "data": fetch(conc, "threat.category", size=20, label="threat.category")
    }

    data["sections"]["threat_desc"] = {
        "title": "Threat descriptions (threat.desc)",
        "desc": "Detailed feed descriptions — specific malicious hosts / IP ranges.",
        "data": fetch(conc, "threat.desc", size=20, label="threat.desc")
    }

    # 13. Beacon candidates
    data["sections"]["beacons"] = {
        "title": "Potential beacons — top IPs (potential beacon)",
        "desc": "IPs connecting at regular intervals. Classic C2 or malware pattern.",
        "data": fetch(conc, "ip.dst",
                      where=f"{tw} && analysis.session='potential beacon'",
                      size=15, label="beacon dst IPs")
    }

    # 14. Long connections
    data["sections"]["long_conn"] = {
        "title": "Long connections — top destinations (long connection)",
        "desc": "Sessions lasting >30s. C2, tunnels, streaming. External IPs require analysis.",
        "data": fetch(conc, "ip.dst",
                      where=f"{tw} && analysis.session='long connection'",
                      size=15, label="long connection IPs")
    }

    # 15. Large outbound transfers
    data["sections"]["large_outbound"] = {
        "title": "Large outbound transfers — top destinations",
        "desc": "Sessions with requestPayload >= 4MB. Exfil, backup, upload. External IPs require verification.",
        "data": fetch(conc, "ip.dst",
                      where=f"{tw} && analysis.session='high transmitted outbound'",
                      size=15, label="high outbound IPs")
    }

    # 16. Decoder — payload sizes (if available)
    if dec:
        print("\n[DECODER — Payload analysis]")
        data["sections"]["decoder_payload"] = {
            "title": "Request payload per protocol (Decoder)",
            "desc": "Request payload sizes per service. Decoder data — more accurate than Concentrator.",
            "data": fetch(dec, "service", size=20, label="decoder services")
        }
        data["sections"]["decoder_clients"] = {
            "title": "Top User-Agent / clients (Decoder)",
            "desc": "Apps generating HTTP traffic. Unknown user-agents = potential malware.",
            "data": fetch(dec, "client", size=20, label="decoder clients")
        }
    else:
        data["sections"]["decoder_payload"] = {
            "title": "Decoder unavailable",
            "desc": "Skipped or connection failed.",
            "data": []
        }

    # Compute summary statistics
    total_sessions = sum(c for _, c in data["sections"]["protocols"]["data"])
    tls_sessions = sum(c for v, c in data["sections"]["protocols"]["data"] if v == "443")
    unknown_sessions = sum(c for v, c in data["sections"]["protocols"]["data"] if v == "0")
    boc_count = sum(c for _, c in data["sections"]["boc"]["data"])
    ioc_count = sum(c for _, c in data["sections"]["ioc"]["data"])

    data["summary"] = {
        "total_sessions": total_sessions,
        "tls_sessions": tls_sessions,
        "tls_pct": round(tls_sessions / total_sessions * 100, 1) if total_sessions else 0,
        "unknown_sessions": unknown_sessions,
        "unknown_pct": round(unknown_sessions / total_sessions * 100, 1) if total_sessions else 0,
        "boc_count": boc_count,
        "ioc_count": ioc_count,
        "has_threat_intel": len(data["sections"]["threat_cat"]["data"]) > 0,
        "beacon_count": len(data["sections"]["beacons"]["data"]),
    }

    return data


# ─────────────────────────────────────────────
# HTML GENERATOR
# ─────────────────────────────────────────────

def generate_html(data):
    meta = data["meta"]
    summary = data["summary"]
    sections = data["sections"]

    def risk_color(value, thresholds):
        """Return a color based on thresholds (low, medium, high)."""
        if value >= thresholds[1]:
            return "#ef4444"
        elif value >= thresholds[0]:
            return "#f59e0b"
        return "#22c55e"

    def make_table(rows, col1="Value", col2="Sessions", section_id=""):
        if not rows:
            return '<p class="no-data">No data — the field may not be indexed or there is no traffic in this range.</p>'
        html = f'''
        <div class="table-wrapper">
          <input type="text" class="table-search" placeholder="Search..."
                 onkeyup="filterTable(this, '{section_id}')" />
          <table id="{section_id}" class="data-table">
            <thead>
              <tr>
                <th onclick="sortTable('{section_id}', 0)">{col1} ↕</th>
                <th onclick="sortTable('{section_id}', 1)">{col2} ↕</th>
                <th>Share %</th>
                <th>Bar</th>
              </tr>
            </thead>
            <tbody>
        '''
        total = sum(c for _, c in rows) or 1
        max_val = max((c for _, c in rows), default=1) or 1
        for val, cnt in rows:
            pct = round(cnt / total * 100, 1)
            bar_w = round(cnt / max_val * 100)
            html += f'''
              <tr>
                <td class="mono">{val}</td>
                <td class="num">{cnt:,}</td>
                <td class="num">{pct}%</td>
                <td><div class="bar" style="width:{bar_w}%"></div></td>
              </tr>
            '''
        html += '</tbody></table></div>'
        return html

    def make_section(key, col1="Value", col2="Sessions"):
        s = sections.get(key, {})
        title = s.get("title", key)
        desc = s.get("desc", "")
        rows = s.get("data", [])
        sid = f"tbl_{key}"
        return f'''
        <section class="card" id="sec_{key}">
          <div class="card-header">
            <h2>{title}</h2>
            <span class="badge">{len(rows)} rows</span>
          </div>
          <p class="card-desc">{desc}</p>
          {make_table(rows, col1, col2, sid)}
        </section>
        '''

    # Chart data
    proto_labels = [v for v, _ in sections["protocols"]["data"][:10]]
    proto_counts = [c for _, c in sections["protocols"]["data"][:10]]
    dir_labels = [v for v, _ in sections["direction"]["data"]]
    dir_counts = [c for _, c in sections["direction"]["data"]]
    size_labels = [v.replace("session size ", "") for v, _ in sections["session_sizes"]["data"]]
    size_counts = [c for _, c in sections["session_sizes"]["data"]]

    # Risk indicators
    tls_risk = risk_color(summary["tls_pct"], [60, 80])  # high TLS = ok
    unknown_risk = risk_color(summary["unknown_pct"], [10, 30])  # high unknown = bad
    ioc_risk = "#ef4444" if summary["ioc_count"] > 0 else "#22c55e"
    beacon_risk = "#ef4444" if summary["beacon_count"] > 5 else ("#f59e0b" if summary["beacon_count"] > 0 else "#22c55e")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetWitness PoC — Traffic Analysis Report</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;600;700;800&display=swap');

  :root {{
    --bg: #0a0e1a;
    --bg2: #111827;
    --bg3: #1a2235;
    --border: #1e2d45;
    --accent: #00d4ff;
    --accent2: #7c3aed;
    --green: #22c55e;
    --red: #ef4444;
    --amber: #f59e0b;
    --text: #e2e8f0;
    --muted: #64748b;
    --mono: 'JetBrains Mono', monospace;
    --sans: 'Syne', sans-serif;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.6;
  }}

  /* HEADER */
  .site-header {{
    background: linear-gradient(135deg, #0a0e1a 0%, #0f1929 50%, #0a1628 100%);
    border-bottom: 1px solid var(--border);
    padding: 32px 40px;
    position: relative;
    overflow: hidden;
  }}
  .site-header::before {{
    content: '';
    position: absolute;
    top: -50%;
    right: -10%;
    width: 600px;
    height: 600px;
    background: radial-gradient(circle, rgba(0,212,255,0.04) 0%, transparent 70%);
    pointer-events: none;
  }}
  .header-top {{
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 20px;
  }}
  .header-title {{
    font-size: 28px;
    font-weight: 800;
    letter-spacing: -0.5px;
    color: #fff;
  }}
  .header-title span {{ color: var(--accent); }}
  .header-sub {{
    color: var(--muted);
    font-size: 13px;
    margin-top: 4px;
    font-family: var(--mono);
  }}
  .header-meta {{
    text-align: right;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    line-height: 1.8;
  }}
  .header-meta strong {{ color: var(--accent); }}

  /* NAV */
  .nav {{
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 0 40px;
    display: flex;
    gap: 0;
    overflow-x: auto;
    position: sticky;
    top: 0;
    z-index: 100;
  }}
  .nav a {{
    color: var(--muted);
    text-decoration: none;
    padding: 12px 16px;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    border-bottom: 2px solid transparent;
    white-space: nowrap;
    transition: all 0.2s;
  }}
  .nav a:hover {{ color: var(--accent); border-bottom-color: var(--accent); }}

  /* MAIN */
  main {{ padding: 32px 40px; max-width: 1400px; margin: 0 auto; }}

  /* SUMMARY CARDS */
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }}
  .metric {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    position: relative;
    overflow: hidden;
  }}
  .metric::before {{
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
    background: var(--accent-color, var(--accent));
  }}
  .metric-label {{
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 8px;
  }}
  .metric-value {{
    font-family: var(--mono);
    font-size: 28px;
    font-weight: 600;
    color: var(--accent-color, var(--accent));
  }}
  .metric-sub {{
    font-size: 11px;
    color: var(--muted);
    margin-top: 4px;
    font-family: var(--mono);
  }}

  /* CHARTS ROW */
  .charts-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 16px;
    margin-bottom: 32px;
  }}
  @media (max-width: 900px) {{ .charts-grid {{ grid-template-columns: 1fr; }} }}
  .chart-card {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
  }}
  .chart-card h3 {{
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 16px;
  }}
  .chart-wrapper {{ position: relative; height: 200px; }}

  /* SECTION CARDS */
  .section-title {{
    font-size: 20px;
    font-weight: 700;
    margin: 40px 0 16px;
    color: #fff;
    display: flex;
    align-items: center;
    gap: 10px;
  }}
  .section-title::after {{
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }}

  .card {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 20px;
    transition: border-color 0.2s;
  }}
  .card:hover {{ border-color: rgba(0,212,255,0.3); }}
  .card-header {{
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 8px;
  }}
  .card-header h2 {{
    font-size: 15px;
    font-weight: 700;
    color: #fff;
  }}
  .badge {{
    font-family: var(--mono);
    font-size: 10px;
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--muted);
    padding: 2px 8px;
    border-radius: 4px;
  }}
  .card-desc {{
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 16px;
    line-height: 1.5;
  }}

  /* TABLES */
  .table-wrapper {{ overflow-x: auto; }}
  .table-search {{
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 6px 12px;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 12px;
    width: 280px;
    margin-bottom: 10px;
    outline: none;
  }}
  .table-search:focus {{ border-color: var(--accent); }}

  .data-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }}
  .data-table th {{
    text-align: left;
    padding: 8px 12px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    white-space: nowrap;
    user-select: none;
  }}
  .data-table th:hover {{ color: var(--accent); }}
  .data-table td {{
    padding: 7px 12px;
    border-bottom: 1px solid rgba(30,45,69,0.5);
    vertical-align: middle;
  }}
  .data-table tr:hover td {{ background: rgba(0,212,255,0.03); }}
  .mono {{ font-family: var(--mono); font-size: 12px; }}
  .num {{ font-family: var(--mono); text-align: right; }}

  .bar {{
    height: 6px;
    background: linear-gradient(90deg, var(--accent), var(--accent2));
    border-radius: 3px;
    min-width: 2px;
    transition: width 0.3s;
  }}

  .no-data {{
    font-family: var(--mono);
    font-size: 12px;
    color: var(--muted);
    padding: 16px;
    border: 1px dashed var(--border);
    border-radius: 4px;
    text-align: center;
  }}

  /* INTERPRETATION */
  .interp-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 32px;
  }}
  @media (max-width: 700px) {{ .interp-grid {{ grid-template-columns: 1fr; }} }}
  .interp-card {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent-color, var(--accent));
    border-radius: 4px;
    padding: 16px;
  }}
  .interp-card h4 {{
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 8px;
    color: var(--accent-color, var(--accent));
  }}
  .interp-card ul {{
    list-style: none;
    font-size: 12px;
    color: var(--muted);
    line-height: 1.8;
  }}
  .interp-card ul li::before {{ content: '→ '; color: var(--accent); }}

  /* FOOTER */
  footer {{
    text-align: center;
    padding: 32px;
    color: var(--muted);
    font-family: var(--mono);
    font-size: 11px;
    border-top: 1px solid var(--border);
    margin-top: 40px;
  }}
</style>
</head>
<body>

<header class="site-header">
  <div class="header-top">
    <div>
      <div class="header-title">NetWitness NDR <span>PoC Analysis</span></div>
      <div class="header-sub">Traffic Quality & Volume Assessment Report</div>
    </div>
    <div class="header-meta">
      <strong>Generated:</strong> {meta["generated"]}<br>
      <strong>Range:</strong> last {meta["hours"]}h<br>
      <strong>Concentrator:</strong> {meta["concentrator"]}<br>
      <strong>Decoder:</strong> {meta["decoder"]}
    </div>
  </div>
</header>

<nav class="nav">
  <a href="#summary">Summary</a>
  <a href="#charts">Charts</a>
  <a href="#protocols">Protocols</a>
  <a href="#traffic">IP traffic</a>
  <a href="#quality">Quality</a>
  <a href="#threats">Threats</a>
  <a href="#filtering">Filtering</a>
  <a href="#interpretation">Interpretation</a>
</nav>

<main>

<!-- SUMMARY -->
<div id="summary">
  <div class="summary-grid">
    <div class="metric" style="--accent-color: var(--accent)">
      <div class="metric-label">Total sessions</div>
      <div class="metric-value">{summary["total_sessions"]:,}</div>
      <div class="metric-sub">over {meta["hours"]}h</div>
    </div>
    <div class="metric" style="--accent-color: {tls_risk}">
      <div class="metric-label">TLS ratio</div>
      <div class="metric-value">{summary["tls_pct"]}%</div>
      <div class="metric-sub">{summary["tls_sessions"]:,} HTTPS sessions</div>
    </div>
    <div class="metric" style="--accent-color: {unknown_risk}">
      <div class="metric-label">Unknown</div>
      <div class="metric-value">{summary["unknown_pct"]}%</div>
      <div class="metric-sub">{summary["unknown_sessions"]:,} service=0 sessions</div>
    </div>
    <div class="metric" style="--accent-color: {ioc_risk}">
      <div class="metric-label">IOC alerts</div>
      <div class="metric-value">{summary["ioc_count"]:,}</div>
      <div class="metric-sub">{"⚠ needs review" if summary["ioc_count"] > 0 else "✓ none"}</div>
    </div>
    <div class="metric" style="--accent-color: {beacon_risk}">
      <div class="metric-label">Beacon candidates</div>
      <div class="metric-value">{summary["beacon_count"]}</div>
      <div class="metric-sub">distinct IP sources</div>
    </div>
    <div class="metric" style="--accent-color: {'var(--green)' if summary['has_threat_intel'] else 'var(--red)'}">
      <div class="metric-label">Threat Intel</div>
      <div class="metric-value">{"ACTIVE" if summary["has_threat_intel"] else "NONE"}</div>
      <div class="metric-sub">{"feeds loaded" if summary["has_threat_intel"] else "load CSV feed"}</div>
    </div>
  </div>
</div>

<!-- CHARTS -->
<div id="charts" class="charts-grid">
  <div class="chart-card">
    <h3>Top protocols</h3>
    <div class="chart-wrapper">
      <canvas id="chartProto"></canvas>
    </div>
  </div>
  <div class="chart-card">
    <h3>Traffic direction</h3>
    <div class="chart-wrapper">
      <canvas id="chartDir"></canvas>
    </div>
  </div>
  <div class="chart-card">
    <h3>Session size distribution</h3>
    <div class="chart-wrapper">
      <canvas id="chartSize"></canvas>
    </div>
  </div>
</div>

<!-- PROTOCOLS -->
<h2 class="section-title" id="protocols">📡 Protocol analysis</h2>
{make_section("protocols")}
{make_section("unknown_ports", col1="Port (tcp.dstport)", col2="Sessions")}
{make_section("tls", col1="TLS version", col2="Sessions")}

<!-- IP TRAFFIC -->
<h2 class="section-title" id="traffic">🌐 IP traffic analysis</h2>
{make_section("top_src", col1="Source IP", col2="Sessions")}
{make_section("top_dst", col1="Destination IP", col2="Sessions")}
{make_section("top_host", col1="Hostname (alias.host)", col2="Sessions")}
{make_section("direction", col1="Direction", col2="Sessions")}

<!-- QUALITY -->
<h2 class="section-title" id="quality">🔬 Quality analysis</h2>
{make_section("session_analysis", col1="Session trait", col2="Sessions")}
{make_section("session_sizes", col1="Size range", col2="Sessions")}
{make_section("http_analysis", col1="HTTP trait", col2="Sessions")}
{make_section("beacons", col1="Destination IP (beacon)", col2="Sessions")}
{make_section("long_conn", col1="Destination IP (long conn)", col2="Sessions")}
{make_section("large_outbound", col1="Destination IP (large transfers)", col2="Sessions")}

<!-- THREATS -->
<h2 class="section-title" id="threats">🚨 Threat indicators</h2>
{make_section("ioc", col1="IOC tag", col2="Sessions")}
{make_section("boc", col1="BOC tag", col2="Sessions")}
{make_section("eoc", col1="EOC tag", col2="Sessions")}
{make_section("threat_cat", col1="Threat category", col2="Sessions")}
{make_section("threat_desc", col1="Threat description", col2="Sessions")}

<!-- FILTERING -->
<h2 class="section-title" id="filtering">🔧 Filtering recommendations</h2>
{make_section("decoder_payload", col1="Service (Decoder)", col2="Sessions")}
{make_section("decoder_clients", col1="User-Agent / Client", col2="Sessions")}

<!-- INTERPRETATION -->
<h2 class="section-title" id="interpretation">📋 Interpretation</h2>
<div class="interp-grid">
  <div class="interp-card" style="--accent-color: var(--accent)">
    <h4>TLS Ratio — how to read</h4>
    <ul>
      <li>&gt;80% = most traffic encrypted. Session reconstruction limited without SSL inspection.</li>
      <li>40-80% = mix. HTTP traffic is visible and reconstructible.</li>
      <li>&lt;40% = lots of cleartext traffic. Compliance issue (NIS2, PCI).</li>
    </ul>
  </div>
  <div class="interp-card" style="--accent-color: var(--amber)">
    <h4>service=0 — how to read</h4>
    <ul>
      <li>&gt;30% = big blind spot. Check top tcp.dstport — a parser may be missing.</li>
      <li>10-30% = typical for environments with custom apps.</li>
      <li>&lt;10% = good parser coverage.</li>
    </ul>
  </div>
  <div class="interp-card" style="--accent-color: var(--red)">
    <h4>IOC/BOC — how to read</h4>
    <ul>
      <li>IOC = high priority. Each tag needs review — may be a true positive.</li>
      <li>BOC = contextually suspicious behavior. Check ip.src for each tag.</li>
      <li>EOC = enablers. Telnet, cleartext, default creds — compliance and risk.</li>
    </ul>
  </div>
  <div class="interp-card" style="--accent-color: var(--accent2)">
    <h4>Beacons — how to read</h4>
    <ul>
      <li>External IPs with potential beacon = priority. Check alias.host and threat.category.</li>
      <li>Internal IPs with beacon = could be monitoring or backup agent.</li>
      <li>Whitelist known IPs before starting an investigation.</li>
    </ul>
  </div>
  <div class="interp-card" style="--accent-color: var(--green)">
    <h4>What to filter (DROP)</h4>
    <ul>
      <li>service=123 (NTP) — no analytical value, high volume.</li>
      <li>Windows Update, antivirus updates — known sources, large transfers.</li>
      <li>zero payload + single sided tcp — no-data connections (scans, RST).</li>
    </ul>
  </div>
  <div class="interp-card" style="--accent-color: var(--accent)">
    <h4>What to keep meta-only</h4>
    <ul>
      <li>Backup agents (ports 873, 9100, 10000) lateral — payload is not valuable.</li>
      <li>Spotify, YouTube (alias.host) — encrypted anyway, keep meta only.</li>
      <li>CDN traffic (akamaiedge.net, fastly.net) — careful, other services ride these too!</li>
    </ul>
  </div>
</div>

</main>

<footer>
  NetWitness NDR v12.5 · PoC Traffic Analysis · {meta["generated"]} ·
  Data from: {meta["concentrator"]} (Concentrator) + {meta["decoder"]} (Decoder)
</footer>

<script>
// ── CHARTS ──
const chartDefaults = {{
  responsive: true,
  maintainAspectRatio: false,
  plugins: {{
    legend: {{ labels: {{ color: '#64748b', font: {{ size: 11, family: 'JetBrains Mono' }} }} }}
  }}
}};

const palette = [
  '#00d4ff','#7c3aed','#22c55e','#f59e0b','#ef4444',
  '#06b6d4','#8b5cf6','#84cc16','#fb923c','#f43f5e',
];

// Protocols — bar chart
new Chart(document.getElementById('chartProto'), {{
  type: 'bar',
  data: {{
    labels: {json.dumps(proto_labels)},
    datasets: [{{
      data: {json.dumps(proto_counts)},
      backgroundColor: palette.slice(0, {len(proto_labels)}),
      borderRadius: 4,
      borderSkipped: false,
    }}]
  }},
  options: {{
    ...chartDefaults,
    plugins: {{ ...chartDefaults.plugins, legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#64748b', font: {{ size: 10, family: 'JetBrains Mono' }} }} }},
      y: {{ ticks: {{ color: '#64748b', font: {{ size: 10 }} }}, grid: {{ color: '#1e2d45' }} }}
    }}
  }}
}});

// Direction — doughnut
new Chart(document.getElementById('chartDir'), {{
  type: 'doughnut',
  data: {{
    labels: {json.dumps(dir_labels)},
    datasets: [{{
      data: {json.dumps(dir_counts)},
      backgroundColor: palette,
      borderWidth: 0,
      hoverOffset: 8,
    }}]
  }},
  options: {{
    ...chartDefaults,
    cutout: '65%',
  }}
}});

// Sizes — horizontal bar
new Chart(document.getElementById('chartSize'), {{
  type: 'bar',
  data: {{
    labels: {json.dumps(size_labels)},
    datasets: [{{
      data: {json.dumps(size_counts)},
      backgroundColor: palette,
      borderRadius: 4,
      borderSkipped: false,
    }}]
  }},
  options: {{
    ...chartDefaults,
    indexAxis: 'y',
    plugins: {{ ...chartDefaults.plugins, legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#64748b', font: {{ size: 10 }} }}, grid: {{ color: '#1e2d45' }} }},
      y: {{ ticks: {{ color: '#64748b', font: {{ size: 10, family: 'JetBrains Mono' }} }} }}
    }}
  }}
}});

// ── TABLE SORT ──
function sortTable(tableId, col) {{
  const table = document.getElementById(tableId);
  const tbody = table.querySelector('tbody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  const asc = table.dataset.sortCol == col && table.dataset.sortDir == 'asc';
  table.dataset.sortCol = col;
  table.dataset.sortDir = asc ? 'desc' : 'asc';
  rows.sort((a, b) => {{
    const av = a.cells[col].textContent.replace(/[,%]/g,'').trim();
    const bv = b.cells[col].textContent.replace(/[,%]/g,'').trim();
    const an = parseFloat(av), bn = parseFloat(bv);
    if (!isNaN(an) && !isNaN(bn)) return asc ? bn - an : an - bn;
    return asc ? bv.localeCompare(av) : av.localeCompare(bv);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}

// ── TABLE FILTER ──
function filterTable(input, tableId) {{
  const q = input.value.toLowerCase();
  const rows = document.getElementById(tableId).querySelectorAll('tbody tr');
  rows.forEach(r => {{
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}

// ── NAV HIGHLIGHT ──
const sections = document.querySelectorAll('h2.section-title, #summary, #charts');
const navLinks = document.querySelectorAll('.nav a');
window.addEventListener('scroll', () => {{
  let current = '';
  sections.forEach(s => {{
    if (window.scrollY >= s.offsetTop - 80) current = s.id;
  }});
  navLinks.forEach(a => {{
    a.style.color = a.getAttribute('href') === '#' + current ? '#00d4ff' : '';
    a.style.borderBottomColor = a.getAttribute('href') === '#' + current ? '#00d4ff' : 'transparent';
  }});
}});
</script>
</body>
</html>"""

    return html


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NetWitness PoC Traffic Analysis — generates an HTML report"
    )
    parser.add_argument("--concentrator", required=True,
                        help="Concentrator IP or hostname")
    parser.add_argument("--concentrator-port", default=50104, type=int,
                        help="Concentrator port (default 50104)")
    parser.add_argument("--decoder",
                        help="Decoder IP or hostname (optional)")
    parser.add_argument("--decoder-port", default=50102, type=int,
                        help="Decoder port (default 50102)")
    parser.add_argument("--user", required=True, help="Username")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--hours", default=24, type=int,
                        help="Analysis range in hours (default 24)")
    parser.add_argument("--output", default="nw_poc_report.html",
                        help="Output HTML file (default nw_poc_report.html)")
    args = parser.parse_args()

    print("=" * 60)
    print("NetWitness PoC Traffic Analysis")
    print("=" * 60)
    print(f"Concentrator: {args.concentrator}:{args.concentrator_port}")
    print(f"Decoder:      {args.decoder or 'skipped'}:{args.decoder_port}")
    print(f"Range:        last {args.hours}h")
    print(f"Output:       {args.output}")
    print()

    # Initialize clients
    conc = NWClient(args.concentrator, args.concentrator_port,
                    args.user, args.password)
    dec = None
    if args.decoder:
        dec = NWClient(args.decoder, args.decoder_port,
                       args.user, args.password)

    # Ping test
    print("Checking connections...")
    if not conc.ping():
        print(f"ERROR: Cannot connect to Concentrator {args.concentrator}:{args.concentrator_port}")
        print("Check: IP, port, user/password, firewall, SSL certificate")
        sys.exit(1)
    print(f"  ✓ Concentrator {args.concentrator}:{args.concentrator_port}")

    if dec:
        if not dec.ping():
            print(f"  ⚠ Decoder {args.decoder}:{args.decoder_port} unavailable — skipping")
            dec = None
        else:
            print(f"  ✓ Decoder {args.decoder}:{args.decoder_port}")

    # Analysis
    t0 = time.time()
    data = run_analysis(conc, dec, args.hours)
    elapsed = time.time() - t0
    print(f"\nAnalysis finished in {elapsed:.1f}s")

    # Generate HTML
    print(f"Generating HTML report → {args.output}")
    html = generate_html(data)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html)

    # Terminal summary
    s = data["summary"]
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Total sessions:    {s['total_sessions']:,}")
    print(f"  TLS ratio:         {s['tls_pct']}%")
    print(f"  Unknown:           {s['unknown_pct']}%  {'⚠' if s['unknown_pct'] > 20 else '✓'}")
    print(f"  IOC alerts:        {s['ioc_count']}  {'⚠ INVESTIGATE!' if s['ioc_count'] > 0 else '✓'}")
    print(f"  BOC alerts:        {s['boc_count']}")
    print(f"  Beacon candidates: {s['beacon_count']}  {'⚠' if s['beacon_count'] > 5 else '✓'}")
    print(f"  Threat intel:      {'ACTIVE ✓' if s['has_threat_intel'] else 'NONE — load feeds!'}")
    print(f"\nReport: {args.output}")


if __name__ == "__main__":
    main()
