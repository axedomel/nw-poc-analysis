#!/usr/bin/env python3
"""
NetWitness NDR v12.5 — PoC Traffic Analysis
Generuje dynamiczny raport HTML z analizy jakościowej i ilościowej ruchu.

╔══════════════════════════════════════════════════════════════════════╗
║  ŚRODOWISKO LAB — 192.168.1.112 (Network Hybrid)                     ║
╠══════════════════════════════════════════════════════════════════════╣
║  Host 192.168.1.112 to Network Hybrid — Decoder + Concentrator       ║
║  na jednym boxie. Mapa portów (HTTPS, self-signed cert):             ║
║                                                                      ║
║    50104  →  Packet/Log DECODER SDK      (/sdk, /decoder)            ║
║    50105  →  CONCENTRATOR SDK            (/sdk, /concentrator,       ║
║                                           /index, /database)         ║
║    50106  →  NwAppliance (mgmt agent)    (/appliance, /services)     ║
║                                           — NIE MA tu /sdk!          ║
║                                                                      ║
║  Message bus (AMQP):   192.168.1.111:5671                            ║
║  Credentials:          admin / netwitness                            ║
║                                                                      ║
║  UWAGA: Użytkownik może wskazać port 50106 jako "dostęp do hybrydy"  ║
║  — to management agent, NIE data service. Do zapytań o dane używaj   ║
║  50105 (Concentrator — indeksowane meta) lub 50104 (Decoder —        ║
║  payload/client).                                                    ║
╚══════════════════════════════════════════════════════════════════════╝

Użycie (dla lab 192.168.1.112):
  python3 nw_poc_analysis.py \\
    --concentrator 192.168.1.112 --concentrator-port 50105 \\
    --decoder      192.168.1.112 --decoder-port      50104 \\
    --user admin --password 'netwitness' \\
    --hours 168 \\
    --output /home/sysadmin/Uploads/nw_report.html

Użycie (template generyczny):
  python3 nw_poc_analysis.py \\
    --concentrator <IP> --concentrator-port 50105 \\
    --decoder      <IP> --decoder-port      50104 \\
    --user admin --password '<PASS>' \\
    --hours 24 \\
    --output report.html

╔══════════════════════════════════════════════════════════════════════╗
║  NW 12 SDK API — KWIRKI (potwierdzone na tym labie)                  ║
╠══════════════════════════════════════════════════════════════════════╣
║  1. Parametr pola:  fieldName=X     (NIE value=X — zwraca HTTP 500)  ║
║  2. XML odpowiedzi:                                                  ║
║       <results><field count="N" type="svc">VALUE</field></results>   ║
║     (nie <count value="X">N</count>, nie <value count="N">X</value>) ║
║  3. where= z czasem:  time=1700000000-1700086400   (unix timestamps) ║
║     Forma ISO z apostrofami ('2026-...Z'-'...') → 400 rule syntax.   ║
║  4. Compound where:  time=A-B && service=443 && analysis.session='x' ║
║  5. Non-indexed meta keys → 500 'non-indexed meta key: X'.           ║
║     Skrypt łapie to przez _get() → pusty wynik (nie crash).          ║
╚══════════════════════════════════════════════════════════════════════╝

Szybka weryfikacja ręczna (curl) że port to faktycznie Concentrator:
  curl -sk -u admin:netwitness https://192.168.1.112:50105/ | grep -o '/concentrator'
  # → powinno zwrócić '/concentrator'
  # Dla Decodera analogicznie: https://.../50104/ → '/decoder'

Wymagania:
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
        """Pobiera top N wartości dla danego pola (msg=values)."""
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
        """Pobiera łączną liczbę sesji."""
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
            # Szukamy atrybutu total lub sumujemy counts
            total = root.get("total") or root.get("count")
            if total:
                return int(total)
            counts = root.findall(".//count")
            return sum(int(c.get("count", c.text or 0)) for c in counts)
        except Exception:
            return None

    def _parse_values(self, raw, field):
        """Parsuje XML z msg=values → lista (wartość, count)."""
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
            # Fallback: próba parsowania jako plain text
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
        """Sprawdza czy endpoint jest dostępny."""
        params = {"msg": "values", "fieldName": "service", "size": 1,
                  "flags": 0, "id1": 0, "id2": 0}
        raw = self._get(params)
        return raw is not None


# ─────────────────────────────────────────────
# ANALIZA
# ─────────────────────────────────────────────

def build_time_where(hours):
    """Buduje warunek czasu dla SDK (unix timestamps)."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    return f"time={int(start.timestamp())}-{int(now.timestamp())}"

def run_analysis(conc, dec, hours):
    """Wykonuje pełną analizę. Zwraca dict z wynikami."""
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
        print(f"{'OK' if result else 'BRAK'} ({elapsed:.1f}s, {len(result)} wierszy)")
        return result

    print("\n[CONCENTRATOR — Analiza ilościowa]")

    # 1. Rozkład protokołów
    data["sections"]["protocols"] = {
        "title": "Rozkład protokołów (service)",
        "desc": "Dominujące protokoły w ruchu. service=0 to ruch nierozpoznany przez parsery.",
        "data": fetch(conc, "service", size=30, label="protokoły")
    }

    # 2. Top źródłowe IP
    data["sections"]["top_src"] = {
        "title": "Top źródłowych IP (ip.src)",
        "desc": "Hosty generujące największy ruch sieciowy — kandydaci do analizy i filtrowania.",
        "data": fetch(conc, "ip.src", size=20, label="top src IP")
    }

    # 3. Top docelowych IP
    data["sections"]["top_dst"] = {
        "title": "Top docelowych IP (ip.dst)",
        "desc": "Najczęstsze destynacje. Zewnętrzne IP warte zbadania pod kątem threat intel.",
        "data": fetch(conc, "ip.dst", size=20, label="top dst IP")
    }

    # 4. Top hostname (alias.host)
    data["sections"]["top_host"] = {
        "title": "Top hostnames (alias.host)",
        "desc": "Domeny do których trafia ruch. Pozwala identyfikować streaming, update, CDN.",
        "data": fetch(conc, "alias.host", size=25, label="top hostnames")
    }

    # 5. Kierunkowość ruchu
    data["sections"]["direction"] = {
        "title": "Kierunkowość ruchu (direction)",
        "desc": "inbound=z zewnątrz, outbound=na zewnątrz, lateral=wewnętrzny East-West. Wymaga traffic_flow.lua.",
        "data": fetch(conc, "direction", size=10, label="direction")
    }

    # 6. Session analysis
    data["sections"]["session_analysis"] = {
        "title": "Charakterystyki sesji (analysis.session)",
        "desc": "Wartości z session_analysis.lua. Kluczowe: potential beacon, high transmitted outbound, long connection.",
        "data": fetch(conc, "analysis.session", size=34, label="session analysis")
    }

    # 7. Analiza serwisów HTTP
    data["sections"]["http_analysis"] = {
        "title": "Charakterystyki HTTP (analysis.service)",
        "desc": "Anomalie HTTP: no user-agent, direct to IP, post no get. Wymaga HTTP_lua advanced()=true.",
        "data": fetch(conc, "analysis.service", size=30, label="analysis.service")
    }

    # 8. Nierozpoznany ruch — top porty
    data["sections"]["unknown_ports"] = {
        "title": "Nierozpoznane porty docelowe (service=0)",
        "desc": "Ruch gdzie parser nie rozpoznał protokołu. To jest 'ślepa plamka' — brak meta poza IP i portem.",
        "data": fetch(conc, "tcp.dstport",
                      where=f"{tw} && service=0", size=20,
                      label="unknown tcp.dstport")
    }

    # 9. Szyfrowanie TLS
    data["sections"]["tls"] = {
        "title": "Wersje TLS (analysis.service)",
        "desc": "TLS 1.0/1.1 = podatne, powinny być wyeliminowane. TLS 1.3 = gold standard.",
        "data": fetch(conc, "analysis.service",
                      where=f"{tw} && service=443",
                      size=15, label="TLS versions")
    }

    # 10. IOC/BOC/EOC tagi
    data["sections"]["boc"] = {
        "title": "Behaviors of Compromise (boc)",
        "desc": "Aktywne reguły AR które wygenerowały tagi BOC. To co system już wykrył.",
        "data": fetch(conc, "boc", size=30, label="boc tags")
    }

    data["sections"]["ioc"] = {
        "title": "Indicators of Compromise (ioc)",
        "desc": "Aktywne reguły AR które wygenerowały tagi IOC — wyższy priorytet niż BOC.",
        "data": fetch(conc, "ioc", size=20, label="ioc tags")
    }

    data["sections"]["eoc"] = {
        "title": "Enablers of Compromise (eoc)",
        "desc": "Tagi EOC — zachowania które umożliwiają atak (telnet, cleartext, default creds).",
        "data": fetch(conc, "eoc", size=20, label="eoc tags")
    }

    # 11. Rozmiary sesji
    data["sections"]["session_sizes"] = {
        "title": "Rozkład wielkości sesji",
        "desc": "Dużo sesji 0-5k = szum, NTP, DNS, beaconing. Dużo 100k+ = backup, streaming, exfil.",
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
        "desc": "Kategorie z feedów threat intelligence. Jeśli puste — feed nie jest załadowany.",
        "data": fetch(conc, "threat.category", size=20, label="threat.category")
    }

    data["sections"]["threat_desc"] = {
        "title": "Threat descriptions (threat.desc)",
        "desc": "Szczegółowe opisy z feedów — konkretne złośliwe hosty/zakresy IP.",
        "data": fetch(conc, "threat.desc", size=20, label="threat.desc")
    }

    # 13. Beacon candidates
    data["sections"]["beacons"] = {
        "title": "Potencjalne beacony — top IP (potential beacon)",
        "desc": "IP które regularnie łączą się w rytmicznych odstępach. Klasyczny wzorzec C2 lub malware.",
        "data": fetch(conc, "ip.dst",
                      where=f"{tw} && analysis.session='potential beacon'",
                      size=15, label="beacon dst IPs")
    }

    # 14. Długie połączenia
    data["sections"]["long_conn"] = {
        "title": "Długie połączenia — top destynacje (long connection)",
        "desc": "Sesje trwające >30s. C2, tunele, streaming. Zewnętrzne IP wymagają analizy.",
        "data": fetch(conc, "ip.dst",
                      where=f"{tw} && analysis.session='long connection'",
                      size=15, label="long connection IPs")
    }

    # 15. Duże transfery wychodzące
    data["sections"]["large_outbound"] = {
        "title": "Duże transfery wychodzące — top destynacje",
        "desc": "Sesje z requestPayload >= 4MB. Exfil, backup, upload. Zewnętrzne IP wymagają weryfikacji.",
        "data": fetch(conc, "ip.dst",
                      where=f"{tw} && analysis.session='high transmitted outbound'",
                      size=15, label="high outbound IPs")
    }

    # 16. Decoder — payload sizes (jeśli dostępny)
    if dec:
        print("\n[DECODER — Analiza payload]")
        data["sections"]["decoder_payload"] = {
            "title": "Payload request per protokół (Decoder)",
            "desc": "Rozmiary payloadu requestów per service. Dane z Decodera — dokładniejsze niż Concentrator.",
            "data": fetch(dec, "service", size=20, label="decoder services")
        }
        data["sections"]["decoder_clients"] = {
            "title": "Top User-Agent / klientów (Decoder)",
            "desc": "Aplikacje generujące ruch HTTP. Nieznane user-agenty = potencjalne malware.",
            "data": fetch(dec, "client", size=20, label="decoder clients")
        }
    else:
        data["sections"]["decoder_payload"] = {
            "title": "Decoder niedostępny",
            "desc": "Pomiń lub sprawdź połączenie.",
            "data": []
        }

    # Oblicz sumaryczne statystyki
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
        """Zwraca kolor na podstawie progów (low, medium, high)."""
        if value >= thresholds[1]:
            return "#ef4444"
        elif value >= thresholds[0]:
            return "#f59e0b"
        return "#22c55e"

    def make_table(rows, col1="Wartość", col2="Sesje", section_id=""):
        if not rows:
            return '<p class="no-data">Brak danych — pole może nie być indeksowane lub nie ma ruchu w tym okresie.</p>'
        html = f'''
        <div class="table-wrapper">
          <input type="text" class="table-search" placeholder="Szukaj..." 
                 onkeyup="filterTable(this, '{section_id}')" />
          <table id="{section_id}" class="data-table">
            <thead>
              <tr>
                <th onclick="sortTable('{section_id}', 0)">{col1} ↕</th>
                <th onclick="sortTable('{section_id}', 1)">{col2} ↕</th>
                <th>Udział %</th>
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

    def make_section(key, col1="Wartość", col2="Sesje"):
        s = sections.get(key, {})
        title = s.get("title", key)
        desc = s.get("desc", "")
        rows = s.get("data", [])
        sid = f"tbl_{key}"
        return f'''
        <section class="card" id="sec_{key}">
          <div class="card-header">
            <h2>{title}</h2>
            <span class="badge">{len(rows)} wierszy</span>
          </div>
          <p class="card-desc">{desc}</p>
          {make_table(rows, col1, col2, sid)}
        </section>
        '''

    # Dane do wykresów
    proto_labels = [v for v, _ in sections["protocols"]["data"][:10]]
    proto_counts = [c for _, c in sections["protocols"]["data"][:10]]
    dir_labels = [v for v, _ in sections["direction"]["data"]]
    dir_counts = [c for _, c in sections["direction"]["data"]]
    size_labels = [v.replace("session size ", "") for v, _ in sections["session_sizes"]["data"]]
    size_counts = [c for _, c in sections["session_sizes"]["data"]]

    # Risk indicators
    tls_risk = risk_color(summary["tls_pct"], [60, 80])  # wysoki TLS = ok
    unknown_risk = risk_color(summary["unknown_pct"], [10, 30])  # wysoki unknown = zle
    ioc_risk = "#ef4444" if summary["ioc_count"] > 0 else "#22c55e"
    beacon_risk = "#ef4444" if summary["beacon_count"] > 5 else ("#f59e0b" if summary["beacon_count"] > 0 else "#22c55e")

    html = f"""<!DOCTYPE html>
<html lang="pl">
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
      <strong>Wygenerowano:</strong> {meta["generated"]}<br>
      <strong>Zakres:</strong> ostatnie {meta["hours"]}h<br>
      <strong>Concentrator:</strong> {meta["concentrator"]}<br>
      <strong>Decoder:</strong> {meta["decoder"]}
    </div>
  </div>
</header>

<nav class="nav">
  <a href="#summary">Podsumowanie</a>
  <a href="#charts">Wykresy</a>
  <a href="#protocols">Protokoły</a>
  <a href="#traffic">Ruch IP</a>
  <a href="#quality">Jakość</a>
  <a href="#threats">Zagrożenia</a>
  <a href="#filtering">Filtrowanie</a>
  <a href="#interpretation">Interpretacja</a>
</nav>

<main>

<!-- SUMMARY -->
<div id="summary">
  <div class="summary-grid">
    <div class="metric" style="--accent-color: var(--accent)">
      <div class="metric-label">Sesje łącznie</div>
      <div class="metric-value">{summary["total_sessions"]:,}</div>
      <div class="metric-sub">w ciągu {meta["hours"]}h</div>
    </div>
    <div class="metric" style="--accent-color: {tls_risk}">
      <div class="metric-label">TLS ratio</div>
      <div class="metric-value">{summary["tls_pct"]}%</div>
      <div class="metric-sub">{summary["tls_sessions"]:,} sesji HTTPS</div>
    </div>
    <div class="metric" style="--accent-color: {unknown_risk}">
      <div class="metric-label">Nierozpoznany</div>
      <div class="metric-value">{summary["unknown_pct"]}%</div>
      <div class="metric-sub">{summary["unknown_sessions"]:,} sesji service=0</div>
    </div>
    <div class="metric" style="--accent-color: {ioc_risk}">
      <div class="metric-label">IOC alerts</div>
      <div class="metric-value">{summary["ioc_count"]:,}</div>
      <div class="metric-sub">{"⚠ wymaga analizy" if summary["ioc_count"] > 0 else "✓ brak"}</div>
    </div>
    <div class="metric" style="--accent-color: {beacon_risk}">
      <div class="metric-label">Beacon candidates</div>
      <div class="metric-value">{summary["beacon_count"]}</div>
      <div class="metric-sub">distinct IP sources</div>
    </div>
    <div class="metric" style="--accent-color: {'var(--green)' if summary['has_threat_intel'] else 'var(--red)'}">
      <div class="metric-label">Threat Intel</div>
      <div class="metric-value">{"ACTIVE" if summary["has_threat_intel"] else "BRAK"}</div>
      <div class="metric-sub">{"feedy załadowane" if summary["has_threat_intel"] else "załaduj feed CSV"}</div>
    </div>
  </div>
</div>

<!-- CHARTS -->
<div id="charts" class="charts-grid">
  <div class="chart-card">
    <h3>Top protokoły</h3>
    <div class="chart-wrapper">
      <canvas id="chartProto"></canvas>
    </div>
  </div>
  <div class="chart-card">
    <h3>Kierunkowość ruchu</h3>
    <div class="chart-wrapper">
      <canvas id="chartDir"></canvas>
    </div>
  </div>
  <div class="chart-card">
    <h3>Rozkład wielkości sesji</h3>
    <div class="chart-wrapper">
      <canvas id="chartSize"></canvas>
    </div>
  </div>
</div>

<!-- PROTOKOŁY -->
<h2 class="section-title" id="protocols">📡 Analiza protokołów</h2>
{make_section("protocols")}
{make_section("unknown_ports", col1="Port (tcp.dstport)", col2="Sesje")}
{make_section("tls", col1="Wersja TLS", col2="Sesje")}

<!-- RUCH IP -->
<h2 class="section-title" id="traffic">🌐 Analiza ruchu IP</h2>
{make_section("top_src", col1="IP źródłowy", col2="Sesje")}
{make_section("top_dst", col1="IP docelowy", col2="Sesje")}
{make_section("top_host", col1="Hostname (alias.host)", col2="Sesje")}
{make_section("direction", col1="Kierunek", col2="Sesje")}

<!-- JAKOŚĆ -->
<h2 class="section-title" id="quality">🔬 Analiza jakościowa</h2>
{make_section("session_analysis", col1="Charakterystyka sesji", col2="Sesje")}
{make_section("session_sizes", col1="Zakres rozmiaru", col2="Sesje")}
{make_section("http_analysis", col1="Charakterystyka HTTP", col2="Sesje")}
{make_section("beacons", col1="IP docelowy (beacon)", col2="Sesje")}
{make_section("long_conn", col1="IP docelowy (long conn)", col2="Sesje")}
{make_section("large_outbound", col1="IP docelowy (duże transfery)", col2="Sesje")}

<!-- ZAGROŻENIA -->
<h2 class="section-title" id="threats">🚨 Wskaźniki zagrożeń</h2>
{make_section("ioc", col1="IOC tag", col2="Sesje")}
{make_section("boc", col1="BOC tag", col2="Sesje")}
{make_section("eoc", col1="EOC tag", col2="Sesje")}
{make_section("threat_cat", col1="Threat category", col2="Sesje")}
{make_section("threat_desc", col1="Threat description", col2="Sesje")}

<!-- FILTROWANIE -->
<h2 class="section-title" id="filtering">🔧 Rekomendacje filtrowania</h2>
{make_section("decoder_payload", col1="Service (Decoder)", col2="Sesje")}
{make_section("decoder_clients", col1="User-Agent / Client", col2="Sesje")}

<!-- INTERPRETACJA -->
<h2 class="section-title" id="interpretation">📋 Interpretacja wyników</h2>
<div class="interp-grid">
  <div class="interp-card" style="--accent-color: var(--accent)">
    <h4>TLS Ratio — jak czytać</h4>
    <ul>
      <li>&gt;80% = większość ruchu zaszyfrowana. Rekonstrukcja sesji ograniczona bez SSL inspection.</li>
      <li>40-80% = mix. HTTP ruch jest widoczny i możliwy do rekonstrukcji.</li>
      <li>&lt;40% = dużo nieszyfrowanego ruchu. Compliance issue (NIS2, PCI).</li>
    </ul>
  </div>
  <div class="interp-card" style="--accent-color: var(--amber)">
    <h4>service=0 — jak czytać</h4>
    <ul>
      <li>&gt;30% = duża ślepa plamka. Sprawdź top tcp.dstport — może brakować parsera.</li>
      <li>10-30% = normalny poziom dla środowisk ze specyficznymi aplikacjami.</li>
      <li>&lt;10% = dobra coverage parserów.</li>
    </ul>
  </div>
  <div class="interp-card" style="--accent-color: var(--red)">
    <h4>IOC/BOC — jak czytać</h4>
    <ul>
      <li>IOC = wysoki priorytet. Każdy tag wymaga weryfikacji — może być true positive.</li>
      <li>BOC = zachowania podejrzane w kontekście. Sprawdź ip.src dla każdego tagu.</li>
      <li>EOC = enablery. Telnet, cleartext, default creds — compliance i ryzyko.</li>
    </ul>
  </div>
  <div class="interp-card" style="--accent-color: var(--accent2)">
    <h4>Beacons — jak czytać</h4>
    <ul>
      <li>Zewnętrzne IP z potential beacon = priorytet. Sprawdź alias.host i threat.category.</li>
      <li>Wewnętrzne IP z beacon = może być monitoring lub backup agent.</li>
      <li>Dodaj znane IP do whitelist zanim zaczniesz dochodzenie.</li>
    </ul>
  </div>
  <div class="interp-card" style="--accent-color: var(--green)">
    <h4>Co filtrować (DROP)</h4>
    <ul>
      <li>service=123 (NTP) — brak wartości analitycznej, wysoki wolumen.</li>
      <li>Windows Update, antywirus updates — znane źródła, duże transfery.</li>
      <li>zero payload + single sided tcp — połączenia bez danych (skany, RST).</li>
    </ul>
  </div>
  <div class="interp-card" style="--accent-color: var(--accent)">
    <h4>Co meta-only</h4>
    <ul>
      <li>Backup agents (port 873, 9100, 10000) lateral — payload nie ma wartości.</li>
      <li>Spotify, YouTube (alias.host) — TLS i tak zaszyfrowane, zostaw meta.</li>
      <li>CDN traffic (akamaiedge.net, fastly.net) — ostrożnie, też inne serwisy!</li>
    </ul>
  </div>
</div>

</main>

<footer>
  NetWitness NDR v12.5 · PoC Traffic Analysis · {meta["generated"]} · 
  Dane z: {meta["concentrator"]} (Concentrator) + {meta["decoder"]} (Decoder)
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

// Protokoły — bar chart
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

// Kierunek — doughnut
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

// Rozmiary — bar horizontal
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
        description="NetWitness PoC Traffic Analysis — generuje raport HTML"
    )
    parser.add_argument("--concentrator", required=True,
                        help="IP lub hostname Concentratora")
    parser.add_argument("--concentrator-port", default=50104, type=int,
                        help="Port Concentratora (domyślnie 50104)")
    parser.add_argument("--decoder",
                        help="IP lub hostname Decodera (opcjonalnie)")
    parser.add_argument("--decoder-port", default=50102, type=int,
                        help="Port Decodera (domyślnie 50102)")
    parser.add_argument("--user", required=True, help="Nazwa użytkownika")
    parser.add_argument("--password", required=True, help="Hasło")
    parser.add_argument("--hours", default=24, type=int,
                        help="Zakres analizy w godzinach (domyślnie 24)")
    parser.add_argument("--output", default="nw_poc_report.html",
                        help="Plik wyjściowy HTML (domyślnie nw_poc_report.html)")
    args = parser.parse_args()

    print("=" * 60)
    print("NetWitness PoC Traffic Analysis")
    print("=" * 60)
    print(f"Concentrator: {args.concentrator}:{args.concentrator_port}")
    print(f"Decoder:      {args.decoder or 'pominięty'}:{args.decoder_port}")
    print(f"Zakres:       ostatnie {args.hours}h")
    print(f"Output:       {args.output}")
    print()

    # Inicjalizacja klientów
    conc = NWClient(args.concentrator, args.concentrator_port,
                    args.user, args.password)
    dec = None
    if args.decoder:
        dec = NWClient(args.decoder, args.decoder_port,
                       args.user, args.password)

    # Ping test
    print("Sprawdzam połączenia...")
    if not conc.ping():
        print(f"ERROR: Nie mogę połączyć się z Concentratorem {args.concentrator}:{args.concentrator_port}")
        print("Sprawdź: IP, port, login/hasło, firewall, certyfikat SSL")
        sys.exit(1)
    print(f"  ✓ Concentrator {args.concentrator}:{args.concentrator_port}")

    if dec:
        if not dec.ping():
            print(f"  ⚠ Decoder {args.decoder}:{args.decoder_port} niedostępny — pomijam")
            dec = None
        else:
            print(f"  ✓ Decoder {args.decoder}:{args.decoder_port}")

    # Analiza
    t0 = time.time()
    data = run_analysis(conc, dec, args.hours)
    elapsed = time.time() - t0
    print(f"\nAnaliza zakończona w {elapsed:.1f}s")

    # Generowanie HTML
    print(f"Generuję raport HTML → {args.output}")
    html = generate_html(data)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html)

    # Podsumowanie w terminalu
    s = data["summary"]
    print("\n" + "=" * 60)
    print("PODSUMOWANIE")
    print("=" * 60)
    print(f"  Sesje łącznie:     {s['total_sessions']:,}")
    print(f"  TLS ratio:         {s['tls_pct']}%")
    print(f"  Nierozpoznany:     {s['unknown_pct']}%  {'⚠' if s['unknown_pct'] > 20 else '✓'}")
    print(f"  IOC alerts:        {s['ioc_count']}  {'⚠ SPRAWDŹ!' if s['ioc_count'] > 0 else '✓'}")
    print(f"  BOC alerts:        {s['boc_count']}")
    print(f"  Beacon candidates: {s['beacon_count']}  {'⚠' if s['beacon_count'] > 5 else '✓'}")
    print(f"  Threat intel:      {'ACTIVE ✓' if s['has_threat_intel'] else 'BRAK — załaduj feedy!'}")
    print(f"\nRaport: {args.output}")


if __name__ == "__main__":
    main()
