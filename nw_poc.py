#!/usr/bin/env python3
"""NetWitness NDR v12.5 — PoC Analysis + Threat Check v0.9"""

# ─────────────────────────────────────────────
# IMPORTS
# ─────────────────────────────────────────────
import argparse
import json
import re
import sys
import time
import warnings
import xml.etree.ElementTree as ET
from collections import Counter
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
# CONSTANTS
# ─────────────────────────────────────────────
VERSION = "0.9"

# Inline Chart.js fallback — works offline, no CDN needed
_CHARTJS_INLINE = """<script>
window.Chart=window.Chart||(function(){
  function Chart(el,cfg){
    if(!el)return;
    var c=el.getContext("2d");
    var w=el.offsetWidth||el.getAttribute("width")||300;
    var h=el.offsetHeight||el.getAttribute("height")||80;
    el.width=w; el.height=h;
    var ds=cfg.data.datasets[0]||{};
    var vals=ds.data||[];
    var lbls=cfg.data.labels||[];
    var max=Math.max.apply(null,vals)||1;
    var bw=Math.floor(w/Math.max(vals.length,1));
    var pad=2;
    var dk=document.documentElement.getAttribute("data-theme")==="dark";
    c.fillStyle=dk?"#141720":"#f8fafc";
    c.fillRect(0,0,w,h);
    var barColor=ds.backgroundColor||(dk?"rgba(94,234,212,0.4)":"rgba(15,118,110,0.4)");
    vals.forEach(function(v,i){
      var bh=Math.round((v/max)*(h-14));
      c.fillStyle=barColor;
      c.fillRect(i*bw+pad,h-14-bh,Math.max(bw-pad*2,1),bh);
      if(lbls[i]){
        c.fillStyle=dk?"#475569":"#94a3b8";
        c.font="8px monospace";
        c.fillText(String(lbls[i]).slice(0,5),i*bw+pad,h-2);
      }
    });
  }
  return Chart;
})();
</script>"""

TIER_CFG = {
    "CRITICAL": {"color": "#dc2626", "label": "CRITICAL - IMMEDIATELY", "bg": "#fee2e2"},
    "HIGH":     {"color": "#d97706", "label": "HIGH - ACT TODAY",       "bg": "#fef3c7"},
    "MEDIUM":   {"color": "#0f766e", "label": "MEDIUM - THIS WEEK",     "bg": "#ccfbf1"},
    "INFO":     {"color": "#64748b", "label": "INFO",                    "bg": "#f1f5f9"},
}

URGENCY_CFG = {
    "now":   {"color": "#dc2626", "bg": "#fee2e2", "label": "NOW"},
    "today": {"color": "#d97706", "bg": "#fef3c7", "label": "TODAY"},
    "week":  {"color": "#0f766e", "bg": "#ccfbf1", "label": "THIS WEEK"},
}


FEED_FALLBACK = {
    "openai.com": "llm-enterprise", "api.openai.com": "llm-enterprise",
    "openai.azure.com": "llm-enterprise", "api.anthropic.com": "llm-enterprise",
    "anthropic.com": "llm-enterprise", "api.mistral.ai": "llm-enterprise",
    "mistral.ai": "llm-enterprise", "aiplatform.googleapis.com": "llm-enterprise",
    "generativelanguage.googleapis.com": "llm-enterprise",
    "api.groq.com": "llm-enterprise", "groq.com": "llm-enterprise",
    "api.together.xyz": "llm-enterprise", "together.ai": "llm-enterprise",
    "api.perplexity.ai": "llm-enterprise", "perplexity.ai": "llm-enterprise",
    "api.cohere.com": "llm-enterprise", "cohere.com": "llm-enterprise",
    "api.replicate.com": "llm-enterprise", "replicate.com": "llm-enterprise",
    "bedrock.amazonaws.com": "llm-enterprise", "bedrock.us-east-1.amazonaws.com": "llm-enterprise",
    "api.stability.ai": "llm-enterprise", "stability.ai": "llm-enterprise",
    "api.deepseek.com": "llm-enterprise", "deepseek.com": "llm-enterprise",
    "api.qwen.ai": "llm-enterprise", "dashscope.aliyuncs.com": "llm-enterprise",
    "github.com/features/copilot": "llm-enterprise", "copilot.github.com": "llm-enterprise",
    "api.github.com": "llm-enterprise",
    "cursor.sh": "llm-coding", "api.cursor.sh": "llm-coding",
    "codeium.com": "llm-coding", "api.codeium.com": "llm-coding",
    "tabnine.com": "llm-coding", "api.tabnine.com": "llm-coding",
    "wormgpt.ai": "llm-malicious", "ghostgpt.io": "llm-malicious",
    "darkgpt.cc": "llm-malicious", "fraudgpt.net": "llm-malicious",
    "localhost:11434": "local-llm", "ollama.ai": "local-llm",
    "lmstudio.ai": "local-llm",
}

LLM_FEED = dict(FEED_FALLBACK)  # offline fallback only

MITRE_TACTIC_MAP = {
    "T1071": "C2", "T1071.001": "C2", "T1102": "C2",
    "T1567": "Exfiltration", "T1567.002": "Exfiltration",
    "T1213": "Collection", "T1552": "Credential Access",
    "T1105": "Execution", "T1021": "Lateral Movement",
    "T1046": "Discovery", "T1078": "Initial Access",
    "T1557": "Credential Access", "T1059": "Execution",
    "T1036": "Defense Evasion", "T1041": "Exfiltration",
}

KW_TACTIC_MAP = {
    "lolbas": "Execution", "malicious service": "Initial Access",
    "api key": "Credential Access", "server outbound": "C2",
    "c2 channel": "C2", "c2 beacon": "C2", "lateral": "Lateral Movement",
    "file upload": "Exfiltration", "large prompt": "Exfiltration",
    "non-browser": "Collection", "browser access": "Collection",
    "no user agent": "C2", "plaintext http": "Defense Evasion",
    "long connection": "C2", "beacon": "C2", "typosquat": "C2",
    "dga": "C2", "dns tunnel": "C2", "chunked": "Exfiltration",
    "exfil": "Exfiltration", "enumerate": "Discovery",
}

TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "C2",
]

TACTIC_COLORS = {
    "Initial Access": "#dc2626", "Execution": "#d97706",
    "Persistence": "#7c3aed", "Defense Evasion": "#64748b",
    "Credential Access": "#b91c1c", "Discovery": "#0891b2",
    "Lateral Movement": "#d97706", "Collection": "#0f766e",
    "Exfiltration": "#7c3aed", "C2": "#dc2626",
}

NON_INDEXED = {"analysis.session", "analysis.service", "analysis.file"}

# ─────────────────────────────────────────────
# NW SDK CLIENT
# ─────────────────────────────────────────────
class NonIndexedKeyError(Exception):
    """Raised when API returns 500 due to non-indexed meta key in where clause."""
    pass


class NWClient:
    def __init__(self, host, port, user, password, timeout=60):
        self.base = f"https://{host}:{port}"
        self.auth = (user, password)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.auth = self.auth

    def _get(self, params, debug=False, raise_on_500=False):
        try:
            r = self.session.get(
                f"{self.base}/sdk",
                params=params,
                timeout=self.timeout
            )
            if debug:
                print(f"\n    RAW status={r.status_code} body={r.text[:200]}")
            if r.status_code == 500 and raise_on_500:
                # Raise so caller can detect non-indexed-key errors
                raise NonIndexedKeyError(f"500 from API: {r.text[:200]}")
            if r.status_code != 200:
                return None
            return r.text
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.Timeout:
            return None
        except NonIndexedKeyError:
            raise
        except Exception:
            return None

    def values(self, field, where=None, size=25, debug=False):
        """Fetch top N values for a given field (msg=values).
        Raises NonIndexedKeyError if where clause references a non-indexed meta key (HTTP 500)."""
        params = {
            "msg":       "values",
            "fieldName": field,
            "size":      size,
            "flags":     "sessions,sort-total,order-descending",
            "expiry":    120,
        }
        if where:
            params["where"] = where
        raw = self._get(params, debug=debug, raise_on_500=bool(where))
        return self._parse_values(raw, field)

    def query_pairs(self, where=None, limit=5, debug=False):
        """Fetch src→dst pairs using msg=query with JSON response.
        Uses force-content-type=application/json — same approach as NW visualization tools.
        Groups fields by group number to form pairs (no IndexKeys requirement)."""
        try:
            if where:
                nwql = f"select ip.src, ip.dst where {where} group by ip.src, ip.dst"
            else:
                nwql = "select ip.src, ip.dst group by ip.src, ip.dst"

            params = {
                "msg":                "query",
                "query":              nwql,
                "size":               limit * 3,
                "force-content-type": "application/json",
                "expiry":             120,
            }
            if debug:
                print(f"  [query_pairs] nwql={nwql}")

            raw = self._get(params, debug=debug, raise_on_500=False)
            if not raw:
                return []

            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                if debug:
                    print(f"  [query_pairs] JSON parse failed, raw={str(raw)[:200]}")
                return []

            # Group fields by group number — each group is one src→dst pair
            groups: dict = {}
            fields = []
            if isinstance(data, dict):
                results = data.get("results", data)
                if isinstance(results, dict):
                    fields = results.get("fields", [])
                elif isinstance(results, list):
                    fields = results

            for field in fields:
                if not isinstance(field, dict):
                    continue
                grp   = str(field.get("group", "0"))
                ftype = str(field.get("type", "")).lower()
                val   = str(field.get("value", "")).strip()
                cnt   = int(field.get("count", 0) or 0)
                if not val or val == "0.0.0.0":
                    continue
                if grp not in groups:
                    groups[grp] = {"src": "", "dst": "", "count": 0}
                if ftype == "ip.src":
                    groups[grp]["src"] = val
                elif ftype == "ip.dst":
                    groups[grp]["dst"] = val
                if cnt > groups[grp]["count"]:
                    groups[grp]["count"] = cnt

            seen = set()
            pairs = []
            for grp in sorted(groups.keys(), key=lambda x: int(x) if x.isdigit() else 0):
                p = groups[grp]
                if p["src"] and p["dst"]:
                    key = (p["src"], p["dst"])
                    if key not in seen:
                        seen.add(key)
                        pairs.append({"src": p["src"], "dst": p["dst"],
                                      "count": p["count"], "precise": True})
                        if len(pairs) >= limit:
                            break

            if debug:
                print(f"  [query_pairs] found {len(pairs)} pairs: {pairs[:2]}")
            return pairs

        except Exception as e:
            if debug:
                print(f"  [query_pairs] exception: {e}")
            return []


    def _parse_query_pairs(self, raw):
        """Parse msg=query GROUP BY XML — fields share group number to form pairs."""
        if not raw:
            return []
        try:
            root = ET.fromstring(raw)
            # Collect fields by group number
            groups = {}
            for field_el in root.findall(".//field"):
                ftype   = field_el.get("type", "").lower()
                grp     = field_el.get("group", "0")
                count   = int(field_el.get("count", 0) or 0)
                val     = (field_el.text or "").strip()
                if not val:
                    continue
                if grp not in groups:
                    groups[grp] = {"src": "", "dst": "", "count": 0}
                if ftype == "ip.src":
                    groups[grp]["src"] = val
                elif ftype == "ip.dst":
                    groups[grp]["dst"] = val
                if count > groups[grp]["count"]:
                    groups[grp]["count"] = count

            pairs = []
            for grp in sorted(groups.keys(), key=lambda x: int(x) if x.isdigit() else 0):
                p = groups[grp]
                if p["src"] and p["dst"]:
                    # Skip 0.0.0.0 fallback entries
                    if p["src"] == "0.0.0.0" or p["dst"] == "0.0.0.0":
                        continue
                    pairs.append({"src": p["src"], "dst": p["dst"], "count": p["count"]})

            return pairs
        except ET.ParseError:
            return []
        except Exception:
            return []

    def count(self, where=None):
        """Fetch total session count."""
        params = {
            "msg": "values",
            "fieldName": "service",
            "size": 1,
            "expiry": 120,
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
        params = {"msg": "values", "fieldName": "service", "size": 1, "expiry": 10}
        raw = self._get(params)
        return raw is not None


# ─────────────────────────────────────────────
# ANALYSIS
# ─────────────────────────────────────────────

# ─── GLOBALS ───
LLM_FEED = dict(FEED_FALLBACK)  # offline fallback only

MITRE_TACTIC_MAP = {
    "T1071":"C2","T1071.001":"C2","T1102":"C2",
    "T1567":"Exfiltration","T1567.002":"Exfiltration",
    "T1213":"Collection","T1552":"Credential Access",
    "T1105":"Execution","T1021":"Lateral Movement",
    "T1046":"Discovery","T1078":"Initial Access",
    "T1557":"Credential Access","T1059":"Execution",
    "T1036":"Defense Evasion","T1041":"Exfiltration",
}

KW_TACTIC_MAP = {
    "lolbas":"Execution","malicious service":"Initial Access",
    "api key":"Credential Access","server outbound":"C2",
    "c2 channel":"C2","c2 beacon":"C2","lateral":"Lateral Movement",
    "file upload":"Exfiltration","large prompt":"Exfiltration",
    "non-browser":"Collection","browser access":"Collection",
    "no user agent":"C2","plaintext http":"Defense Evasion",
    "long connection":"C2","beacon":"C2","typosquat":"C2","dga":"C2",
    "chunked":"Exfiltration","exfil":"Exfiltration","enumerate":"Discovery",
}

TACTIC_ORDER = [
    "Initial Access","Execution","Persistence","Defense Evasion",
    "Credential Access","Discovery","Lateral Movement",
    "Collection","Exfiltration","C2",
]

TACTIC_COLORS = {
    "Initial Access":"#dc2626","Execution":"#d97706","Persistence":"#7c3aed",
    "Defense Evasion":"#64748b","Credential Access":"#b91c1c","Discovery":"#0891b2",
    "Lateral Movement":"#d97706","Collection":"#0f766e","Exfiltration":"#7c3aed","C2":"#dc2626",
}

NON_INDEXED = {'analysis.session', 'analysis.service', 'analysis.file'}

SESSION_FIELDS = [
    "ip.src","ip.dst","alias.host","service","direction",
    "boc","ioc","eoc","analysis.session","tcp.dstport","time",
]


def build_time_where(hours):
    """Build the time where-clause for SDK (unix timestamps)."""
    if hours == 0:
        return "time >= 1577836800"   # all-time: from 2020-01-01
    now   = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    return f"time >= {int(start.timestamp())} && time <= {int(now.timestamp())}"

def feed_lookup(alias_host) -> tuple:
    """Look up a domain in LLM_FEED. Returns (category, desc) or ('','')."""
    if not alias_host:
        return ('', '')
    if isinstance(alias_host, list):
        alias_host = alias_host[0] if alias_host else ''
    if not alias_host:
        return ('', '')
    db    = LLM_FEED if LLM_FEED else FEED_FALLBACK
    alias = str(alias_host).lower().strip()
    if alias in db:
        val = db[alias]
        return (val[0], val[1]) if isinstance(val, tuple) else (val, alias)
    parts = alias.split('.')
    for i in range(1, len(parts)):
        parent = '.'.join(parts[i:])
        if parent in db:
            val = db[parent]
            return (val[0], val[1]) if isinstance(val, tuple) else (val, alias)
    return ('', '')


# ─────────────────────────────────────────────
# FP SCORING
# ─────────────────────────────────────────────

# Hypotheses where FP scoring is applied (Groups 1 & 2 — high FP noise)
FP_SCORING_HYPOTHESES = {
    'H-01','H-02','H-03','H-04','H-05','H-06','H-07',
    'H-08','H-09','H-10','H-11','H-12','H-15','H-17',
    'H-21','H-22','H-23','H-25','H-26','H-27','H-29',
    'H-30','H-31','H-32','H-36','H-37','H-40','H-42',
    'H-45','H-49','H-50','H-51','H-52','H-54','H-55',
    'H-86',  # LLM plaintext http — FP on known providers
}

FP_DOMAIN_WHITELIST = [
    'microsoft.com','windows.com','windowsupdate.com','microsoftonline.com',
    'office.com','office365.com','live.com','outlook.com','azure.com',
    'msftconnecttest.com','msecnd.net','akadns.net','trafficmanager.net',
    'google.com','googleapis.com','gstatic.com','googleusercontent.com',
    'apple.com','icloud.com','symantec.com',
    'symcb.com','digicert.com','verisign.com','globalsign.com',
    'sectigo.com','letsencrypt.org','comodoca.com','entrust.net',
    'akamai.net','akamaiedge.net','akamaihd.net',
    'cloudfront.net','fastly.net','cdn77.com',
    'amazonaws.com','azure.net','azureedge.net',
    '7-zip.org','mozilla.org','firefox.com','adobe.com',
    'dropbox.com','box.com','onedrive.com','sharepoint.com',
    'zoom.us','webex.com',
]

FP_DOMAIN_PATTERNS = [
    'in-addr.arpa', 'awsdns-', '.windowsupdate.com',
    '.data.microsoft.com', 'metaservices.microsoft.',
    'vortex-win.', 'settings-win.', 'spynet',
    'ctldl.', 'delivery.mp.microsoft', 'fe2.update.',
    'go.microsoft.com', 'cdn.microsoft.', '.sfx.ms',
    '.digicert.com', '.verisign.com', '.letsencrypt.org',
]

FP_IP_PREFIXES = [
    '52.111.', '52.112.', '52.113.', '52.114.', '52.115.',
    '13.64.', '13.65.', '13.66.', '13.67.', '13.68.', '13.69.',
    '13.70.', '13.71.', '13.72.', '13.73.', '13.74.', '13.75.',
    '13.76.', '13.77.', '13.78.', '13.79.', '13.80.', '13.81.',
    '13.82.', '13.83.', '13.84.', '13.85.', '13.86.', '13.87.',
    '13.88.', '13.89.', '13.90.', '13.91.', '13.92.', '13.93.',
    '13.94.', '13.95.', '13.96.', '13.97.', '13.98.', '13.99.',
    '13.100.', '13.101.', '13.102.', '13.103.', '13.104.',
    '13.105.', '13.106.', '13.107.',
    '20.33.', '20.34.', '20.35.', '20.36.', '20.37.', '20.38.',
    '20.39.', '20.40.', '20.41.', '20.42.', '20.43.', '20.44.',
    '20.45.', '20.46.', '20.47.', '20.48.', '20.49.', '20.50.',
    '20.60.', '20.70.', '20.80.', '20.90.', '20.100.',
    '20.150.', '20.160.', '20.170.', '20.180.', '20.189.',
    '20.190.', '20.200.', '20.210.',
    '40.74.', '40.75.', '40.76.', '40.77.', '40.78.',
    '40.79.', '40.80.', '40.81.', '40.82.', '40.83.',
    '40.112.', '40.113.', '40.114.', '40.115.',
    '40.120.', '40.121.', '40.122.', '40.123.',
    '23.44.', '23.45.', '23.46.', '23.47.',
    '23.192.', '23.193.', '23.194.', '23.195.',
    '23.9.',
]

FP_DNS_RESOLVERS = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
                    '9.9.9.9', '149.112.112.112', '208.67.222.222'}

TP_BAD_TLDS      = {'.top', '.xyz', '.tk', '.cc', '.pw', '.ga',
                    '.cf', '.gq', '.ml', '.work', '.click', '.download', '.zip'}
TP_BAD_KEYWORDS  = ['shadow', 'kali', 'malware', 'phish', 'hack',
                    'ransom', 'exploit', '0day', 'c2server', 'botnet']


def _is_rfc1918(ip):
    if not ip:
        return False
    return (ip.startswith('10.') or ip.startswith('192.168.') or
            any(ip.startswith(f'172.{i}.') for i in range(16, 32)))


def score_fp_pair(ip_src, ip_dst, alias_host, count=1):
    """
    Score a src→dst pair for false-positive likelihood.
    Returns (score 0-100, verdict, short_reason)
      score >= 60  → 'FP likely'
      score 30-59  → 'Review'
      score < 30   → 'Investigate'
    ioc/boc overrides are handled by the caller (score → 0 if ioc).
    """
    alias = (alias_host or '').lower().strip()
    ip_d  = (ip_dst  or '').strip()
    ip_s  = (ip_src  or '').strip()

    # ── Feed F.07 override — LLM provider domains are NEVER FP ──
    # Checked before any whitelist match to prevent google.com / azure.com
    # catching AI provider subdomains (aiplatform.googleapis.com etc.)
    feed_cat, feed_desc = feed_lookup(alias)
    if feed_cat:
        return 0, 'Investigate', f'LLM provider — {feed_desc}'

    score = 0
    top_reason = ''

    # ── Negative signals (TP direction) ──────────────────────
    for tld in TP_BAD_TLDS:
        if alias.endswith(tld):
            score -= 40
            top_reason = top_reason or f'Suspicious TLD ({tld})'
            break

    for kw in TP_BAD_KEYWORDS:
        if kw in alias:
            score -= 60
            top_reason = top_reason or f'Suspicious keyword ({kw})'
            break

    # DGA heuristic — long random-looking subdomain
    if alias and '.' in alias:
        sub = alias.split('.')[0]
        if len(sub) > 10:
            consonants = sum(1 for c in sub if c.isalpha() and c not in 'aeiou')
            digits     = sum(1 for c in sub if c.isdigit())
            if consonants > 6 and digits > 2:
                score -= 50
                top_reason = top_reason or 'DGA pattern — random subdomain'

    # No hostname resolved
    if not alias or alias == ip_d:
        score -= 15

    # ── Positive signals (FP direction) ──────────────────────
    fp_reason = ''

    # RFC1918 destination
    if _is_rfc1918(ip_d):
        score   += 50
        fp_reason = fp_reason or 'RFC1918 destination — internal host'

    # RFC1918 source (weaker signal)
    if _is_rfc1918(ip_s):
        score += 10

    # Known DNS resolver
    if ip_d in FP_DNS_RESOLVERS:
        score    += 55
        fp_reason = fp_reason or f'Known public DNS resolver ({ip_d})'

    # Domain whitelist
    matched = False
    for wl in FP_DOMAIN_WHITELIST:
        if alias == wl or alias.endswith('.' + wl):
            score    += 60
            fp_reason = fp_reason or f'Known vendor ({wl})'
            matched   = True
            break

    # Structural pattern
    if not matched:
        for pat in FP_DOMAIN_PATTERNS:
            if pat in alias:
                score    += 40
                fp_reason = fp_reason or f'Known infra pattern'
                matched   = True
                break

    # Known cloud/vendor IP prefix
    if not matched and not _is_rfc1918(ip_d):
        for pfx in FP_IP_PREFIXES:
            if ip_d.startswith(pfx):
                score    += 30
                fp_reason = fp_reason or f'Known vendor IP range'
                break

    score = max(0, min(100, score))

    if score >= 60:
        verdict = 'FP likely'
        reason  = fp_reason or top_reason
    elif score >= 30:
        verdict = 'Review'
        reason  = fp_reason or top_reason
    else:
        verdict = 'Investigate'
        reason  = top_reason or fp_reason

    return score, verdict, reason


# ─────────────────────────────────────────────
# HTML GENERATOR
# ─────────────────────────────────────────────

def check_parsers(conc, time_where):
    """
    Run parser health checks against the Concentrator.
    Returns list of dicts: parser, label, status, count, impact.
    status: OK | LOW | UNAVAILABLE
    """
    results = []
    print("\n[MODULE 0 — Parser Health Check]")

    for chk in PARSER_CHECKS:
        where = time_where
        if chk["where"]:
            where = (f"{time_where} && {chk['where']}" if time_where else chk['where'])

        print(f"  [{chk['parser']}]...", end=" ", flush=True)
        t0 = time.time()
        try:
            rows = conc.values(chk["field"], where=where, size=10)
        except NonIndexedKeyError:
            rows = []
        elapsed = time.time() - t0

        count = sum(c for _, c in rows)
        found_values = [v for v, _ in rows]

        if count == 0:
            status = "UNAVAILABLE"
        else:
            # Parser is active if it produced any meta at all.
            # Expected values are informational — their absence doesn't mean the parser is down.
            status = "OK"

        icon = {"OK": "✅", "LOW": "⚠️ ", "UNAVAILABLE": "❌"}[status]
        print(f"{icon} {status} ({elapsed:.1f}s, {count} sessions)")

        results.append({
            "parser":  chk["parser"],
            "label":   chk["label"],
            "status":  status,
            "count":   count,
            "impact":  chk["impact"],
        })

    ok    = sum(1 for r in results if r["status"] == "OK")
    low   = sum(1 for r in results if r["status"] == "LOW")
    miss  = sum(1 for r in results if r["status"] == "UNAVAILABLE")
    print(f"\n  Parsers: {ok} OK  |  {low} LOW  |  {miss} UNAVAILABLE")
    return results


# ─────────────────────────────────────────────
# ─────────────────────────────────────────────
# MODULE 3 — THREAT HUNT
# ─────────────────────────────────────────────


# ─────────────────────────────────────────────
# SESSION-BASED HUNT (v2 approach)
# ─────────────────────────────────────────────

SESSION_SELECT_FIELDS = [
    "ip.src", "ip.dst",
    "analysis.session", "analysis.service",
    "direction",
    "boc", "ioc", "eoc",
    "service", "tcp.dstport",
    "time", "alias.host",
]

def fetch_sessions(conc, time_where, size=50000, debug=False):
    """
    Fetch raw sessions from Concentrator using msg=query.
    One call, all sessions — no IndexKeys required.
    Returns list of session dicts keyed by meta field name.
    """
    from collections import defaultdict as _defaultdict

    select_clause = ", ".join(SESSION_SELECT_FIELDS)
    nwql = f"select {select_clause} where {time_where}" if time_where else f"select {select_clause}"

    print(f"  [Sessions] Fetching (size={size:,})... ", end="", flush=True)
    t0 = time.time()

    params = {
        "msg":                "query",
        "query":              nwql,
        "size":               size,
        "force-content-type": "application/json",
        "expiry":             300,
    }
    raw_resp = conc._get(params, debug=debug, raise_on_500=False)
    elapsed = time.time() - t0

    if not raw_resp:
        print(f"FAILED ({elapsed:.1f}s)")
        return []

    try:
        data = json.loads(raw_resp)
    except (json.JSONDecodeError, ValueError):
        print(f"PARSE ERROR ({elapsed:.1f}s)")
        return []

    fields_list = []
    try:
        results = data.get("results", data)
        if isinstance(results, dict):
            fields_list = results.get("fields", [])
        elif isinstance(results, list):
            fields_list = results
    except Exception:
        print(f"EXTRACT ERROR ({elapsed:.1f}s)")
        return []

    # Group by session (group number)
    sessions_raw = _defaultdict(dict)
    for field in fields_list:
        if not isinstance(field, dict):
            continue
        grp   = field.get("group", 0)
        ftype = field.get("type", "")
        val   = field.get("value", "")
        if not ftype or not val:
            continue
        existing = sessions_raw[grp].get(ftype)
        if existing is None:
            sessions_raw[grp][ftype] = val
        elif isinstance(existing, list):
            if val not in existing:
                existing.append(val)
        else:
            if val != existing:
                sessions_raw[grp][ftype] = [existing, val]

    sessions = list(sessions_raw.values())

    # Normalize alias.host — take first value if multi-valued list
    for s in sessions:
        ah = s.get('alias.host')
        if isinstance(ah, list):
            s['alias.host'] = ah[0] if ah else ''
    print(f"OK ({elapsed:.1f}s, {len(sessions):,} sessions)")
    if len(sessions) >= int(size * 0.95):
        print(f"  \033[1;33m[WARN] Near session limit ({len(sessions):,}/{size:,}) "
              f"— data may be incomplete. Rerun with --session-size {size*2}\033[0m")

    # Diagnostic — LLM session detection
    llm_boc = sum(1 for s in sessions if any(
        'llm' in str(v).lower()
        for v in _as_list(s.get('boc')) + _as_list(s.get('eoc')) + _as_list(s.get('ioc'))
    ))
    if llm_boc:
        print(f"  [LLM] {llm_boc} sessions with LLM boc/eoc/ioc tags found in fetched data")
    else:
        print(f"  [LLM] WARNING: 0 LLM-tagged sessions in fetched {len(sessions):,} — "
              f"LLM sessions may be outside the fetch window or on a different decoder")
        # Show distinct boc/eoc/ioc values present in fetched sessions
        boc_vals = set()
        for s in sessions:
            for v in _as_list(s.get('boc')): boc_vals.add(v)
        eoc_vals = set()
        for s in sessions:
            for v in _as_list(s.get('eoc')): eoc_vals.add(v)
        if boc_vals:
            sample = sorted(boc_vals)[:8]
            print(f"  [LLM] BOC values in fetched sessions: {sample}")
        else:
            print(f"  [LLM] No BOC values in any of the {len(sessions):,} fetched sessions")
        if eoc_vals:
            print(f"  [LLM] EOC values: {sorted(eoc_vals)[:8]}")
        # Show time range of fetched sessions
        times = [s.get('time') for s in sessions if s.get('time')]
        if times:
            try:
                import datetime
                t_min = min(int(t) for t in times if str(t).isdigit())
                t_max = max(int(t) for t in times if str(t).isdigit())
                print(f"  [LLM] Session time range: "
                      f"{datetime.datetime.utcfromtimestamp(t_min).strftime('%Y-%m-%d %H:%M')} → "
                      f"{datetime.datetime.utcfromtimestamp(t_max).strftime('%Y-%m-%d %H:%M')} UTC")
            except Exception:
                print(f"  [LLM] Raw time values sample: {times[:3]}")

    return sessions


def _as_list(val):
    """Normalize field value to list of strings."""
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]


def _session_matches(session, query):
    """
    Evaluate whether a session matches a hypothesis query.
    Supports: key = 'value' && key2 = 'value2'
    """
    conditions = []
    for part in re.split(r'\s*&&\s*', query.strip()):
        m = re.match(r"(\S+)\s*=\s*'([^']+)'", part.strip())
        if m:
            conditions.append((m.group(1).strip(), m.group(2).strip()))
    if not conditions:
        return False
    for key, val in conditions:
        if not any(sv.lower() == val.lower() for sv in _as_list(session.get(key))):
            return False
    return True


def _extract_pairs(sessions):
    """Extract unique src→dst pairs sorted by count."""
    from collections import Counter as _Counter
    pair_counter = _Counter()
    pair_aliases = {}
    for s in sessions:
        srcs = [ip for ip in _as_list(s.get("ip.src")) if ip and ip != "0.0.0.0"]
        dsts = [ip for ip in _as_list(s.get("ip.dst")) if ip and ip != "0.0.0.0"]
        alias = _as_list(s.get("alias.host"))
        for src in srcs:
            for dst in dsts:
                pair_counter[(src, dst)] += 1
                if alias and (src, dst) not in pair_aliases:
                    pair_aliases[(src, dst)] = alias[0]
    pairs = []
    for (src, dst), count in pair_counter.most_common(5):
        pairs.append({"src": src, "dst": dst, "count": count,
                      "alias": pair_aliases.get((src, dst), ""), "precise": True})
    return pairs


def evaluate_hypotheses(sessions, hypotheses, debug=False):
    """
    Evaluate hypotheses locally against fetched sessions.
    Returns results in same format as run_hunt() — compatible with all renderers.
    """
    from collections import Counter as _Counter

    print(f"\n[Local Hypothesis Evaluation — {len(sessions):,} sessions × {len(hypotheses)} hypotheses]")
    results = []
    found_count = not_obs_count = 0

    for h in hypotheses:
        hid   = h["id"]
        query = h.get("query", "")

        if not query:
            results.append(_build_hunt_result(h, [], "NOT_OBSERVED"))
            not_obs_count += 1
            continue

        matching = [s for s in sessions if _session_matches(s, query)]

        if not matching:
            results.append(_build_hunt_result(h, [], "NOT_OBSERVED"))
            not_obs_count += 1
            print(f"  {hid} ◻  NOT_OBSERVED")
            continue

        # Precise pairs from matching sessions
        pairs = _extract_pairs(matching)

        # Top IPs from matching sessions
        src_ctr = _Counter()
        dst_ctr = _Counter()
        aliases  = {}
        for s in matching:
            for ip in _as_list(s.get("ip.src")):
                if ip and ip != "0.0.0.0":
                    src_ctr[ip] += 1
            for ip in _as_list(s.get("ip.dst")):
                if ip and ip != "0.0.0.0":
                    dst_ctr[ip] += 1
                    al = _as_list(s.get("alias.host"))
                    if al and ip not in aliases:
                        aliases[ip] = al[0]

        r = _build_hunt_result(h, matching, "FOUND")
        r["count"]          = len(matching)
        r["top_pairs"]      = pairs
        r["ip_src"]         = [ip for ip, _ in src_ctr.most_common(5)]
        r["ip_dst"]         = [ip for ip, _ in dst_ctr.most_common(5)]
        r["ip_src_counts"]  = list(src_ctr.most_common(5))
        r["alias_host"]     = [aliases.get(ip, "") for ip in r["ip_dst"]]

        results.append(r)
        found_count += 1
        pair_str = f", {len(pairs)} pairs" if pairs else ""
        print(f"  {hid} ● FOUND ({len(matching):,} sessions{pair_str})")

    print(f"\n  Hunt complete: {found_count} FOUND | {not_obs_count} NOT_OBSERVED | 0 PARSER_UNAVAILABLE")
    return results


def _build_hunt_result(h, sessions, status):
    """Build result dict compatible with render_threathunting_html()."""
    return {
        "id":               h["id"],
        "name":             h["name"],
        "category":         h.get("category", ""),
        "pack":             h.get("pack", "Hunting Pack"),
        "severity":         h.get("severity", "M"),
        "poc_priority":     h.get("poc_priority", "★"),
        "mitre":            h.get("mitre", ""),
        "nis2":             h.get("nis2", ""),
        "status":           status,
        "count":            len(sessions),
        "ip_src":           [],
        "ip_dst":           [],
        "ip_src_counts":    [],
        "alias_host":       [],
        "top_pairs":        [],
        "narrative":        h.get("template", ""),
        "mitigations":      h.get("mitigations", ""),
        # fields used by renderer
        "threat_context":   h.get("threat_context", ""),
        "investigate_steps": h.get("investigate_steps", []),
        "mitigation_steps": h.get("mitigation_steps", []),
        "query":            h.get("query", ""),
    }


# ─────────────────────────────────────────────
# ENRICH ENGINEER SECTIONS WITH SESSION DATA
# ─────────────────────────────────────────────

def get_tier(r):
    poc = r.get("poc_priority","")
    if poc in TIER_CFG: return poc
    cnt = r.get("count",0)
    if cnt>100: return "CRITICAL"
    if cnt>20:  return "HIGH"
    if cnt>0:   return "MEDIUM"
    return "INFO"

def get_tactic(r):
    for part in r.get("mitre","").replace(" ","").split(","):
        t = MITRE_TACTIC_MAP.get(part, MITRE_TACTIC_MAP.get(part[:6],""))
        if t: return t
    nl = r.get("name","").lower()
    for kw,tac in KW_TACTIC_MAP.items():
        if kw in nl: return tac
    return ""


def build_host_profiles(sessions: list, found: list, host_findings: dict) -> dict:
    profiles = {}
    for s in sessions:
        src = s.get("ip.src", "")
        if not src:
            continue
        if src not in profiles:
            profiles[src] = {
                "sessions": 0,
                "dst_counts": Counter(),
                "dst_alias": {},
                "direction": Counter(),
                "services": Counter(),
                "boc": set(), "eoc": set(), "ioc": set(),
                "traits": set(),
                "times": [],
            }
        p = profiles[src]
        p["sessions"] += 1
        dst = s.get("ip.dst", "")
        if dst:
            p["dst_counts"][dst] += 1
            a = s.get("alias.host", "")
            if a:
                p["dst_alias"][dst] = a
        d = s.get("direction", "")
        if d:
            p["direction"][str(d)] += 1
        svc = s.get("service", "")
        if svc and str(svc) not in ("0", ""):
            p["services"][str(svc)] += 1
        for fld in ("boc", "eoc", "ioc"):
            v = s.get(fld)
            if v:
                for item in (v if isinstance(v, list) else [v]):
                    if item:
                        p[fld].add(str(item).strip())
        trait = s.get("analysis.session", "")
        if trait:
            for item in (trait if isinstance(trait, list) else [trait]):
                if item:
                    p["traits"].add(str(item).strip())
        t = s.get("time", "")
        if t:
            try:
                p["times"].append(int(t))
            except Exception:
                pass
    return profiles

# ─────────────────────────────────────────────
# SHARED CSS / HTML ATOMS
# ─────────────────────────────────────────────
_FONT_IMPORT = "@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;600;700;800&display=swap');"

_CSS_VARS_LIGHT = """
  :root {
    --bg: #f8fafc; --bg2: #ffffff; --bg3: #f1f5f9;
    --border: #e2e8f0; --text: #0f172a; --muted: #64748b;
    --accent: #0f766e; --accent2: #7c3aed;
    --green: #16a34a; --red: #dc2626; --amber: #d97706;
    --mono: 'JetBrains Mono', ui-monospace, Consolas, monospace;
    --sans: 'Syne', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  }"""

_CSS_VARS_DARK = """
  [data-theme="dark"] {
    --bg: #0f1117; --bg2: #141720; --bg3: #1e2330;
    --border: #2a2d3a; --text: #e2e8f0; --muted: #64748b;
    --accent: #5eead4; --accent2: #a78bfa;
    --green: #4ade80; --red: #f87171; --amber: #fbbf24;
  }
  [data-theme="dark"] body                { background:#0f1117; color:#e2e8f0; }
  [data-theme="dark"] .site-header        { background:linear-gradient(135deg,#0f172a 0%,#134e4a 50%,#0f172a 100%); }
  [data-theme="dark"] .nav                { background:#141720; border-bottom-color:#2a2d3a; }
  [data-theme="dark"] .tab-btn            { color:#64748b; }
  [data-theme="dark"] .tab-btn.active     { color:#5eead4; border-bottom-color:#5eead4; }
  [data-theme="dark"] .metric-tile        { background:#141720; border-color:#2a2d3a; }
  [data-theme="dark"] .metric-value       { color:#e2e8f0; }
  [data-theme="dark"] .metric-frac        { color:#475569; }
  [data-theme="dark"] .metric-label       { color:#94a3b8; }
  [data-theme="dark"] .li-item            { border-bottom-color:#1e2330; }
  [data-theme="dark"] .li-item:hover      { background:#1e2330; }
  [data-theme="dark"] .li-item.active     { background:#0c2420; border-left-color:#5eead4; }
  [data-theme="dark"] .li-item.active .li-name { color:#5eead4; }
  [data-theme="dark"] .li-grp-header      { background:#0f1117; color:#475569; border-color:#2a2d3a; }
  [data-theme="dark"] .filter-btn         { background:#1e2330; color:#94a3b8; border-color:#2a2d3a; }
  [data-theme="dark"] .code-block         { background:#0c0f18 !important; color:#5eead4 !important; }
  [data-theme="dark"] code                { background:#1e2330; color:#5eead4; }
  [data-theme="dark"] .threat-ctx         { background:#1a1f2e; border-left-color:#334155; color:#94a3b8; }
  [data-theme="dark"] .card-desc          { color:#94a3b8; }
  [data-theme="dark"] .detected-section   { background:#141720; border-color:#2a2d3a; }
  [data-theme="dark"] .pair-table td      { border-color:#1e2330 !important; color:#e2e8f0; background:transparent !important; }
  [data-theme="dark"] .pair-table tr:hover td { background:#1e2330 !important; }
  [data-theme="dark"] .mit-row            { border-color:#1e2330; color:#cbd5e1; }
  [data-theme="dark"] .section-label      { color:#64748b; }
  [data-theme="dark"] .step-look          { color:#64748b; }
  [data-theme="dark"] .hosts-table th     { background:#0c2420; color:#5eead4; border-color:#2a2d3a; }
  [data-theme="dark"] .hosts-table td     { border-color:#1e2330; color:#e2e8f0; }
  [data-theme="dark"] .hosts-table tr:hover td { background:#1e2330; }
  [data-theme="dark"] .fs-group           { border-color:#2a2d3a; }
  [data-theme="dark"] .fs-group-header    { background:#141720; border-color:#2a2d3a; }
  [data-theme="dark"] .fs-row             { border-color:#1e2330; }
  [data-theme="dark"] .fs-row:hover       { background:#1e2330; }
  [data-theme="dark"] .fs-name            { color:#e2e8f0; }
  [data-theme="dark"] #list-col           { background:#141720 !important; border-right-color:#2a2d3a !important; }
  [data-theme="dark"] #detail-panel       { background:#0f1117 !important; }
  [data-theme="dark"] td[style*="border-right"] { border-right-color:#2a2d3a !important; }
  [data-theme="dark"] .htag-ioc           { background:#3b1212; border-color:#991b1b; color:#fca5a5; }
  [data-theme="dark"] .htag-boc           { background:#2d1f05; border-color:#92400e; color:#fde68a; }
  [data-theme="dark"] .htag-eoc           { background:#0c2420; border-color:#0f766e; color:#5eead4; }
  [data-theme="dark"] .htag-trait         { background:#1e1a3a; border-color:#4338ca; color:#a5b4fc; }
  [data-theme="dark"] .h-list-item:hover  { background:#1e2330; }
  [data-theme="dark"] .h-list-item.active { background:#0f1117; border-left-color:#5eead4; }
  [data-theme="dark"] .nobs-cell          { background:#1e2330; color:#475569; border-color:#2a2d3a; }
  [data-theme="dark"] details summary     { color:#5eead4; border-top-color:#2a2d3a; }"""

_CSS_HEADER = """
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:var(--sans); background:var(--bg); color:var(--text);
         line-height:1.5; font-size:14px; }
  .site-header {
    background:linear-gradient(135deg,#0f172a 0%,#134e4a 50%,#0f172a 100%);
    border-bottom:1px solid var(--border); padding:28px 40px; position:relative; overflow:hidden;
  }
  .site-header::before {
    content:''; position:absolute; top:-50%; right:-10%; width:500px; height:500px;
    background:radial-gradient(circle,rgba(0,212,255,0.04) 0%,transparent 70%); pointer-events:none;
  }
  .header-top { display:flex; align-items:flex-start; justify-content:space-between; gap:20px; }
  .header-title { font-size:26px; font-weight:800; letter-spacing:-0.5px; color:#fff; font-family:var(--sans); }
  .header-title span { color:#5eead4; }
  .header-sub { color:rgba(255,255,255,0.55); font-size:12px; margin-top:4px; font-family:var(--mono); }
  .header-meta { text-align:right; font-family:var(--mono); font-size:11px; color:rgba(255,255,255,0.5); }
  .header-badge {
    display:inline-block; padding:2px 8px; border-radius:4px; font-size:10px;
    font-weight:700; letter-spacing:.5px; margin-top:6px;
  }
  .nav {
    background:var(--bg2); border-bottom:1px solid var(--border);
    padding:0 40px; display:flex; gap:0; position:sticky; top:0; z-index:100;
  }
  .tab-btn {
    background:none; border:none; border-bottom:2px solid transparent;
    padding:14px 16px; font-size:12px; font-weight:600; color:var(--muted);
    cursor:pointer; letter-spacing:.3px; font-family:var(--sans);
    transition:color .15s;
  }
  .tab-btn:hover { color:var(--text); }
  .tab-btn.active { color:var(--accent); border-bottom-color:var(--accent); }
  .tab-count {
    display:inline-flex; align-items:center; justify-content:center;
    background:var(--accent); color:#fff; border-radius:10px;
    font-size:10px; font-weight:700; padding:1px 6px; margin-left:5px;
  }
  .tab-btn.active .tab-count { background:var(--accent); }
  .tab-panel { display:none; padding:28px 40px; }
  .tab-panel.active { display:block; }
  /* METRICS */
  .metrics-ribbon { display:grid; grid-template-columns:repeat(6,1fr); gap:12px; margin-bottom:20px; }
  .metric-tile {
    background:var(--bg2); border:1px solid var(--border); border-radius:8px;
    padding:16px; text-align:center;
  }
  .metric-value { font-size:28px; font-weight:700; font-family:var(--mono); color:var(--text); }
  .metric-frac { font-size:16px; color:var(--muted); }
  .metric-label { font-size:11px; font-weight:600; text-transform:uppercase;
                  letter-spacing:.5px; color:var(--muted); margin-top:4px; }
  .metric-sub { font-size:10px; color:var(--muted); margin-top:2px; }
  /* FINDINGS LIST */
  .filter-bar {
    display:flex; gap:6px; flex-wrap:wrap; padding:10px 12px;
    background:var(--bg2); border-radius:8px; margin-bottom:12px;
  }
  .filter-btn {
    background:var(--bg3); border:1px solid var(--border); border-radius:20px;
    padding:3px 12px; font-size:11px; font-weight:600; cursor:pointer;
    color:var(--muted); font-family:var(--sans);
  }
  .filter-btn:hover { border-color:var(--accent); color:var(--accent); }
  .filter-btn.active { background:var(--accent); color:#fff; border-color:var(--accent); }
  .li-grp-header {
    padding:5px 12px; font-size:10px; font-weight:700; text-transform:uppercase;
    letter-spacing:.6px; color:var(--muted); background:var(--bg3);
    border-bottom:1px solid var(--border); border-top:1px solid var(--border);
    position:sticky; top:0;
  }
  .li-item {
    padding:10px 12px; border-bottom:1px solid var(--border); cursor:pointer;
    transition:background .12s;
  }
  .li-item:hover { background:var(--bg3); }
  .li-item.active { border-left:3px solid var(--accent); padding-left:9px;
                    background:var(--bg2); }
  .li-item.active .li-name { color:var(--accent); }
  .li-hid {
    display:inline-block; font-size:9px; font-weight:700; padding:1px 5px;
    border-radius:3px; color:#fff; margin-right:5px; font-family:var(--mono);
  }
  .li-name { font-size:12px; font-weight:500; color:var(--text); }
  .li-meta { font-size:10px; color:var(--muted); margin-top:2px; font-family:var(--mono); }
  /* CARD */
  .card-detail { display:none; }
  .card-detail.active { display:block; }
  .card-header-row {
    display:flex; align-items:center; gap:10px; margin-bottom:12px; flex-wrap:wrap;
  }
  .card-id { font-family:var(--mono); font-size:12px; color:var(--muted); }
  .tier-badge {
    font-size:10px; font-weight:700; padding:3px 10px; border-radius:4px;
    color:#fff; letter-spacing:.5px;
  }
  .card-title { font-size:20px; font-weight:700; color:var(--text); }
  .threat-ctx {
    background:var(--bg3); border-left:3px solid var(--border);
    border-radius:0 6px 6px 0; padding:10px 14px; margin-bottom:14px;
    font-size:12px; color:var(--muted); line-height:1.7;
  }
  .detected-section {
    background:var(--bg2); border:1px solid var(--border); border-radius:8px;
    padding:14px 16px; margin-bottom:14px;
  }
  .section-label {
    font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:.6px;
    color:var(--muted); margin-bottom:8px;
  }
  .pair-table { width:100%; border-collapse:collapse; font-size:12px; }
  .pair-table td { padding:5px 8px; border-bottom:1px solid var(--border); }
  .pair-table tr:last-child td { border-bottom:none; }
  .pair-table tr:hover td { background:var(--bg3); }
  .ip-src-cell { font-family:var(--mono); font-size:10px; font-weight:500;
                 background:var(--bg3); padding:2px 7px; border-radius:3px; }
  .ip-dst-cell { font-family:var(--mono); font-size:11px; font-weight:600;
                 padding:2px 7px; border-radius:3px; border:1px solid; }
  .code-block {
    background:var(--bg3); border-radius:4px; padding:6px 10px;
    font-family:var(--mono); font-size:11px; color:var(--accent);
    margin:3px 0; display:block;
  }
  .step-look { font-size:10px; color:var(--muted); font-style:italic; margin-top:2px; }
  .mit-row { display:flex; gap:8px; align-items:flex-start; padding:5px 0;
             border-bottom:1px solid var(--border); font-size:12px; }
  .mit-badge { font-size:9px; font-weight:700; padding:2px 6px; border-radius:3px;
               color:#fff; flex-shrink:0; margin-top:1px; }
  /* HOSTS TAB */
  .h-list-item { padding:9px 12px; border-bottom:1px solid var(--border); cursor:pointer; }
  .h-list-item:hover { background:var(--bg3); }
  .h-list-item.active { background:var(--bg2); border-left:3px solid var(--accent);
                        padding-left:9px; }
  .h-detail { display:none; }
  .h-detail.active { display:block; }
  /* HTAG BADGES */
  .htag { font-size:10px; padding:2px 8px; border-radius:4px; border:1px solid;
          cursor:pointer; display:inline-block; transition:transform .1s; margin:2px; }
  .htag:hover { transform:scale(1.05); }
  .htag-ioc   { background:#fef2f2; border-color:#fca5a5; color:#991b1b; }
  .htag-boc   { background:#fffbeb; border-color:#fde68a; color:#92400e; }
  .htag-eoc   { background:#f0fdfa; border-color:#99f6e4; color:#0f766e; }
  .htag-trait { background:#f0f4ff; border-color:#c7d2fe; color:#3730a3; }
  /* FINDINGS SUMMARY */
  .fs-wrap { margin-top:4px; }
  .fs-group { margin-bottom:12px; border:1px solid var(--border); border-radius:6px; overflow:hidden; }
  .fs-group-header { display:flex; align-items:center; padding:7px 12px;
                     background:var(--bg2); border-bottom:1px solid var(--border); gap:0; }
  .fs-row { display:flex; align-items:center; gap:8px; padding:7px 12px;
            border-bottom:1px solid var(--border); cursor:pointer; font-size:11px; }
  .fs-row:last-child { border-bottom:none; }
  .fs-row:hover { background:var(--bg3); }
  .fs-hid { font-family:var(--mono); font-size:10px; font-weight:700;
            color:var(--muted); min-width:42px; flex-shrink:0; }
  .fs-name { flex:1; font-weight:500; color:var(--text); }
  .fs-cnt { font-size:11px; color:var(--muted); font-family:var(--mono); flex-shrink:0; }
  /* NOT OBSERVED */
  .nobs-cell { background:var(--bg3); border:1px solid var(--border); border-radius:4px;
               padding:2px 6px; font-size:9px; color:var(--muted); font-family:var(--mono);
               display:inline-block; margin:2px; }
  /* FOOTER */
  .th-footer { margin-top:32px; padding:16px; text-align:center; color:var(--muted);
               font-size:11px; border-top:1px solid var(--border); font-family:var(--mono); }"""

# ─────────────────────────────────────────────
# THREAT HUNTING REPORT RENDERER
# ─────────────────────────────────────────────
def render_threathunting_html(data: dict, theme: str = "light") -> str:
    meta         = data.get("meta", {})
    summary      = data.get("summary", {})
    hunt_results = data.get("hunt", [])
    raw_sessions = data.get("sessions", [])
    client_name  = meta.get("client", "Client")
    generated    = meta.get("generated", "")

    found    = [r for r in hunt_results if r["status"] == "FOUND"]
    not_obs  = [r for r in hunt_results if r["status"] == "NOT_OBSERVED"]
    gaps     = [r for r in hunt_results if r["status"] == "PARSER_UNAVAILABLE"]

    # ── host findings map ──
    host_findings: dict = {}
    for r in found:
        tier = get_tier(r)
        for p in r.get("top_pairs", []):
            src = p.get("src", "")
            if src:
                host_findings.setdefault(src, [])
                entry = (r["id"], r["name"], tier)
                if entry not in host_findings[src]:
                    host_findings[src].append(entry)

    # ── top hosts sorted by risk ──
    host_score = {}
    for ip, findings in host_findings.items():
        tiers = [f[2] for f in findings]
        score = sum({"CRITICAL": 100, "HIGH": 10, "MEDIUM": 1, "INFO": 0}.get(t, 0) for t in tiers)
        host_score[ip] = score
    top_hosts = sorted(host_score.items(), key=lambda x: -x[1])[:15]

    def host_max_tier(ip):
        tiers = [f[2] for f in host_findings.get(ip, [])]
        for t in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
            if t in tiers:
                return t
        return "INFO"

    # ── metrics ──
    n_total     = summary.get("total_sessions", len(raw_sessions))
    n_found     = len(found)
    n_total_hyp = len(hunt_results)
    n_crit      = sum(1 for r in found if get_tier(r) == "CRITICAL")
    n_high      = sum(1 for r in found if get_tier(r) == "HIGH")
    n_med       = sum(1 for r in found if get_tier(r) == "MEDIUM")
    n_info      = sum(1 for r in found if get_tier(r) == "INFO")
    n_sources   = len(set(
        p.get("src", "") for r in found for p in r.get("top_pairs", []) if p.get("src")
    ))

    crit_color = TIER_CFG["CRITICAL"]["color"]
    high_color = TIER_CFG["HIGH"]["color"]
    med_color  = TIER_CFG["MEDIUM"]["color"]

    metrics_html = (
        '<div class="metrics-ribbon">'
        f'<div class="metric-tile"><div class="metric-value">{n_total:,}</div>'
        f'<div class="metric-label">Sessions Analyzed</div>'
        f'<div class="metric-sub">{meta.get("time_range","")}</div></div>'
        f'<div class="metric-tile"><div class="metric-value">{n_found}'
        f'<span class="metric-frac"> / {n_total_hyp}</span></div>'
        f'<div class="metric-label">Hypotheses with Findings</div>'
        f'<div class="metric-sub">{n_total_hyp} evaluated</div></div>'
        f'<div class="metric-tile" style="border-color:{crit_color}">'
        f'<div class="metric-value" style="color:{crit_color}">{n_crit}</div>'
        f'<div class="metric-label">Critical</div>'
        f'<div class="metric-sub">act immediately</div></div>'
        f'<div class="metric-tile" style="border-color:{high_color}">'
        f'<div class="metric-value" style="color:{high_color}">{n_high}</div>'
        f'<div class="metric-label">High</div>'
        f'<div class="metric-sub">act today</div></div>'
        f'<div class="metric-tile" style="border-color:{med_color}">'
        f'<div class="metric-value" style="color:{med_color}">{n_med}</div>'
        f'<div class="metric-label">Medium</div>'
        f'<div class="metric-sub">this week</div></div>'
        f'<div class="metric-tile"><div class="metric-value">{n_sources}'
        f'<span class="metric-frac"> / {len(host_findings)}</span></div>'
        f'<div class="metric-label">Detection Sources</div>'
        f'<div class="metric-sub">{len(gaps)} config gaps</div></div>'
        '</div>'
    )

    # ── MITRE coverage ──
    covered = set()
    for r in found:
        tac = get_tactic(r)
        if tac:
            covered.add(tac)
    mitre_badges = ""
    for tac in TACTIC_ORDER:
        if tac in covered:
            mitre_badges += f'<span style="font-size:10px;font-weight:700;padding:3px 8px;border-radius:4px;background:{TACTIC_COLORS[tac]};color:#fff;white-space:nowrap">{tac}</span>'
        else:
            mitre_badges += f'<span style="font-size:10px;padding:3px 8px;border-radius:4px;background:var(--bg3);color:var(--muted);border:1px solid var(--border);white-space:nowrap">{tac}</span>'
    mitre_html = (
        f'<div style="margin-bottom:20px">'
        f'<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:8px">'
        f'MITRE ATT&CK Coverage — {len(covered)}/{len(TACTIC_ORDER)} tactics observed</div>'
        f'<div style="display:flex;flex-wrap:wrap;gap:6px">{mitre_badges}</div></div>'
    ) if found else ""

    # ── findings summary (overview) ──
    def make_findings_summary():
        if not found:
            return '<p style="color:var(--muted);font-size:13px">No findings in this analysis window.</p>'
        parts = []
        for tname, color, urgency in [
            ("CRITICAL", "#dc2626", "Act immediately"),
            ("HIGH",     "#d97706", "Act today"),
            ("MEDIUM",   "#0f766e", "This week"),
            ("INFO",     "#64748b", "Monitor"),
        ]:
            items = [r for r in found if get_tier(r) == tname]
            if not items:
                continue
            rows = ""
            for r in sorted(items, key=lambda x: -x.get("count", 0)):
                cid   = r["id"].replace("-", "_")
                cnt   = r.get("count", 0)
                pairs = len(r.get("top_pairs", []))
                rows += (
                    f'<div class="fs-row" onclick="goToFinding(\'{cid}\')">'
                    f'<span class="fs-hid">{r["id"]}</span>'
                    f'<span class="fs-name">{r["name"]}</span>'
                    f'<span class="fs-cnt">{cnt:,} sess · {pairs} pairs</span>'
                    '</div>'
                )
            parts.append(
                f'<div class="fs-group">'
                f'<div class="fs-group-header" style="border-left:3px solid {color}">'
                f'<span style="color:{color};font-weight:700;font-size:11px">{tname}</span>'
                f'<span style="color:var(--muted);font-size:10px;margin-left:8px">{urgency}</span>'
                f'<span style="color:var(--muted);font-size:10px;margin-left:auto">'
                f'{len(items)} finding{"s" if len(items)!=1 else ""}</span>'
                '</div>' + rows + '</div>'
            )
        return "".join(parts)

    grid_html = (
        '<div class="fs-wrap">'
        '<div style="font-size:11px;font-weight:600;text-transform:uppercase;'
        'letter-spacing:.6px;color:var(--muted);margin-bottom:10px">'
        'Findings Summary — click any row to open details</div>'
        + make_findings_summary() + '</div>'
    )

    # ── tactical cards (Findings tab) ──
    list_items_html = ""
    cards_html      = ""

    grp_order = ["CRITICAL", "HIGH", "MEDIUM", "INFO"]
    by_tier   = {t: [] for t in grp_order}
    for r in found:
        by_tier[get_tier(r)].append(r)

    first_card = True
    for tier_name in grp_order:
        items = by_tier[tier_name]
        if not items:
            continue
        color = TIER_CFG[tier_name]["color"]
        list_items_html += (
            f'<div class="li-grp-header">{tier_name} — {len(items)}</div>'
        )
        for r in sorted(items, key=lambda x: -x.get("count", 0)):
            cid    = r["id"].replace("-", "_")
            cnt    = r.get("count", 0)
            pairs  = len(r.get("top_pairs", []))
            active = "active" if first_card else ""
            list_items_html += (
                f'<div class="li-item {active}" data-tier="{tier_name}" '
                f'data-cid="{cid}" onclick="selectCard(\'{cid}\',this)">'
                f'<div><span class="li-hid" style="background:{color}">{r["id"]}</span>'
                f'<span class="li-name">{r["name"]}</span></div>'
                f'<div class="li-meta">{cnt:,} sess · {pairs} pairs</div>'
                '</div>'
            )

            # Build pair rows
            pair_rows = ""
            for p in r.get("top_pairs", []):
                src_ip  = p.get("src", "")
                dst_ip  = p.get("dst", "")
                alias   = p.get("alias", "")
                pcnt    = p.get("count", 0)
                fc      = p.get("feed_cat", "")
                verdict = p.get("verdict", "Review")
                pill_map = {
                    "llm-enterprise": ("#eff6ff", "#1d4ed8"),
                    "llm-coding":     ("#faf5ff", "#7c3aed"),
                    "llm-malicious":  ("#fef2f2", "#dc2626"),
                    "local-llm":      ("#fffbeb", "#d97706"),
                }
                pb, pc = pill_map.get(fc, ("var(--bg3)", "var(--muted)"))
                pill   = f'<span style="font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px;background:{pb};color:{pc}">{fc}</span>' if fc else ""
                dst_color = "#dc2626" if verdict == "Investigate" else "#d97706" if verdict == "Review" else "var(--border)"
                pair_rows += (
                    f'<tr><td><span class="ip-src-cell">{src_ip}</span></td>'
                    f'<td style="color:var(--muted);text-align:center">→</td>'
                    f'<td><span class="ip-dst-cell" style="border-color:{dst_color};color:{dst_color}">{dst_ip}</span></td>'
                    f'<td style="font-size:11px;color:var(--muted)">{alias}</td>'
                    f'<td style="text-align:right;font-size:11px;color:var(--muted);font-family:var(--mono)">{pcnt}</td>'
                    f'<td>{pill}</td>'
                    f'<td style="text-align:right"><span style="font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px;background:{dst_color};color:#fff">{verdict}</span></td>'
                    '</tr>'
                )

            # Build investigate steps — replace {src_ip}/{dst_ip} placeholders
            inv_steps   = ""
            top_src_ip  = r["top_pairs"][0]["src"] if r.get("top_pairs") else ""
            top_dst_ip  = r["top_pairs"][0]["dst"] if r.get("top_pairs") else ""
            base_query  = r.get("query", "")
            for i, step in enumerate(r.get("investigate_steps", [])[:4], 1):
                q    = step.get("query", "")
                desc = step.get("description", "") or step.get("step", "")
                look = step.get("look_for", "")
                q = (q.replace("{src_ip}",    top_src_ip)
                      .replace("{dst_ip}",    top_dst_ip)
                      .replace("{base_query}", base_query)
                      .replace("{ip_src}",    top_src_ip)
                      .replace("{ip_dst}",    top_dst_ip))
                inv_steps += (
                    f'<div style="margin-bottom:10px">'
                    f'<div style="font-size:11px;font-weight:600;color:var(--text);margin-bottom:3px">'
                    f'{i}. {desc}</div>'
                    f'<code class="code-block">{q}</code>'
                    + (f'<div class="step-look">↳ Look for: {look}</div>' if look else '')
                    + '</div>'
                )

            # Build mitigation steps — replace {ip_src}/{ip_dst} placeholders
            mit_rows = ""
            for m in r.get("mitigation_steps", []):
                urgency  = m.get("urgency", "week")
                ucfg     = URGENCY_CFG.get(urgency, URGENCY_CFG["week"])
                text     = (m.get("text", m.get("action", ""))
                             .replace("{ip_src}", top_src_ip)
                             .replace("{ip_dst}", top_dst_ip)
                             .replace("{src_ip}", top_src_ip)
                             .replace("{dst_ip}", top_dst_ip))
                mit_rows += (
                    f'<div class="mit-row">'
                    f'<span class="mit-badge" style="background:{ucfg["color"]}">{ucfg["label"]}</span>'
                    f'<span style="font-size:12px">{text}</span>'
                    '</div>'
                )

            threat_ctx = r.get("threat_context", "")
            mitre_val  = r.get("mitre", "")
            tac        = get_tactic(r)
            tac_badge  = f'<span style="font-size:10px;padding:2px 8px;border-radius:3px;background:{TACTIC_COLORS.get(tac,"#64748b")};color:#fff;font-weight:600">{tac}</span>' if tac else ""

            cards_html += (
                f'<div class="card-detail {active}" id="detail-{cid}">'
                f'<div class="card-header-row">'
                f'<span class="card-id">{r["id"]}</span>'
                f'<span class="tier-badge" style="background:{color}">'
                f'{TIER_CFG[tier_name]["label"]}</span>'
                f'<span class="card-title">{r["name"]}</span>'
                '</div>'
                + (f'<div class="threat-ctx">{threat_ctx}</div>' if threat_ctx else '')
                + f'<div class="detected-section">'
                f'<div class="section-label">Detected</div>'
                f'<div class="section-label" style="margin-top:6px">Connections</div>'
                f'<table class="pair-table">{pair_rows}</table>'
                f'<div style="margin-top:8px;font-size:11px;color:var(--muted)">'
                f'{cnt:,} total sessions · {pairs} src→dst pairs</div>'
                '</div>'
                f'<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:14px">'
                f'<div>'
                f'<div class="section-label" style="margin-bottom:8px">How to investigate in NetWitness</div>'
                + inv_steps +
                '</div>'
                f'<div>'
                f'<div class="section-label" style="margin-bottom:8px">Mitigations</div>'
                + mit_rows +
                f'<div style="margin-top:10px;font-size:11px;color:var(--muted)">'
                f'MITRE: <code>{mitre_val}</code>'
                + (f' · {tac_badge}' if tac_badge else '')
                + '</div></div></div>'
                '</div>'
            )
            first_card = False

    # ── NOT OBSERVED + GAPS ──
    nobs_html = ""
    if not_obs:
        cells = "".join(f'<span class="nobs-cell">{r["id"]}</span>' for r in not_obs)
        nobs_html = (
            '<details style="margin-bottom:12px">'
            f'<summary style="cursor:pointer;font-size:11px;color:var(--muted);padding:8px 0;border-top:1px solid var(--border)">'
            f'Not observed ({len(not_obs)}) — click to expand</summary>'
            f'<div style="padding:10px 0">{cells}</div></details>'
        )
    gaps_html = ""
    if gaps:
        cells = "".join(f'<span class="nobs-cell" style="border-color:#fed7aa;color:#9a3412">{r["id"]}</span>' for r in gaps)
        gaps_html = (
            '<details id="visibility-gaps" style="margin-bottom:12px">'
            f'<summary style="cursor:pointer;font-size:11px;color:#d97706;padding:8px 0;border-top:1px solid var(--border)">'
            f'Configuration gaps ({len(gaps)}) — parser unavailable</summary>'
            f'<div style="padding:10px 0">{cells}</div></details>'
        )

    # ── HOST-CENTRIC TAB ──
    host_profiles   = build_host_profiles(raw_sessions, found, host_findings)
    host_list_html  = ""
    host_detail_html = ""
    first_host      = True

    for ip, _score in top_hosts:
        prof       = host_profiles.get(ip, {})
        tags_src   = host_findings.get(ip, [])
        max_tier   = host_max_tier(ip)
        tcfg       = TIER_CFG[max_tier]
        n_sess     = prof.get("sessions", 0)
        hid_safe   = ip.replace(".", "_")
        active_cls = "active" if first_host else ""

        # timeline
        import datetime as _dt
        tms = prof.get("times", [])
        tl_labels, tl_values = "[]", "[]"
        if tms:
            mt   = min(tms)
            hc   = Counter((t - mt) // 3600 for t in tms)
            mb   = max(hc.keys())
            lbls = []
            vals = []
            for b in range(mb + 1):
                try:
                    lbls.append(_dt.datetime.utcfromtimestamp(mt + b * 3600).strftime("%H:%M"))
                except Exception:
                    lbls.append(str(b))
                vals.append(hc.get(b, 0))
            tl_labels = json.dumps(lbls)
            tl_values = json.dumps(vals)

        # time range
        try:
            ts = (f'{_dt.datetime.utcfromtimestamp(min(tms)).strftime("%d/%m %H:%M")} → '
                  f'{_dt.datetime.utcfromtimestamp(max(tms)).strftime("%d/%m %H:%M")} UTC') if tms else ""
        except Exception:
            ts = ""

        # direction bars
        dir_total = sum(prof.get("direction", {}).values()) or 1
        dir_rows  = ""
        for d, col in [("outbound", "#0f766e"), ("lateral", "#d97706"), ("inbound", "#64748b")]:
            cnt = prof.get("direction", {}).get(d, 0)
            pct = round(cnt / dir_total * 100)
            if pct > 0:
                dir_rows += (
                    f'<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">'
                    f'<span style="width:58px;text-align:right;color:var(--muted);font-size:10px">{d}</span>'
                    f'<div style="flex:1;height:5px;background:var(--border);border-radius:3px;overflow:hidden">'
                    f'<div style="height:100%;width:{pct}%;background:{col};border-radius:3px"></div></div>'
                    f'<span style="width:28px;text-align:right;color:var(--muted);font-size:10px">{pct}%</span></div>'
                )

        # service bars
        svc_total  = sum(prof.get("services", {}).values()) or 1
        svc_colors = {"443": "#0f766e", "80": "#d97706", "445": "#64748b",
                      "53": "#94a3b8", "https": "#0f766e", "http": "#d97706",
                      "smb": "#64748b", "dns": "#94a3b8"}
        svc_rows = ""
        for svc, cnt in sorted(prof.get("services", {}).items(), key=lambda x: -x[1])[:5]:
            pct = round(cnt / svc_total * 100)
            col = svc_colors.get(str(svc).lower(), "#7c3aed")
            svc_rows += (
                f'<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">'
                f'<span style="width:58px;text-align:right;color:var(--muted);font-size:10px;font-family:var(--mono)">{svc}</span>'
                f'<div style="flex:1;height:5px;background:var(--border);border-radius:3px;overflow:hidden">'
                f'<div style="height:100%;width:{pct}%;background:{col};border-radius:3px"></div></div>'
                f'<span style="width:28px;text-align:right;color:var(--muted);font-size:10px">{pct}%</span></div>'
            )

        # destinations
        dst_rows = ""
        for dst, cnt in sorted(prof.get("dst_counts", {}).items(), key=lambda x: -x[1])[:8]:
            alias = prof.get("dst_alias", {}).get(dst, "")
            fc, _ = feed_lookup(alias or dst)
            pill_map = {
                "llm-enterprise": ("#eff6ff", "#1d4ed8"),
                "llm-coding":     ("#faf5ff", "#7c3aed"),
                "llm-malicious":  ("#fef2f2", "#dc2626"),
                "local-llm":      ("#fffbeb", "#d97706"),
            }
            pb, pc = pill_map.get(fc, ("", ""))
            pill   = f'<span style="font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;background:{pb};color:{pc}">{fc}</span>' if fc else ""
            # find related finding
            hf     = next((r for r in found if any(p.get("dst") == dst for p in r.get("top_pairs", []))), None)
            click  = f'onclick="goToFinding(\'{hf["id"].replace("-","_")}\')" style="cursor:pointer"' if hf else ""
            dst_rows += (
                f'<div {click} style="display:flex;align-items:center;gap:6px;padding:5px 0;'
                f'border-bottom:1px solid var(--border);font-size:11px">'
                f'<span style="font-family:var(--mono);font-size:10px;font-weight:500;min-width:105px">{dst}</span>'
                f'<span style="flex:1;color:var(--muted);font-size:10px">{alias}</span>'
                f'<span style="color:var(--muted);font-size:10px;min-width:44px;text-align:right">{cnt}</span>'
                f'{pill}</div>'
            )

        # findings list
        finding_rows = ""
        for hid, hname, htier in sorted(tags_src, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}.get(x[2], 4)):
            r   = next((r for r in found if r["id"] == hid), {})
            cnt = r.get("count", 0)
            cid = hid.replace("-", "_")
            col = TIER_CFG.get(htier, TIER_CFG["INFO"])["color"]
            tac = get_tactic(r)
            tb  = f'<span style="font-size:9px;padding:1px 5px;border-radius:3px;background:{TACTIC_COLORS.get(tac,"#64748b")};color:#fff;margin-left:4px">{tac}</span>' if tac else ""
            finding_rows += (
                f'<div onclick="goToFinding(\'{cid}\')" title="Click to open" '
                f'style="display:flex;align-items:center;gap:7px;padding:5px 0;'
                f'border-bottom:1px solid var(--border);cursor:pointer">'
                f'<span style="background:{col};color:#fff;font-size:9px;font-weight:700;'
                f'padding:1px 5px;border-radius:3px;flex-shrink:0">{hid}</span>'
                f'<span style="flex:1;font-size:11px;font-weight:500">{hname}</span>'
                f'{tb}<span style="font-size:10px;color:var(--muted);font-family:var(--mono);flex-shrink:0">{cnt:,}</span>'
                '</div>'
            )

        # kill chain
        kc_map = {}
        for hid, hname, htier in tags_src:
            r   = next((r for r in found if r["id"] == hid), {})
            tac = get_tactic(r)
            if tac:
                kc_map.setdefault(tac, []).append(hid)
        kc_steps = [t for t in TACTIC_ORDER if t in kc_map]
        kc_inner = ""
        if len(kc_steps) >= 2:
            for i, tac in enumerate(kc_steps):
                kc_inner += f'<span style="font-size:10px;padding:2px 8px;border-radius:3px;background:{TACTIC_COLORS.get(tac,"#64748b")};color:#fff;font-weight:600">{tac}</span>'
                if i < len(kc_steps) - 1:
                    kc_inner += '<span style="color:var(--muted);font-size:11px">→</span>'
        kc_block = (
            '<div style="display:flex;flex-wrap:wrap;align-items:center;gap:5px;'
            'padding:9px 12px;background:var(--bg3);border-radius:6px;'
            'border-left:3px solid #dc2626;margin-bottom:14px">'
            '<div style="font-size:10px;font-weight:700;text-transform:uppercase;'
            'letter-spacing:.6px;color:#dc2626;width:100%;margin-bottom:4px">Attack chain</div>'
            + kc_inner + '</div>'
        ) if kc_steps else ""

        # htags
        def _htag_row(fld, cls):
            tags = sorted(prof.get(fld, set()))
            if not tags:
                return '<span style="font-size:10px;color:var(--muted)">none</span>'
            parts = []
            for tag in tags:
                hf = next((r for r in found if any(
                    tag in _as_list(s.get(fld, ""))
                    for s in raw_sessions if s.get("ip.src") == ip
                )), None)
                if hf:
                    hf_cid   = hf["id"].replace("-", "_")
                    hf_id    = hf["id"]
                    hf_name  = hf["name"]
                    parts.append(
                        f'<span class="htag {cls}" onclick="goToFinding(\'{hf_cid}\')" ' +
                        f'title="{hf_id}: {hf_name}">{tag}</span>'
                    )
                else:
                    parts.append(f'<span class="htag {cls}">{tag}</span>')
            return " ".join(parts)

        traits_html = " ".join(f'<span class="htag htag-trait">{t}</span>' for t in sorted(prof.get("traits", set()))) or '<span style="font-size:10px;color:var(--muted)">none</span>'

        # left list item
        host_list_html += (
            f'<div class="h-list-item {active_cls}" id="hl-{hid_safe}" onclick="selectHost(\'{hid_safe}\')">'
            f'<div style="display:flex;align-items:center;gap:6px;margin-bottom:3px">'
            f'<span style="background:{tcfg["color"]};color:#fff;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px">{max_tier[:4]}</span>'
            f'<span style="font-size:12px;font-weight:500;font-family:var(--mono)">{ip}</span></div>'
            f'<div style="font-size:10px;color:var(--muted)">{len(tags_src)} findings · {n_sess:,} sess</div>'
            '</div>'
        )

        # right detail panel
        udst = len(prof.get("dst_counts", {}))
        host_detail_html += (
            f'<div class="h-detail {active_cls}" id="hd-{hid_safe}">'
            f'<div style="font-size:18px;font-weight:500;font-family:var(--mono);margin-bottom:3px">{ip}</div>'
            f'<div style="font-size:11px;color:var(--muted);margin-bottom:12px">'
            f'{len(tags_src)} findings · {n_sess:,} sessions · {udst} destinations · {ts}</div>'
            + kc_block
            + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px">'
            f'<div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:11px">'
            f'<div style="font-size:10px;font-weight:500;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:7px">Direction</div>'
            + (dir_rows or '<div style="font-size:11px;color:var(--muted)">no data</div>')
            + '</div>'
            f'<div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:11px">'
            f'<div style="font-size:10px;font-weight:500;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:7px">Protocols</div>'
            + (svc_rows or '<div style="font-size:11px;color:var(--muted)">no data</div>')
            + '</div></div>'
            f'<div style="font-size:10px;font-weight:500;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:5px">Activity timeline</div>'
            f'<div style="position:relative;width:100%;height:80px;margin-bottom:14px">'
            f'<canvas id="tl-{hid_safe}"></canvas></div>'
            f'<div style="font-size:10px;font-weight:500;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:5px">Top destinations</div>'
            f'<div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:8px 12px;margin-bottom:14px">'
            + (dst_rows or '<div style="font-size:11px;color:var(--muted)">no data</div>')
            + '</div>'
            f'<div style="font-size:10px;font-weight:500;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:5px">Findings</div>'
            f'<div style="margin-bottom:14px">'
            + (finding_rows or '<div style="font-size:11px;color:var(--muted)">none</div>')
            + '</div>'
            f'<div style="font-size:10px;font-weight:500;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:5px">Threat tags</div>'
            f'<div style="font-size:10px;color:var(--muted);margin-bottom:3px">IOC</div>'
            f'<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:7px">{_htag_row("ioc","htag-ioc")}</div>'
            f'<div style="font-size:10px;color:var(--muted);margin-bottom:3px">BOC</div>'
            f'<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:7px">{_htag_row("boc","htag-boc")}</div>'
            f'<div style="font-size:10px;color:var(--muted);margin-bottom:3px">Session traits</div>'
            f'<div style="display:flex;flex-wrap:wrap;gap:4px">{traits_html}</div>'
            + f'<script>(function(){{var c=document.getElementById("tl-{hid_safe}");if(!c||typeof Chart==="undefined")return;var d=document.documentElement.getAttribute("data-theme")==="dark";new Chart(c,{{type:"bar",data:{{labels:{tl_labels},datasets:[{{data:{tl_values},backgroundColor:d?"rgba(94,234,212,0.4)":"rgba(15,118,110,0.4)",borderColor:d?"#5eead4":"#0f766e",borderWidth:1,borderRadius:2}}]}},options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{display:false}}}},scales:{{x:{{ticks:{{color:d?"#475569":"#94a3b8",font:{{size:9}}}},grid:{{display:false}}}},y:{{ticks:{{color:d?"#475569":"#94a3b8",font:{{size:9}}}},grid:{{color:d?"rgba(255,255,255,0.04)":"rgba(0,0,0,0.04)"}},beginAtZero:true}}}}}}}})}})();</script>'
            + '</div>'
        )
        first_host = False

    hosts_tab_html = (
        '<div style="display:table;width:100%;border:1px solid var(--border);'
        'border-radius:8px;overflow:hidden;margin-bottom:24px">'
        '<div style="display:table-cell;width:240px;vertical-align:top;'
        'border-right:1px solid var(--border);background:var(--bg2)">'
        f'<div style="padding:7px 12px;font-size:10px;font-weight:500;text-transform:uppercase;'
        f'letter-spacing:.6px;color:var(--muted);border-bottom:1px solid var(--border)">'
        f'{len(top_hosts)} hosts at risk</div>'
        f'<div style="max-height:680px;overflow-y:auto">{host_list_html}</div>'
        '</div>'
        '<div id="host-detail-panel" style="display:table-cell;vertical-align:top;'
        'padding:20px 22px;background:var(--bg);max-height:680px;overflow-y:auto">'
        + host_detail_html + '</div></div>'
    ) if top_hosts else '<p style="color:var(--muted)">No hosts at risk in this window.</p>'

    # ── pre-computed JS strings (no backslash in f-string) ──
    _btn_ov  = "switchTab('overview',this)"
    _btn_h   = "switchTab('hosts',this)"
    _btn_f   = "switchTab('findings',this)"

    # ── ASSEMBLE HTML ──
    html = (
        f'<!DOCTYPE html>\n'
        f'<html lang="en" data-theme="{theme}">\n'
        f'<head>\n'
        f'<meta charset="UTF-8">\n'
        f'<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        f'<title>Threat Check — {client_name}</title>\n'
        f'{_CHARTJS_INLINE}\n'
        f'<style>\n'
        f'{_FONT_IMPORT}\n'
        f'{_CSS_VARS_LIGHT}\n'
        f'{_CSS_VARS_DARK}\n'
        f'{_CSS_HEADER}\n'
        f'</style>\n'
        f'</head>\n'
        f'<body>\n'
        f'<header class="site-header">\n'
        f'  <div class="header-top">\n'
        f'    <div>\n'
        f'      <div class="header-title">NetWitness <span>Threat Check</span></div>\n'
        f'      <div class="header-sub">{client_name} · {generated}</div>\n'
        f'    </div>\n'
        f'    <div class="header-meta">\n'
        f'      <div>v{VERSION} · {meta.get("time_range","")}</div>\n'
        f'      <div>{meta.get("concentrator","")}</div>\n'
        f'      <div class="header-badge" style="background:{"#dc2626" if n_crit > 0 else "#0f766e"};color:#fff">\n'
        f'        {"⚠ " + str(n_crit) + " CRITICAL" if n_crit > 0 else "✓ No critical findings"}\n'
        f'      </div>\n'
        f'    </div>\n'
        f'  </div>\n'
        f'</header>\n'
        f'<nav class="nav">\n'
        f'  <button class="tab-btn active" onclick="{_btn_ov}">Overview</button>\n'
        f'  <button class="tab-btn" onclick="{_btn_h}">Hosts <span class="tab-count">{len(top_hosts)}</span></button>\n'
        f'  <button class="tab-btn" onclick="{_btn_f}">Findings <span class="tab-count">{len(found)}</span></button>\n'
        f'</nav>\n'
        f'<div id="tab-overview" class="tab-panel active">\n'
        f'{metrics_html}\n'
        f'{mitre_html}\n'
        f'{grid_html}\n'
        f'</div>\n'
        f'<div id="tab-hosts" class="tab-panel">\n'
        f'{hosts_tab_html}\n'
        f'</div>\n'
        f'<div id="tab-findings" class="tab-panel">\n'
        f'  <div class="filter-bar" style="border-radius:8px 8px 0 0;margin-bottom:0;border-bottom:1px solid var(--border)">\n'
        f'    <button class="filter-btn active" data-tier="ALL" onclick="filterList(\'ALL\',this)">All {len(found)}</button>\n'
        f'    <button class="filter-btn" data-tier="CRITICAL" onclick="filterList(\'CRITICAL\',this)" style="color:#991b1b;border-color:#fecaca;background:#fef2f2">CRIT <span id="cnt-CRITICAL"></span></button>\n'
        f'    <button class="filter-btn" data-tier="HIGH" onclick="filterList(\'HIGH\',this)" style="color:#92400e;border-color:#fde68a;background:#fffbeb">HIGH <span id="cnt-HIGH"></span></button>\n'
        f'    <button class="filter-btn" data-tier="MEDIUM" onclick="filterList(\'MEDIUM\',this)" style="color:#0f766e;border-color:#99f6e4;background:#f0fdfa">MED <span id="cnt-MEDIUM"></span></button>\n'
        f'    <button class="filter-btn" data-tier="INFO" onclick="filterList(\'INFO\',this)" style="color:#475569;border-color:#e2e8f0;background:#f8fafc">INFO <span id="cnt-INFO"></span></button>\n'
        f'  </div>\n'
        f'  <table style="width:100%;border-collapse:collapse;border:1px solid var(--border);border-top:none;border-radius:0 0 8px 8px;margin-bottom:24px">\n'
        f'    <tr style="vertical-align:top">\n'
        f'      <td id="list-col" style="width:290px;min-width:290px;max-width:290px;border-right:1px solid var(--border);padding:0;background:var(--bg2);vertical-align:top">\n'
        f'        <div id="list-scroll" style="overflow-y:auto;max-height:640px">\n'
        f'{list_items_html}\n'
        f'        </div>\n'
        f'      </td>\n'
        f'      <td id="detail-panel" style="padding:20px 24px;background:var(--bg);overflow-y:auto;max-height:660px;vertical-align:top">\n'
        f'{cards_html}\n'
        f'      </td>\n'
        f'    </tr>\n'
        f'  </table>\n'
        f'{nobs_html}\n'
        f'{gaps_html}\n'
        f'</div>\n'
        f'<footer class="th-footer">NetWitness Threat Check v{VERSION} · {client_name} · {generated}</footer>\n'
        f'<script>\n'
        'function switchTab(name, btn) {\n'
        '  document.querySelectorAll(".tab-panel").forEach(function(p){p.classList.remove("active");});\n'
        '  document.querySelectorAll(".tab-btn").forEach(function(b){b.classList.remove("active");});\n'
        '  var p=document.getElementById("tab-"+name);\n'
        '  if(p) p.classList.add("active");\n'
        '  if(btn) btn.classList.add("active");\n'
        '}\n'
        'function selectCard(cid, el) {\n'
        '  document.querySelectorAll(".card-detail").forEach(function(d){d.classList.remove("active");});\n'
        '  document.querySelectorAll(".li-item").forEach(function(i){i.classList.remove("active");});\n'
        '  var d=document.getElementById("detail-"+cid);\n'
        '  if(d) d.classList.add("active");\n'
        '  if(el) el.classList.add("active");\n'
        '}\n'
        'function goToFinding(cid) {\n'
        '  var fb=document.querySelector(".tab-btn[onclick*=findings]");\n'
        '  if(fb) switchTab("findings",fb);\n'
        '  setTimeout(function(){\n'
        '    var li=document.querySelector("[data-cid="+cid+"]");\n'
        '    selectCard(cid,li);\n'
        '    if(li) li.scrollIntoView({block:"nearest"});\n'
        '  },50);\n'
        '}\n'
        'function selectHost(hid) {\n'
        '  document.querySelectorAll(".h-list-item").forEach(function(i){i.classList.remove("active");});\n'
        '  document.querySelectorAll(".h-detail").forEach(function(d){d.classList.remove("active");});\n'
        '  var li=document.getElementById("hl-"+hid);\n'
        '  var det=document.getElementById("hd-"+hid);\n'
        '  if(li) li.classList.add("active");\n'
        '  if(det){det.classList.add("active");var p=document.getElementById("host-detail-panel");if(p) p.scrollTop=0;}\n'
        '}\n'
        'function filterList(tier, btn) {\n'
        '  document.querySelectorAll(".filter-btn").forEach(function(b){b.classList.remove("active");});\n'
        '  btn.classList.add("active");\n'
        '  document.querySelectorAll(".li-item").forEach(function(item){\n'
        '    item.style.display=(tier==="ALL"||item.dataset.tier===tier)?"":"none";\n'
        '  });\n'
        '  document.querySelectorAll(".li-grp-header").forEach(function(h){\n'
        '    var next=h.nextElementSibling,vis=false;\n'
        '    while(next&&!next.classList.contains("li-grp-header")){if(next.style.display!=="none")vis=true;next=next.nextElementSibling;}\n'
        '    h.style.display=vis?"":"none";\n'
        '  });\n'
        '  var first=document.querySelector(".li-item:not([style*=none])");\n'
        '  if(first&&!first.classList.contains("active")) selectCard(first.dataset.cid,first);\n'
        '}\n'
        '// init counts\n'
        '(function(){\n'
        '  ["CRITICAL","HIGH","MEDIUM","INFO"].forEach(function(t){\n'
        '    var el=document.getElementById("cnt-"+t);\n'
        '    if(el) el.textContent=document.querySelectorAll(".li-item[data-tier="+t+"]").length;\n'
        '  });\n'
        '})();\n'
        '</script>\n'
        '</body>\n'
        '</html>'
    )
    return html



def generate_html(data, report_type="engineer", theme="light"):
    """
    Generate HTML report.
    report_type: 'engineer' | 'threathunting' | 'nis2'
    theme: 'light' | 'dark'
    """
    # New tactical-cards renderer for threathunting
    if report_type == "threathunting":
        return render_threathunting_html(data, theme=theme)

    meta = data["meta"]
    summary = data["summary"]
    sections = data["sections"]

    is_eng  = report_type == "engineer"
    is_hunt = report_type == "threathunting"
    is_nis2 = report_type == "nis2"

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
        if not rows:
            return ""   # skip empty sections — no noise in report
        sid = f"tbl_{key}"
        return f'''
        <section class="card" id="sec_{key}">
          <div class="card-header">
            <h2>{title}</h2>
            <span class="badge">{len(rows)} rows</span>
          </div>
          <p class="card-desc">{desc}</p>
          {make_table(rows, col1, col2, sid)}
          {make_eng_note(key, rows) if is_eng else ""}
        </section>
        '''

    # Engineering notes per section
    ENG_NOTES = {
        "protocols": [
            ("service=0 > 20%", "Parser coverage gap. Check which ports are unrecognised — run <code>service=0</code> in Investigate, sort by port. Add parsers or index-decoder entries for top unknown ports."),
            ("service=443 < 40% in corporate env", "Lower TLS ratio than expected. Verify decryption policy is active. Check if traffic is being mirrored correctly from SSL termination points."),
            ("Many unique services > 50", "High protocol diversity. May indicate non-standard applications, tunnelling, or P2P. Filter top 20 and validate each with the client."),
        ],
        "direction": [
            ("lateral > 30%", "High lateral movement volume. Check which hosts are talking laterally — run <code>direction='lateral'</code> + top ip.src in Investigate. Validate against known admin traffic (AD, SCCM, backup)."),
            ("inbound > outbound", "Unusual direction ratio. Verify traffic_flow.lua has correct internal subnet definitions. Check <code>/etc/netwitness/ng/service/decoder/services.xml</code>."),
            ("direction empty / 0 sessions", "traffic_flow.lua not parsing or subnets not configured. Add internal network ranges to traffic_flow_options.lua and restart Decoder."),
        ],
        "unknown_ports": [
            ("any results", "Review top unknown ports with client. For each: is it a known internal application? If yes — request parser or add service alias. If no — investigate further."),
            ("port 4444/1337/31337", "Classic malware ports. Escalate immediately — run full session reconstruction in Investigate."),
        ],
        "tls": [
            ("TLS 1.0 or 1.1 present", "Legacy TLS detected. Identify source hosts — run <code>tls.version='TLS 1.0'</code> in Investigate. Report to client as EOC/hygiene finding. Maps to NIS2 Art.21(2)(h)."),
            ("TLS ratio < 30%", "Low encryption. Check if decryption policy is misconfigured or if traffic is genuinely unencrypted. Significant compliance risk if sensitive data flows unencrypted."),
        ],
        "session_analysis": [
            ("potential beacon > 0", "Run H-01 hunt hypothesis. In Investigate: <code>analysis.session='potential beacon' && direction='outbound'</code> — review periodicity and destination IPs."),
            ("long connection > 0", "Investigate long connection destinations. Legitimate: VPN, streaming. Suspicious: unknown external IPs with low-volume sustained sessions."),
            ("high transmitted outbound > 0", "Review destinations. Exfil indicator if external IPs. Normal if backup/sync targets. Correlate with backup_traffic section."),
        ],
        "http_analysis": [
            ("http post no get > 100", "POST-only traffic pattern — typical for C2, exfil, or bots. Investigate top source IPs."),
            ("http short user-agent > 50", "Automated HTTP clients (scripts, malware). Run <code>analysis.service='http short user-agent'</code> + ip.src in Investigate."),
            ("http no referer > 200", "Direct navigation or automated requests. Cross-reference with top destinations."),
        ],
        "session_sizes": [
            ("session size 0-5k dominant > 60%", "Small session dominant — typical for C2, DNS tunnelling, beaconing. Check beacon hypothesis H-01."),
            ("session size 100-250k > 10%", "Large sessions present. Identify destinations — could be exfil, legitimate backup, or software updates."),
        ],
        "ioc": [
            ("any IOC present", "Priority: open each IOC category in Investigate. Reconstruct sessions. Validate with threat intel. Even 1 IOC hit in a clean environment is worth escalating to client."),
            ("rekaf_beacon > 10", "Significant beacon activity detected. High confidence C2 indicator. Escalate immediately."),
            ("schoolbell malware present", "Known malware signature. Full IR response warranted."),
        ],
        "boc": [
            ("runs chained command shell > 0", "Lateral movement / post-exploitation indicator. Investigate source host immediately."),
            ("large outbound data transfer > 10", "Potential exfiltration. Identify destination IPs and cross-reference with known services."),
            ("non-standard port use dominant", "Review which non-standard ports. Some expected (custom apps) — unknown ones warrant investigation."),
        ],
        "eoc": [
            ("plaintext password > 0", "Critical hygiene finding. Identify protocol (FTP, SMTP, HTTP Basic Auth) and source/destination. Report to client — maps to NIS2 Art.21(2)(h)."),
            ("smb v1 request > 0", "SMBv1 in use. Disable immediately — EternalBlue vector. Identify hosts and escalate."),
            ("plaintext smtp password", "Mail credentials in cleartext. Check SMTP AUTH configuration. Should use STARTTLS."),
        ],
        "threat_cat": [
            ("any results", "Threat intel feed is active. Review categories — <code>threat.category</code> in Investigate filtered by category name for full context."),
            ("empty", "No threat intel hits — verify feeds are loaded: Administration → Context Hub → Feeds. If feeds missing, load F.07 CSV first."),
        ],
        "beacons": [
            ("any beacon destinations", "Cross-reference IPs with threat intel and geolocation. Expected: legitimate CDNs. Suspicious: unknown foreign IPs, cloud VPS. Run full session reconstruction per destination."),
            ("> 5 unique destinations", "Multiple potential beacons — could indicate multiple malware families or lateral spread. Prioritise by session count."),
        ],
        "long_conn": [
            ("any results", "Identify if VPN/legitimate or suspicious. Long connections to unknown external IPs at low bandwidth = C2 tunnel indicator."),
        ],
        "large_outbound": [
            ("external IPs present", "Verify with client — expected backup/sync targets? Unknown external IPs with high outbound = exfil investigation trigger."),
            ("volume > 1GB per destination", "Significant data transfer. If destination is not a known backup target — immediate investigation required."),
        ],
        "ja4": [
            ("empty", "JA4 not indexed. Add <code>ja4</code> to index-concentrator-custom.xml and restart Concentrator."),
            ("many unique fingerprints > 20", "High client diversity. Identify rare fingerprints — cross-reference against JA4 threat intel database. Known malware hashes take priority."),
            ("few fingerprints 1-3", "Homogeneous environment — expected for corporate managed endpoints. Any outlier fingerprint is immediately visible."),
        ],
        "ja3": [
            ("empty", "JA3 not indexed. Add <code>ja3</code> to index-concentrator-custom.xml."),
            ("any results", "Cross-reference top JA3 hashes at ja3er.com. Note: JA3 has higher collision rate than JA4 — use JA4 as primary."),
        ],
        "tls_sni": [
            ("empty", "tls.sni not indexed or no TLS traffic in window. Add <code>tls.sni</code> to index-concentrator-custom.xml."),
            ("DGA-like names (random strings)", "Potential C2 domain. Run full session reconstruction. Check domain age and registration."),
            ("unexpected cloud providers (AWS/Azure regions not matching client geography)", "Data residency concern. Flag for NIS2 Art.21(2)(d) supply chain review."),
            ("SNI absent on port 443 sessions", "Raw IP TLS — no hostname. Suspicious unless known internal service. Investigate source."),
        ],
        "zero_payload": [
            ("high volume > 30% of total", "Identify top destinations — configure meta-only capture for known infrastructure (backup, NTP, monitoring). Reduces storage by 15-30%."),
            ("single external IP dominant", "Potential C2 keepalive pattern. Correlate with beacon hypothesis H-01."),
        ],
        "request_no_payload": [
            ("external IPs > 10 unique", "Review destinations — streaming and CDN expected. Unknown IPs with high session count = C2 polling pattern."),
        ],
        "backup_traffic": [
            ("any results", "Confirm with client which backup solution is in use. Configure selective capture (meta-only) for these IPs to reduce storage costs."),
            ("external IPs on backup ports", "Backup to external destination — verify it's a known cloud backup target. If unknown: potential exfil via backup protocol masquerading."),
        ],
        "first_carve": [
            ("any external IPs", "Priority review — these are destinations not seen before. Check geolocation, reverse DNS, and threat intel for each. New C2, shadow SaaS, or exfil endpoints appear here first."),
            ("> 20 new destinations in < 24h", "High rate of new external connectivity. Anomalous — investigate for malware spreading or compromised host reaching out to multiple C2s."),
        ],
    }

    CLIENT_QUESTIONS = {
        "protocols": [
            "What applications and services are running in your environment? Do you have a documented application inventory?",
            "Are there any known legacy systems that may still use non-standard ports or protocols?",
            "Do you have any IoT or OT devices on this network segment? What protocols do they use?",
            "Is there any monitoring or network management traffic we should expect to see (SNMP, NetFlow, syslog)?",
        ],
        "direction": [
            "What are your internal network ranges? Are all subnets covered in the traffic_flow configuration?",
            "Do you have any DMZ segments, cloud-connected subnets, or guest networks that may appear as 'external'?",
            "Is lateral traffic between servers expected? Do you have east-west firewall policies in place?",
            "What admin tools are used internally (SCCM, Ansible, RDP, WMI)? From which hosts?",
        ],
        "unknown_ports": [
            "Do you have any custom or legacy applications using non-standard ports? Can you provide a list?",
            "Are there any proprietary protocols or vendor-specific tools communicating on unusual ports?",
            "Do developers or IT staff run any personal tools or services on workstations that could generate unusual traffic?",
        ],
        "tls": [
            "Do you have a corporate TLS policy? What minimum TLS version is required?",
            "Are there any known legacy systems or appliances that cannot support TLS 1.2+?",
            "Do you use SSL inspection / NPB inline decryption? If so, which categories are bypassed (banking, medical, HR)?",
            "Are there any internal services using self-signed certificates or expired certificates?",
        ],
        "session_analysis": [
            "Do you have any scheduled tasks, scripts, or monitoring agents that make regular outbound calls?",
            "Are there any legitimate automation tools (RPA, bots, API integrations) that might generate repetitive session patterns?",
            "What are your authorised backup and sync solutions? Which hosts are backup agents installed on?",
            "Do you have VPN users connecting from outside? From which IP ranges?",
        ],
        "http_analysis": [
            "Do you have any internal or external APIs being consumed by automated processes?",
            "Are developers allowed to run local scripts or tools that make HTTP calls from their workstations?",
            "Do you have a web proxy or content filter? Is all HTTP traffic supposed to go through it?",
            "Are there any monitoring agents or vulnerability scanners that perform HTTP checks?",
        ],
        "session_sizes": [
            "What does a typical data transfer look like in your environment? Are large transfers expected daily?",
            "Do you use any file sync services (SharePoint, OneDrive, Dropbox) from managed endpoints?",
            "Are software updates and patches distributed centrally (WSUS, SCCM)? From which servers?",
        ],
        "ioc": [
            "Have you had any recent security incidents, infections, or alerts from your AV/EDR?",
            "Are there any known compromised systems or hosts that are being investigated or remediated?",
            "Do you have an existing incident response process? Who would be notified if an active threat is confirmed?",
            "Is your SOC or security team aware we are running this analysis? Should we loop them in now?",
        ],
        "boc": [
            "Do you use PowerShell heavily for administration? From which hosts and by whom?",
            "Are there any penetration tests or red team exercises currently underway or recently completed?",
            "Do you have EDR deployed on all endpoints? Are there any hosts without coverage?",
            "Are there any known tools used by your IT team that involve chained command execution (deployment scripts, patch management)?",
        ],
        "eoc": [
            "Do you have a policy prohibiting cleartext protocols (Telnet, FTP, plain HTTP)? Is it enforced?",
            "Are there any legacy systems that still require SMBv1? Have they been risk-accepted?",
            "Do any mail relays or applications use SMTP without STARTTLS?",
            "Has a vulnerability assessment or configuration audit been performed recently? What were the findings?",
            "Do you have network access control (NAC) or endpoint compliance checking in place?",
        ],
        "threat_cat": [
            "Have you recently changed external-facing IP ranges, domains, or DNS records?",
            "Do you have any systems that communicate with known hosting providers (AWS, Azure, DO) for legitimate reasons?",
            "Are there any third-party integrations or SaaS connections that might generate threat intel hits?",
        ],
        "beacons": [
            "Do you have any scheduled outbound connections — monitoring agents, license checks, update services?",
            "Are there any cloud management tools (Azure Arc, AWS SSM) installed that check in regularly?",
            "Do you use any remote access tools (TeamViewer, AnyDesk, ConnectWise) that make periodic connections?",
            "Which of these destination IPs do you recognise? Can you account for all of them?",
        ],
        "long_conn": [
            "Do you have any persistent VPN connections or always-on tunnels to partners or cloud providers?",
            "Are there any real-time streaming or monitoring connections that stay open for extended periods?",
            "Do any of your applications maintain persistent WebSocket or long-poll connections to external services?",
        ],
        "large_outbound": [
            "What are your authorised cloud backup destinations? Can you provide the IP ranges?",
            "Do you sync large datasets to external partners or cloud storage? How often and what volume?",
            "Are developers allowed to push code or large artifacts to external repositories from these hosts?",
            "Do you use any CDN push or media upload services from your internal network?",
        ],
        "ja4": [
            "Do you manage all endpoints centrally? Are all clients on corporate-managed images?",
            "Are there any BYOD devices, IoT devices, or unmanaged assets on this network segment?",
            "Do developers use non-standard tools or libraries for making HTTPS connections (custom code, Go clients, Python scripts)?",
        ],
        "tls_sni": [
            "Do you have a list of approved cloud services and SaaS platforms? Can you share it?",
            "Are employees allowed to use personal AI tools (ChatGPT, Gemini) from corporate devices?",
            "Do you have a shadow IT discovery programme? Are you aware of which SaaS services are in use?",
            "Are any of these domains unfamiliar to you? Which ones should not be present in your environment?",
        ],
        "zero_payload": [
            "Do you have any monitoring systems that perform heartbeat checks or keepalives to external endpoints?",
            "Are there any network devices (switches, UPS, printers) that generate regular polling traffic?",
            "Do you have selective capture configured on the Decoder? Which traffic categories are set to meta-only?",
        ],
        "backup_traffic": [
            "What backup solution(s) do you use? Veeam, Commvault, NetBackup, Acronis?",
            "Are backups stored on-premises only, or also replicated to cloud/offsite?",
            "What is the backup schedule? Do backups run during business hours or overnight?",
            "Have you had a successful restore test recently? How long did it take?",
        ],
        "first_carve": [
            "Are you in the middle of any IT projects, migrations, or integrations that might involve new external connections?",
            "Have any new SaaS tools, cloud services, or vendor integrations been activated recently?",
            "Do employees have the ability to install software or connect to new services without IT approval?",
            "Which of these new destination IPs do you recognise? Are any of them expected?",
        ],
        "lateral_services": [
            "Do you have a network segmentation policy? Are servers, workstations, and sensitive systems in separate VLANs?",
            "Is lateral RDP or SMB traffic expected between all workstations, or only from admin hosts?",
            "Do you have east-west firewall rules between segments, or is internal traffic largely unrestricted?",
            "Are there any shared file servers or collaboration platforms generating high lateral traffic volumes?",
        ],
        "boc_outbound": [
            "Are there any authorised outbound admin tools — remote management platforms, cloud consoles, API calls?",
            "Do any of your applications make outbound calls as part of their normal operation?",
            "Is outbound traffic filtered at the firewall or proxy? What categories are blocked?",
        ],
        "decryption_status": [
            "Do you have SSL/TLS inspection in place? Inline decryption via NPB (Gigamon, Ixia) or proxy-based?",
            "Which traffic categories are excluded from decryption (banking, healthcare, HR platforms)?",
            "If using Gigamon/Ixia — is port remapping configured? What port does decrypted traffic arrive on?",
            "Is there a legal or policy constraint on inspecting certain encrypted traffic?",
        ],
    }

    def make_eng_note(key, rows):
        notes = ENG_NOTES.get(key, [])
        questions = CLIENT_QUESTIONS.get(key, [])
        if not notes and not questions:
            return ""

        eng_html = ""
        if notes:
            items = "".join(
                f'<li><span class="eng-trigger">{trigger}:</span> {action}</li>'
                for trigger, action in notes
            )
            eng_html = (
                f'<div class="eng-notes">'
                f'<div class="eng-notes-title">🔧 Engineer notes</div>'
                f'<ul>{items}</ul>'
                f'</div>'
            )

        q_html = ""
        if questions:
            q_items = "".join(f'<li>{q}</li>' for q in questions)
            q_html = (
                f'<div class="eng-notes" style="background:#141d2e;border-color:#1e3a5f">'
                f'<div class="eng-notes-title" style="color:#60a5fa">💬 Ask the client</div>'
                f'<ul style="color:#93c5fd">{q_items}</ul>'
                f'</div>'
            )

        return eng_html + q_html

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

    client_name   = meta.get("client", "Client")
    scope_days    = meta.get("scope_days", round(meta.get("hours", 0) / 24))
    range_label   = "ALL available data" if meta.get("all_time") else f"last {scope_days}d ({meta.get('hours', 0)}h)"
    parser_health = data.get("parser_health", [])
    hunt_results  = data.get("hunt", [])
    nis2_results  = data.get("nis2", [])
    exec_sum      = data.get("exec_summary", {})

    # ── Executive Summary HTML ──────────────────────────────────
    def make_exec_summary_html():
        if not exec_sum:
            return '<p class="no-data">Executive summary not available.</p>'
        risk    = exec_sum.get("risk_level", "UNKNOWN")
        r_color = exec_sum.get("risk_color", "#64748b")
        findings = exec_sum.get("key_findings", [])
        top_found = exec_sum.get("top_findings", [])
        findings_html = "".join(
            f'<li style="margin:6px 0;line-height:1.6">{f}</li>' for f in findings
        )
        top_html = ""
        if top_found:
            for r in top_found:
                sc = {"H": "#dc2626", "M": "#d97706", "L": "#16a34a"}.get(r.get("severity","L"), "#64748b")
                top_html += f'<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)"><span style="color:{sc};font-weight:700;font-family:var(--mono);min-width:40px">{r["id"]}</span><span style="flex:1">{r["name"]}</span><span style="font-family:var(--mono);font-size:12px;color:var(--muted)">{r.get("count",0):,} sessions</span><span style="background:{sc}20;color:{sc};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">SEV {r.get("severity","?")}</span></div>'
        nis2_nc = exec_sum.get("nis2_findings", 0)
        nis2_t  = exec_sum.get("nis2_total", 0)
        ioc_c   = exec_sum.get("ioc_count", 0)
        bea_c   = exec_sum.get("beacon_count", 0)
        ioc_col = "#dc2626" if ioc_c > 0 else "var(--text)"
        bea_col = "#d97706" if bea_c > 0 else "var(--text)"
        nc_col  = "#16a34a" if nis2_nc > 0 else "var(--text)"
        return f'''
        <div style="display:grid;grid-template-columns:200px 1fr;gap:24px;align-items:start">
          <div style="text-align:center;padding:24px;background:var(--bg3);border-radius:8px;border:2px solid {r_color}">
            <div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Overall Risk</div>
            <div style="font-size:36px;font-weight:800;color:{r_color}">{risk}</div>
            <div style="font-size:12px;color:var(--muted);margin-top:8px;font-family:var(--mono)">{exec_sum.get("hunt_found",0)}/{exec_sum.get("hunt_total",0)} hypotheses FOUND</div>
          </div>
          <div>
            <h3 style="font-size:13px;font-weight:700;margin-bottom:10px">Key Findings</h3>
            <ul style="margin:0 0 16px 18px">{findings_html}</ul>
            {"<h3 style='font-size:13px;font-weight:700;margin-bottom:8px'>Top Threats</h3>" + top_html if top_html else ""}
          </div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:20px">
          <div style="background:var(--bg3);border-radius:6px;padding:14px;text-align:center">
            <div style="font-size:22px;font-weight:700;font-family:var(--mono)">{exec_sum.get("total_sessions",0):,}</div>
            <div style="font-size:11px;color:var(--muted);margin-top:4px">Total Sessions</div>
          </div>
          <div style="background:var(--bg3);border-radius:6px;padding:14px;text-align:center">
            <div style="font-size:22px;font-weight:700;color:{ioc_col};font-family:var(--mono)">{ioc_c:,}</div>
            <div style="font-size:11px;color:var(--muted);margin-top:4px">IOC Alerts</div>
          </div>
          <div style="background:var(--bg3);border-radius:6px;padding:14px;text-align:center">
            <div style="font-size:22px;font-weight:700;color:{bea_col};font-family:var(--mono)">{bea_c}</div>
            <div style="font-size:11px;color:var(--muted);margin-top:4px">Beacon Candidates</div>
          </div>
          <div style="background:var(--bg3);border-radius:6px;padding:14px;text-align:center">
            <div style="font-size:22px;font-weight:700;color:{nc_col};font-family:var(--mono)">{nis2_nc}/{nis2_t}</div>
            <div style="font-size:11px;color:var(--muted);margin-top:4px">NIS2 Capabilities Demonstrated</div>
          </div>
        </div>'''

    # ── NIS2 Section HTML ───────────────────────────────────────
    def make_nis2_section():
        if not nis2_results:
            return '<p class="no-data">NIS2 capability mapping not available. Run with hunt enabled.</p>'

        status_cfg = {
            "CAPABILITY_DEMONSTRATED": ("#16a34a", "✅ Capability Demonstrated"),
            "CAPABILITY_AVAILABLE":    ("#0f766e", "🔵 Capability Available"),
            "PARTIAL_CAPABILITY":      ("#0891b2", "🔷 Partial Capability"),
            "REQUIRES_CONFIGURATION":  ("#d97706", "⚙️ Requires Configuration"),
            "CAPABILITY_DESCRIBED":    ("#94a3b8", "📋 Capability Described"),
        }

        counts = {k: sum(1 for r in nis2_results if r["status"] == k) for k in status_cfg}
        # Only show non-zero badges
        summary_html = " &nbsp;|&nbsp; ".join(
            f'<span style="color:{cfg[0]};font-weight:600">{counts[k]} {cfg[1]}</span>'
            for k, cfg in status_cfg.items() if counts[k] > 0
        )

        intro = (
            '<div style="background:#f0f9ff;border:1px solid #bae6fd;border-radius:6px;'
            'padding:12px 16px;margin-bottom:20px;font-size:13px;line-height:1.6;color:#0c4a6e">'
            '<strong>How to read this section:</strong> This is not a compliance audit. Each NIS2 Art.21 control '
            'is mapped to NetWitness capabilities — what the platform can monitor and provide evidence for. '
            'Observations from this analysis window demonstrate that the capability is operational. '
            'Use this as a guide to understanding how NetWitness supports your NIS2 programme.'
            '</div>'
        )

        cards = ""
        for r in nis2_results:
            color, label = status_cfg.get(r["status"], ("#94a3b8", "📋 Described"))
            border_color = color

            # Hypothesis categories — what we can monitor
            cat_items = "".join(f'<li style="margin:3px 0">{c}</li>' for c in r["hypothesis_categories"])

            # Found findings (if any)
            found_items = "".join(
                f'<li style="margin:4px 0;color:#166534">'
                f'<span style="font-family:var(--mono);font-size:12px;font-weight:600;color:#15803d">{h["id"]}</span> '
                f'— <span style="color:#166534">{h["name"]}</span> '
                f'<span style="color:#4b7a5a;font-size:11px">({h.get("count",0):,} sessions)</span></li>'
                for h in r["found"]
            )

            # Not observed list (collapsed)
            not_ob_items = "".join(
                f'<li style="margin:3px 0;color:#64748b;font-size:12px">{h["id"]} — {h["name"]}</li>'
                for h in r["not_observed"][:6]
            )
            more = (
                f'<li style="color:#64748b;font-size:12px">…and {len(r["not_observed"])-6} more</li>'
                if len(r["not_observed"]) > 6 else ""
            )

            findings_block = ""
            if found_items:
                findings_block = (
                    '<div style="margin-top:10px;padding:12px 14px;background:#f0fdf4;border-radius:6px;'
                    'font-size:13px;line-height:1.6;border-left:3px solid #16a34a">'
                    '<div style="font-weight:700;margin-bottom:6px;color:#15803d;font-size:12px;'
                    'text-transform:uppercase;letter-spacing:.5px">Sample observations from this window</div>'
                    f'<ul style="margin:0;padding-left:18px">{found_items}</ul>'
                    '<div style="margin-top:8px;font-size:11px;color:#4b7a5a;font-style:italic">'
                    'These observations demonstrate active monitoring capability for NIS2 audit documentation.'
                    '</div>'
                    '</div>'
                )

            details_block = ""
            if not_ob_items:
                details_block = (
                    '<details style="margin-top:8px">'
                    f'<summary style="cursor:pointer;color:var(--muted);font-size:12px">'
                    f'Other hypotheses available for this control ({len(r["not_observed"])})</summary>'
                    f'<ul style="margin:6px 0 0 18px">{not_ob_items}{more}</ul>'
                    '</details>'
                )

            cards += f'''
            <div class="card" style="border-left:4px solid {border_color};margin-bottom:14px">
              <div class="card-header">
                <h2>{r["article"]}</h2>
                <span class="badge" style="color:{color}">{label}</span>
              </div>

              <div style="display:grid;grid-template-columns:1fr;gap:10px;margin-top:12px">

                <div style="padding:12px;background:var(--bg3);border-radius:6px;font-size:13px;line-height:1.6">
                  <div style="font-weight:600;margin-bottom:6px;color:var(--text)">NetWitness capability for this control</div>
                  {r["capability"]}
                </div>

                <div style="padding:12px;background:var(--bg3);border-radius:6px;font-size:13px;line-height:1.6">
                  <div style="font-weight:600;margin-bottom:6px;color:var(--text)">What NetWitness can monitor</div>
                  <ul style="margin:6px 0 0 18px">{cat_items}</ul>
                </div>

                <div style="padding:12px;background:var(--bg3);border-radius:6px;font-size:13px;line-height:1.6">
                  <div style="font-weight:600;margin-bottom:6px;color:var(--text)">In this analysis window</div>
                  {r["observed"]}
                </div>

                {findings_block}

                <div style="margin-top:6px;padding:16px 20px;background:linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%);border:2px solid #16a34a;border-radius:8px;font-size:14px;line-height:1.7">
                  <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
                    <span style="font-size:18px">🎯</span>
                    <span style="font-weight:700;color:#15803d;font-size:15px;text-transform:uppercase;letter-spacing:0.5px">How NetWitness supports your NIS2 programme</span>
                  </div>
                  <div style="color:#14532d">{r["value_to_nis2"]}</div>
                </div>

                {details_block}

              </div>
            </div>'''

        return f'<div style="margin-bottom:14px;font-family:var(--mono);font-size:13px">{summary_html}</div>{intro}{cards}'

    def make_decryption_status():
        """Card showing SSL/TLS decryption status with NPB checklist."""
        ds = sections.get("decryption_status", {})
        raw = ds.get("raw", {})
        if not raw:
            return ""
        total = raw.get("total", 0)
        dec   = raw.get("decrypted", 0)
        enc   = raw.get("encrypted", 0)
        pct   = raw.get("pct", 0)

        if total == 0:
            status_html = '<p class="card-desc">No port 443 traffic detected in this window.</p>'
        else:
            bar_dec = round(pct)
            bar_enc = 100 - bar_dec
            status_color = "#22c55e" if pct > 50 else "#f59e0b" if pct > 10 else "#94a3b8"
            status_label = "Active decryption" if pct > 50 else "Partial decryption" if pct > 10 else "No decryption detected"
            status_html = f'''
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:12px;margin-bottom:16px">
              <div style="background:var(--bg3);border-radius:6px;padding:12px;text-align:center">
                <div style="font-size:20px;font-weight:700;font-family:var(--mono)">{total:,}</div>
                <div style="font-size:11px;color:var(--muted);margin-top:4px">Total port 443</div>
              </div>
              <div style="background:var(--bg3);border-radius:6px;padding:12px;text-align:center">
                <div style="font-size:20px;font-weight:700;font-family:var(--mono);color:#22c55e">{dec:,}</div>
                <div style="font-size:11px;color:var(--muted);margin-top:4px">Decrypted</div>
              </div>
              <div style="background:var(--bg3);border-radius:6px;padding:12px;text-align:center">
                <div style="font-size:20px;font-weight:700;font-family:var(--mono);color:#64748b">{enc:,}</div>
                <div style="font-size:11px;color:var(--muted);margin-top:4px">Encrypted (TLS only)</div>
              </div>
              <div style="background:var(--bg3);border-radius:6px;padding:12px;text-align:center;border:1px solid {status_color}">
                <div style="font-size:20px;font-weight:700;font-family:var(--mono);color:{status_color}">{pct}%</div>
                <div style="font-size:11px;color:var(--muted);margin-top:4px">{status_label}</div>
              </div>
            </div>
            <div style="background:#f8fafc;border-radius:4px;height:12px;margin-bottom:16px;overflow:hidden">
              <div style="height:100%;width:{bar_dec}%;background:#22c55e;float:left"></div>
              <div style="height:100%;width:{bar_enc}%;background:#e2e8f0;float:left"></div>
            </div>'''

        npb_note = '''
            <div class="eng-notes">
              <div class="eng-notes-title">🔧 NPB / Inline decryption checklist</div>
              <ul>
                <li><span class="eng-trigger">Decryption = 0%:</span> No NPB inline decryption active. TLS traffic is visible as metadata only (JA4/SNI) — no HTTP body, no URL, no user-agent.</li>
                <li><span class="eng-trigger">Port 443 with HTTP meta:</span> NPB is decrypting and reinjecting as HTTP. Confirm port remapping — if still port 443, parser may double-decrypt (error). Recommended: remap to port 80 or dedicated port on NPB.</li>
                <li><span class="eng-trigger">If Gigamon/Ixia:</span> Check GigaSMART policy → SSL decryption → port remapping to 80. In NW assign http parser to that port.</li>
                <li><span class="eng-trigger">If ErSPAN:</span> Verify <code>capture.erspan=true</code> on Decoder. Check GRE decapsulation.</li>
                <li><span class="eng-trigger">Low % but HTTP meta exists:</span> Partial decryption — some categories bypassed (banking, medical). Check bypass rules on NPB.</li>
              </ul>
            </div>'''

        return f'''<section class="card" id="sec_decryption">
          <div class="card-header">
            <h2>SSL/TLS Decryption Status</h2>
            <span class="badge">port 443</span>
          </div>
          <p class="card-desc">Compares port 443 sessions with HTTP meta (decrypted by NPB) vs raw TLS only (encrypted). Determines visibility into HTTPS traffic.</p>
          {status_html}
          {npb_note if is_eng else ""}
        </section>'''

    def make_protocol_ratio():
        """Show encrypted/unknown ratio as a callout after protocol table."""
        proto_stats = sections.get("protocols", {}).get("stats", {})
        if not proto_stats:
            return ""
        enc_pct = proto_stats.get("encrypted_pct", 0)
        unk_pct = proto_stats.get("unknown_pct", 0)
        total   = proto_stats.get("total", 0)
        items = []
        if enc_pct:
            color = "#22c55e" if enc_pct > 40 else "#f59e0b"
            items.append(f'<span style="color:{color}"><strong>{enc_pct}%</strong> encrypted (port 443)</span>')
        if unk_pct:
            color = "#f59e0b" if unk_pct < 20 else "#dc2626"
            items.append(f'<span style="color:{color}"><strong>{unk_pct}%</strong> unidentified (service=0)</span>')
        if not items:
            return ""
        return f'<div style="padding:8px 12px;background:var(--bg3);border-radius:6px;font-size:13px;margin:-8px 0 8px;display:flex;gap:24px">{"&nbsp;&nbsp;·&nbsp;&nbsp;".join(items)}</div>'

    def make_priority_ips_callout():
        """Red callout if any IP appears in 2+ threat categories."""
        pips = sections.get("priority_ips", {}).get("data", [])
        if not pips:
            return ""
        items = "".join(
            f'<li style="margin:4px 0"><code style="font-family:var(--mono);background:#fee2e2;padding:1px 6px;border-radius:3px">{ip}</code> — {cats}</li>'
            for ip, cats in pips
        )
        return f'''<div style="background:#fef2f2;border:1px solid #fecaca;border-radius:6px;padding:12px 16px;margin-bottom:16px">
          <div style="font-weight:700;color:#dc2626;margin-bottom:6px">⚠️ Priority IPs — multiple threat categories</div>
          <div style="font-size:12px;color:#7f1d1d;margin-bottom:8px">These IPs appear in 2 or more of: potential beacon, long connection, large outbound. Investigate immediately.</div>
          <ul style="margin:0;padding-left:18px;font-size:13px">{items}</ul>
        </div>'''

    def make_ioc_callout():
        """Red banner if any IOC present."""
        ioc_data = sections.get("ioc", {}).get("data", [])
        ioc_count = sum(c for _, c in ioc_data)
        if ioc_count == 0:
            return '<div style="padding:8px 14px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;margin-bottom:8px;font-size:13px;color:#166534">✅ No IOC alerts in this window.</div>'
        top = ioc_data[0][0] if ioc_data else "unknown"
        return f'''<div style="background:#fef2f2;border:2px solid #dc2626;border-radius:6px;padding:12px 16px;margin-bottom:12px">
          <div style="font-weight:700;color:#dc2626;font-size:15px">🔴 {ioc_count:,} IOC alerts detected — immediate investigation required</div>
          <div style="font-size:13px;color:#7f1d1d;margin-top:4px">
            Top: <code>{top}</code>. Each IOC category = confirmed threat signature or known-bad IP/domain hit.
            Do not wait — reconstruct sessions for each IOC category in Investigate.
          </div>
        </div>'''

    def make_eoc_hygiene():
        """EOC hygiene score card."""
        eoc_sec = sections.get("eoc", {})
        score = eoc_sec.get("hygiene_score", 0)
        label = eoc_sec.get("hygiene_label", "CLEAN")
        color_map = {
            "CRITICAL": "#dc2626", "HIGH": "#f97316",
            "MEDIUM": "#f59e0b",   "LOW": "#84cc16", "CLEAN": "#22c55e"
        }
        color = color_map.get(label, "#64748b")
        if score == 0:
            return '<div style="padding:8px 14px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;margin-bottom:8px;font-size:13px;color:#166534">✅ No EOC events — hygiene looks clean in this window.</div>'
        return f'''<div style="display:flex;align-items:center;gap:20px;padding:12px 16px;background:var(--bg3);border-left:4px solid {color};border-radius:6px;margin-bottom:12px">
          <div style="text-align:center;min-width:80px">
            <div style="font-size:28px;font-weight:800;color:{color};font-family:var(--mono)">{score:,}</div>
            <div style="font-size:11px;color:var(--muted)">EOC events</div>
          </div>
          <div>
            <div style="font-weight:700;color:{color}">Hygiene Score: {label}</div>
            <div style="font-size:12px;color:var(--muted);margin-top:2px">
              EOC = Enablers of Compromise. Each event represents a configuration gap (cleartext creds, legacy protocol, default config)
              that could be exploited. Use this count as a measurable KPI for the client.
            </div>
          </div>
        </div>'''

    # Hunt section HTML
    def make_hunt_section():
        if not hunt_results:
            return '<p class="no-data">Hunt data not available. Run without --no-hunt flag.</p>'

        found   = [r for r in hunt_results if r["status"] == "FOUND"]
        not_ob  = [r for r in hunt_results if r["status"] == "NOT_OBSERVED"]
        unavail = [r for r in hunt_results if r["status"] == "PARSER_UNAVAILABLE"]

        badge_f = f'<span style="color:#ef4444;font-weight:600">{len(found)} FOUND</span>'
        badge_n = f'<span style="color:#22c55e;font-weight:600">{len(not_ob)} NOT OBSERVED</span>'
        badge_u = f'<span style="color:#f59e0b;font-weight:600">{len(unavail)} PARSER UNAVAILABLE</span>'

        html = f'<div style="margin-bottom:16px;font-family:var(--mono);font-size:13px">{badge_f} &nbsp;|&nbsp; {badge_n} &nbsp;|&nbsp; {badge_u}</div>'

        # FOUND — expanded cards
        if found:
            html += '<h3 style="color:#ef4444;margin:20px 0 10px">🔴 Found — Requires Investigation</h3>'
            for r in found:
                sev_color = {"H": "#ef4444", "M": "#f59e0b", "L": "#22c55e"}.get(r["severity"], "#64748b")
                src_list  = ", ".join(r["ip_src"][:3]) or "—"
                dst_list  = ", ".join(r["ip_dst"][:3]) or "—"
                host_list = ", ".join(r["alias_host"][:3]) or "—"
                mit_html  = "".join(f"<li>{line.lstrip('0123456789. ')}</li>"
                                    for line in r["mitigations"].split("\n") if line.strip())
                html += f'''
                <div class="card" style="border-left:4px solid {sev_color};margin-bottom:12px">
                  <div class="card-header">
                    <h2>{r["id"]} — {r["name"]}</h2>
                    <span class="badge" style="background:{sev_color}20;color:{sev_color}">SEV {r["severity"]}</span>
                    <span class="badge">{r["poc_priority"]}</span>
                    <span class="badge">{r["pack"]}</span>
                  </div>
                  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:12px 0;font-size:13px">
                    <div><span style="color:var(--muted)">Sessions:</span> <strong>{r["count"]:,}</strong></div>
                    <div><span style="color:var(--muted)">MITRE:</span> <code>{r["mitre"]}</code></div>
                    <div><span style="color:var(--muted)">Top src:</span> <code>{src_list}</code></div>
                    <div><span style="color:var(--muted)">Top dst:</span> <code>{dst_list}</code></div>
                    <div style="grid-column:1/-1"><span style="color:var(--muted)">Hosts:</span> <code>{host_list}</code></div>
                    <div style="grid-column:1/-1"><span style="color:var(--muted)">NIS2:</span> {r["nis2"]}</div>
                  </div>
                  <p style="font-style:italic;color:var(--muted);margin:8px 0">{r["narrative"]}</p>
                  <details style="margin-top:8px">
                    <summary style="cursor:pointer;color:var(--accent)">Mitigations</summary>
                    <ul style="margin:8px 0 0 20px;line-height:1.8">{mit_html}</ul>
                  </details>
                </div>'''

        # NOT OBSERVED — collapsed table
        if not_ob:
            html += '<h3 style="color:#22c55e;margin:20px 0 10px">✅ Not Observed</h3>'
            html += '<div class="table-wrapper"><table class="data-table"><thead><tr><th>ID</th><th>Hypothesis</th><th>Category</th><th>MITRE</th></tr></thead><tbody>'
            for r in not_ob:
                html += f'<tr><td class="mono">{r["id"]}</td><td>{r["name"]}</td><td>{r["category"]}</td><td class="mono">{r["mitre"]}</td></tr>'
            html += '</tbody></table></div>'

        # PARSER UNAVAILABLE
        if unavail:
            html += '<h3 style="color:#f59e0b;margin:20px 0 10px">⚠️ Parser Unavailable — Cannot Assess</h3>'
            html += '<div class="table-wrapper"><table class="data-table"><thead><tr><th>ID</th><th>Hypothesis</th><th>Parser Required</th></tr></thead><tbody>'
            for r in unavail:
                html += f'<tr><td class="mono">{r["id"]}</td><td>{r["name"]}</td><td class="mono">{r["parser"] if "parser" in r else "—"}</td></tr>'
            html += '</tbody></table></div>'

        return html

    # Parser health HTML block
    def make_parser_health():
        if not parser_health:
            return '<p class="no-data">Parser health data not available (loaded from cache without --check).</p>'
        rows_html = ""
        for r in parser_health:
            color = {"OK": "#22c55e", "LOW": "#f59e0b", "UNAVAILABLE": "#94a3b8"}[r["status"]]
            icon  = {"OK": "✅", "LOW": "⚠️", "UNAVAILABLE": "—"}[r["status"]]
            impact_style = "" if r["status"] == "OK" else f'style="color:#64748b"'
            rows_html += f"""
              <tr>
                <td class="mono">{r['parser']}</td>
                <td>{r['label']}</td>
                <td style="color:{color};font-weight:600">{icon} {r['status']}</td>
                <td class="num">{r['count']:,}</td>
                <td {impact_style}>{r['impact'] if r['status'] != 'OK' else '—'}</td>
              </tr>"""
        ok   = sum(1 for r in parser_health if r["status"] == "OK")
        low  = sum(1 for r in parser_health if r["status"] == "LOW")
        miss = sum(1 for r in parser_health if r["status"] == "UNAVAILABLE")
        badge_ok   = f'<span style="color:#22c55e;font-weight:600">{ok} OK</span>'
        badge_low  = f'<span style="color:#f59e0b;font-weight:600">{low} LOW</span>'
        badge_miss = f'<span style="color:#94a3b8;font-weight:600">{miss} not detected in window</span>'
        return f"""
        <div style="margin-bottom:12px;font-family:var(--mono);font-size:13px">
          {badge_ok} &nbsp;|&nbsp; {badge_low} &nbsp;|&nbsp; {badge_miss}
        </div>
        <div class="table-wrapper">
          <table class="data-table">
            <thead><tr>
              <th>Parser</th><th>Description</th><th>Status</th>
              <th>Sessions</th><th>Impact if unavailable</th>
            </tr></thead>
            <tbody>{rows_html}</tbody>
          </table>
        </div>"""

    # ── Pre-compute conditional sections (avoids nested f-string issues) ──
    sec_exec = ""
    if is_hunt:
        exec_html = make_exec_summary_html()
        sec_exec = (
            f'<section class="card" id="exec">\n'
            f'  <div class="card-header">\n'
            f'    <h2>Executive Summary</h2>\n'
            f'    <span class="badge">{client_name}</span>\n'
            f'    <span class="badge">{meta["generated"]}</span>\n'
            f'  </div>\n'
            f'  {exec_html}\n'
            f'</section>'
        )

    sec_metrics_open = '<div id="summary">' if is_eng else '<!-- metrics skipped\n'

    sec_parsers = ""
    if is_eng:
        ph_html = make_parser_health()
        sec_parsers = (
            f'<section class="card" id="parsers">\n'
            f'  <div class="card-header">\n'
            f'    <h2>Parser Health Check</h2>\n'
            f'    <span class="badge">{len(parser_health)} parsers</span>\n'
            f'  </div>\n'
            f'  <p class="card-desc">Verifies which parsers are active and producing meta in the selected time window. '
            f'Parsers not producing meta in this time window — may indicate no traffic of that type, or parser configuration needed.</p>\n'
            f'  {ph_html}\n'
            f'</section>'
        )

    sec_hunt = ""
    if is_hunt:
        hunt_html = make_hunt_section()
        sec_hunt = (
            f'<section class="card" id="hunt">\n'
            f'  <div class="card-header">\n'
            f'    <h2>Threat Hunting Results</h2>\n'
            f'    <span class="badge">{len(hunt_results)} hypotheses</span>\n'
            f'  </div>\n'
            f'  <p class="card-desc">Systematic evaluation of {len(hunt_results)} threat hypotheses against captured traffic. '
            f'FOUND items require investigation. NOT OBSERVED means no indicators in this window.</p>\n'
            f'  {hunt_html}\n'
            f'</section>'
        )

    sec_nis2 = ""
    if is_nis2:
        nis2_html = make_nis2_section()
        sec_nis2 = (
            f'<section class="card" id="nis2">\n'
            f'  <div class="card-header">\n'
            f'    <h2>NIS2 Art.21 — How NetWitness supports your programme</h2>\n'
            f'    <span class="badge">{len(nis2_results)} controls mapped</span>\n'
            f'  </div>\n'
            f'  <p class="card-desc">Eight Art.21(2) controls (b, c, d, f, g, h, i, j) where NetWitness provides direct '
            f'network-layer evidence and monitoring capability. Each control shows what NetWitness can monitor and '
            f'sample observations from this analysis window — demonstrating capability, not certifying compliance.</p>\n'
            f'  {nis2_html}\n'
            f'</section>'
        )

    # ── LLM Connections Table (engineer report only) ───────────────────────────
    sec_llm = ""
    if is_eng:
        hunt = data.get("hunt", [])
        # Gather all pairs from LLM Pack T1 FOUND results
        llm_rows = {}  # (src, dst, alias, category) → count
        category_map = {
            'llm browser access':       'llm-provider',
            'llm api non browser':      'llm-provider',
            'llm plaintext http':       'llm-provider',
            'llm server outbound':      'llm-provider/enterprise',
            'llm api key in url':       'llm-provider',
            'llm file upload':          'llm-provider',
            'llm large prompt':         'llm-provider',
            'llm model download large': 'llm-provider',
            'llm coding source upload': 'llm-coding',
            'llm lolbas access':        'llm-provider',
            'llm no user agent':        'llm-provider',
            'llm c2 channel':           'llm-provider',
            'llm c2 beacon pattern':    'llm-provider',
            'llm malicious service access': 'llm-malicious',
            'local llm service lateral': 'local-llm',
        }
        for r in hunt:
            h_pack = r.get("pack","")
            h_tier = r.get("llm_tier","T1")
            if "LLM" not in h_pack or h_tier != "T1":
                continue
            if r.get("status") != "FOUND":
                continue
            boc_tag = r.get("query","").split("= '")[-1].rstrip("'") if "= '" in r.get("query","") else ""
            cat = category_map.get(boc_tag, "llm-provider")
            for p in r.get("top_pairs", []):
                key = (p.get("src",""), p.get("dst",""), p.get("alias",""), cat)
                llm_rows[key] = llm_rows.get(key, 0) + p.get("count", 0)

        if llm_rows:
            tier_colors = {
                'llm-provider':            ('#f0fdfa', '#0f766e'),
                'llm-provider/enterprise': ('#eff6ff', '#1d4ed8'),
                'llm-enterprise':          ('#eff6ff', '#1d4ed8'),
                'llm-coding':              ('#faf5ff', '#7c3aed'),
                'llm-malicious':           ('#fef2f2', '#dc2626'),
                'local-llm':               ('#fffbeb', '#d97706'),
            }
            table_rows = ""
            for (src, dst, alias, cat), cnt in sorted(llm_rows.items(),
                                                       key=lambda x: -x[1]):
                bg, fg = tier_colors.get(cat, ('#f8fafc', '#475569'))
                # Enrich with feed description
                feed_cat, feed_desc = feed_lookup(alias)
                provider_cell = (
                    f"<span style='font-weight:600'>{feed_desc}</span>"
                    f"<br><span style='font-size:10px;color:#94a3b8'>{alias}</span>"
                    if feed_desc else
                    f"<span style='color:#64748b'>{alias or '—'}</span>"
                )
                display_cat = feed_cat or cat
                bg, fg = tier_colors.get(display_cat, ('#f8fafc', '#475569'))
                table_rows += (
                    f"<tr>"
                    f"<td style='font-family:monospace;font-size:12px'>{src}</td>"
                    f"<td style='font-family:monospace;font-size:12px'>{dst}</td>"
                    f"<td style='font-size:12px'>{provider_cell}</td>"
                    f"<td><span style='font-size:10px;font-weight:700;padding:2px 7px;"
                    f"border-radius:3px;background:{bg};color:{fg}'>{display_cat}</span></td>"
                    f"<td style='text-align:right;font-weight:600'>{cnt:,}</td>"
                    f"</tr>"
                )
            sec_llm = (
                f'<section class="card" id="llm">\n'
                f'  <div class="card-header">\n'
                f'    <h2>AI / LLM Connections</h2>\n'
                f'    <span class="badge">{len(llm_rows)} connections</span>\n'
                f'  </div>\n'
                f'  <p class="card-desc">All detected AI provider connections from T1 LLM Pack rules. '
                f'Sorted by session count. Categories: '
                f'<b>llm-provider</b> = consumer AI, '
                f'<b>llm-enterprise</b> = Azure OpenAI / AWS Bedrock / GCP Vertex, '
                f'<b>llm-coding</b> = GitHub Copilot / Cursor / Tabnine, '
                f'<b>llm-malicious</b> = WormGPT / GhostGPT, '
                f'<b>local-llm</b> = Ollama / LM Studio.</p>\n'
                f'  <div class="table-wrapper">\n'
                f'  <table class="data-table">\n'
                f'    <thead><tr>'
                f'<th>Source IP</th><th>Destination IP</th>'
                f'<th>AI Provider</th><th>Category</th><th style="text-align:right">Sessions</th>'
                f'</tr></thead>\n'
                f'    <tbody>{table_rows}</tbody>\n'
                f'  </table></div>\n'
                f'</section>'
            )
        else:
            sec_llm = (
                f'<section class="card" id="llm">\n'
                f'  <div class="card-header"><h2>AI / LLM Connections</h2></div>\n'
                f'  <p class="card-desc">No LLM Pack T1 findings in this analysis window. '
                f'Ensure Feed F.07 v2.0 is loaded on Decoder.</p>\n'
                f'</section>'
            )

    sec_metrics = ""
    if is_eng:
        sec_metrics = f'''<div id="summary">
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
</div>'''

        sec_charts_open = '<div id="charts" class="charts-grid">' if is_eng else '<!-- charts skipped'

    def make_traffic_html():
        # TLS visibility metrics
        tls_data   = sections.get("tls", {}).get("data", [])
        proto_data = sections.get("protocols", {}).get("data", [])
        total_sess = summary.get("total_sessions", 1) or 1
        tls_total  = sum(c for _, c in tls_data)
        tls12  = next((c for v, c in tls_data if "1.2" in str(v)), 0)
        tls13  = next((c for v, c in tls_data if "1.3" in str(v)), 0)
        tls_old = sum(c for v, c in tls_data if any(x in str(v) for x in ["1.0","1.1","SSL"]))
        https_count = next((c for v, c in proto_data if "443" in str(v) or "https" in str(v).lower()), 0)
        http_count  = next((c for v, c in proto_data if v in ("80","http") or str(v) == "80"), 0)
        enc_pct = round(tls_total / total_sess * 100) if tls_total else round(https_count / total_sess * 100)
        clear_pct = 100 - enc_pct

        tls_version_rows = ""
        for v, c in tls_data[:6]:
            pct = round(c / total_sess * 100)
            color = "#0f766e" if "1.3" in str(v) else "#d97706" if "1.2" in str(v) else "#dc2626"
            tls_version_rows += (
                f"<tr><td style='font-family:var(--mono);font-weight:600'>{v}</td>"
                f"<td style='text-align:right'>{c:,}</td>"
                f"<td style='width:120px'><div style='height:6px;background:var(--border);border-radius:3px;overflow:hidden'>"
                f"<div style='height:100%;width:{min(pct,100)}%;background:{color};border-radius:3px'></div></div></td>"
                f"<td style='text-align:right;font-family:var(--mono);font-size:11px;color:var(--muted)'>{pct}%</td></tr>"
            )

        tls_section = f'''
<div class="card" style="margin-bottom:20px">
  <div class="card-header"><h2>🔐 TLS / SSL Visibility</h2></div>
  <div class="tls-grid" style="margin-top:14px">
    <div class="tls-meter">
      <div class="tls-meter-label">Encrypted traffic</div>
      <div class="tls-meter-bar"><div class="tls-meter-fill" style="width:{enc_pct}%;background:#0f766e"></div></div>
      <div class="tls-meter-val" style="color:#0f766e">{enc_pct}%</div>
    </div>
    <div class="tls-meter">
      <div class="tls-meter-label">Cleartext (HTTP/other)</div>
      <div class="tls-meter-bar"><div class="tls-meter-fill" style="width:{clear_pct}%;background:{"#dc2626" if clear_pct > 20 else "#d97706"}"></div></div>
      <div class="tls-meter-val" style="color:{"#dc2626" if clear_pct > 20 else "#d97706"}">{clear_pct}%</div>
    </div>
    <div class="tls-meter">
      <div class="tls-meter-label">TLS 1.3 (modern)</div>
      <div class="tls-meter-bar"><div class="tls-meter-fill" style="width:{min(round(tls13/total_sess*100),100)}%;background:#7c3aed"></div></div>
      <div class="tls-meter-val" style="color:#7c3aed">{round(tls13/total_sess*100) if total_sess else 0}%</div>
    </div>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
    <div>
      <div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:8px">TLS version breakdown</div>
      <table style="width:100%;border-collapse:collapse;font-size:12px">
        <thead><tr>
          <th style="text-align:left;padding:4px 8px;font-size:10px;color:var(--muted);font-weight:500;border-bottom:1px solid var(--border)">Version</th>
          <th style="text-align:right;padding:4px 8px;font-size:10px;color:var(--muted);font-weight:500;border-bottom:1px solid var(--border)">Sessions</th>
          <th style="padding:4px 8px;border-bottom:1px solid var(--border)"></th>
          <th style="text-align:right;padding:4px 8px;font-size:10px;color:var(--muted);font-weight:500;border-bottom:1px solid var(--border)">%</th>
        </tr></thead>
        <tbody>{tls_version_rows if tls_version_rows else "<tr><td colspan='4' style='padding:8px;color:var(--muted);text-align:center'>No TLS version data — check tls.lua parser</td></tr>"}</tbody>
      </table>
      {"<div style='margin-top:8px;padding:6px 10px;background:#fef2f2;border-radius:4px;font-size:11px;color:#dc2626'><strong>⚠ Legacy TLS detected</strong> — " + str(tls_old) + " sessions use TLS 1.0/1.1/SSL. These are deprecated and should be disabled.</div>" if tls_old > 0 else ""}
    </div>
    <div>
      <div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:8px">Visibility interpretation</div>
      <div style="font-size:12px;line-height:1.7;color:var(--muted)">
        {"<div style='padding:6px 10px;background:#f0fdfa;border-left:3px solid #0f766e;border-radius:4px;margin-bottom:8px;color:var(--text)'><strong>Good encryption posture</strong> — majority of traffic uses TLS. Without SSL inspection, NetWitness captures metadata (IP, port, JA4, SNI, session timing) but cannot reconstruct payload. <strong>JA4/JA3 fingerprinting</strong> provides TLS client identification without decryption.</div>" if enc_pct >= 70 else ""}
        {"<div style='padding:6px 10px;background:#fffbeb;border-left:3px solid #d97706;border-radius:4px;margin-bottom:8px;color:var(--text)'><strong>Mixed traffic</strong> — significant cleartext present. HTTP sessions are fully reconstructible — payload, credentials, and content visible in Investigate.</div>" if 20 < clear_pct < 70 else ""}
        {"<div style='padding:6px 10px;background:#fef2f2;border-left:3px solid #dc2626;border-radius:4px;margin-bottom:8px;color:var(--text)'><strong>High cleartext exposure</strong> — over 30% of traffic is unencrypted. NIS2 Art.21(2)(h) compliance risk.</div>" if clear_pct >= 30 else ""}
        <div style="margin-top:8px;font-size:11px">
          TLS fingerprints (JA4/JA3) and SNI hostnames are visible below in the Protocol section — these enable client identification and destination mapping without payload decryption.
        </div>
      </div>
    </div>
  </div>
</div>'''

        return (
            tls_section
            + '<div id="charts" class="charts-grid">\n'
            + f'''  <div class="chart-card"><h3>Top protocols</h3><div class="chart-wrapper"><canvas id="chartProto"></canvas></div></div>
  <div class="chart-card"><h3>Traffic direction</h3><div class="chart-wrapper"><canvas id="chartDir"></canvas></div></div>
  <div class="chart-card"><h3>Session sizes</h3><div class="chart-wrapper"><canvas id="chartSize"></canvas></div></div>
</div>
<h2 class="section-title" id="protocols">📡 Protocol analysis</h2>
{make_decryption_status()}
{make_section("protocols")}
{make_protocol_ratio()}
{make_section("unknown_ports", col1="Port (tcp.dstport)", col2="Sessions")}
{make_section("tls", col1="TLS version", col2="Sessions")}
{make_section("ja4", col1="JA4 fingerprint", col2="Sessions")}
{make_section("ja3", col1="JA3 fingerprint", col2="Sessions")}
{make_section("tls_sni", col1="SNI hostname", col2="Sessions")}
<h2 class="section-title" id="traffic">🌐 IP traffic analysis</h2>
{make_section("top_src", col1="Source IP", col2="Sessions")}
{make_section("top_dst", col1="Destination IP", col2="Sessions")}
{make_section("top_host", col1="Hostname (alias.host)", col2="Sessions")}
{make_section("direction", col1="Direction", col2="Sessions")}
{make_section("lateral_services", col1="Service (lateral)", col2="Sessions")}
{make_section("outbound_services", col1="Service (outbound)", col2="Sessions")}
'''
        )

    def make_security_html():
        return f'''
<h2 class="section-title" id="quality">🔬 Quality analysis</h2>
{make_priority_ips_callout()}
{make_section("session_analysis", col1="Session trait", col2="Sessions")}
{make_section("session_sizes", col1="Size range", col2="Sessions")}
{make_section("http_analysis", col1="HTTP trait", col2="Sessions")}
{make_section("beacons", col1="Destination IP (beacon)", col2="Sessions")}
{make_section("long_conn", col1="Destination IP (long conn)", col2="Sessions")}
{make_section("large_outbound", col1="Destination IP (large transfers)", col2="Sessions")}
<h2 class="section-title" id="threats">🚨 Threat indicators</h2>
{make_ioc_callout()}
{make_section("ioc", col1="IOC tag", col2="Sessions")}
{make_section("boc", col1="BOC tag", col2="Sessions")}
{make_section("boc_outbound", col1="BOC tag (outbound only)", col2="Sessions")}
{make_eoc_hygiene()}
{make_section("eoc", col1="EOC tag", col2="Sessions")}
{make_section("threat_cat", col1="Threat category", col2="Sessions")}
{make_section("threat_desc", col1="Threat description", col2="Sessions")}
<h2 class="section-title" id="tls_fp">🔐 Encrypted traffic</h2>
{make_section("ja4", col1="JA4 fingerprint", col2="Sessions")}
{make_section("ja3", col1="JA3 fingerprint", col2="Sessions")}
{make_section("tls_sni", col1="SNI hostname", col2="Sessions")}
<h2 class="section-title" id="payload">📦 Payload & infrastructure</h2>
{make_section("zero_payload", col1="Destination IP", col2="Sessions")}
{make_section("request_no_payload", col1="Destination IP", col2="Sessions")}
{make_section("backup_traffic", col1="Destination IP", col2="Sessions")}
{make_section("first_carve", col1="New destination IP", col2="Sessions")}
'''

    def make_config_html():
        return f'''
<h2 class="section-title" id="filtering">🔧 Filtering recommendations</h2>
{make_section("decoder_payload", col1="Service (Decoder)", col2="Sessions")}
{make_section("decoder_clients", col1="User-Agent / Client", col2="Sessions")}
<h2 class="section-title" id="interpretation">📋 Interpretation guide</h2>
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
    <h4>First-carve — new destinations</h4>
    <ul>
      <li>First-carve flags connections to IPs not seen in the previous baseline period.</li>
      <li>Any first-carve to an external IP outside known cloud/CDN ranges should be investigated.</li>
      <li>C2 infrastructure, shadow SaaS, and exfiltration endpoints typically appear here before anywhere else.</li>
    </ul>
  </div>
</div>
'''

    sec_charts    = make_traffic_html()  if is_eng else ""
    sec_security  = make_security_html() if is_eng else ""
    sec_config    = make_config_html()   if is_eng else ""

    # Pre-compute nav tab buttons — 4 tabs: Overview / Traffic / Security / Config
    _btn_ov  = '<button class="tab-eng active" onclick="swEng(\'overview\',this)">📊 Overview</button>'  if is_eng else ''
    _btn_tr  = '<button class="tab-eng" onclick="swEng(\'traffic\',this)">🌐 Traffic & TLS</button>'    if is_eng else ''
    _btn_sec = '<button class="tab-eng" onclick="swEng(\'security\',this)">🔍 Security</button>'        if is_eng else ''
    _btn_cfg = '<button class="tab-eng" onclick="swEng(\'config\',this)">⚙️ Config</button>'            if is_eng else ''
    _btn_ex  = '<a href="#exec">Executive Summary</a>'                                                  if is_hunt and not is_eng else ''
    _btn_n2  = '<a href="#nis2">NIS2</a>'                                                               if is_nis2 and not is_eng else ''

    html = f"""<!DOCTYPE html>
<html lang="en" data-theme="{theme}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetWitness PoC — {client_name} — Traffic Analysis Report</title>
{_CHARTJS_INLINE}
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;600;700;800&display=swap');

  :root {{
    --bg: #f8fafc; --bg2: #ffffff; --bg3: #f1f5f9;
    --border: #e2e8f0; --accent: #0f766e; --accent2: #7c3aed;
    --green: #16a34a; --red: #dc2626; --amber: #d97706;
    --text: #0f172a; --muted: #64748b;
    --mono: 'JetBrains Mono', monospace; --sans: 'Syne', sans-serif;
  }}
  [data-theme="dark"] {{
    --bg:#0f1117; --bg2:#141720; --bg3:#1e2330;
    --border:#2a2d3a; --text:#e2e8f0; --muted:#64748b;
    --accent:#5eead4; --accent2:#a78bfa;
    --green:#4ade80; --red:#f87171; --amber:#fbbf24;
  }}
  [data-theme="dark"] body {{ background:#0f1117; color:#e2e8f0; }}
  [data-theme="dark"] .site-header {{ background:linear-gradient(135deg,#0f172a 0%,#134e4a 50%,#0f172a 100%); }}
  [data-theme="dark"] .nav {{ background:#141720; border-bottom-color:#2a2d3a; }}
  [data-theme="dark"] .nav a {{ color:#64748b; }}
  [data-theme="dark"] .nav a:hover {{ color:#e2e8f0; border-bottom-color:#5eead4; }}
  [data-theme="dark"] .card {{ background:#141720; border-color:#2a2d3a; }}
  [data-theme="dark"] .card-header {{ border-bottom-color:#2a2d3a; background:#141720; color:#e2e8f0; }}
  [data-theme="dark"] .card-desc {{ color:#94a3b8; }}
  [data-theme="dark"] .section-title {{ color:#e2e8f0; border-bottom-color:#2a2d3a; }}
  [data-theme="dark"] table th {{ background:#1e2330; color:#94a3b8; border-color:#2a2d3a; }}
  [data-theme="dark"] table td {{ border-color:#2a2d3a; color:#e2e8f0; background:#141720; }}
  [data-theme="dark"] table tbody td {{ background:#141720; }}
  [data-theme="dark"] table tr:hover td {{ background:#1e2330 !important; }}
  [data-theme="dark"] code {{ background:#1e2330; color:#5eead4; }}
  [data-theme="dark"] .badge {{ border-color:#2a2d3a; color:#94a3b8; background:#1e2330; }}
  [data-theme="dark"] .no-data {{ color:#475569; }}
  [data-theme="dark"] .pair-table td {{ background:#141720 !important; border-color:#1e2330 !important; color:#e2e8f0; }}
  [data-theme="dark"] .pair-table tr:hover td {{ background:#1e2330 !important; }}
  [data-theme="dark"] .parser-status-ok {{ background:#0c2420; color:#5eead4; }}
  [data-theme="dark"] .parser-status-low {{ background:#2d1f05; color:#fbbf24; }}
  [data-theme="dark"] .parser-status-miss {{ background:#3b1212; color:#f87171; }}
  [data-theme="dark"] .eng-notes {{ background:#1e2330; border-color:#2a2d3a; color:#cbd5e1; }}
  [data-theme="dark"] .eng-notes-title {{ color:#5eead4; }}
  [data-theme="dark"] .tls-meter {{ background:#141720; border-color:#2a2d3a; }}
  [data-theme="dark"] .tls-meter-bar {{ background:#2a2d3a; }}
  [data-theme="dark"] .interp-card {{ background:#141720; border-color:#2a2d3a; }}
  [data-theme="dark"] .interp-card h4 {{ color:#e2e8f0; border-bottom-color:#2a2d3a; }}
  [data-theme="dark"] .interp-card li {{ color:#94a3b8; }}
  [data-theme="dark"] .chart-card {{ background:#141720; border-color:#2a2d3a; }}
  [data-theme="dark"] .chart-card h3 {{ color:#94a3b8; }}
  [data-theme="dark"] .eng-panel {{ background:#0f1117; }}
  [data-theme="dark"] .tab-eng {{ color:#64748b; }}
  [data-theme="dark"] .tab-eng.active {{ color:#5eead4; border-bottom-color:#5eead4; }}
  /* Alert boxes */
  [data-theme="dark"] div[style*="background:#fef2f2"] {{ background:#2d1212 !important; border-color:#7f1d1d !important; color:#fca5a5 !important; }}
  [data-theme="dark"] div[style*="background:#f0fdfa"] {{ background:#0c2420 !important; border-color:#134e4a !important; color:#5eead4 !important; }}
  [data-theme="dark"] div[style*="background:#fffbeb"] {{ background:#2d1f05 !important; border-color:#78350f !important; color:#fde68a !important; }}
  [data-theme="dark"] div[style*="background:#f8fafc"] {{ background:#141720 !important; color:#e2e8f0 !important; }}
  [data-theme="dark"] div[style*="background:#fef2f2"] strong {{ color:#f87171; }}
  [data-theme="dark"] div[style*="background:#f0fdfa"] strong {{ color:#5eead4; }}
  /* NIS2 status cells */
  [data-theme="dark"] td[style*="color:#16a34a"] {{ color:#4ade80 !important; }}
  [data-theme="dark"] td[style*="color:#22c55e"] {{ color:#4ade80 !important; }}
  [data-theme="dark"] td[style*="color:#dc2626"] {{ color:#f87171 !important; }}
  [data-theme="dark"] td[style*="color:#d97706"] {{ color:#fbbf24 !important; }}

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
    background: linear-gradient(135deg, #0f172a 0%, #134e4a 50%, #0f172a 100%);
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
    color: var(--text);
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
  .card:hover {{ border-color: rgba(2,132,199,0.3); }}
  .card-header {{
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 8px;
  }}
  .card-header h2 {{
    font-size: 15px;
    font-weight: 700;
    color: var(--text);
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
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
    background: var(--bg2);
    color: var(--text);
  }}
  .data-table tr:hover td {{ background: rgba(2,132,199,0.06) !important; }}
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
  .eng-notes {{
    margin-top: 12px;
    padding: 12px 14px;
    background: #1e2330;
    border: 1px solid #2a2d3a;
    border-radius: 6px;
    font-size: 12px;
    line-height: 1.7;
  }}
  .eng-notes-title {{
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: #5eead4;
    margin-bottom: 6px;
  }}
  .eng-notes ul {{
    margin: 0;
    padding-left: 16px;
    color: #cbd5e1;
  }}
  .eng-notes li {{ margin: 3px 0; color: #cbd5e1; }}
  .eng-trigger {{
    font-weight: 600;
    color: #cbd5e1;
    font-family: var(--mono);
    font-size: 11px;
  }}
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
  /* ENGINEER TABS */
  .tab-eng {{
    background: none; border: none; border-bottom: 2px solid transparent;
    padding: 12px 16px; font-size: 12px; font-weight: 600;
    color: var(--muted); cursor: pointer; letter-spacing: 0.3px;
    font-family: var(--sans);
  }}
  .tab-eng:hover {{ color: var(--text); }}
  .tab-eng.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
  .eng-panel {{ display: none !important; }}
  .eng-panel.active {{ display: block !important; }}
  /* TLS VISIBILITY */
  .tls-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 12px;
    margin-bottom: 16px;
  }}
  .tls-meter {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 16px;
  }}
  .tls-meter-label {{ font-size: 11px; color: var(--muted); margin-bottom: 6px; }}
  .tls-meter-bar {{
    height: 8px; border-radius: 4px;
    background: var(--border); overflow: hidden; margin-bottom: 6px;
  }}
  .tls-meter-fill {{ height: 100%; border-radius: 4px; }}
  .tls-meter-val {{ font-size: 18px; font-weight: 700; font-family: var(--mono); }}
</style>
</head>
<body>

<header class="site-header">
  <div class="header-top">
    <div>
      <div class="header-title">NetWitness NDR <span>PoC Analysis</span></div>
      <div class="header-sub">{client_name} — Traffic Quality &amp; Volume Assessment</div>
    </div>
    <div class="header-meta">
      <strong>Client:</strong> {client_name}<br>
      <strong>Generated:</strong> {meta["generated"]}<br>
      <strong>Range:</strong> {range_label}<br>
      <strong>Concentrator:</strong> {meta["concentrator"]}<br>
      <strong>Decoder:</strong> {meta["decoder"]}
    </div>
  </div>
</header>

<nav class="nav">
  {_btn_ov}
  {_btn_tr}
  {_btn_sec}
  {_btn_cfg}
  {_btn_ex}
  {_btn_n2}
</nav>

<main>

  {'<!-- NIS2 standalone -->' if is_nis2 and not is_eng else ''}
  {sec_nis2 if is_nis2 and not is_eng else ''}
  {sec_exec if is_hunt and not is_eng else ''}

  <div id="ep-overview" class="eng-panel {'active' if is_eng else ''}">
    {f'''<div style="padding:14px 18px;margin-bottom:20px;background:{"#fef2f2" if summary.get("critical_count",0) > 0 else "#f0fdfa"};border-radius:8px;border-left:4px solid {"#dc2626" if summary.get("critical_count",0) > 0 else "#0f766e"};display:flex;align-items:center;justify-content:space-between">
      <div>
        <div style="font-size:13px;font-weight:700;color:{"#991b1b" if summary.get("critical_count",0) > 0 else "#0f766e"}">
          {"⚠ Critical findings require immediate attention" if summary.get("critical_count",0) > 0 else "✓ No critical findings in this analysis window"}
        </div>
        <div style="font-size:12px;color:var(--muted);margin-top:3px">
          {summary.get("total_sessions",0):,} sessions analysed · {summary.get("unique_src",0)} internal hosts · {summary.get("unique_dst",0)} external destinations
        </div>
      </div>
      <div style="text-align:right;flex-shrink:0;margin-left:24px">
        <span style="font-size:22px;font-weight:700;font-family:var(--mono);color:{"#dc2626" if summary.get("critical_count",0) > 0 else "#0f766e"}">{summary.get("critical_count",0)}</span>
        <div style="font-size:10px;color:var(--muted)">CRITICAL</div>
      </div>
    </div>''' if is_eng else ""}
    {sec_metrics}
    {sec_exec if is_eng else ''}
  </div>

  <div id="ep-traffic" class="eng-panel">
    {sec_charts}
  </div>

  <div id="ep-security" class="eng-panel">
    {sec_security}
    {sec_hunt}
  </div>

  <div id="ep-config" class="eng-panel">
    {sec_parsers if is_eng else ''}
    {sec_nis2 if is_eng else ''}
    {sec_config}
  </div>

</main>

<script>
function swEng(name, btn) {{
  document.querySelectorAll('.eng-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-eng').forEach(b => b.classList.remove('active'));
  var panel = document.getElementById('ep-' + name);
  if (panel) panel.classList.add('active');
  if (btn) btn.classList.add('active');
}}
</script>

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
      y: {{ ticks: {{ color: '#64748b', font: {{ size: 10 }} }}, grid: {{ color: '#e2e8f0' }} }}
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
      x: {{ ticks: {{ color: '#64748b', font: {{ size: 10 }} }}, grid: {{ color: '#e2e8f0' }} }},
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
    a.style.color = a.getAttribute('href') === '#' + current ? 'var(--accent)' : '';
    a.style.borderBottomColor = a.getAttribute('href') === '#' + current ? 'var(--accent)' : 'transparent';
  }});
}});
</script>
</body>
</html>"""

    return html


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
# PARSER HEALTH CHECK
# ─────────────────────────────────────────────

PARSER_CHECKS = [
    {
        "parser":  "traffic_flow.lua",
        "label":   "Traffic Flow (direction)",
        "field":   "direction",
        "where":   None,
        "expect":  ["outbound", "inbound", "lateral"],
        "impact":  "No direction meta — H-05, H-07, H-55 and all directional hypotheses unavailable.",
    },
    {
        "parser":  "session_analysis.lua",
        "label":   "Session Analysis (analysis.session)",
        "field":   "analysis.session",
        "where":   None,
        "expect":  ["potential beacon", "long connection", "high transmitted outbound"],
        "impact":  "No session characterization — H-01, H-02, H-07, H-15..H-20 unavailable.",
    },
    {
        "parser":  "http.lua (advanced)",
        "label":   "HTTP Analysis (analysis.service @ port 80)",
        "field":   "analysis.service",
        "where":   "service=80",
        "expect":  ["http"],
        "impact":  "No HTTP anomaly detection — H-06, H-09, H-10, H-11 unavailable.",
    },
    {
        "parser":  "TLD_lua",
        "label":   "TLD / DNS Analysis (analysis.service @ port 53)",
        "field":   "analysis.service",
        "where":   "service=53",
        "expect":  ["dns"],
        "impact":  "No DNS analysis — H-03, H-04 (DGA / DNS tunneling) unavailable.",
    },
    {
        "parser":  "smb.lua",
        "label":   "SMB Analysis (boc @ port 445)",
        "field":   "boc",
        "where":   "service=445",
        "expect":  [],
        "impact":  "No SMB behavioral tags — H-08, H-13, H-14 unavailable.",
    },
    {
        "parser":  "TLS_lua",
        "label":   "TLS Analysis (analysis.service @ port 443)",
        "field":   "analysis.service",
        "where":   "service=443",
        "expect":  ["tls"],
        "impact":  "No TLS version detection — H-25, H-26 (weak TLS) unavailable.",
    },
    {
        "parser":  "MAIL_lua",
        "label":   "Mail Analysis (analysis.service @ port 25)",
        "field":   "analysis.service",
        "where":   "service=25",
        "expect":  ["smtp"],
        "impact":  "No mail analysis — H-30..H-32 (phishing, BEC) unavailable.",
    },
    {
        "parser":  "windows_command_shell.lua",
        "label":   "Windows Shell (analysis.service = windows*)",
        "field":   "analysis.service",
        "where":   "analysis.service='windows command shell'",
        "expect":  [],
        "impact":  "No Windows shell telemetry — H-33..H-36 (lateral movement via CLI) unavailable.",
    },
]



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
        try:
            result = client.values(field, where=where, size=size)
        except NonIndexedKeyError:
            result = []
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
                      where=f"{tw} && service=0" if tw else "service=0", size=20,
                      label="unknown tcp.dstport")
    }

    # 9. TLS encryption
    data["sections"]["tls"] = {
        "title": "TLS versions (analysis.service)",
        "desc": "TLS 1.0/1.1 = vulnerable, should be eliminated. TLS 1.3 = gold standard.",
        "data": fetch(conc, "analysis.service",
                      where=f"{tw} && service=443" if tw else "service=443",
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
                            where=(f"{tw} && analysis.session='{tag}'" if tw else f"analysis.session='{tag}'"),
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
                      where=(f"{tw} && analysis.session='potential beacon'" if tw else f"analysis.session='potential beacon'"),
                      size=15, label="beacon dst IPs")
    }

    # 14. Long connections
    data["sections"]["long_conn"] = {
        "title": "Long connections — top destinations (long connection)",
        "desc": "Sessions lasting >30s. C2, tunnels, streaming. External IPs require analysis.",
        "data": fetch(conc, "ip.dst",
                      where=(f"{tw} && analysis.session='long connection'" if tw else f"analysis.session='long connection'"),
                      size=15, label="long connection IPs")
    }

    # 15. Large outbound transfers
    data["sections"]["large_outbound"] = {
        "title": "Large outbound transfers — top destinations",
        "desc": "Sessions with requestPayload >= 4MB. Exfil, backup, upload. External IPs require verification.",
        "data": fetch(conc, "ip.dst",
                      where=(f"{tw} && analysis.session='high transmitted outbound'" if tw else f"analysis.session='high transmitted outbound'"),
                      size=15, label="high outbound IPs")
    }

    # 17. JA3/JA4 TLS fingerprints
    print("\n[TLS Fingerprints & Encrypted Traffic]")
    data["sections"]["ja4"] = {
        "title": "JA4 TLS client fingerprints",
        "desc": (
            "JA4 fingerprints identify TLS client implementations without decryption. "
            "Each unique fingerprint represents a distinct TLS client (browser, tool, malware). "
            "Rare or unknown fingerprints warrant investigation — known malware families have documented JA4 hashes."
        ),
        "data": fetch(conc, "ja4", where=tw or None, size=20, label="ja4 fingerprints")
    }
    data["sections"]["ja3"] = {
        "title": "JA3 TLS client fingerprints (legacy)",
        "desc": (
            "Legacy TLS fingerprinting method. Included for compatibility with threat intel feeds "
            "that still use JA3. Cross-reference against known malware JA3 databases."
        ),
        "data": fetch(conc, "ja3", where=tw or None, size=15, label="ja3 fingerprints")
    }
    data["sections"]["tls_sni"] = {
        "title": "TLS SNI — top encrypted destinations",
        "desc": (
            "Server Name Indication extracted from TLS ClientHello — visible even without decryption. "
            "Shows which external services are accessed over HTTPS. Unusual SNI values "
            "(DGA-like names, unexpected cloud providers, unknown domains) are key indicators."
        ),
        "data": fetch(conc, "tls.sni",
                      where=(f"{tw} && service=443" if tw else "service=443"),
                      size=20, label="tls sni")
    }

    # 18. Zero payload & no-payload sessions
    print("\n[Session Payload Analysis]")
    data["sections"]["zero_payload"] = {
        "title": "Zero payload sessions",
        "desc": (
            "Sessions where no application payload was captured. "
            "Expected for backup replication, streaming control channels, and keepalive traffic. "
            "High volumes may also indicate selective capture configurations or evasion techniques "
            "where payloads are deliberately minimal."
        ),
        "data": fetch(conc, "ip.dst",
                      where=(f"{tw} && analysis.session='zero payload'" if tw else "analysis.session='zero payload'"),
                      size=10, label="zero payload sessions")
    }
    data["sections"]["request_no_payload"] = {
        "title": "Request no payload sessions",
        "desc": (
            "Sessions with responses but no request payload — typical for polling, streaming, "
            "and command-and-control check-ins. High counts from single sources may indicate beaconing."
        ),
        "data": fetch(conc, "ip.dst",
                      where=(f"{tw} && analysis.session='request no payload'" if tw else "analysis.session='request no payload'"),
                      size=10, label="request no payload")
    }

    # 19. Backup & high-volume infrastructure traffic
    print("\n[Backup & Infrastructure Traffic]")
    BACKUP_PORTS = "service=9000 || service=9001 || service=9002 || service=10082 || service=2049 || service=873"
    backup_where = f"{tw} && ({BACKUP_PORTS})" if tw else f"({BACKUP_PORTS})"
    data["sections"]["backup_traffic"] = {
        "title": "Backup & infrastructure traffic (ports 873/2049/9000-9002/10082)",
        "desc": (
            "Traffic on common backup and replication ports: rsync (873), NFS (2049), "
            "Veeam/generic backup (9000-9002), NetBackup (10082). "
            "This traffic typically does not require payload storage. "
            "Identifying volume here helps right-size storage and configure selective capture policies."
        ),
        "data": fetch(conc, "ip.dst", where=backup_where, size=10, label="backup traffic")
    }

    # 20. First-carve as standalone metric
    data["sections"]["first_carve"] = {
        "title": "First-carve — new external destinations",
        "desc": (
            "Connections to external IP addresses seen for the first time in this environment. "
            "First-carve is one of the most valuable early indicators — new external destinations "
            "not in the top-20 known IPs warrant investigation. "
            "C2 infrastructure, shadow SaaS, and exfiltration endpoints often appear here first."
        ),
        "data": fetch(conc, "ip.dst",
                      where=(f"{tw} && analysis.session='first carve not top 20 dst'" if tw else "analysis.session='first carve not top 20 dst'"),
                      size=20, label="first carve destinations")
    }

    # 21. Decryption status — encrypted vs decrypted on port 443
    print("\n[Decryption Status]")
    tls_total  = fetch(conc, "service",
                       where=(f"{tw} && service=443" if tw else "service=443"),
                       size=1, label="port 443 total")
    tls_w_http = fetch(conc, "analysis.service",
                       where=(f"{tw} && service=443 && analysis.service exists" if tw
                              else "service=443 && analysis.service exists"),
                       size=5, label="port 443 w/ HTTP meta (decrypted)")
    tls_total_count = sum(c for _, c in tls_total)
    tls_decrypted_count = sum(c for _, c in tls_w_http)
    tls_encrypted_count = max(0, tls_total_count - tls_decrypted_count)
    data["sections"]["decryption_status"] = {
        "title": "SSL/TLS decryption status",
        "desc": "Compares port 443 sessions with HTTP meta (decrypted by NPB/inline) vs raw TLS (encrypted).",
        "data": [
            ("Total port 443 sessions",    tls_total_count),
            ("Decrypted (HTTP meta present)", tls_decrypted_count),
            ("Encrypted (TLS only, no HTTP meta)", tls_encrypted_count),
            ("Decryption coverage %",
             round(100 * tls_decrypted_count / tls_total_count, 1) if tls_total_count else 0),
        ],
        "raw": {
            "total": tls_total_count,
            "decrypted": tls_decrypted_count,
            "encrypted": tls_encrypted_count,
            "pct": round(100 * tls_decrypted_count / tls_total_count, 1) if tls_total_count else 0,
        }
    }

    # 22. Direction × Service matrix
    print("\n[Direction × Service]")
    lateral_services = fetch(conc, "service",
                             where=(f"{tw} && direction='lateral'" if tw else "direction='lateral'"),
                             size=15, label="lateral by service")
    outbound_services = fetch(conc, "service",
                              where=(f"{tw} && direction='outbound'" if tw else "direction='outbound'"),
                              size=10, label="outbound by service")
    data["sections"]["lateral_services"] = {
        "title": "Lateral traffic — top services",
        "desc": "East-West traffic breakdown by protocol. SMB/RPC = expected AD traffic. Unknown ports = investigate.",
        "data": lateral_services
    }
    data["sections"]["outbound_services"] = {
        "title": "Outbound traffic — top services",
        "desc": "Most common protocols leaving the network. Baseline for what external connectivity looks like.",
        "data": outbound_services
    }

    # 23. BOC filtered by outbound direction
    boc_outbound = fetch(conc, "boc",
                         where=(f"{tw} && direction='outbound'" if tw else "direction='outbound'"),
                         size=20, label="boc outbound")
    data["sections"]["boc_outbound"] = {
        "title": "Behaviors of Compromise — outbound only",
        "desc": "BOC tags on outbound sessions only. Outbound BOC is higher priority than lateral — data leaving the network.",
        "data": boc_outbound
    }

    # 24. Priority IP cross-reference — same IP in beacon + long_conn + large_outbound
    print("\n[Priority IP Cross-reference]")
    beacon_ips  = {v for v, _ in data["sections"]["beacons"]["data"]}
    longconn_ips = {v for v, _ in data["sections"]["long_conn"]["data"]}
    largeout_ips = {v for v, _ in data["sections"]["large_outbound"]["data"]}

    priority_ips = []
    all_suspicious = beacon_ips | longconn_ips | largeout_ips
    for ip in all_suspicious:
        categories = []
        if ip in beacon_ips:    categories.append("potential beacon")
        if ip in longconn_ips:  categories.append("long connection")
        if ip in largeout_ips:  categories.append("large outbound")
        if len(categories) > 1:
            priority_ips.append((ip, " + ".join(categories)))

    data["sections"]["priority_ips"] = {
        "title": "Priority IPs — multiple threat categories",
        "desc": "IPs appearing in 2 or more of: beacon, long connection, large outbound. Highest investigation priority.",
        "data": priority_ips
    }
    if priority_ips:
        print(f"  ⚠  {len(priority_ips)} priority IP(s): {[ip for ip, _ in priority_ips]}")
    else:
        print(f"  OK no IPs in multiple threat categories")

    # 25. EOC hygiene score
    eoc_data = data["sections"]["eoc"]["data"]
    eoc_total_count = sum(c for _, c in eoc_data)
    data["sections"]["eoc"]["hygiene_score"] = eoc_total_count
    data["sections"]["eoc"]["hygiene_label"] = (
        "CRITICAL" if eoc_total_count > 500 else
        "HIGH"     if eoc_total_count > 100 else
        "MEDIUM"   if eoc_total_count > 20  else
        "LOW"      if eoc_total_count > 0   else
        "CLEAN"
    )

    # 26. Encrypted ratio in protocol summary
    all_proto = data["sections"]["protocols"]["data"]
    total_all = sum(c for _, c in all_proto)
    enc_count = next((c for v, c in all_proto if str(v) == "443"), 0)
    unk_count = next((c for v, c in all_proto if str(v) == "0"), 0)
    data["sections"]["protocols"]["stats"] = {
        "total": total_all,
        "encrypted_pct": round(100 * enc_count / total_all, 1) if total_all else 0,
        "unknown_pct":   round(100 * unk_count / total_all, 1) if total_all else 0,
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
# LLM PROVIDER FEED (F.07) — built-in baseline, no network required
# ─────────────────────────────────────────────

FEED_FALLBACK = {
    'about.meta.com': ('llm-provider', 'meta'),
    'about.sourcegraph.com': ('llm-coding', 'sourcegraph cody'),
    'adept.ai': ('llm-provider', 'adept ai'),
    'ai.facebook.com': ('llm-provider', 'meta'),
    'ai.google.dev': ('llm-provider', 'google gemini'),
    'ai.meta.com': ('llm-provider', 'meta'),
    'ai.replit.com': ('llm-provider', 'replit ai'),
    'ai21.com': ('llm-provider', 'ai21 labs'),
    'aiplatform.googleapis.com': ('llm-provider', 'google gemini'),
    'amazonq.aws': ('llm-provider', 'amazon q'),
    'andisearch.com': ('llm-provider', 'andi search'),
    'anthropic.com': ('llm-provider', 'anthropic'),
    'api-free.deepl.com': ('llm-provider', 'deepl write'),
    'api-inference.huggingface.co': ('llm-provider', 'hugging face inference'),
    'api.adept.ai': ('llm-enterprise', 'adept ai api'),
    'api.ai21.com': ('llm-enterprise', 'ai21 labs api'),
    'api.andisearch.com': ('llm-enterprise', 'andi search api'),
    'api.anthropic.com': ('llm-enterprise', 'anthropic api'),
    'api.character.ai': ('llm-enterprise', 'character.ai api'),
    'api.codeium.com': ('llm-coding', 'codeium api'),
    'api.cohere.ai': ('llm-enterprise', 'cohere api'),
    'api.copy.ai': ('llm-enterprise', 'copy.ai api'),
    'api.cursor.sh': ('llm-coding', 'cursor ai api'),
    'api.deepl.com': ('llm-enterprise', 'deepl write api'),
    'api.deepseek.com': ('llm-enterprise', 'deepseek api'),
    'api.elevenlabs.io': ('llm-enterprise', 'elevenlabs api'),
    'api.fireflies.ai': ('llm-enterprise', 'fireflies.ai api'),
    'api.forefront.ai': ('llm-enterprise', 'forefront ai api'),
    'api.grammarly.com': ('llm-enterprise', 'grammarly ai api'),
    'api.groq.com': ('llm-enterprise', 'groq api'),
    'api.huggingface.co': ('llm-enterprise', 'hugging face inference api'),
    'api.inflection.ai': ('llm-enterprise', 'pi by inflection ai api'),
    'api.jasper.ai': ('llm-enterprise', 'jasper ai api'),
    'api.kagi.com': ('llm-enterprise', 'kagi ai api'),
    'api.leonardo.ai': ('llm-enterprise', 'leonardo.ai api'),
    'api.litellm.ai': ('llm-enterprise', 'open-router & other proxy api'),
    'api.mem.ai': ('llm-enterprise', 'mem.ai api'),
    'api.mistral.ai': ('llm-enterprise', 'mistral ai api'),
    'api.neeva.com': ('llm-enterprise', 'neeva ai api'),
    'api.notion.com': ('llm-enterprise', 'notion ai api'),
    'api.ollama.com': ('llm-enterprise', 'deepseek api'),
    'api.openai.com': ('llm-enterprise', 'openai api'),
    'api.openrouter.ai': ('llm-enterprise', 'open-router & other proxy api'),
    'api.otter.ai': ('llm-enterprise', 'otter.ai api'),
    'api.perplexity.ai': ('llm-enterprise', 'perplexity ai api'),
    'api.poe.com': ('llm-enterprise', 'poe by quora api'),
    'api.quillbot.com': ('llm-enterprise', 'quillbot api'),
    'api.replicate.com': ('llm-enterprise', 'replicate api'),
    'api.replit.com': ('llm-enterprise', 'replit ai api'),
    'api.runwayml.com': ('llm-enterprise', 'runway ml api'),
    'api.scale.ai': ('llm-enterprise', 'scale ai api'),
    'api.stability.ai': ('llm-enterprise', 'stability ai api'),
    'api.synthesia.io': ('llm-enterprise', 'synthesia api'),
    'api.tabnine.com': ('llm-coding', 'tabnine api'),
    'api.together.ai': ('llm-enterprise', 'together ai api'),
    'api.together.xyz': ('llm-enterprise', 'together ai api'),
    'api.wordtune.com': ('llm-enterprise', 'wordtune api'),
    'api.writesonic.com': ('llm-enterprise', 'writesonic api'),
    'api.x.ai': ('llm-enterprise', 'xai api'),
    'api.you.com': ('llm-enterprise', 'you.com api'),
    'app.ai21.com': ('llm-provider', 'ai21 labs'),
    'app.claude.ai': ('llm-provider', 'anthropic'),
    'app.cohere.ai': ('llm-provider', 'cohere'),
    'app.copy.ai': ('llm-provider', 'copy.ai'),
    'app.grammarly.com': ('llm-provider', 'grammarly ai'),
    'app.jasper.ai': ('llm-provider', 'jasper ai'),
    'app.leonardo.ai': ('llm-provider', 'leonardo.ai'),
    'app.openrouter.ai': ('llm-provider', 'open-router & other proxy'),
    'app.perplexity.ai': ('llm-provider', 'perplexity ai'),
    'app.runwayml.com': ('llm-provider', 'runway ml'),
    'app.synthesia.io': ('llm-provider', 'synthesia'),
    'app.tabnine.com': ('llm-coding', 'tabnine'),
    'app.writesonic.com': ('llm-provider', 'writesonic'),
    'auth0.openai.com': ('llm-provider', 'openai'),
    'automl.googleapis.com': ('llm-provider', 'google gemini'),
    'bard.google.com': ('llm-provider', 'google gemini'),
    'bedrock-runtime.amazonaws.com': ('llm-provider', 'amazon bedrock'),
    'bedrock-runtime.us-east-1.amazonaws.com': ('llm-provider', 'amazon bedrock'),
    'bedrock-runtime.us-west-2.amazonaws.com': ('llm-provider', 'amazon bedrock'),
    'bedrock.amazonaws.com': ('llm-provider', 'amazon bedrock'),
    'bedrock.ap-southeast-1.amazonaws.com': ('llm-provider', 'amazon bedrock'),
    'bedrock.eu-central-1.amazonaws.com': ('llm-provider', 'amazon bedrock'),
    'bedrock.us-east-1.amazonaws.com': ('llm-provider', 'amazon bedrock'),
    'bedrock.us-west-2.amazonaws.com': ('llm-provider', 'amazon bedrock'),
    'beta.character.ai': ('llm-provider', 'character.ai'),
    'beta.dreamstudio.ai': ('llm-provider', 'stability ai'),
    'beta.elevenlabs.io': ('llm-provider', 'elevenlabs'),
    'beta.openai.com': ('llm-provider', 'openai'),
    'bing.com': ('llm-provider', 'microsoft copilot'),
    'blog.perplexity.ai': ('llm-provider', 'perplexity ai'),
    'cdn.anthropic.com': ('llm-provider', 'anthropic'),
    'cdn.midjourney.com': ('llm-provider', 'midjourney'),
    'cdn.openai.com': ('llm-provider', 'openai'),
    'character.ai': ('llm-provider', 'character.ai'),
    'chat.deepseek.com': ('llm-provider', 'deepseek chat'),
    'chat.forefront.ai': ('llm-provider', 'forefront ai chat'),
    'chat.mistral.ai': ('llm-provider', 'mistral ai chat'),
    'chat.openai.com': ('llm-provider', 'openai chat'),
    'chatsonic.com': ('llm-provider', 'writesonic'),
    'chrome.jasper.ai': ('llm-provider', 'jasper ai'),
    'claude.ai': ('llm-provider', 'anthropic'),
    'clipdrop.co': ('llm-provider', 'stability ai'),
    'cloud.google.com': ('llm-provider', 'google gemini'),
    'codeium.com': ('llm-coding', 'codeium'),
    'codex.openai.com': ('llm-provider', 'codex by openai'),
    'cody.ai': ('llm-provider', 'sourcegraph cody'),
    'cognitiveservices.azure.com': ('llm-provider', 'openai'),
    'cohere.ai': ('llm-provider', 'cohere'),
    'community.openai.com': ('llm-provider', 'openai'),
    'console.anthropic.com': ('llm-provider', 'anthropic'),
    'console.cohere.ai': ('llm-provider', 'cohere'),
    'console.groq.com': ('llm-provider', 'groq'),
    'console.mistral.ai': ('llm-provider', 'mistral ai'),
    'cookbook.openai.com': ('llm-provider', 'openai'),
    'copilot-proxy.githubusercontent.com': ('llm-coding', 'microsoft copilot'),
    'copilot.azure.com': ('llm-coding', 'microsoft copilot'),
    'copilot.github.com': ('llm-coding', 'microsoft copilot'),
    'copilot.microsoft.com': ('llm-coding', 'microsoft copilot'),
    'copilot.microsoft365.com': ('llm-coding', 'microsoft copilot'),
    'copy.ai': ('llm-provider', 'copy.ai'),
    'creator.poe.com': ('llm-provider', 'poe by quora'),
    'cursor.com': ('llm-coding', 'cursor ai'),
    'cursor.sh': ('llm-coding', 'cursor ai'),
    'dashboard.cohere.ai': ('llm-provider', 'cohere'),
    'datasets.huggingface.co': ('llm-provider', 'hugging face inference'),
    'deepl.com': ('llm-provider', 'deepl write'),
    'deepseek.com': ('llm-provider', 'deepseek'),
    'developer.openai.com': ('llm-provider', 'openai'),
    'developers.facebook.com': ('llm-provider', 'meta'),
    'developers.generativeai.google': ('llm-provider', 'google gemini'),
    'dialogflow.googleapis.com': ('llm-provider', 'google gemini'),
    'discord.com': ('llm-provider', 'midjourney'),
    'discuss.huggingface.co': ('llm-provider', 'hugging face inference'),
    'docs.ai21.com': ('llm-provider', 'ai21 labs'),
    'docs.anthropic.com': ('llm-provider', 'anthropic'),
    'docs.cohere.ai': ('llm-provider', 'cohere'),
    'docs.huggingface.co': ('llm-provider', 'hugging face inference'),
    'docs.litellm.ai': ('llm-provider', 'open-router & other proxy'),
    'docs.mistral.ai': ('llm-provider', 'mistral ai'),
    'docs.openai.com': ('llm-provider', 'openai'),
    'docs.openrouter.ai': ('llm-provider', 'open-router & other proxy'),
    'docs.perplexity.ai': ('llm-provider', 'perplexity ai'),
    'docs.replicate.com': ('llm-provider', 'replicate'),
    'docs.vllm.ai': ('llm-provider', 'open-router & other proxy'),
    'dreamstudio.ai': ('llm-provider', 'stability ai'),
    'edgeservices.bing.com': ('llm-provider', 'microsoft copilot'),
    'elevenlabs.io': ('llm-provider', 'elevenlabs'),
    'fireflies.ai': ('llm-provider', 'fireflies.ai'),
    'forefront.ai': ('llm-provider', 'forefront ai'),
    'forum.openai.com': ('llm-provider', 'openai'),
    'gemini.google.com': ('llm-provider', 'google gemini'),
    'generativelanguage.googleapis.com': ('llm-provider', 'google gemini'),
    'github.copilot.com': ('llm-coding', 'microsoft copilot'),
    'grammarly.com': ('llm-provider', 'grammarly ai'),
    'grok.x.ai': ('llm-provider', 'xai'),
    'groq.com': ('llm-provider', 'groq'),
    'help.openai.com': ('llm-provider', 'openai'),
    'hf.co': ('llm-provider', 'hugging face inference'),
    'huggingface.co': ('llm-provider', 'hugging face inference'),
    'imagine.meta.com': ('llm-provider', 'meta'),
    'inference-api.huggingface.co': ('llm-provider', 'hugging face inference'),
    'inflection.ai': ('llm-provider', 'pi by inflection ai'),
    'jasper.ai': ('llm-provider', 'jasper ai'),
    'kagi.com': ('llm-provider', 'kagi ai'),
    'labs.openai.com': ('llm-provider', 'openai'),
    'labs.perplexity.ai': ('llm-provider', 'perplexity ai'),
    'language.googleapis.com': ('llm-provider', 'google gemini'),
    'leonardo.ai': ('llm-provider', 'leonardo.ai'),
    'litellm.ai': ('llm-provider', 'open-router & other proxy'),
    'llama.meta.com': ('llm-provider', 'meta'),
    'llama2.ai': ('llm-provider', 'meta'),
    'makersuite.google.com': ('llm-provider', 'google gemini'),
    'mem.ai': ('llm-provider', 'mem.ai'),
    'meta.ai': ('llm-provider', 'meta'),
    'midjourney.com': ('llm-provider', 'midjourney'),
    'mistral.ai': ('llm-provider', 'mistral ai'),
    'models.bedrock.amazonaws.com': ('llm-provider', 'amazon bedrock'),
    'models.huggingface.co': ('llm-provider', 'hugging face inference'),
    'neeva.com': ('llm-provider', 'neeva ai'),
    'notion.so': ('llm-provider', 'notion ai'),
    'ollama.ai': ('llm-provider', 'ollama'),
    'ollama.com': ('llm-provider', 'ollama'),
    'openai.azure.com': ('llm-enterprise', 'azure openai'),
    'openai.com': ('llm-provider', 'openai'),
    'openrouter.ai': ('llm-provider', 'open-router & other proxy'),
    'otter.ai': ('llm-provider', 'otter.ai'),
    'palm.googleapis.com': ('llm-provider', 'google gemini'),
    'perplexity.ai': ('llm-provider', 'perplexity ai'),
    'phind.com': ('llm-provider', 'phind'),
    'pi.ai': ('llm-provider', 'pi by inflection ai'),
    'platform.deepseek.com': ('llm-provider', 'deepseek'),
    'platform.openai.com': ('llm-provider', 'openai'),
    'platform.stability.ai': ('llm-provider', 'stability ai'),
    'playground.ai21.com': ('llm-provider', 'ai21 labs'),
    'playground.openai.com': ('llm-provider', 'openai'),
    'plus.character.ai': ('llm-provider', 'character.ai'),
    'poe.com': ('llm-provider', 'poe by quora'),
    'production.cohere.ai': ('llm-provider', 'cohere'),
    'q.aws': ('llm-provider', 'amazon q'),
    'quillbot.com': ('llm-provider', 'quillbot'),
    'r8.im': ('llm-provider', 'replicate'),
    'registry.ollama.ai': ('llm-provider', 'ollama'),
    'replicate.com': ('llm-provider', 'replicate'),
    'replicate.delivery': ('llm-provider', 'replicate'),
    'replit.com': ('llm-provider', 'replit ai'),
    'runwayml.com': ('llm-provider', 'runway ml'),
    'scale.ai': ('llm-provider', 'scale ai'),
    'scale.com': ('llm-provider', 'scale ai'),
    'sourcegraph.com': ('llm-coding', 'sourcegraph cody'),
    'spaces.huggingface.co': ('llm-provider', 'hugging face inference'),
    'speech.googleapis.com': ('llm-provider', 'google gemini'),
    'spellbook.scale.com': ('llm-provider', 'scale ai'),
    'stability.ai': ('llm-provider', 'stability ai'),
    'stablediffusionweb.com': ('llm-provider', 'stability ai'),
    'status.anthropic.com': ('llm-provider', 'anthropic'),
    'status.openai.com': ('llm-provider', 'openai'),
    'studio.ai21.com': ('llm-provider', 'ai21 labs'),
    'support.anthropic.com': ('llm-provider', 'anthropic'),
    'support.perplexity.ai': ('llm-provider', 'perplexity ai'),
    'sydney.bing.com': ('llm-provider', 'microsoft copilot'),
    'synthesia.io': ('llm-provider', 'synthesia'),
    'tabnine.com': ('llm-coding', 'tabnine'),
    'together.ai': ('llm-provider', 'together ai'),
    'translate.googleapis.com': ('llm-provider', 'google gemini'),
    'txt.cohere.ai': ('llm-provider', 'cohere'),
    'vertexai.googleapis.com': ('llm-provider', 'google gemini'),
    'vision.googleapis.com': ('llm-provider', 'google gemini'),
    'vllm.ai': ('llm-provider', 'open-router & other proxy'),
    'wordtune.com': ('llm-provider', 'wordtune'),
    'wow.groq.com': ('llm-provider', 'groq'),
    'writesonic.com': ('llm-provider', 'writesonic'),
    'www.ai21.com': ('llm-provider', 'ai21 labs'),
    'www.anthropic.com': ('llm-provider', 'anthropic'),
    'www.cohere.ai': ('llm-provider', 'cohere'),
    'www.meta.ai': ('llm-provider', 'meta'),
    'www.midjourney.com': ('llm-provider', 'midjourney'),
    'www.perplexity.ai': ('llm-provider', 'perplexity ai'),
    'www.phind.com': ('llm-provider', 'phind'),
    'www.replicate.com': ('llm-provider', 'replicate'),
    'x.ai': ('llm-provider', 'xai'),
    'you.com': ('llm-provider', 'you.com'),
    'youchat.com': ('llm-provider', 'you.com'),
}

# Global feed dict — populated at startup, used by score_fp_pair and report renderers
LLM_FEED = dict(FEED_FALLBACK)  # offline fallback only


def check_parsers(conc, time_where):
    """
    Run parser health checks against the Concentrator.
    Returns list of dicts: parser, label, status, count, impact.
    status: OK | LOW | UNAVAILABLE
    """
    results = []
    print("\n[MODULE 0 — Parser Health Check]")

    for chk in PARSER_CHECKS:
        where = time_where
        if chk["where"]:
            where = (f"{time_where} && {chk['where']}" if time_where else chk['where'])

        print(f"  [{chk['parser']}]...", end=" ", flush=True)
        t0 = time.time()
        try:
            rows = conc.values(chk["field"], where=where, size=10)
        except NonIndexedKeyError:
            rows = []
        elapsed = time.time() - t0

        count = sum(c for _, c in rows)
        found_values = [v for v, _ in rows]

        if count == 0:
            status = "UNAVAILABLE"
        else:
            # Parser is active if it produced any meta at all.
            # Expected values are informational — their absence doesn't mean the parser is down.
            status = "OK"

        icon = {"OK": "✅", "LOW": "⚠️ ", "UNAVAILABLE": "❌"}[status]
        print(f"{icon} {status} ({elapsed:.1f}s, {count} sessions)")

        results.append({
            "parser":  chk["parser"],
            "label":   chk["label"],
            "status":  status,
            "count":   count,
            "impact":  chk["impact"],
        })

    ok    = sum(1 for r in results if r["status"] == "OK")
    low   = sum(1 for r in results if r["status"] == "LOW")
    miss  = sum(1 for r in results if r["status"] == "UNAVAILABLE")
    print(f"\n  Parsers: {ok} OK  |  {low} LOW  |  {miss} UNAVAILABLE")
    return results


# ─────────────────────────────────────────────
# ─────────────────────────────────────────────
# MODULE 3 — THREAT HUNT
# ─────────────────────────────────────────────


# ─────────────────────────────────────────────
# SESSION-BASED HUNT (v2 approach)
# ─────────────────────────────────────────────



def enrich_sections_with_sessions(sections, sessions):
    """
    Replace approximate engineer sections with session-derived precise data.
    Covers: beacons, long_conn, large_outbound, zero_payload, request_no_payload.
    """
    from collections import Counter as _Counter

    tag_map = {
        "beacons":              ("analysis.session", "potential beacon"),
        "long_conn":            ("analysis.session", "long connection"),
        "large_outbound":       ("analysis.session", "high transmitted outbound"),
        "zero_payload":         ("analysis.session", "zero payload"),
        "request_no_payload":   ("analysis.session", "request no payload"),
    }

    for section_key, (meta_key, tag_value) in tag_map.items():
        if section_key not in sections:
            continue
        matching = [s for s in sessions
                    if any(v.lower() == tag_value.lower()
                           for v in _as_list(s.get(meta_key)))]
        if not matching:
            continue

        # Count by ip.dst
        dst_ctr = _Counter()
        for s in matching:
            for ip in _as_list(s.get("ip.dst")):
                if ip and ip != "0.0.0.0":
                    dst_ctr[ip] += 1

        sections[section_key]["data"] = list(dst_ctr.most_common(15))
        sections[section_key]["session_precise"] = True

    return sections



NIS2_CONTROLS = {
    "Art.21(2)(b)": {
        "name": "Incident Handling",
        "article": "Art.21(2)(b) — Incident handling",
        "capability": (
            "NetWitness provides full network-layer incident detection capability — real-time alerting on suspicious "
            "behaviour, behavioural hunting across the kill chain (initial access, lateral movement, command-and-control, "
            "exfiltration), forensic session reconstruction, and correlation with threat intelligence feeds. "
            "This addresses the detection and analysis pillars of Art.21(2)(b)."
        ),
        "hypothesis_categories": [
            "C2 and beaconing detection (regular outbound communication patterns)",
            "Lateral movement detection (SMB, RPC, WMI, PsExec patterns)",
            "Data exfiltration detection (large outbound transfers, anomalous protocols)",
            "Initial access and exploitation indicators",
        ],
        "value_to_nis2": (
            "Use NetWitness as documented evidence of continuous network monitoring during NIS2 audits. "
            "The detection layer reduces mean time to detect (MTTD), which is critical for the 72-hour reporting requirement under Art.23. "
            "Map NetWitness alert categories to your existing IR playbooks to demonstrate end-to-end incident response capability."
        ),
    },
    "Art.21(2)(c)": {
        "name": "Business Continuity & Backup",
        "article": "Art.21(2)(c) — Business continuity, including backup management and disaster recovery",
        "capability": (
            "NetWitness provides visibility into backup operations at the network layer — backup traffic patterns, "
            "replication flows, backup destination verification. The platform can also detect pre-ransomware behaviour "
            "(mass file access, VSS deletion patterns, backup service tampering) which directly threatens continuity capability."
        ),
        "hypothesis_categories": [
            "Backup traffic visibility (rsync, NFS, Veeam, NetBackup, generic 9000-port range)",
            "Pre-ransomware behaviour patterns (mass SMB access, encryption-like traffic patterns)",
            "Backup destination validation (on-premises vs cloud, expected vs anomalous)",
            "Backup service availability (heartbeat patterns, scheduled job traffic)",
        ],
        "value_to_nis2": (
            "Network-layer visibility into backup operations allows you to evidence that backups are actually running, "
            "not just scheduled. Pre-ransomware detection provides early warning before continuity is compromised. "
            "Use this data to validate that your business continuity plan reflects actual network behaviour."
        ),
    },
    "Art.21(2)(d)": {
        "name": "Supply Chain Security",
        "article": "Art.21(2)(d) — Supply chain security, including security-related aspects of supplier relationships",
        "capability": (
            "NetWitness provides full visibility into third-party connectivity at the network layer — every external "
            "destination your environment communicates with, every cloud service, every SaaS platform, every AI provider. "
            "First-carve detection surfaces previously unseen external connections, supporting supplier discovery and validation."
        ),
        "hypothesis_categories": [
            "External destination discovery (first-carve to new IPs, new SNI/domains)",
            "AI and SaaS provider visibility (LLM API access, cloud service patterns)",
            "Software supply chain monitoring (package downloads, AI model downloads, npm/PyPI traffic)",
            "Approved vs unapproved provider tracking via SNI and IP correlation",
        ],
        "value_to_nis2": (
            "Network visibility makes the supplier inventory verifiable — you cannot have a supply chain you cannot see. "
            "Use NetWitness data to validate your approved-supplier list against actual network behaviour and identify "
            "shadow IT or shadow AI usage that bypasses procurement controls."
        ),
    },
    "Art.21(2)(f)": {
        "name": "Effectiveness Assessment",
        "article": "Art.21(2)(f) — Policies and procedures to assess the effectiveness of cybersecurity risk-management measures",
        "capability": (
            "NetWitness produces measurable, repeatable security telemetry — enabling effectiveness assessment of every "
            "control category mapped to other Art.21 paragraphs. Reports, dashboards, and KPIs derived from network "
            "evidence provide the data foundation for periodic risk-management measure reviews."
        ),
        "hypothesis_categories": [
            "Hygiene KPIs (EOC count trends, plaintext credential exposure, legacy protocol usage)",
            "Detection coverage metrics (parser health, hypothesis coverage, indexed meta keys)",
            "Encryption posture metrics (TLS version distribution, decryption coverage)",
            "Threat detection rate (IOC/BOC volume trends over time)",
        ],
        "value_to_nis2": (
            "Effectiveness assessment requires measurement. NetWitness provides the measurement layer — every other Art.21 "
            "control becomes assessable through network telemetry. Use periodic reports as evidence that your risk-management "
            "measures are reviewed and evidence-based, not just documented."
        ),
    },
    "Art.21(2)(g)": {
        "name": "Cyber Hygiene & Training",
        "article": "Art.21(2)(g) — Basic cyber hygiene practices and cybersecurity training",
        "capability": (
            "NetWitness provides network-layer visibility into hygiene gaps — Enablers of Compromise (EOC) tags surface "
            "configuration weaknesses such as cleartext credentials, deprecated protocols, default configurations, and "
            "exposed administrative interfaces. EOC counts provide a measurable hygiene KPI."
        ),
        "hypothesis_categories": [
            "Cleartext protocol usage (plaintext FTP, SMTP, Telnet, HTTP authentication)",
            "Legacy protocol detection (SMBv1, weak TLS, deprecated cipher suites)",
            "Default credential and configuration patterns",
            "Administrative service exposure (open RDP, exposed databases, unauthenticated services)",
        ],
        "value_to_nis2": (
            "Cyber hygiene is hard to measure without network visibility. Use EOC counts as a baseline hygiene score "
            "and track them over time as a measurable KPI for your hygiene programme. Each EOC category maps to a "
            "specific remediation action — turning hygiene from policy into measurable practice."
        ),
    },
    "Art.21(2)(h)": {
        "name": "Cryptography & Encryption",
        "article": "Art.21(2)(h) — Policies and procedures regarding the use of cryptography and encryption",
        "capability": (
            "NetWitness reveals the actual cryptographic state of your network — TLS version distribution, cipher suite "
            "negotiation, JA3/JA4 client fingerprinting, plaintext protocol detection. This is the ground truth of your "
            "encryption policy enforcement."
        ),
        "hypothesis_categories": [
            "TLS version distribution (1.0/1.1/1.2/1.3 across all encrypted traffic)",
            "Weak cipher suite negotiation",
            "Plaintext protocol identification (HTTP, FTP, Telnet, plain SMTP without STARTTLS)",
            "TLS client fingerprinting (JA3/JA4) for unauthorised crypto libraries",
            "SSL/TLS decryption coverage analysis",
        ],
        "value_to_nis2": (
            "An encryption policy without measurement is only aspirational. NetWitness provides the measurement — "
            "TLS distribution by host, cleartext protocol identification by source. Use this data to validate policy "
            "enforcement and identify gaps where cryptography controls need strengthening."
        ),
    },
    "Art.21(2)(i)": {
        "name": "Access Control & Asset Management",
        "article": "Art.21(2)(i) — Human resources security, access control policies and asset management",
        "capability": (
            "NetWitness provides network-layer visibility into access patterns and asset behaviour — every host that "
            "appears on the network, every authentication flow, every administrative action visible at the network level. "
            "First-carve detection identifies hosts not previously seen, supporting asset inventory validation."
        ),
        "hypothesis_categories": [
            "Authentication anomaly detection (LDAP enumeration, Kerberos abuse patterns)",
            "Privileged access pattern monitoring (admin protocols from non-admin hosts)",
            "Asset discovery (first-carve, new internal hosts, unmanaged endpoints)",
            "Lateral movement and east-west access patterns",
        ],
        "value_to_nis2": (
            "Asset management on paper is incomplete without network-layer validation. NetWitness shows what is actually "
            "on the network and how access is exercised. Use first-carve data to identify unmanaged assets and access "
            "pattern data to validate that privileged access is exercised only by authorised hosts."
        ),
    },
    "Art.21(2)(j)": {
        "name": "MFA & Secure Communications",
        "article": "Art.21(2)(j) — Multi-factor authentication and secured communications",
        "capability": (
            "NetWitness provides visibility into authentication flows and the security posture of communication channels. "
            "Cleartext credential detection, weak TLS on authentication endpoints, and protocol-level analysis of "
            "authentication traffic all support assessment of MFA and secure communication controls."
        ),
        "hypothesis_categories": [
            "Authentication endpoint security (TLS version, cipher suite per auth flow)",
            "Cleartext credential exposure (HTTP Basic Auth, plaintext SMTP AUTH, FTP, Telnet)",
            "Authentication protocol analysis (Kerberos, NTLM, SAML, OAuth flows)",
            "Secure communication enforcement (encrypted vs unencrypted authentication)",
        ],
        "value_to_nis2": (
            "MFA enforcement requires knowing where authentication happens. NetWitness identifies authentication flows "
            "across the network and their cryptographic protection. Use this to prioritise MFA rollout — start with "
            "endpoints where authentication is currently in cleartext or over weak crypto."
        ),
    },
}

def run_nis2(hunt_results, parser_health):
    """
    Map hunt results to NIS2 Art.21 controls.
    New status framing: focuses on NetWitness capability, not compliance verdict.
    
    Status:
    - CAPABILITY_DEMONSTRATED: hypotheses returned observations in this window — system is actively monitoring
    - CAPABILITY_AVAILABLE: hypotheses checked, no specific findings — but capability is ready
    - REQUIRES_CONFIGURATION: required parsers/feeds/rules unavailable — capability needs setup
    """
    if not hunt_results:
        # Even without hunt results, we can describe capabilities
        hunt_results = []

    # Build control → hypothesis results mapping
    control_map = {}
    for r in hunt_results:
        nis2_field = r.get("nis2", "").strip()
        if not nis2_field:
            continue
        for ctrl in [c.strip() for c in nis2_field.split(",") if c.strip()]:
            key = ctrl.replace(" ", "").replace("Art21", "Art.21")
            if key not in control_map:
                control_map[key] = []
            control_map[key].append(r)

    assessments = []
    for ctrl_id, ctrl_info in NIS2_CONTROLS.items():
        results = control_map.get(ctrl_id, [])

        found   = [r for r in results if r["status"] == "FOUND"]
        not_ob  = [r for r in results if r["status"] == "NOT_OBSERVED"]
        unavail = [r for r in results if r["status"] == "PARSER_UNAVAILABLE"]

        # Capability-based status
        if found:
            # System is actively producing observations relevant to this control
            status = "CAPABILITY_DEMONSTRATED"
        elif not_ob:
            # Hypotheses ran successfully — capability works, no specific findings in this window
            status = "CAPABILITY_AVAILABLE"
        elif unavail and not results:
            status = "REQUIRES_CONFIGURATION"
        elif unavail:
            # Some parsers unavailable but others worked
            status = "PARTIAL_CAPABILITY"
        else:
            # No hypotheses mapped at all — capability is described, not measured
            status = "CAPABILITY_DESCRIBED"

        # Build observation narrative
        if found:
            sample_obs = "; ".join(
                f"{r['id']} ({r['count']:,} sessions)" for r in found[:3]
            )
            if len(found) > 3:
                sample_obs += f" and {len(found)-3} more"
            observed_text = (
                f"In this analysis window, NetWitness produced observations across {len(found)} hypothesis category(ies) "
                f"relevant to this control — including {sample_obs}. This demonstrates that the monitoring layer is "
                f"actively producing evidence for this control."
            )
        elif not_ob:
            observed_text = (
                f"NetWitness evaluated {len(not_ob)} hypothesis category(ies) for this control with no specific findings "
                f"in this window. This is a positive baseline — the detection capability is configured and operational, "
                f"ready to alert when relevant patterns appear."
            )
        elif unavail:
            observed_text = (
                f"{len(unavail)} hypothesis category(ies) for this control require parser/feed configuration to be "
                f"fully operational. Once configured, these will provide additional monitoring depth for this control."
            )
        else:
            observed_text = (
                "No hypotheses are currently mapped to evaluate this control in this analysis window. "
                "The capability description above outlines what NetWitness can monitor for this control area."
            )

        assessments.append({
            "id":                    ctrl_id,
            "name":                  ctrl_info["name"],
            "article":               ctrl_info["article"],
            "status":                status,
            "capability":            ctrl_info["capability"],
            "hypothesis_categories": ctrl_info["hypothesis_categories"],
            "observed":              observed_text,
            "value_to_nis2":         ctrl_info["value_to_nis2"],
            "found":                 found,
            "not_observed":          not_ob,
            "unavailable":           unavail,
            "total":                 len(results),
        })

    return assessments


def compute_executive_summary(data, hunt_results, nis2_results):
    """
    Build executive summary dict from all module results.
    """
    summary = data.get("summary", {})
    sections = data.get("sections", {})

    # Risk level
    found_high = [r for r in hunt_results if r["status"] == "FOUND" and r.get("severity") == "H"]
    found_any  = [r for r in hunt_results if r["status"] == "FOUND"]

    if found_high:
        risk_level = "HIGH"
        risk_color = "#dc2626"
    elif found_any:
        risk_level = "MEDIUM"
        risk_color = "#d97706"
    elif hunt_results:
        risk_level = "LOW"
        risk_color = "#16a34a"
    else:
        risk_level = "UNKNOWN"
        risk_color = "#64748b"

    # Top 3 findings (severity H first, then M, then session count)
    sev_order = {"H": 0, "M": 1, "L": 2}
    top_findings = sorted(
        found_any,
        key=lambda r: (sev_order.get(r.get("severity", "L"), 2), -r.get("count", 0))
    )[:3]

    # NIS2 scorecard
    nis2_total      = len(nis2_results)
    nis2_findings   = sum(1 for r in nis2_results if r["status"] == "CAPABILITY_DEMONSTRATED")
    nis2_not_comp   = 0  # removed — no compliance verdicts on POC
    nis2_not_assess = sum(1 for r in nis2_results if r["status"] in ("REQUIRES_CONFIGURATION", "CAPABILITY_DESCRIBED"))

    # Key metrics
    ioc_data = sections.get("ioc", {}).get("data", [])
    boc_data = sections.get("boc", {}).get("data", [])
    beacon_data = sections.get("beacons", {}).get("data", [])

    # Build 3 business-language key findings
    key_findings = []
    if found_high:
        key_findings.append(
            f"{len(found_high)} critical threat pattern(s) confirmed in network traffic, "
            f"including {found_high[0]['name']}. Immediate investigation required."
        )
    if summary.get("ioc_count", 0) > 0:
        top_ioc = ioc_data[0][0] if ioc_data else "unknown"
        key_findings.append(
            f"NetWitness detection rules fired {summary['ioc_count']:,} IOC alerts. "
            f"Most prevalent: '{top_ioc}'."
        )
    if summary.get("beacon_count", 0) > 0:
        key_findings.append(
            f"{summary['beacon_count']} potential beacon destination(s) identified — "
            f"consistent with malware C2 communication patterns."
        )
    if not key_findings:
        if hunt_results:
            key_findings.append("No critical threats confirmed in the analysis window. Baseline appears clean.")
        else:
            key_findings.append("Analysis completed. Review individual sections for detailed findings.")

    # Pad to 3
    while len(key_findings) < 3:
        boc_count = summary.get("boc_count", 0)
        if boc_count > 0 and len(key_findings) < 3:
            key_findings.append(
                f"{boc_count:,} Behavior of Compromise (BOC) events detected — "
                f"review the Initial Findings section for breakdown."
            )
            continue
        unknown_pct = summary.get("unknown_pct", 0)
        if unknown_pct > 15 and len(key_findings) < 3:
            key_findings.append(
                f"{unknown_pct}% of traffic is unidentified (service=0). "
                f"Parser coverage gaps limit threat visibility."
            )
            continue
        break

    return {
        "risk_level":      risk_level,
        "risk_color":      risk_color,
        "top_findings":    top_findings,
        "key_findings":    key_findings[:3],
        "hunt_found":      len(found_any),
        "hunt_total":      len(hunt_results),
        "nis2_total":      nis2_total,
        "nis2_findings":   nis2_findings,
        "nis2_not_comp":   nis2_not_comp,
        "nis2_not_assess": nis2_not_assess,
        "ioc_count":       summary.get("ioc_count", 0),
        "boc_count":       summary.get("boc_count", 0),
        "beacon_count":    summary.get("beacon_count", 0),
        "total_sessions":  summary.get("total_sessions", 0),
    }


# CACHE HELPERS
# ─────────────────────────────────────────────

def save_cache(data, cache_path):
    import os
    os.makedirs(os.path.dirname(cache_path) if os.path.dirname(cache_path) else ".", exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"  Cache saved → {cache_path}")

def load_cache(cache_path):
    from pathlib import Path
    p = Path(cache_path)
    if p.exists():
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    return None


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NetWitness PoC Traffic Analysis — generates an HTML report"
    )
    parser.add_argument("--concentrator", required=True,
                        help="Concentrator IP or hostname")
    parser.add_argument("--concentrator-port", default=50105, type=int,
                        help="Concentrator port (default 50104)")
    parser.add_argument("--decoder",
                        help="Decoder IP or hostname (optional)")
    parser.add_argument("--decoder-port", default=50102, type=int,
                        help="Decoder port (default 50102)")
    parser.add_argument("--user", required=True, help="Username")
    parser.add_argument("--password", required=True, help="Password")

    # New: scope in days (replaces --hours)
    parser.add_argument("--scope", default=7, type=int,
                        help="Analysis range in days (default 7)")
    parser.add_argument("--hours", default=None, type=int,
                        help="Analysis range in hours — overrides --scope if set")

    # New: client name, cache, check mode
    parser.add_argument("--client", default="Client",
                        help="Client name for report header (default: Client)")
    parser.add_argument("--cache", default=None,
                        help="Path to JSON cache file. If exists: skip API calls and load from file. "
                             "Always written after a live run.")
    parser.add_argument("--check", action="store_true",
                        help="Run parser health check only, skip full analysis")

    parser.add_argument("--llm-pack", action="store_true",
                        help="Enable LLM Pack v2.2 hypotheses (H-56..H-64, H-70, H-86..H-95)")
    parser.add_argument("--ai-pack", action="store_true",
                        help="Enable H-71..H-85 (AI Threats Pack hypotheses)")
    parser.add_argument("--no-hunt", action="store_true",
                        help="Skip Module 3 — threat hunt (faster run)")
    parser.add_argument("--session-size", type=int, default=50000,
                        help="Max sessions to fetch for local hypothesis evaluation (default: 50000)")
    parser.add_argument("--all-time", action="store_true",
                        help="Query all available data, ignore --scope/--hours time window")

    parser.add_argument("--report",
                        choices=["engineer", "threathunting", "nis2", "all"],
                        default="engineer",
                        help="Report type: engineer (default), threathunting, nis2, all")
    parser.add_argument("--output", default="nw_poc_report.html",
                        help="Output HTML file (default nw_poc_report.html)")
    parser.add_argument("--theme", choices=["light","dark"], default="light",
                        help="Report colour theme: light (default) or dark")
    args = parser.parse_args()

    # Resolve hours
    hours = args.hours if args.hours is not None else args.scope * 24

    print("=" * 60)
    print("NetWitness PoC Traffic Analysis")
    print("=" * 60)
    print(f"Client:       {args.client}")
    print(f"Concentrator: {args.concentrator}:{args.concentrator_port}")
    print(f"Decoder:      {args.decoder or 'skipped'}:{args.decoder_port}")
    print(f"Range:        {'ALL available data' if args.all_time else f'last {args.scope}d ({hours}h)'}")
    print(f"Cache:        {args.cache or 'none'}")
    print(f"Output:       {args.output}")
    print()

    # Initialize clients
    conc = NWClient(args.concentrator, args.concentrator_port,
                    args.user, args.password)
    dec = None
    if args.decoder:
        dec = NWClient(args.decoder, args.decoder_port,
                       args.user, args.password)

    # ── Load LLM provider feed (F.07) ────────────────────────
    global LLM_FEED

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

    # Time where clause
    if args.all_time:
        # epoch 1577836800 = 2020-01-01 — covers all practical session history
        # without routing to NW archived storage (time >= 0 hits wrong tier)
        # Bounded all-time: from 2020-01-01 to now
        # Unbounded queries can hit wrong storage tier in NW SDK
        import time as _t
        time_where = f"time >= 1577836800 && time <= {int(_t.time())}"
        print("  Time range: ALL available data (--all-time, from 2020-01-01)")
    else:
        time_where = build_time_where(hours)
        print(f"  Time range: last {args.scope}d ({hours}h)")

    # --check mode: parser health only
    if args.check:
        check_parsers(conc, time_where)
        print("\nDone (--check mode, no report generated).")
        return

    # Load from cache or run live
    data = None
    if args.cache:
        data = load_cache(args.cache)
        if data:
            print(f"  Loaded from cache: {args.cache}")
        else:
            print(f"  Cache not found — running live analysis")

    if data is None:
        # Parser health check first (results stored in data)
        parser_health = check_parsers(conc, time_where)

        print("\n[Running full analysis]")
        t0 = time.time()
        data = run_analysis(conc, dec, hours)
        elapsed = time.time() - t0
        print(f"\nAnalysis finished in {elapsed:.1f}s")

        # Attach parser health and client name to data
        data["parser_health"] = parser_health
        data["meta"]["client"] = args.client
        data["meta"]["scope_days"] = args.scope
        data["meta"]["all_time"] = args.all_time

        # Module 3 — Threat Hunt (session-based, no IndexKeys required)
        if not args.no_hunt:
            # Fetch all sessions once
            sessions = fetch_sessions(conc, time_where, size=args.session_size)
            data["_sessions"] = sessions  # keep for section enrichment

            # Evaluate hypotheses locally
            from hypotheses_data import HYPOTHESES
            hyp_list = [h for h in HYPOTHESES if h.get("pack") == "Hunting Pack"]
            # LLM Pack T1 (AR-based) — always included
            hyp_list += [h for h in HYPOTHESES if "LLM" in h.get("pack","")
                         and h.get("llm_tier","T1") == "T1"]
            if args.llm_pack:
                hyp_list += [h for h in HYPOTHESES if "LLM" in h.get("pack","")
                              and h.get("llm_tier","T1") != "T1"]
            if args.ai_pack:
                hyp_list += [h for h in HYPOTHESES if "AI Threats" in h.get("pack","")]

            hunt_results = evaluate_hypotheses(sessions, hyp_list)

            # Enrich engineer sections with precise session data
            data["sections"] = enrich_sections_with_sessions(data["sections"], sessions)

            data["hunt"]     = hunt_results
            data["sessions"] = sessions
        else:
            data["hunt"]     = []
            data["sessions"] = []

        # Module 4 — NIS2 mapping
        data["nis2"] = run_nis2(data["hunt"], parser_health)

        # Executive summary
        data["exec_summary"] = compute_executive_summary(data, data["hunt"], data["nis2"])

        # Save cache
        if args.cache:
            save_cache(data, args.cache)
    else:
        # Cache hit — patch client name if re-running with different --client
        data["meta"]["client"] = args.client

    # Generate HTML report(s)
    report_map = {
        "engineer":     args.output or "report_engineer.html",
        "threathunting": args.output.replace(".html", "_threathunting.html") if args.output != "nw_poc_report.html" else "report_threathunting.html",
        "nis2":          args.output.replace(".html", "_nis2.html") if args.output != "nw_poc_report.html" else "report_nis2.html",
    }

    # Determine which reports to generate
    reports_to_run = [args.report] if args.report != "all" else ["engineer", "threathunting", "nis2"]

    for rtype in reports_to_run:
        # Default output name per type if not overridden
        if args.output == "nw_poc_report.html":
            out = f"report_{rtype}.html"
        else:
            base = args.output.replace(".html", "")
            out = f"{base}_{rtype}.html" if len(reports_to_run) > 1 else args.output

        print(f"Generating [{rtype}] → {out}")
        html = generate_html(data, report_type=rtype, theme=args.theme)
        with open(out, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"  ✓ {out}")

    # Terminal summary
    s = data["summary"]
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Client:            {args.client}")
    print(f"  Total sessions:    {s['total_sessions']:,}")
    print(f"  TLS ratio:         {s['tls_pct']}%")
    print(f"  Unknown:           {s['unknown_pct']}%  {'⚠' if s['unknown_pct'] > 20 else '✓'}")
    print(f"  IOC alerts:        {s['ioc_count']}  {'⚠ INVESTIGATE!' if s['ioc_count'] > 0 else '✓'}")
    print(f"  BOC alerts:        {s['boc_count']}")
    print(f"  Beacon candidates: {s['beacon_count']}  {'⚠' if s['beacon_count'] > 5 else '✓'}")
    print(f"  Threat intel:      {'ACTIVE ✓' if s['has_threat_intel'] else 'NONE — load feeds!'}")
    print(f"\nDone. Report type: {args.report}")


if __name__ == "__main__":
    main()
