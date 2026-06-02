# NetWitness PoC Analysis Tool — v0.9

Queries a NetWitness NDR Concentrator or Broker, evaluates up to 95 threat hunting hypotheses against the fetched session data, and generates self-contained HTML reports. No client-side dependencies — the output file works offline in any browser.

**Delivered and run by the SE. The client sees only the HTML report.**

---

## Requirements

```bash
pip install requests --break-system-packages
```

- Python 3.8+
- Network access to Concentrator (port `50105`) or Broker (port `50103`)
- NetWitness account with SDK read access

Tested on RHEL 8/9. Runs on ESA Primary or Admin Server without additional setup.

---

## Files

| File | Description |
|------|-------------|
| `nw_poc_v2_7.py` | Main script (internal build v2.7) |
| `hypotheses_data.py` | Hypothesis database — keep in same directory |
| `nw_poc_launcher.py` | Interactive wizard — recommended entry point |

---

## Quick start

```bash
python3 nw_poc_launcher.py
```

The wizard walks through all options and builds the command. For direct use:

```bash
python3 nw_poc_v2_7.py \
  --concentrator 192.168.1.112 \
  --user admin --password netwitness \
  --client "Acme Corp" \
  --hours 336 \
  --report all \
  --theme dark
```

---

## Launcher options

**Connection**
- Concentrator/Broker IP and port (`50105` for Concentrator, `50103` for Broker)
- Username and password
- Session fetch limit — default `50,000`. Increase for large environments. A warning is shown if the limit is nearly reached.

**Time range**

| Option | Hours | When to use |
|--------|-------|-------------|
| Last 24h | 24 | Quick connectivity test |
| Last 72h | 72 | Small environments |
| Last 7 days | 168 | Minimum for meaningful results |
| **Last 14 days** | **336** | **Recommended for PoC** |
| Last 30 days | 720 | Full baseline |
| All available data | — | Use with caution — may return only PCAP data |

**Reports**

| Option | Audience | Description |
|--------|----------|-------------|
| Threat Hunting | SOC / Security team | Tactical finding cards — main PoC deliverable |
| Engineer | SE internal | Traffic breakdown, parser health, SE notes |
| NIS2 | CISO / Compliance | Art.21 capability mapping |
| All three | — | Single data fetch, all three outputs |

**Theme** — `Light` (print/presentation) or `Dark` (screen sharing)

**Cache** — saves fetched session data to JSON. Re-run with same cache to re-render reports without reconnecting to the Concentrator.

---

## Reports

### Threat Hunting

Three tabs:

**Overview** — session count, hypothesis results by severity (Critical / High / Medium / Info), MITRE ATT&CK coverage bar, findings summary with direct links to detail cards.

**Hosts** — risk-ranked host list. Per host: attack chain, traffic direction and protocol breakdown, activity timeline, top destinations with LLM provider categorisation, and linked findings.

**Findings** — per-hypothesis detail cards. Each card contains:
- Threat context (what this pattern indicates)
- Detected connections table with verdict (Investigate / Review)
- Investigation steps with ready-to-run NWQL queries
- Mitigations with priority (NOW / TODAY / THIS WEEK)

### Engineer

For the SE, not the client. Contains parser health, protocol and traffic distribution, TLS visibility, IP traffic analysis, threat indicators (IOC/BOC/EOC), and per-section **Engineer Notes** with trigger-action guidance and client questions.

### NIS2

Maps hunt findings to 8 NIS2 Art.21(2) controls (b, c, d, f, g, h, i, j). Each control shows: capability status, sample observations from the analysis window, and what NetWitness monitors in that area. Positioned as readiness evidence — not a compliance verdict.

---

## Hypothesis packs

| Pack | IDs | Count | Requirement |
|------|-----|-------|-------------|
| Hunting Pack | H-01..H-55 | 55 | Hunting Pack parsers + AR rules |
| LLM Pack | H-56..H-95 | 40 | Feed F.07 + LLM AR rules (H-86..H-95 AR-based, H-56..H-70 ESA-based) |
| AI Threats Pack | H-71..H-85 | 15 | AI Threats Pack AR rules |

Hunting Pack hypotheses (H-01..H-55) run in all environments. LLM and AI packs require the respective AR rules deployed on the Decoder before data was captured — otherwise they return NOT_OBSERVED.

---

## Notes

- `alias.host` (hostname resolution) requires DNS/HTTP/SSL parsers active during capture
- Charts render offline — no internet required
- If session fetch hits 95% of the limit, a warning is shown with a suggested new limit
- For Broker: same API, same queries — just change the IP and port to `50103`
