# nw-poc-analysis

[🇵🇱 Polski](README.md) | **🇬🇧 English**

NetWitness NDR 12.x PoC traffic analysis tool — queries Concentrator and Decoder via the SDK (`/sdk?msg=values`), computes basic qualitative and quantitative traffic metrics, and generates a single-file HTML report with charts (Chart.js) and sortable tables.

Two language versions:
- [`nw_poc_analysis.py`](nw_poc_analysis.py) — Polish (labels, messages, report)
- [`nw_poc_analysis_en.py`](nw_poc_analysis_en.py) — English

Same logic in both, just the UI strings differ.

## Usage

```bash
pip install requests --break-system-packages

python3 nw_poc_analysis_en.py \
  --concentrator <IP> --concentrator-port 50105 \
  --decoder      <IP> --decoder-port      50104 \
  --user admin --password '<PASS>' \
  --hours 168 \
  --output report.html
```

The argparse defaults (`50104`/`50102`) are historical — in real deployments **Concentrator = 50105**, **Packet/Log Decoder = 50104**. Detailed port map, NW 12 SDK quirks, and manual service-role verification via `curl` — see the header of [`nw_poc_analysis_en.py`](nw_poc_analysis_en.py).

## What the script does

- Connects over HTTPS with Basic Auth (self-signed cert tolerated)
- Queries `msg=values` for ~20 meta keys (service, ip.src/dst, alias.host, direction, analysis.session, boc/ioc/eoc, threat.*, tcp.dstport, TLS versions, session sizes, beacon/long-connection/high-outbound candidates)
- From the Decoder additionally pulls top services and clients
- Computes summaries: TLS ratio, unknown ratio, IOC/BOC counts, beacon candidate count
- Renders an HTML report (dark theme, charts, table filtering, interpretation sections)

Non-indexed meta keys and queries with no results are handled — those sections come out empty; the script doesn't crash.

## Requirements

- Python 3.11+
- `requests`
- Network access to Concentrator (port 50105) and Decoder (50104)
- An account with SDK access (defaults to `admin`)
