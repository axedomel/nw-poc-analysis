# nw-poc-analysis

NetWitness NDR 12.x PoC traffic analysis tool — odpytuje Concentrator i Decoder przez SDK (`/sdk?msg=values`), liczy podstawowe metryki jakościowe i ilościowe ruchu, generuje jednoplikowy raport HTML z wykresami (Chart.js) i sortowalnymi tabelami.

## Użycie

```bash
pip install requests --break-system-packages

python3 nw_poc_analysis.py \
  --concentrator <IP> --concentrator-port 50105 \
  --decoder      <IP> --decoder-port      50104 \
  --user admin --password '<PASS>' \
  --hours 168 \
  --output report.html
```

Domyślne porty w argparserze (`50104`/`50102`) są historyczne — w realnych instalacjach **Concentrator = 50105**, **Packet/Log Decoder = 50104**. Szczegółowa mapa portów, kwirki SDK NW 12 i weryfikacja roli serwisu przez `curl` — w nagłówku [`nw_poc_analysis.py`](nw_poc_analysis.py).

## Co robi skrypt

- Łączy się przez HTTPS + Basic Auth (self-signed cert tolerowany)
- Odpytuje `msg=values` dla ~20 meta keys (service, ip.src/dst, alias.host, direction, analysis.session, boc/ioc/eoc, threat.*, tcp.dstport, TLS versions, rozmiary sesji, beacon/long-connection/high-outbound candidates)
- Dla Decodera dodatkowo pobiera top services i clients
- Liczy sumaryczne: TLS ratio, unknown ratio, IOC/BOC counts, liczba beacon candidates
- Renderuje raport HTML (dark theme, wykresy, filtrowanie tabel, sekcje interpretacyjne)

Non-indexed meta keys i queries bez wyników są obsłużone — sekcje będą puste, skrypt nie wywali się.

## Wymagania

- Python 3.11+
- `requests`
- Sieciowy dostęp do Concentratora (port 50105) i Decodera (50104)
- Konto z dostępem do SDK (domyślnie `admin`)
