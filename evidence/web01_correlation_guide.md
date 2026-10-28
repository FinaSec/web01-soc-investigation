# web01 HTTP logs + PCAP correlation guide

## Files and timeline

- `web01_access_2026-03-12.log` — **88 entries**, Common Log Format style matching the three user-provided entries. Extracted 85 readable inbound HTTP request/response pairs from the original synthetic PCAP, shifted to March 12, and added three exact user-defined web events.
- `web01_error_2026-03-12.log` — **3 entries**, nginx-style simulated file-not-found diagnostic lines corresponding to the PCAP's three 404 `/favicon.ico` responses. The exact OS error text is a plausible simulation, not something obtainable from network packets.
- `web01_2026-03-12_correlated.pcap` — the **new**, March-dated synthetic capture containing the three supplied HTTP transactions as actual TCP/HTTP packet flows, the original traffic pattern and background noise, and the three five-minute encrypted sessions.
- `web01_access_2026-10-20_original_pcap.log` — **85 entries** from the earlier, unchanged October 20 PCAP without the added March 12 activities. This version aligns exactly with its original date/traffic.

**Date mismatch resolved:** The previous `web01_beacon_with_background_traffic.pcap` was generated for **October 20, 2026**. Your provided HTTP entries occurred **March 12, 2026**, eight months earlier. It would be inaccurate to claim they existed in the original October packet capture. Instead, the new capture reproduces the original traffic pattern for March 12 and adds the actual HTTP transactions, so packet/log correlation works end to end. The original PCAP remains unmodified.

The new March capture uses America/New_York, **EDT (UTC−04:00)**.

## Provided log events (preserved verbatim)

```text
10.40.99.51 - - [12/Mar/2026:08:12:44 -0400] "POST /upload.php HTTP/1.1" 200 412
10.40.99.51 - - [12/Mar/2026:08:12:51 -0400] "GET /uploads/report.php HTTP/1.1" 200 88
10.40.20.15 - - [12/Mar/2026:08:13:02 -0400] "GET /health HTTP/1.1" 200 19
```

The final number on each log line is the HTTP **response body byte length** (Content-Length), **not** the full TCP packet length. Requests are logged at the time the response is returned, to the nearest whole second.

## Independent packet observations

| Local time (Mar 12, 2026) | Source | Destination | Outbound TCP payload | Inbound TCP payload |
|---|---|---|---:|---:|
| 08:13:10 | 10.40.20.15:50614 | 198.51.100.44:443 | 612 B | 924 B |
| 08:18:10 | 10.40.20.15:50615 | 198.51.100.44:443 | 612 B | 924 B |
| 08:23:10 | 10.40.20.15:50616 | 198.51.100.44:443 | 612 B | 924 B |

These are **outbound HTTPS client sessions** initiated by web01, not requests **to** the web server. Accordingly, they do not belong in the web server's inbound access log. The TLS records are synthetic and cannot be decrypted. The combination of a POST to `/upload.php`, subsequent GET of `/uploads/report.php`, and recurrent encrypted egress merits investigation, but does **not** alone establish a web shell or a confirmed malicious command-and-control channel.

## Suggested student questions

1. Which request sequence involving `10.40.99.51` stands out? What does the access log actually prove?
2. Locate the same POST, GET and self-health GET in the **March** PCAP (`http.request` or `tcp.port == 80`). Do request lines, statuses and response body sizes agree?
3. Determine how long after the `/uploads/report.php` GET the first connection to `198.51.100.44:443` occurs.
4. Show that the external sessions begin at five-minute intervals and have matching payload totals.
5. Contrast those sessions with known routine activity, including HTTP service monitoring (`10.40.20.50`), DNS to `10.40.20.53`, NTP to `10.40.20.8`, and other outbound update traffic.
6. What additional host evidence could confirm or refute a compromise (process tree, uploaded file contents, PHP interpreter logs, EDR, service configuration)?

## Example analysis commands

```sh
# Access entries from the suspicious client
grep '^10\.40\.99\.51 ' web01_access_2026-03-12.log

# All 404s in the observed HTTP logs
awk '$9 == 404 { print }' web01_access_2026-03-12.log

# Wireshark display filters:
# http && ip.addr == 10.40.99.51
# ip.src == 10.40.20.15 && ip.dst == 198.51.100.44 && tcp.dstport == 443 && tcp.flags.syn == 1 && tcp.flags.ack == 0
# ntp || dns || udp.port == 514
```

All material is entirely synthetic for classroom use. The public addresses are documentation ranges, not active destinations.
