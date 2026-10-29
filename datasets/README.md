# JA4+ mapping dataset

`ja4plus-mapping.csv` is the FoxIO JA4+ mapping table:

- Source: https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv
- Snapshot: 2026-10-29
- Rows: 66 (35 with a JA4 value, 32 unique fingerprints)

Columns: `Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes`.

Rows may share a JA4. For example, the Go TLS fingerprint is listed both as
generic `GoLang` and as `Sliver Agent`, because JA4 does not distinguish them.
`internal/dataset` keeps every candidate and prefers the row with the most
specific identity for single-record lookups.

This file is reference data only. It contains fingerprints, not packet
payloads, so it cannot validate ClientHello extraction by itself. Use
`cmd/ja4check` with a pcap file for wire-level verification.

```bash
# compare explicit fingerprints
go run ./cmd/ja4check -ja4 t13d1516h2_8daaf6152771_02713d6af862

# compare every ClientHello in an offline capture
go run ./cmd/ja4check -pcap sample.pcap -strict
```
