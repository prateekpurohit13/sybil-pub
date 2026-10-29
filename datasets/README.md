# JA4+ reference data

## Committed dataset

`ja4plus-mapping.csv` is the FoxIO JA4+ mapping table:

- Source: https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv
- Snapshot: 2026-10-29
- Rows: 66 (35 with a JA4 value, 32 unique fingerprints)

Columns: `Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes`.

Rows may share a JA4. For example, the Go TLS fingerprint is listed both as
generic `GoLang` and as `Sliver Agent`, because JA4 does not distinguish them.
`internal/dataset` keeps every candidate and prefers the row with the most
specific identity for single-record lookups.

This file contains fingerprints, not packet payloads, so it cannot validate
ClientHello extraction by itself. Use a pcap for wire-level verification.

## Other free sources

### Fingerprint mappings

- **JA4DB frozen export**: https://github.com/Niicolaa/ja4db-export
  - `csv/all_records.csv` is about 32 MB and was last updated on 2026-05-15.
  - JA4DB's public API is no longer accessible, so this is a snapshot, not a
    maintained feed. Check its terms before redistributing.
  - The export uses `ja4_fingerprint` instead of `ja4`; both headers are
    supported.
  - It contains about 74k rows, 1.5k unique JA4 values, and many observations
    per fingerprint. Use `-lenient` because a few rows have malformed values.
- **FoxIO JA4+ mapping**: https://github.com/FoxIO-LLC/ja4
- **JA4DB**: https://ja4db.com (registration/access terms apply)

Download the frozen JA4DB export and compare:

```bash
curl -fsSL https://raw.githubusercontent.com/Niicolaa/ja4db-export/main/csv/all_records.csv \
  -o datasets/ja4db-all_records.csv
./bin/ja4check -dataset datasets/ja4db-all_records.csv -lenient -ja4 <fingerprint>
```

### Pcap samples

- **FoxIO test pcaps**: https://github.com/FoxIO-LLC/ja4/tree/main/pcap
  - Includes TLS, ALPN, non-ASCII ALPN, GREASE, SNI, QUIC, and IPv6 samples.
  - Fetch a working subset with `scripts/fetch-ja4-samples.sh`.
- **UNSW-NB15**: https://research.unsw.edu.au/projects/unsw-nb15-dataset
  - Academic/non-commercial use only.
- **CIC-IDS2017 / CIC-IDS2018**: https://www.unb.ca/cic/datasets/ids-2017.html
  - Registration and dataset terms apply.
- **Malware Traffic Analysis**: https://www.malware-traffic-analysis.net/
  - Free malware traffic pcaps; follow the site's terms.
- **Wireshark sample captures**: https://wiki.wireshark.org/SampleCaptures
- **Suricata public data sets**: https://docs.suricata.io/en/suricata-8.0.6/public-data-sets.html
- **CTU-13 botnet captures**: https://www.stratosphereips.org/datasets-ctu13
- **Netresec public pcaps**: https://www.netresec.com/?page=PcapFiles
  and https://www.netresec.com/?page=MACCDC

Downloaded pcaps, the JA4DB export, and local databases are ignored by git.

## CSV compatibility

The loader accepts the FoxIO header (`ja4`) and JA4DB headers
(`ja4_fingerprint`, `ja4s_fingerprint`, and so on). It also reads
`user_agent_string`, `certificate_authority`, `verified`, `notes`, and
`observation_count` when present.

Use `-lenient` for community exports:

```bash
./bin/ja4check -dataset datasets/ja4db-all_records.csv -lenient -ja4 t13d1516h2_8daaf6152771_02713d6af862
```

## Database workflow

Sybil uses the libSQL driver, which supports local SQLite files and remote
Turso databases. The table is `fingerprints`, matching the existing live
enrichment query.

Import the committed CSV into a local database:

```bash
./bin/ja4import -dataset datasets/ja4plus-mapping.csv -db file:datasets/ja4.db -replace
```

Compare against the database:

```bash
./bin/ja4check -db file:datasets/ja4.db -ja4 t13d1516h2_8daaf6152771_02713d6af862
./bin/ja4check -db file:datasets/ja4.db -pcap capture.pcap -strict
```

Remote libSQL/Turso:

```bash
./bin/ja4check -db libsql://your-db.turso.io -db-auth-token "$AUTH_TOKEN" -ja4 <fingerprint>
```

`-db` takes precedence over `-dataset`.
