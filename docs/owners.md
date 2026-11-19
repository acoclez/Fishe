# Owner and country

Fishe can show who owns each Internet address an endpoint uses (the network
operator and its ASN) and the country the address is registered in. It
appears in:

- the **Owner** column of the endpoints table (live and in recordings), with
  a two-letter country badge and the organisation; hover for
  `AS13335 Cloudflare, Inc. · Australia · source`;
- the header in **host mode**, next to the target;
- recordings and the endpoints CSV export (`asn`, `org`, `country`).

The endpoint filter also matches owner names, `as13335`, country codes and
country names.

Only **Internet (public)** addresses are looked up. LAN, loopback,
link-local, CGNAT and multicast addresses never are.

## Sources

| | Offline: DB-IP Lite | Online: ipinfo.io |
|---|---|---|
| What | ASN + organisation, country | the same |
| Default | **not installed** | **off** |
| Network use | one download (~9 MB, ~18 MB installed) from `download.db-ip.com`, **only when you click** Download / Update | each looked-up address is **sent to ipinfo.io** over HTTPS |
| When used | always, once installed | only for public addresses the offline data doesn't cover (or when it isn't installed) |
| Freshness | monthly releases; Settings shows when a newer month is available | live |
| Rate | local, microseconds per lookup | ≤ 1 request/s, each address once per app run; pauses 60 s on HTTP 429 |
| Licence / terms | CC BY 4.0, attribution shown in Settings and under tables using it | ipinfo.io free tier terms |

Both are managed in **Settings → Owner & country**.

### Installing DB-IP Lite

**Download (~10 MB)** fetches two files for the current month (falling back
to the previous month early in a month):

```
https://download.db-ip.com/free/dbip-asn-lite-YYYY-MM.mmdb.gz
https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz
```

Each is decompressed into a `.part` file; both are validated as MMDB
databases before replacing the installed pair, so a failed download never
breaks what's installed. Files live in:

```
%APPDATA%\com.fishe.app\geo\
├─ dbip-asn-lite.mmdb
├─ dbip-country-lite.mmdb
└─ meta.json            { "month": "2026-11", "downloadedAt": … }
```

**Update** appears when a newer month exists. **Remove** (with confirmation)
deletes the files.

### Online lookup

Turn on **Look up unknown addresses online** to resolve public addresses the
offline data doesn't cover, or all of them if the database isn't installed.
Results arrive a tick or two later (the gauge never waits) and are marked
with ↗ in the table. The choice is remembered and re-applied when Fishe
starts.

## Accuracy notes

- "Country" is where the address block is **registered or geolocated** by
  the provider, not necessarily where the server is. Anycast networks
  (Cloudflare, Google) report one country for addresses served worldwide.
- The free ASN data doesn't cover every block; some rows show a country
  without an organisation (e.g. a Cloudflare IPv6 range in testing).
- Organisation names are the ASN holder's registered name ("Google LLC",
  "OVH SAS"), which is usually the hosting network, not the website.

## Code map

| File | Role |
|---|---|
| `geo/mod.rs` | `Geo` service (shared, Tauri-managed `Arc<Geo>`), `Owner`, offline-then-online lookup |
| `geo/db.rs` | MMDB readers, record decoding |
| `geo/download.rs` | Month logic, streaming download, gzip, atomic install |
| `geo/online.rs` | ipinfo.io worker, cache, rate limit, parser |
| `monitor/endpoints.rs` | `EndpointRow.owner` |
| `archive/db.rs`, `recorder.rs`, `export.rs` | Schema v2 columns, saving, CSV |
| `src/lib/pages/settings/GeoSettings.svelte`, `src/lib/components/OwnerCell.svelte`, `src/lib/utils/geo.ts` | UI |
