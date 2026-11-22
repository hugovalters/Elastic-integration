# Elastic Integration

Ship ValtersIT CVE scan results into Elasticsearch — one ECS-style
document per matched CVE plus a summary per scan — to search, alert on and
graph them in Kibana alongside the rest of your security data. Open source,
auditable, privacy-first — powered by the ValtersIT CVE API.

> Part of the ValtersIT platform — CVE & Threat-IP data you can query or run yourself.
> Explore both API and scanners: https://www.valtersit.com/platform/
> Scanner plans & pricing: https://www.valtersit.com/cve/pricing/#scanners

## What it does

`valtersit-elastic.py` takes the result of a ValtersIT scan and writes it to
Elasticsearch with the `_bulk` API:

- **One document per matched CVE** — `vulnerability.id`,
  `vulnerability.score.base` (CVSS), `vulnerability.severity`
  (critical/high/medium/low derived from CVSS), `package.name`,
  `package.version`, `package.fixed_version`, `host.name`,
  `valtersit.scanner`, and any extra fields the API returned (e.g. EPSS)
  under `valtersit.result.*`.
- **One summary document per scan** — `valtersit.scan.matched_cves`,
  `.critical`, `.high`, for trend lines.

CVE documents get a stable `_id` (host + scanner + CVE + package + version +
day), so re-running a scan on the same day updates them instead of
duplicating. Indices are monthly by default (`valtersit-cve-2026.11`).

Where the results come from — pick one:

| Mode | Use when |
|---|---|
| `--run CMD …` | Run any ValtersIT scanner now and index its result |
| `--input FILE` | Index a saved scanner output (or a raw scan-response JSON); `-` = stdin |
| `--inventory FILE` | Submit a component list (a scanner's `--json` output) to ValtersIT from here, then index |

`index-template.json` is a composable index template for
`valtersit-cve-*` with the right field types (keyword IDs, float scores),
installed with `--install-template`.

Works with Elasticsearch 7.10+ / 8.x and Elastic Cloud. OpenSearch accepts
the same `_bulk` payload; install the template there by hand.

## Your data stays yours

- **What ValtersIT receives:** nothing from this script in `--run` and
  `--input` modes — it only reads a scan that already happened. In
  `--inventory` mode, the component names and versions in the file you
  pass, plus the usual opaque system identifier (a one-way hash of local
  machine signals that cannot be reversed to any of them), exactly as any
  scanner sends.
- **What goes to your Elasticsearch:** the scan results above, plus
  `host.name` (this machine's hostname, so you can tell hosts apart —
  `--host-name ''` to omit it). This is your own cluster; hostname is never
  sent to ValtersIT.
- **What it does not do:** no other network calls, no changes outside the
  `valtersit-cve-*` indices and the `valtersit-cve` index template.
- **Audit it yourself.** This is open source — `valtersit-elastic.py`,
  `valtersit_client.py` and `index-template.json`, ~900 lines total.

## Install

```bash
git clone https://gitlab.com/valtersit/elastic-integration
cd elastic-integration
```

Or, no git:

```bash
mkdir -p elastic-integration && cd elastic-integration
for f in valtersit-elastic.py valtersit_client.py index-template.json; do
  curl -fsSLO "https://gitlab.com/valtersit/elastic-integration/-/raw/main/$f"
done
```

Requires only a stock Python 3 interpreter (3.7+). No `pip install`, no
Elasticsearch client library.

### Elasticsearch credentials

Create an API key that can only write these indices (Kibana › Stack
Management › API keys, or Dev Tools):

```json
POST /_security/api_key
{
  "name": "valtersit-writer",
  "role_descriptors": {
    "valtersit_writer": {
      "cluster": ["manage_index_templates"],
      "indices": [{ "names": ["valtersit-cve-*"], "privileges": ["create_index", "index", "write"] }]
    }
  }
}
```

Use the returned `encoded` value:

```bash
export ES_URL="https://es.example.internal:9200"
export ES_API_KEY="<encoded value>"
# or basic auth:  export ES_USER=valtersit ES_PASSWORD=...
```

Drop `manage_index_templates` after the first `--install-template`.

## Usage

```bash
# Once: install the index template
python3 valtersit-elastic.py --install-template --input saved-scan.txt

# Run the Linux scanner and index the result
python3 valtersit-elastic.py --run python3 /opt/linux-cve-scanner/valtersit-linux-scan.py --yes

# Pipe any scanner's output in
python3 /opt/wordpress-cve-scanner/valtersit-wp-scan.py --path /var/www/html --yes \
  | python3 valtersit-elastic.py --input -

# See exactly what would be sent, without sending it
python3 valtersit-elastic.py --input saved-scan.txt --dry-run
```

`--run` must be the last option — everything after it is the scanner
command. The scanner itself needs `VALTERSIT_API_KEY` and its one-time
authorised-use confirmation, as described in its own README.

| Option | Default | Meaning |
|---|---|---|
| `--es-url` | `$ES_URL` or `http://localhost:9200` | Elasticsearch endpoint |
| `--es-api-key` | `$ES_API_KEY` | API key (`encoded` form) |
| `--es-user` | `$ES_USER` | Basic-auth user; password from `$ES_PASSWORD` |
| `--ca-cert` | system CAs | CA bundle for a private CA |
| `--insecure` | off | Skip TLS verification (testing only) |
| `--index` | `valtersit-cve-%Y.%m` | Target index, `strftime` patterns allowed |
| `--install-template` | off | PUT `index-template.json` first |
| `--host-name` | this hostname | `host.name` in your documents (`''` to omit) |
| `--scanner-name` | detected | `valtersit.scanner` value |
| `--dry-run` | off | Print the NDJSON payload instead of sending |

## Sample output

```
$ python3 valtersit-elastic.py --run python3 /opt/linux-cve-scanner/valtersit-linux-scan.py --yes
[i] 2 CVE document(s) + 1 scan summary for index 'valtersit-cve-2026.11'.
[+] Indexed 3 document(s) into 'valtersit-cve-2026.11'.
```

A CVE document:

```json
{
  "@timestamp": "2026-11-18T03:30:12Z",
  "host": {"name": "web-01"},
  "event": {"kind": "state", "category": ["vulnerability"], "type": ["info"], "dataset": "valtersit.cve"},
  "vulnerability": {
    "id": "CVE-2026-11023", "enumeration": "CVE", "classification": "CVSS",
    "score": {"base": 9.1}, "severity": "critical",
    "reference": "https://www.valtersit.com/cve/CVE-2026-11023/",
    "scanner": {"vendor": "ValtersIT"}
  },
  "package": {"name": "openssl", "version": "3.0.13-0ubuntu3.4", "fixed_version": "3.0.13-0ubuntu3.6"},
  "valtersit": {"scanner": "Linux Package Scanner", "result": {"epss": 0.12}},
  "observer": {"vendor": "ValtersIT", "product": "ValtersIT CVE API", "type": "vulnerability-scanner"}
}
```

Useful Kibana queries:

```
event.dataset : "valtersit.cve" and vulnerability.severity : "critical"
event.dataset : "valtersit.cve" and vulnerability.score.base >= 7 and host.name : web-*
```

## Schedule it

```
30 3 * * * cd /opt/elastic-integration && VALTERSIT_API_KEY=vit_v1_xxx ES_URL=https://es:9200 ES_API_KEY=xxx /usr/bin/python3 valtersit-elastic.py --run /usr/bin/python3 /opt/linux-cve-scanner/valtersit-linux-scan.py --yes >> /var/log/valtersit-elastic.log 2>&1
```

Keep the keys out of the crontab on shared hosts — put them in a `0600`
env file and `set -a; . /etc/valtersit/env; set +a` first.

## Authorised use only

Run the scanners only against systems you own, or for which you have
explicit written authorisation to assess. In `--inventory` mode this script
shows the same notice before its first submission and requires you to type
`YES`:

```
------------------------------------------------------------------------------
 ValtersIT Scanner — Authorised Use Confirmation
------------------------------------------------------------------------------
 Run this tool ONLY against systems you own, or for which you have explicit
 written authorisation to assess.

 This scan sends only component name + version, plus an opaque system
 identifier (a one-way hash of local machine signals such as machine-id
 and disk UUID, so repeat scans are recognised as the same system), to
 the ValtersIT API — no IP address, hostname, MAC address, or file
 contents. See the Privacy Policy: https://www.valtersit.com/privacy

 Type YES to confirm you are authorised to scan this system and continue.
 Anything else aborts without scanning.
------------------------------------------------------------------------------
```

Licensed under Apache-2.0 (see `LICENSE` and `NOTICE`); provided without
warranty of any kind. "ValtersIT" and the ValtersIT logo are trademarks of
Valters Capital, SIA and are not licensed for use. Elasticsearch and Kibana
are trademarks of Elasticsearch B.V.; this project is not affiliated with
or endorsed by it.

## Questions or a bug?

Please **don't** open GitHub/GitLab issues — I don't monitor them.
Reach me through the contact form instead: https://www.valtersit.com/contacts/

Maintained by Hugo Valters
