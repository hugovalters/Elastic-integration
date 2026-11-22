#!/usr/bin/env python3
# Copyright 2026 Valters Capital, SIA
# Licensed under the Apache License, Version 2.0.
# ValtersIT is a trademark of Valters Capital, SIA — see NOTICE.
# Maintained by Hugo Valters

"""
ValtersIT -> Elasticsearch

Ships ValtersIT scan results into Elasticsearch (or OpenSearch) through the
_bulk API, as ECS-style documents - one per matched CVE, plus one summary
document per scan - so they can be searched, alerted on and graphed in
Kibana next to the rest of your security data.

Where the results come from, one of:
  --run CMD ...      run any ValtersIT scanner (with --yes) and take the scan
                     response from its output
  --input FILE       a saved scanner output, or a raw scan-response JSON
                     ("-" for stdin)
  --inventory FILE   a component list (as printed by any scanner's --json)
                     submitted to the ValtersIT API by this script itself

Documents are written to an index named after --index (strftime patterns
allowed, default valtersit-cve-%Y.%m). Each CVE document has a stable _id
derived from host + scanner + CVE + package + version + day, so re-running
the same scan on the same day updates documents instead of duplicating
them.

The Elasticsearch connection is configured with --es-url and either an API
key (--es-api-key / ES_API_KEY) or basic auth (--es-user + ES_PASSWORD).
Nothing is sent anywhere except to that Elasticsearch URL - and, in
--inventory mode only, the scan submission to the ValtersIT API.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import valtersit_client as vit  # noqa: E402

TOOL_NAME = "elastic-integration"
TEMPLATE_FILE = Path(__file__).resolve().parent / "index-template.json"


# ---------------------------------------------------------------------------
# Getting a scan response
# ---------------------------------------------------------------------------

def extract_response(text: str):
    """Returns (response_dict, scanner_label). Accepts either a raw JSON
    response, or the full stdout of a ValtersIT scanner - in which case the
    JSON object printed right after the "[+] Scan submitted" line is used."""
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            return json.loads(stripped), None
        except ValueError:
            pass
    label = None
    m = re.search(r"^ValtersIT (.+?) - ", text, re.MULTILINE)
    if m:
        label = m.group(1).strip()
    marker = text.find("[+] Scan submitted")
    if marker == -1:
        return None, label
    brace = text.find("{", marker)
    if brace == -1:
        return None, label
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[brace:])
        return obj, label
    except ValueError:
        return None, label


def run_scanner(cmd: list[str]) -> str:
    if not cmd:
        print("[!] --run needs a command, e.g. --run python3 /opt/linux-cve-scanner/valtersit-linux-scan.py --yes",
              file=sys.stderr)
        sys.exit(2)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print("[!] Could not run {}: {}".format(cmd[0], exc), file=sys.stderr)
        sys.exit(2)
    sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        print(proc.stdout[-2000:], file=sys.stderr)
        print("[!] Scanner exited with code {} - nothing indexed.".format(proc.returncode), file=sys.stderr)
        sys.exit(1)
    return proc.stdout


def submit_inventory(path: str, non_interactive: bool):
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    start = text.find("[")
    try:
        inventory, _ = json.JSONDecoder().raw_decode(text[start:]) if start != -1 else (None, 0)
    except ValueError:
        inventory = None
    if not isinstance(inventory, list) or not all(isinstance(c, dict) for c in inventory):
        print("[!] {} does not contain a component list (a JSON array as printed by a scanner's --json).".format(path),
              file=sys.stderr)
        sys.exit(2)
    if not vit.require_consent(TOOL_NAME, non_interactive=non_interactive):
        sys.exit(1)
    result = vit.submit_scan(inventory)
    if result.get("reason") == "no_api_key":
        vit.print_no_api_key_notice()
        sys.exit(1)
    if not result["available"]:
        print("[!] " + vit.explain_status(result["status"], result["body"]), file=sys.stderr)
        sys.exit(1)
    return result["body"]


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------

def severity_for(cvss) -> str | None:
    if not isinstance(cvss, (int, float)):
        return None
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "none"


def build_documents(response: dict, host: str | None, scanner: str, now: float):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    results = response.get("results") if isinstance(response, dict) else None
    results = [r for r in (results or []) if isinstance(r, dict)]
    base = {"@timestamp": ts, "observer": {"vendor": "ValtersIT", "product": "ValtersIT CVE API",
                                           "type": "vulnerability-scanner"},
            "valtersit": {"scanner": scanner}}
    if host:
        base["host"] = {"name": host}

    docs = []
    for r in results:
        cve = r.get("cve_id") or r.get("cve") or r.get("id")
        cvss = r.get("cvss")
        doc = json.loads(json.dumps(base))
        doc["event"] = {"kind": "state", "category": ["vulnerability"], "type": ["info"], "dataset": "valtersit.cve"}
        doc["vulnerability"] = {"id": cve, "enumeration": "CVE", "classification": "CVSS",
                                "reference": "https://www.valtersit.com/cve/{}/".format(cve) if cve else None,
                                "scanner": {"vendor": "ValtersIT"}}
        if isinstance(cvss, (int, float)):
            doc["vulnerability"]["score"] = {"base": float(cvss)}
            doc["vulnerability"]["severity"] = severity_for(cvss)
        doc["package"] = {"name": r.get("slug") or r.get("product"), "version": r.get("version")}
        if r.get("patched_in"):
            doc["package"]["fixed_version"] = r["patched_in"]
        known = {"cve_id", "cve", "id", "cvss", "slug", "product", "version", "patched_in"}
        extra = {k: v for k, v in r.items() if k not in known}
        if extra:
            doc["valtersit"]["result"] = extra
        doc_id = hashlib.sha1("|".join(str(x) for x in (host, scanner, cve, doc["package"]["name"],
                                                        doc["package"]["version"], day)).encode()).hexdigest()
        docs.append((doc_id, doc))

    summary = json.loads(json.dumps(base))
    summary["event"] = {"kind": "event", "category": ["vulnerability"], "type": ["info"],
                        "dataset": "valtersit.scan"}
    matched = response.get("matched_cves") if isinstance(response, dict) else None
    summary["valtersit"]["scan"] = {
        "matched_cves": matched if isinstance(matched, int) else len(results),
        "critical": sum(1 for _, d in docs if d["vulnerability"].get("severity") == "critical"),
        "high": sum(1 for _, d in docs if d["vulnerability"].get("severity") == "high"),
    }
    docs.append((None, summary))
    return docs


# ---------------------------------------------------------------------------
# Elasticsearch
# ---------------------------------------------------------------------------

class Elastic:
    def __init__(self, url: str, api_key: str | None, user: str | None, password: str | None,
                 ca_cert: str | None, insecure: bool):
        if not re.match(r"^https?://", url):
            raise SystemExit("[!] --es-url must start with http:// or https://")
        self.url = url.rstrip("/")
        self.headers = {"User-Agent": "valtersit-elastic/{}".format(vit.CLIENT_VERSION)}
        if api_key:
            self.headers["Authorization"] = "ApiKey " + api_key
        elif user:
            token = base64.b64encode("{}:{}".format(user, password or "").encode()).decode()
            self.headers["Authorization"] = "Basic " + token
        self.ctx = None
        if self.url.startswith("https://"):
            self.ctx = ssl.create_default_context(cafile=ca_cert) if ca_cert else ssl.create_default_context()
            if insecure:
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE

    def request(self, method: str, path: str, body: bytes | None, content_type: str = "application/json"):
        headers = dict(self.headers)
        if body is not None:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(self.url + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=60, context=self.ctx) as resp:
                return resp.getcode(), json.loads(resp.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", errors="replace")
            try:
                return exc.code, json.loads(text)
            except ValueError:
                return exc.code, {"error": text[:500]}
        except (urllib.error.URLError, OSError) as exc:
            return None, {"error": str(getattr(exc, "reason", exc))}

    def install_template(self):
        body = TEMPLATE_FILE.read_bytes()
        return self.request("PUT", "/_index_template/valtersit-cve", body)

    def bulk(self, index: str, docs):
        lines = []
        for doc_id, doc in docs:
            action = {"index": {"_index": index}}
            if doc_id:
                action["index"]["_id"] = doc_id
            lines.append(json.dumps(action))
            lines.append(json.dumps(doc, separators=(",", ":")))
        payload = ("\n".join(lines) + "\n").encode("utf-8")
        return self.request("POST", "/_bulk", payload, content_type="application/x-ndjson")


def main():
    parser = argparse.ArgumentParser(description="Ship ValtersIT scan results to Elasticsearch via _bulk.")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--run", nargs=argparse.REMAINDER, help="Run a scanner command (put this option last).")
    src.add_argument("--input", help="Saved scanner output or scan-response JSON ('-' for stdin).")
    src.add_argument("--inventory", help="Component list JSON to submit to ValtersIT first ('-' for stdin).")
    parser.add_argument("--es-url", default=os.environ.get("ES_URL", "http://localhost:9200"),
                        help="Elasticsearch URL (default: $ES_URL or http://localhost:9200).")
    parser.add_argument("--es-api-key", default=os.environ.get("ES_API_KEY"),
                        help="Elasticsearch API key, base64 'id:key' form (default: $ES_API_KEY).")
    parser.add_argument("--es-user", default=os.environ.get("ES_USER"), help="Basic-auth user (password from $ES_PASSWORD).")
    parser.add_argument("--ca-cert", help="CA certificate for a private Elasticsearch CA.")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification (testing only).")
    parser.add_argument("--index", default="valtersit-cve-%Y.%m", help="Target index; strftime patterns allowed.")
    parser.add_argument("--install-template", action="store_true",
                        help="PUT index-template.json as _index_template/valtersit-cve before indexing.")
    parser.add_argument("--scanner-name", help="Value for valtersit.scanner (default: detected from scanner output).")
    parser.add_argument("--host-name", default=socket.gethostname(),
                        help="host.name stored in YOUR Elasticsearch (default: this machine's hostname; "
                             "'' to omit). Never sent to ValtersIT.")
    parser.add_argument("--yes", action="store_true", help="Non-interactive (only relevant with --inventory).")
    parser.add_argument("--dry-run", action="store_true", help="Print the _bulk payload instead of sending it.")
    args = parser.parse_args()

    if args.run is not None:
        response, label = extract_response(run_scanner(args.run))
    elif args.input:
        text = sys.stdin.read() if args.input == "-" else Path(args.input).read_text(encoding="utf-8")
        response, label = extract_response(text)
    else:
        response, label = submit_inventory(args.inventory, args.yes), "inventory"
    if not isinstance(response, dict):
        print("[!] No ValtersIT scan response found (the scan may not have been submitted - check the API key "
              "and the scanner output).", file=sys.stderr)
        sys.exit(1)

    scanner = args.scanner_name or label or "unknown"
    now = time.time()
    docs = build_documents(response, args.host_name or None, scanner, now)
    index = time.strftime(args.index, time.gmtime(now))
    print("[i] {} CVE document(s) + 1 scan summary for index '{}'.".format(len(docs) - 1, index), file=sys.stderr)

    if args.dry_run:
        for doc_id, doc in docs:
            print(json.dumps({"index": {"_index": index, **({"_id": doc_id} if doc_id else {})}}))
            print(json.dumps(doc))
        return

    es = Elastic(args.es_url, args.es_api_key, args.es_user, os.environ.get("ES_PASSWORD"),
                 args.ca_cert, args.insecure)
    if args.install_template:
        status, body = es.install_template()
        if status not in (200, 201):
            print("[!] Installing the index template failed: HTTP {} {}".format(status, body), file=sys.stderr)
            sys.exit(1)
        print("[+] Index template 'valtersit-cve' installed.", file=sys.stderr)

    status, body = es.bulk(index, docs)
    if status not in (200, 201):
        print("[!] _bulk request failed: HTTP {} {}".format(status, body), file=sys.stderr)
        sys.exit(1)
    if body.get("errors"):
        failed = [i for i in body.get("items", []) if list(i.values())[0].get("error")]
        first = list(failed[0].values())[0]["error"] if failed else body
        print("[!] {} document(s) rejected by Elasticsearch, e.g.: {}".format(len(failed), first), file=sys.stderr)
        sys.exit(1)
    print("[+] Indexed {} document(s) into '{}'.".format(len(docs), index))


if __name__ == "__main__":
    main()
