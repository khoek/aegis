#!/usr/bin/env python3
"""One-time, operator-run platform/schema migration. Dry run unless --apply."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def platform(value):
    if set(value) != {"operating_system", "architecture"}:
        raise ValueError("platform requires exactly operating_system and architecture")
    if value["operating_system"] not in {"ubuntu", "arch_linux", "mac_os"}:
        raise ValueError("unsupported operating_system")
    if value["architecture"] not in {"x86_64", "aarch64"}:
        raise ValueError("unsupported architecture")
    if value["operating_system"] == "arch_linux" and value["architecture"] != "x86_64":
        raise ValueError("Arch Linux requires x86_64")
    return {"mapValue": {"fields": {key: {"stringValue": item} for key, item in value.items()}}}


def host_updates(documents, hosts):
    """Validate the entire manifest before returning any writes."""
    known = {document["name"].rsplit("/", 1)[1]: document for document in documents}
    if set(known) != set(hosts):
        raise ValueError("manifest must identify every host exactly; refresh it before applying")
    updates = []
    for host, identity in hosts.items():
        if str(uuid.UUID(host)) != host:
            raise ValueError("host IDs must be canonical UUIDs")
        desired = platform(identity)
        document = known[host]
        existing = document.get("fields", {}).get("platform")
        if existing is not None and existing != desired:
            raise ValueError(f"{host}: recorded platform differs; repair explicitly")
        if existing is None:
            updates.append({
                "update": {"name": document["name"], "fields": {"platform": desired}},
                "updateMask": {"fieldPaths": ["platform"]},
                "currentDocument": {"updateTime": document["updateTime"]},
            })
    return updates


def principal_grant_updates(documents):
    """Rename the removed OAuth principal field in the reviewed host schema."""
    updates = []
    for document in documents:
        report = document.get("fields", {}).get("report", {}).get("mapValue", {}).get("fields", {})
        grants = report.get("principal_grants")
        if grants is None:
            continue
        values = grants.get("arrayValue", {}).get("values", [])
        changed = False
        rewritten = []
        for value in values:
            fields = value.get("mapValue", {}).get("fields", {})
            keys = set(fields)
            if keys <= {"login_principal", "user_id"}:
                rewritten.append(value)
                continue
            if keys != {"login_principal", "oauth_principal"}:
                raise ValueError(
                    f"{document['name']}: principal grant has unexpected fields {sorted(keys)}"
                )
            legacy = fields["oauth_principal"].get("stringValue", "")
            if str(uuid.UUID(legacy)) != legacy:
                raise ValueError(
                    f"{document['name']}: oauth_principal is not a canonical Aegis user UUID"
                )
            rewritten.append({
                "mapValue": {
                    "fields": {
                        "login_principal": fields["login_principal"],
                        "user_id": {"stringValue": legacy},
                    }
                }
            })
            changed = True
        if changed:
            updated_report = json.loads(json.dumps(report))
            updated_report["principal_grants"] = {"arrayValue": {"values": rewritten}}
            updates.append({
                "update": {
                    "name": document["name"],
                    "fields": {"report": {"mapValue": {"fields": updated_report}}},
                },
                "updateMask": {"fieldPaths": ["report.principal_grants"]},
                "currentDocument": {"updateTime": document["updateTime"]},
            })
    return updates


def routing_config(contents):
    raw = tomllib.loads(contents)
    if "bird" not in raw or "routing" in raw:
        raise ValueError("expected a pre-platform config with [bird] and no [routing]")
    if not isinstance(raw["bird"], dict) or set(raw["bird"]) - {"config_path", "service"}:
        raise ValueError("unexpected [bird] fields; inspect before migration")
    if not isinstance(raw["bird"].get("config_path"), str):
        raise ValueError("[bird] must have an explicit config_path")
    updated, count = re.subn(r"(?m)^\[bird\][ \t]*(?:#[^\n]*)?$", '[routing]\nbackend = "bird"', contents)
    if count != 1:
        raise ValueError("expected one ordinary [bird] table; inspect this config manually")
    expected = dict(raw)
    expected["routing"] = {"backend": "bird", **expected.pop("bird")}
    if tomllib.loads(updated) != expected:
        raise ValueError("migration would change unrelated configuration")
    return updated


def backup(path, contents):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as file:
        file.write(contents)
        file.flush()
        os.fsync(file.fileno())


class Firestore:
    def __init__(self, project, database):
        self.root = f"https://firestore.googleapis.com/v1/projects/{project}/databases/{database}/documents"
        self.token = subprocess.run(["gcloud", "auth", "print-access-token"], check=True,
                                    capture_output=True, text=True, timeout=45).stdout.strip()
        if not self.token:
            raise ValueError("gcloud returned an empty access token")

    def request(self, path, data=None):
        request = urllib.request.Request(self.root + path,
            data=None if data is None else json.dumps(data).encode(),
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"Firestore HTTP {error.code}; no token or response body printed") from None

    def hosts(self, namespace):
        documents, token = [], None
        deadline = time.monotonic() + 120
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("host inventory exceeded two minutes; nothing changed")
            query = {"pageSize": 1000}
            if token:
                query["pageToken"] = token
            page = self.request(f"/v2/aegis/namespaces/{namespace}/hosts?" + urllib.parse.urlencode(query))
            documents.extend(page.get("documents", []))
            token = page.get("nextPageToken")
            if not token:
                return documents


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    config = commands.add_parser("local-config")
    config.add_argument("path", type=Path)
    fleet = commands.add_parser("fleet")
    fleet.add_argument("manifest", type=Path)
    grants = commands.add_parser("principal-grants")
    grants.add_argument("--project", required=True)
    grants.add_argument("--database", default="(default)")
    grants.add_argument("namespace")
    args = parser.parse_args()
    if args.apply and args.backup is None:
        parser.error("--apply requires a new --backup path")
    if args.command == "local-config":
        source = args.path.read_bytes()
        updated = routing_config(source.decode()).encode()
        print(f"{args.path}: replace [bird] with validated [routing]", file=sys.stderr)
        if args.apply:
            if os.geteuid() != 0 or args.path.is_symlink() or args.path.stat().st_uid != 0:
                raise ValueError("local config migration requires root and a root-owned regular file")
            backup(args.backup, source)
            descriptor, temporary = tempfile.mkstemp(dir=args.path.parent, prefix=".routing-")
            try:
                with os.fdopen(descriptor, "wb") as file:
                    file.write(updated)
                    file.flush()
                    os.fsync(file.fileno())
                if args.path.read_bytes() != source:
                    raise ValueError("config changed during migration; original backup retained")
                os.replace(temporary, args.path)
            finally:
                Path(temporary).unlink(missing_ok=True)
            print("Config committed; running agent unchanged; backup retained", file=sys.stderr)
        return
    if args.command == "principal-grants":
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", args.namespace):
            raise ValueError("invalid namespace")
        api = Firestore(args.project, args.database)
        documents = api.hosts(args.namespace)
        updates = principal_grant_updates(documents)
        print(f"{len(updates)} of {len(documents)} host records need principal-grant repair", file=sys.stderr)
        if len(updates) > 450:
            raise ValueError("more than 450 changes; prepare reviewed namespace batches explicitly")
        if args.apply and updates:
            backup(args.backup, json.dumps(documents, indent=2).encode())
            api.request(":commit", {"writes": updates})
            print(f"Committed {len(updates)} principal-grant repairs; private backup retained at {args.backup}", file=sys.stderr)
        elif args.apply:
            print("No changes needed", file=sys.stderr)
        else:
            print("Dry run: nothing changed", file=sys.stderr)
        return

    manifest = json.loads(args.manifest.read_text())
    if set(manifest) != {"project", "database", "namespace", "hosts"}:
        raise ValueError("manifest requires project, database, namespace, and hosts")
    for key in ["project", "namespace"]:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", manifest[key]):
            raise ValueError(f"invalid {key}")
    if manifest["database"] != "(default)" and not re.fullmatch(
            r"[a-z][a-z0-9-]{2,61}[a-z0-9]", manifest["database"]):
        raise ValueError("invalid database")
    api = Firestore(manifest["project"], manifest["database"])
    documents = api.hosts(manifest["namespace"])
    updates = host_updates(documents, manifest["hosts"])
    print(f"{len(updates)} of {len(documents)} host records need platform identity", file=sys.stderr)
    if len(updates) > 450:
        raise ValueError("more than 450 changes; prepare reviewed namespace batches explicitly")
    if args.apply and updates:
        backup(args.backup, json.dumps(documents, indent=2).encode())
        api.request(":commit", {"writes": updates})
        print(f"Committed {len(updates)} platform fields; private backup retained at {args.backup}", file=sys.stderr)
    elif args.apply:
        print("No changes needed", file=sys.stderr)
    else:
        print("Dry run: nothing changed", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print(f"Migration stopped: {error}. Inspect any backup and committed state before retrying.", file=sys.stderr)
        sys.exit(1)
