#!/usr/bin/env python3
"""Stateful local GCP fixture. Never invokes gcloud or contacts Google APIs."""
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
path = Path(os.environ["AEGIS_TEST_CLOUD_STATE"])
state = json.loads(path.read_text()) if path.exists() else {"calls": [], "secret_versions": 0}
state["calls"].append(args)
project = args[args.index("--project") + 1]
command = tuple(args[:3])
result = None
if args[:2] == ["billing", "projects"]:
    result = {"billingEnabled": True}
elif args[:2] == ["services", "enable"]:
    pass
elif command == ("projects", "describe", project):
    result = {"projectNumber": "1234567890"}
elif args[:2] == ["auth", "print-access-token"]:
    result = "owner"  # Firestore emulator's documented administrator credential.
elif command == ("firestore", "databases", "list"):
    result = [state["database"]] if "database" in state else []
elif command == ("firestore", "databases", "create"):
    assert "database" not in state
    state["database"] = {"name": f"projects/{project}/databases/aegis", "type": "FIRESTORE_NATIVE", "locationId": "us-central1"}
elif command == ("firestore", "fields", "ttls"):
    result = [] if args[3] == "list" else None
elif command == ("iam", "service-accounts", "list"):
    result = [{"email": f"aegis-api@{project}.iam.gserviceaccount.com"}] if state.get("account") else []
elif command == ("iam", "service-accounts", "create"):
    assert not state.get("account")
    state["account"] = True
elif args[:2] == ["projects", "add-iam-policy-binding"]:
    pass
elif args[:2] == ["secrets", "list"]:
    result = [{"name": f"projects/{project}/secrets/aegis-oidc-client-secret", "labels": {"managed-by": "aegis"}}] if state.get("secret") else []
elif args[:2] == ["secrets", "create"]:
    assert not state.get("secret")
    state["secret"] = True
elif command == ("secrets", "versions", "add"):
    assert sys.stdin.read() == "test-secret-never-log"
    state["secret_versions"] += 1
    result = {"name": f"projects/{project}/secrets/aegis-oidc-client-secret/versions/{state['secret_versions']}"}
elif command == ("secrets", "versions", "list"):
    result = [{"name": f"projects/{project}/secrets/aegis-oidc-client-secret/versions/{version}"} for version in range(1, state["secret_versions"] + 1)]
elif command == ("secrets", "versions", "access"):
    path.write_text(json.dumps(state))
    sys.stdout.write("test-secret-never-log")
    sys.exit(0)
elif args[:2] == ["secrets", "add-iam-policy-binding"]:
    pass
elif command == ("run", "services", "list"):
    result = []
elif args[:2] == ["run", "deploy"]:
    path.write_text(json.dumps(state))
    print("simulated image pull failure; no traffic changed", file=sys.stderr)
    sys.exit(1)
else:
    raise RuntimeError(f"unexpected gcloud operation: {args}")
path.write_text(json.dumps(state))
print(json.dumps(result))
