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
project = args[args.index("--project") + 1] if "--project" in args else None
command = tuple(args[:3])
result = None
if args[0] == "version":
    result = {"Google Cloud SDK": "test"}
elif args[:3] == ["config", "get", "project"]:
    path.write_text(json.dumps(state))
    print(state.get("active_project", "(unset)"))
    sys.exit(0)
elif args[:3] == ["config", "set", "project"]:
    state["active_project"] = args[3]
elif args[:2] == ["projects", "list"]:
    result = state.get("projects", [{"projectId": "aegis-fresh-test"}])
elif args[:2] == ["billing", "projects"]:
    result = {"billingEnabled": state.get("billing_enabled", True) or path.with_suffix(".billing-enabled").exists()}
elif args[:2] == ["services", "enable"]:
    pass
elif command == ("projects", "describe", project):
    result = {"projectNumber": "1234567890"}
elif args[:2] == ["auth", "print-access-token"]:
    if state.get("expired_auth"):
        path.write_text(json.dumps(state))
        print("Reauthentication required", file=sys.stderr)
        sys.exit(1)
    if "--impersonate-service-account" in args and not state.get("runtime_access_observed"):
        state["runtime_access_observed"] = True
        path.write_text(json.dumps(state))
        print("PERMISSION_DENIED: iam.serviceAccounts.getAccessToken is not yet granted", file=sys.stderr)
        sys.exit(1)
    result = {"token": "owner"}  # Firestore emulator's documented administrator credential.
elif args[:2] == ["auth", "list"]:
    result = [] if state.get("signed_out") and not path.with_suffix(".signed-in").exists() else [{"account": "operator@example.com", "status": "ACTIVE"}]
elif command == ("firestore", "databases", "list"):
    if not state.get("firestore_activation_observed"):
        state["firestore_activation_observed"] = True
        path.write_text(json.dumps(state))
        print("Cloud Firestore API activation is propagating\n  reason: SERVICE_DISABLED", file=sys.stderr)
        sys.exit(1)
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
elif command == ("iam", "service-accounts", "add-iam-policy-binding"):
    pass
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
    result = [state["service"]] if "service" in state else []
elif args[:2] == ["run", "deploy"]:
    assert ("--no-traffic" in args) == ("service" in state)
    private = "AEGIS_TEST_PROXY_INVOKER" in os.environ
    assert ("--invoker-iam-check" in args) == private
    assert ("--no-invoker-iam-check" in args) != private
    state["service"] = {"metadata": {"name": "aegis-api", "labels": {"managed-by": "aegis"}}}
    path.write_text(json.dumps(state))
    print("simulated image pull failure; no traffic changed", file=sys.stderr)
    sys.exit(1)
else:
    raise RuntimeError(f"unexpected gcloud operation: {args}")
path.write_text(json.dumps(state))
print(json.dumps(result))
