# Setup

Install `aegis-tool`, `aegis-admin-tool`, and the Google Cloud CLI. Sign in with `gcloud auth login`
and select a project with billing enabled. The operator needs permission to
provision Cloud Run, Firestore, Secret Manager, IAM, Compute Engine, and IAP.

Run `aegis-admin setup`. It proposes a region from your timezone, asks once about
a custom public endpoint, and guides you through creating a Google OAuth web
client. Register the exact callback shown by the wizard and download its JSON.
Google's consent screen and web-client creation are the one manual console step.

Setup provisions a named `aegis` database, scoped runtime identity, pinned OAuth
secret, API revision, namespace, certificate authorities, and one Ubuntu hub VM.
Browser sign-in identifies the owner; local GCP credentials grant membership.
It then enrolls the current Ubuntu/systemd machine and checks readiness.
Use `--no-enroll` on an operator computer that should not join the network.
The hub is an `e2-medium` with a 30 GB disk and reserved public address; GCP bills
these resources to your project.

For an unattended resource plan, supply `--project`, `--region`, `--endpoint`,
`--oauth-client FILE`, and `--yes`. Account authorization still requires a person.
`--remote-auth` supports a browser on another computer.

Custom endpoints may use any HTTPS path prefix. Forward that prefix to the
backend's `/v2`, including OAuth redirects and `/info`. Use `--proxy-invoker`
with your proxy's service account to keep the Cloud Run backend private.
Aegis leaves DNS and your proxy configuration under your control.

Setup records progress in `~/.aegis/deployments/PROJECT.json`. Failures retain
resources, keys, and committed account changes. Rerun the same command to resume;
it rejects conflicting configuration. `aegis-admin doctor` checks the saved
installation. `aegis-admin deploy --image IMAGE@sha256:DIGEST` deploys a new ready
revision before switching traffic.

For another machine, use `aegis manage enroll --remote USER@HOST`. The command
creates its reservation using your signed-in namespace administrator account.
Alternatively, create a reservation with `aegis manage enrollment create`, save
`aegis manage enrollment credential HOST_ID` to a mode-600 file, and run
`aegis manage enroll --local --invitation FILE` there. Invitations contain the
endpoint and namespace; successful enrollment removes the local copy. Keep them
private and revoke unused reservations with `aegis manage enrollment cancel`.

Authorize another person with `aegis-admin authorize`; the person signs in through
the browser. `aegis-admin user` manages account status and namespace membership.
Revocation is explicit. Ordinary users and machines never receive GCP credentials.

For an existing deployment, use `aegis-admin connect NAMESPACE --project PROJECT
--database DATABASE` to save its administration connection. This reads its public
issuer and namespace without provisioning resources or replacing keys.

To host the API yourself, create a Firestore database and run `aegis-admin configure
--project PROJECT --database DATABASE --endpoint https://HOST/PREFIX --oauth-client
FILE`. This initializes identity and certificate authorities without creating Cloud
Run or Compute Engine resources. Supply the downloaded client's secret to the API
as `AEGIS_OIDC_CLIENT_SECRET`, attach credentials with access to that database, map
the public prefix to `/v2`, then run `aegis-admin authorize --role admin`. For a
complete deployment with a first hub and local enrollment, use `aegis-admin setup`.
