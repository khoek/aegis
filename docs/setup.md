# Setup

Install current stable [Rust](https://rustup.rs/), then:

```sh
# Ubuntu build dependencies, if not already installed:
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev
cargo install --locked aegis-tool aegis-admin-tool
aegis-admin setup
```

Setup checks for the Google Cloud CLI and gives installation instructions if it
is missing. It guides GCP sign-in, project selection or creation, and billing
activation when needed. Sign-in and billing checks resume automatically while
you complete the instructions in another terminal or the Cloud Console. The
operator needs permission to provision Cloud Run, Firestore, IAM, Compute Engine,
and IAP; setup identifies the selected account and links to project access settings
if management API activation is denied.

Run `aegis-admin setup`. It proposes a region from your timezone, asks once about
a custom public endpoint, and shows the resource plan. It selects and pins the
official API image automatically. Setup provisions the API,
identity and certificate authorities, a namespace, and Ubuntu hub VMs in the regions you select. It
issues your user credential through local GCP access, signs you in, enrolls the
current Ubuntu/systemd machine, and checks readiness. No OAuth client or browser
configuration is required. Use `--no-enroll` for an operator-only computer.

Each hub is an `e2-medium` with a 30 GB disk and reserved public address. GCP bills
these resources to your project. For unattended setup, complete the prerequisites
and supply `--project`, `--region`, and `--yes`; `--endpoint` is optional. Missing
prerequisites produce repair instructions without waiting for input.

Rerun setup to manage hub regions: Space selects regions, Enter reviews the changes.
New hubs become healthy before removed hubs are deleted. Removal deletes that
hub’s VM, disk, reserved address, subnet and Aegis host record; at least one hub
must remain. For unattended use, repeat `--hub-region REGION` with `--yes` to
specify the complete desired set. Omitting it keeps the saved selection.

Custom endpoints may use any HTTPS path prefix. Forward that prefix to the
backend's `/v2`, including `/auth`, `/oauth`, and `/info`. Use `--proxy-invoker`
with your proxy's service account to keep Cloud Run private. DNS and proxy
configuration remain under your control.

Setup records progress in `~/.aegis/deployments/PROJECT.json`. Failures retain
resources, keys, and committed account changes. Rerun the same command to resume;
it rejects conflicting configuration. Setup waits for API activation and verifies
database access using the API's runtime identity before deployment. It grants the
GCP operator impersonation of that dedicated service account for this check.
`aegis-admin doctor` checks the saved
installation. `aegis-admin deploy` resolves the official image matching the installed
admin release and deploys a ready revision before switching traffic. For custom
builds, setup and deploy accept `--image IMAGE@sha256:DIGEST`.

## Accounts and credentials

`aegis-admin authorize` grants access and signs in the local GCP operator. Use
`--user USER_ID` to select another existing account, and `--role admin` to grant
namespace administration. Only the admin CLI needs GCP credentials.

For another person or client:

```sh
aegis-admin user create person@example.com
aegis-admin user grant USER_ID personal member
aegis-admin credential issue USER_ID --output credential.json
# On the receiving machine:
aegis manage login --credential credential.json
```

The private credential file carries its endpoint and namespace. Import consumes
it and saves a rotating session; issue a separate credential for each client.
Sessions renew while used and expire after 30 days of inactivity. Store and
transfer credential files privately. The server stores only secret verifiers.

`aegis-admin credential list USER_ID` lists sessions; `credential revoke USER_ID
SESSION_ID` invalidates one immediately. `user disable USER_ID` disables access
and revokes all sessions. Namespace membership and Unix login grants are separate
permissions; issuing a credential does not grant SSH access to every host.

## Browser sign-in

Opt in with `aegis-admin setup --oauth`. The wizard guides consent-screen and
Google OAuth web-client configuration, shows the exact callback, and prompts for
the downloaded JSON. `--oauth-client FILE` enables OAuth with an existing client.
Setup stores its secret in Secret Manager and authorizes the owner in the browser.
Use `--remote-auth` when the browser is on another computer.

In an OAuth deployment, ordinary users run `aegis manage login`. Administrators
run `aegis-admin authorize --oauth` to authorize a browser-verified identity.
Administrator-issued credentials remain available independently.

## Machines and other hosting

Enroll another machine with `aegis manage enroll --remote USER@HOST`. Alternatively,
create a reservation with `aegis manage enrollment create`, save its credential
with `aegis manage enrollment credential HOST_ID`, and run `aegis manage enroll
--local --invitation FILE` there. Invitations carry the endpoint and namespace;
successful enrollment removes the local file. Revoke unused reservations with
`aegis manage enrollment cancel`.

For an existing deployment, `aegis-admin connect NAMESPACE --project PROJECT
--database DATABASE` saves its administration connection without provisioning
resources or replacing keys.

For external API hosting, create a Firestore database and run `aegis-admin
configure --project PROJECT --database DATABASE --endpoint https://HOST/PREFIX`.
Attach runtime credentials with database access, map the public prefix to `/v2`,
start the API, then run `aegis-admin authorize --role admin`. Add `--oauth-client
FILE` to configure browser sign-in and supply `AEGIS_OIDC_CLIENT_SECRET` to that
runtime. Complete Cloud Run setup uses `aegis-admin setup` instead.
