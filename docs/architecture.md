# Architecture

`aegis-types` owns the wire format and validated configuration. `aegis-api` owns
HTTP policy and fleet persistence. `aegis-tool` owns the client and host agent; `aegis-admin` owns local
administration. No crate depends on Deus or occultum.

The client package has no database or GCP administration dependencies. The admin
package uses its public client workflows for sign-in and enrollment, keeping both
commands on the same credential, invitation, and progress-reporting paths.

Rete supplies reusable HTTP, Firestore, OAuth, JWT, PKCE, and OIDC libraries.
Capulus supplies CLI reporting and the managed installer. These are ordinary
crates.io dependencies; development patches are local Cargo configuration.

A deployment has one public service issuer and independent namespace subtrees.
Browser sign-in verifies the provider subject, then checks the account and current
namespace membership. Agent credentials are scoped to a host and namespace.
The public endpoint can be proxied; backend invocation authentication and the
user's Authorization header serve separate purposes.

Administration writes directly to Firestore using the operator's local GCP access
token. A PKCE-bound browser proof identifies the account being authorized; only
GCP-authorized administration can create that grant. The browser code is consumed
by the ordinary OAuth exchange. There is no public administration or first-owner
claim endpoint.

OIDC client secrets live outside Firestore. Setup stores them in Secret Manager
and pins the version injected into Cloud Run. API signing and namespace CA keys
remain in their own database records. Repeating setup never silently replaces
existing keys or changes an issuer.

The API can run outside Cloud Run with the same database configuration, runtime
secret, and Application Default Credentials. Only the API runtime needs database
access. The deployment wizard deliberately provisions Google Cloud resources.

Installation and redeployment use exact public `aegis-tool` releases. Initial
bootstrap builds in an isolated Cargo directory; existing system installations
upgrade through the agent-managed installer. No private registry configuration
or registry credentials form part of the Aegis protocol.
