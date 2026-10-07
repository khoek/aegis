# Arch Linux and macOS support

Preserve WireGuard → per-peer VXLAN → Babel, stable dual-stack host addresses,
leaf advertisement policy, hub selection, and failover. Deliver the implementation
and all locally available validation before native-machine acceptance testing.
Publishing, fleet deployment, and production database changes are separate steps.

## Scope

| Function | Ubuntu / Arch | Initial macOS |
| --- | --- | --- |
| Enrollment, API-key and OAuth authentication | Supported | Supported |
| WireGuard / VXLAN / Babel leaf | Supported | Supported |
| Stable IPv4/IPv6 addresses and hub failover | Supported | Supported |
| SSH and transfers, optional inbound certificate SSH | Supported | Supported |
| Service startup, health, agent-managed upgrades | Supported | Supported |
| API administration and satellite profile management | Supported | Supported |
| Internet tunnel client and egress gateway | Supported | Unsupported |
| Hub and direct gateway | Supported | Unsupported |
| Managed SSH lockdown | Supported | Unsupported initially |

Ordinary macOS enrollment must not change system DNS, Internet default routes,
or unrelated firewall settings. Unsupported functions must fail before mutation.

## Work plan

### 1. Platform contract and capability enforcement

- [x] Add a small typed platform/capability model to `aegis-dto`.
- [x] Separate supported capabilities, enabled roles, and observed health.
- [x] Validate enrollment and configuration before side effects.
- [x] Enforce source/target capabilities in the API and selectors.
- [x] Reconcile only applicable subsystems; unsupported hosts have no egress identity.
- [x] Preserve existing authentication and authorization boundaries.

### 2. Shared platform boundaries

- [x] Separate shared agent policy from native network operations.
- [x] Target-gate Linux dependencies; keep ordinary Cargo installation feature-free.
- [x] Extend Capulus managed services to launchd with authenticated local IPC.
- [x] Keep validated named configuration and reusable, cohesive interfaces.

### 3. Arch installation and lifecycle

- [x] Support Arch in local and remote enrollment, prerequisite installation, and repair.
- [x] Resolve native service/configuration paths and validate BIRD configuration.
- [x] Handle optional AppArmor and resolver integration explicitly.
- [x] Preserve the agent-managed update mechanism and supported pacman workflows.
- [x] Validate fresh installation, enrollment, reboot, and service persistence on a disposable Arch GCE VM.
- [ ] Validate managed upgrade and removal after a hub-backed data-plane run.

### 4. macOS mesh

- [x] Implement native WireGuard supervision using a selected userspace implementation.
- [x] Implement bounded per-peer VXLAN over `feth` using `tun-rs`.
- [x] Preserve VNIs, transit addresses, MTUs, multicast, and peer validation.
- [x] Configure and supervise `babeld`, preserving route filters and metrics.
- [x] Normalize installed-route and worker health observations; consume native routing notifications.
- [x] Implement stable aliases and preferred-source verification for arbitrary IPv4/IPv6 applications.
- [ ] Prove source-address selection on the native Mac under route churn and failover.
- [x] Recover owned interfaces after service restart, sleep/wake, and network changes.

### 5. macOS installation and managed lifecycle

- [x] Preflight architecture, OS, build tools, and helper availability.
- [x] Provision versioned helpers without a separate user-operated daemon workflow.
- [x] Install launchd services, native paths, account lookup, and local socket authentication.
- [x] Configure optional inbound certificate SSH and guide any OS permission handoff.
- [x] Preserve endpoint discovery, credential handling, and enrollment recovery.
- [x] Implement upgrades whose worker survives agent restart, with retained status/recovery.
- [x] Remove only Aegis-owned resources during unenrollment.

### 6. Interaction and documentation

- [x] Use shared progress, deadlines, streaming handoffs, and typed cancellation throughout.
- [x] Expose precise unsupported capability errors and healthy unsupported states.
- [x] Document install commands, capabilities, helper licenses, and current validation limits.
- [ ] Record the minimum macOS version actually verified on hardware.
- [x] Prepare explicit operator migration and fleet rollout instructions, with no permanent shims.

### 7. Validation

- [x] Formatting, Clippy, unit/integration tests, dependency-boundary checks.
- [x] API capability rejection, enrollment ordering, and migration fixture tests.
- [x] Linux networking policy regressions and Arch package/service metadata verification.
- [x] Native Arch packaging, prerequisite, enrollment, reboot, WireGuard, BIRD, and systemd lifecycle validation on GCE.
- [ ] Privileged Linux kernel tests and hub-backed Arch data-plane failover.
- [x] macOS compilation for Intel and Apple Silicon where tooling permits.
- [ ] Native Mac: two Linux hubs, dual-stack traffic, stable source addresses, failover.
- [ ] Native Mac: MTU, throughput/CPU, reboot, sleep/wake, network changes, API outage.
- [ ] Native Mac: fresh enrollment, SSH both ways, transfers, upgrade/interruption, unenroll.
- [ ] Native Mac: verify DNS/default routes/unrelated firewall state remain unchanged.

## Release transition

The wire and storage schemas are strict. Before any deployed cutover, test whether
an explicit temporary bridge release is required. Deploy such a bridge through
the existing agent-managed mechanism, verify the participating fleet, run the
auditable one-time migration, deploy the strict final release, and remove bridge
behavior and obsolete fields. Previously deferred offline hosts require explicit
operator repair. Do not infer deployment authorization from this implementation.

## Native acceptance gates

The first target is a newer Intel Mac; its exact model and macOS version are not yet supplied. Source
review does not establish runtime support. Preferred-source routing, privileged
`feth` operation, launchd lifecycle, and the minimum supported macOS version remain
native acceptance gates. Keep implementation progress separate from tests that
have actually run; do not mark these gates complete from compilation alone.

## Progress

- Implemented the strict platform/capability contract, native installation paths,
  Arch prerequisites, and the macOS WireGuard/VXLAN/Babel backend. Unsupported Mac
  roles fail before mutation. Existing records/configs require the documented
  one-time transition; there are no runtime schema migrations.
- Added Capulus launchd activation, authenticated sockets, hidden unprivileged
  builds, independent upgrade workers, deadlines, journals, and recovery.
- Added native route/source verification, shutdown and ownership cleanup, endpoint
  rebinding, optional Remote Login integration, transfer prerequisite checks, and
  bootstrap/SSH path handling. Disabled inbound SSH remains disabled after saving.
- Linux workspace tests pass: 266 CLI, 68 API, and 27 DTO unit tests, plus the
  administration and CLI integration suites. Capulus passes 72 unit tests and two
  terminal tests. The optional zellij test remains unrun because zellij is absent.
- Firestore emulator checks pass: two API tests, seven setup tests, and the admin
  account/CA test. The upstream Babel parser test and two migration fixtures pass.
  No live GCP project is involved in these checks.
- Formatting and Clippy pass for the Linux workspace and standalone Capulus;
  Intel macOS Clippy passes for all CLI and Capulus targets. Dependency inspection
  confirms the Mac CLI excludes Firestore/GCP, rtnetlink, and systemd/zbus.
  The Cargo package listing includes the native helper sources and license notices.
- Intel: entire workspace and all targets cross-check successfully. Apple Silicon:
  CLI/agent and all targets cross-check successfully, including bundled Babel.
  Cross-checks used Zig 0.17 and a macOS SDK; they do not establish native behavior.
- Arch package names and service paths were verified against official package
  metadata. Native Arch installation/kernel tests remain unrun: this shell has
  neither passwordless sudo nor permission to create a mapped user namespace.
- Native acceptance checklist: `aegis-tool/tests/PLATFORMS.md`. Platform guide:
  `docs/platforms.md`. Explicit migration tools and fixtures: `tools/migrations`.
- 2026-10-07 Arch acceptance: VM `aegis-arch-e2e-20261007` in
  `aegis-e2e-261003-22f2fe`, `australia-southeast1-b`, installed the public
  `aegis-tool` 0.4.4 package from crates.io after a full pacman upgrade and
  reboot. Enrollment committed host `382d17c3-d9bb-4f20-901d-0776afd77cfe`,
  configured `wg-aegis` at `10.75.1.4`, BIRD, both Aegis sockets, and the agent;
  all five units returned enabled/active after reboot. `bird -p -c /etc/bird.conf`
  passed. The test API had no reachable hub peer, so the agent's data-plane
  reconciliation correctly remained pending; this is an infrastructure limitation,
  not a skipped Arch installation step. The VM is intentionally retained for review.
- Published `aegis-dto` and `aegis-tool` 0.4.4 after verifying a clean crates.io
  package build. The disposable API ran the matching 0.4.3 workspace image during
  the acceptance run; no production fleet or production database was changed.
