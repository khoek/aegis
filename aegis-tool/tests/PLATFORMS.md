# Native acceptance

Use a disposable fleet with two Linux hubs, one Linux leaf, and the Intel Mac.
Keep a local console open. Record exact release versions, Mac model/OS, Arch
package versions, and results in `PLAN.md`. Cross-compilation is not acceptance.

## Installation and authorization

- Run the ordinary interactive setup and invitation enrollment on clean Arch and
  macOS hosts. Check that unsupported Mac roles fail before any host mutation.
- Exercise API-key and OAuth users, endpoint discovery, invitation reuse rejection,
  revocation, and an API outage after the local inventory has been cached.
- Enroll a Mac with inbound SSH disabled, then one with it enabled. Verify the
  Remote Login handoff, both SSH directions, stable certificate principals, and
  ordinary pre-existing SSH access. Test push/pull with spaces in paths.

## Networking

- Save DNS configuration, default routes, forwarding sysctls, and firewall policy
  before enrollment. Compare after enrollment and removal on the same underlay.
- Check WireGuard handshakes, per-peer VXLAN counters, Babel neighbors and host
  routes. Capture the encrypted underlay and decoded overlay to verify VNIs,
  multicast, IPv4/IPv6, and Linux interoperability.
- From an unbound UDP/TCP socket, verify that a mesh destination selects the
  published stable address for each family. Check the source observed remotely;
  repeat after route churn and switching hubs. A transient source is a failure.
- Interrupt each hub in turn; verify route withdrawal, reconvergence, active SSH,
  and new connections. Restore it before testing the other hub.
- Test MTU boundaries and large transfers in both directions. Measure throughput,
  CPU, packet loss, and reconvergence rather than assuming kernel-like performance.
- Reboot, sleep/wake, switch Wi-Fi/Ethernet, change the underlay address, and
  disconnect/reconnect. Check for abandoned interfaces, workers, sockets, and routes.

## Managed lifecycle

- Redeploy an exact published candidate through `aegis advanced redeploy --version VERSION`.
  Check independent worker survival, both local protocols, journal cleanup, and
  restored mesh connectivity. Do not replace a managed binary manually.
- Interrupt before file commit, during service restart, and after acceptance.
  Verify retained status, explicit repair, and rollback with the prepared release.
- Unenroll. Check that only owned interfaces, aliases, services, SSH integration,
  and helper files disappeared. Remote Login, normal SSH keys, other VPNs, DNS,
  Internet routing, and unrelated firewall policy must remain intact.

Arch additionally needs a full pacman upgrade, reboot, BIRD configuration validation,
SSH socket/service behavior, AppArmor absent/present, and tunnel resolver ownership.
Run the existing isolated Linux kernel suite as root on a disposable Linux host.

## Available automated checks

`cargo test --workspace --all-targets` covers policy, configuration, CLI, and UI.
Firestore tests use the loopback emulator described in `docs/releasing.md`.
`tools/migrations` has independent migration fixtures.

The native Babel parser test is ignored by default. Compile the unmodified bundled
Babel source for the current host and run:

```sh
AEGIS_TEST_BABELD=/absolute/path/to/babeld cargo test -p aegis-tool \
  configuration_is_accepted_by_upstream_babeld_without_kernel_changes -- --ignored
```

It supplies directives with `-C` and exits with `-V` before kernel initialization.
