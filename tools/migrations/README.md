# Platform transition

These are explicit, one-time operator tools. They are not linked into Aegis and
never run during startup. Do not run them against the fleet before its upgrade
and rollback path has been verified.

The strict release requires a platform on every host record, current
`principal_grants`, and `[routing]` in each agent config. The prior release cannot serve as a rollback target after
that config cutover. Prepare an explicit temporary bridge release, publish and
redeploy it through the existing agent mechanism, and verify every participating
host before the cutover. Remove bridge behavior from the final release.

1. Repair removed `oauth_principal` fields first, after reviewing every affected
   host: `python3 tools/migrations/platform.py --apply --backup grants-before.json
   principal-grants --project PROJECT --database DATABASE NAMESPACE`. The command
   only accepts canonical Aegis user UUIDs, uses update-time preconditions, and
   retains a complete private backup.
2. Inventory each host's actual OS and architecture. Resolve outstanding enrollment
   attempts before the cutover; do not infer Ubuntu from a missing field.
3. Prepare a JSON manifest with `project`, `database` (such as `(default)`),
   `namespace`, and a `hosts` object keyed by every canonical host UUID.
   Each value has `operating_system` (`ubuntu`,
   `arch_linux`, or `mac_os`) and `architecture` (`x86_64` or `aarch64`). Arch is x86 only.
4. Run `python3 tools/migrations/platform.py fleet manifest.json` with local gcloud
   credentials. It validates the complete inventory and defaults to a dry run.
5. After the bridge is verified, apply with
   `python3 tools/migrations/platform.py --apply --backup hosts-before.json fleet manifest.json`.
   Writes affect only `platform`, require the observed document revision, and use
   one Firestore commit. The private backup is created exclusively before mutation.
6. On each participating Linux host, dry-run
   `sudo python3 platform.py local-config /etc/aegis/agent.toml`, then apply with
   `sudo python3 platform.py --apply --backup /root/aegis-agent-before.toml local-config /etc/aegis/agent.toml`.
   The exact old table is replaced; all other parsed values must remain identical.
7. While the verified bridge is still available, refresh every shared inventory
   cache from the migrated API. Remove any stale inventory cache explicitly before
   starting the strict release; retain credentials and context. Verify refresh,
   SSH access, and the rollback procedure before proceeding.
8. Deploy the strict API and exact CLI release through agent-managed redeploy.
   Verify both IP families, auth, SSH, health, and redeploy status before retiring
   the bridge. Offline hosts require explicit operator repair.

Backups contain private configuration. Keep them restricted and remove them only
when rollback is no longer needed. A lost commit response requires reading the
host records before retrying; the tool never guesses whether it committed.

Run fixture tests with `python3 -m unittest discover -s tools/migrations`.
