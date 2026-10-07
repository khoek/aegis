# Temporary platform bridge

`aegis-tool 0.4.12` is an explicit fleet transition release. It accepts
`[bird]` and `[routing]`; credential rotation preserves the on-disk schema.
Do not merge this branch into the strict release.

1. Repair invalid agent credentials through the existing reissue-token endpoint.
2. Redeploy the bridge through `aegis advanced redeploy --version 0.4.12`
   or the fleet command. Confirm each participating agent is ready before continuing.
3. As root or a member of the local `aegis` group, explicitly commit the config:

   ```sh
   curl --fail-with-body --max-time 30 --unix-socket /run/aegis/agent.sock \
     -X POST http://localhost/aegis-agent/platform-transition
   ```

   The endpoint retains a mode-0600 `agent.toml.before-platform-transition`
   backup and reports whether it committed. It serializes against token rotation;
   repeat calls on the current schema are harmless.
4. Redeploy the strict stable release. Confirm readiness, SSH, current inventory,
   and that the temporary endpoint is absent. Then yank this temporary release.

Offline hosts were excluded from the rollout and require explicit operator repair.
