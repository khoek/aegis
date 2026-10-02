#!/bin/bash
# Runs only the namespace-isolated egress suite. Build the binaries as the normal user first.
set -euo pipefail
if [[ $# != 2 ]]; then
  echo "usage: sudo $0 TEST_BINARY AEGIS_BINARY" >&2
  exit 2
fi
if [[ $EUID != 0 ]]; then
  echo 'Root is needed to create private network and mount namespaces.' >&2
  exit 2
fi
export AEGIS_TEST_BINARY="$(realpath "$2")"
export RUST_BACKTRACE=0
snapshot() {
  ip -j -4 route show default
  ip -j -6 route show default
  ip -j -4 rule show
  ip -j -6 rule show
}
before="$(snapshot)"
set +e
/usr/bin/timeout --signal=TERM --kill-after=5s 180s "$1" \
  agent::egress_kernel_tests::isolated_tunnel_end_to_end --exact --ignored --nocapture --test-threads=1
result=$?
set -e
if [[ "$before" != "$(snapshot)" ]]; then
  echo 'FAIL: host default routes or policy rules changed during the isolated test' >&2
  exit 1
fi
echo 'PASS: host default routes and policy rules unchanged' >&2
exit "$result"
