set -euo pipefail
: "${aegis_bootstrap_version:?exact Aegis version required}"
[[ "$aegis_bootstrap_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
export aegis_bootstrap_version
echo "==> Bootstrapping trusted system aegis v${aegis_bootstrap_version}"
system_aegis=/usr/local/bin/aegis
if [ -f "$system_aegis" ] && [ ! -L "$system_aegis" ] && [ -x "$system_aegis" ] && \
   [ "$(stat -c '%u:%g' "$system_aegis")" = "0:0" ] && \
   [ "$(stat -c '%a' "$system_aegis")" = "755" ] && \
   [ "$(timeout --signal=TERM --kill-after=2s 10s \
       "$system_aegis" --version | awk '{print $NF}')" = "$aegis_bootstrap_version" ]; then
  echo "==> Trusted system aegis v${aegis_bootstrap_version} is already installed"
else
  if [ -e "$system_aegis" ] || [ -L "$system_aegis" ]; then
    echo "Existing system Aegis must be upgraded through agent-managed redeploy" >&2
    exit 1
  fi
  bash -seuo pipefail <<'EOF_AEGIS_SYSTEM_BOOTSTRAP'
umask 077
bootstrap="$(mktemp -d /run/aegis-system-bootstrap.XXXXXX)"
test -d /usr/local/bin
test ! -L /usr/local/bin
test "$(stat -c '%u:%g' /usr/local/bin)" = "0:0"
test "$((0$(stat -c '%a' /usr/local/bin) & 0022))" -eq 0
system_stage="$(mktemp /usr/local/bin/.aegis-bootstrap.XXXXXX)"
trap 'rm -rf -- "$bootstrap"; rm -f -- "$system_stage"' EXIT
cd "$bootstrap"
export CARGO_HOME="$bootstrap/cargo"
export RUSTUP_HOME="$bootstrap/rustup"
install_root="$bootstrap/install"
mkdir -p "$CARGO_HOME" "$RUSTUP_HOME" "$install_root"
case "$(uname -m)" in
  x86_64) rust_target=x86_64-unknown-linux-gnu ;;
  aarch64) rust_target=aarch64-unknown-linux-gnu ;;
  *) echo "unsupported Rust bootstrap architecture: $(uname -m)" >&2; exit 1 ;;
esac
rustup_url="https://static.rust-lang.org/rustup/dist/$rust_target/rustup-init"
curl --fail --silent --show-error --location --connect-timeout 15 --max-time 180 \
  --max-filesize 67108864 "$rustup_url" -o "$bootstrap/rustup-init"
curl --fail --silent --show-error --location --connect-timeout 15 --max-time 60 \
  "$rustup_url.sha256" -o "$bootstrap/rustup-init.sha256"
expected="$(awk 'NR == 1 {print $1}' "$bootstrap/rustup-init.sha256")"
printf '%s  %s\n' "$expected" "$bootstrap/rustup-init" | sha256sum --check --status
chmod 700 "$bootstrap/rustup-init"
timeout --signal=TERM --kill-after=30s 15m \
  "$bootstrap/rustup-init" -y --profile minimal --no-modify-path --default-toolchain stable
timeout --signal=TERM --kill-after=30s 45m \
  "$CARGO_HOME/bin/cargo" install --locked --force --root "$install_root" \
  --registry crates-io --version "$aegis_bootstrap_version" aegis-tool --bin aegis
test "$(timeout --signal=TERM --kill-after=2s 10s \
  "$install_root/bin/aegis" --version | awk '{print $NF}')" = "$aegis_bootstrap_version"
install -o root -g root -m 0755 "$install_root/bin/aegis" "$system_stage"
test "$(timeout --signal=TERM --kill-after=2s 10s "$system_stage" --version | awk '{print $NF}')" = "$aegis_bootstrap_version"
mv -fT -- "$system_stage" /usr/local/bin/aegis
sync -f /usr/local/bin
EOF_AEGIS_SYSTEM_BOOTSTRAP
fi
