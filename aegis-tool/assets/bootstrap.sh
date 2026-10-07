set -euo pipefail
: "${aegis_bootstrap_version:?exact Aegis version required}"
[[ "$aegis_bootstrap_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
export aegis_bootstrap_version
case "$(uname -s)" in
  Linux)
    system_directory=/usr/local/bin
    root_group=root
    file_owner() { stat -c '%u:%g' "$1"; }
    file_mode() { stat -c '%a' "$1"; }
    deadline() { local seconds=$1; shift; timeout --signal=TERM --kill-after=30s "$seconds" "$@"; }
    digest() { sha256sum "$1" | awk '{print $1}'; }
    case "$(uname -m)" in
      x86_64) rust_target=x86_64-unknown-linux-gnu ;;
      aarch64) rust_target=aarch64-unknown-linux-gnu ;;
      *) echo 'Unsupported Linux architecture' >&2; exit 1 ;;
    esac
    ;;
  Darwin)
    system_directory=/Library/PrivilegedHelperTools
    root_group=wheel
    file_owner() { stat -f '%u:%g' "$1"; }
    file_mode() { stat -f '%Lp' "$1"; }
    deadline() {
      /usr/bin/perl -e '
        use POSIX qw(:sys_wait_h setsid);
        my $seconds = shift @ARGV;
        my $pid = fork(); defined $pid or die "fork: $!";
        if (!$pid) { setsid(); exec @ARGV; die "exec: $!"; }
        $SIG{ALRM} = sub { kill "TERM", -$pid; sleep 2; kill "KILL", -$pid; waitpid($pid, 0); exit 124; };
        alarm($seconds); waitpid($pid, 0); alarm(0);
        exit(($? & 127) ? 128 + ($? & 127) : $? >> 8);
      ' "$@"
    }
    digest() { /usr/bin/shasum -a 256 "$1" | awk '{print $1}'; }
    case "$(uname -m)" in
      x86_64) rust_target=x86_64-apple-darwin ;;
      arm64) rust_target=aarch64-apple-darwin ;;
      *) echo 'Unsupported macOS architecture' >&2; exit 1 ;;
    esac
    ;;
  *) echo 'Unsupported operating system' >&2; exit 1 ;;
esac
system_aegis="$system_directory/aegis"
if [ -f "$system_aegis" ] && [ ! -L "$system_aegis" ] && [ -x "$system_aegis" ] && \
   [ "$(file_owner "$system_aegis")" = '0:0' ] && [ "$(file_mode "$system_aegis")" = 755 ] && \
   [ "$(deadline 10 "$system_aegis" --version | awk '{print $NF}')" = "$aegis_bootstrap_version" ]; then
  echo "Trusted system aegis v${aegis_bootstrap_version} is installed" >&2
  exit 0
fi
if [ -e "$system_aegis" ] || [ -L "$system_aegis" ]; then
  echo 'Existing system Aegis must be upgraded through agent-managed redeploy' >&2
  exit 1
fi
umask 077
if [ ! -e "$system_directory" ]; then
  install -d -o root -g "$root_group" -m 755 "$system_directory"
fi
test -d "$system_directory" && test ! -L "$system_directory"
test "$(file_owner "$system_directory")" = '0:0'
test "$((0$(file_mode "$system_directory") & 0022))" -eq 0
bootstrap="$(mktemp -d /var/tmp/aegis-system-bootstrap.XXXXXX)"
system_stage="$(mktemp "$system_directory/.aegis-bootstrap.XXXXXX")"
trap 'rm -rf -- "$bootstrap"; rm -f -- "$system_stage"' EXIT
cd "$bootstrap"
export CARGO_HOME="$bootstrap/cargo"
export RUSTUP_HOME="$bootstrap/rustup"
export CARGO_TARGET_DIR="$bootstrap/target"
export TMPDIR="$bootstrap/tmp"
install_root="$bootstrap/install"
mkdir -p "$CARGO_HOME" "$RUSTUP_HOME" "$TMPDIR" "$install_root"
rustup_url="https://static.rust-lang.org/rustup/dist/$rust_target/rustup-init"
curl --fail --silent --show-error --location --connect-timeout 15 --max-time 180 \
  --max-filesize 67108864 "$rustup_url" -o "$bootstrap/rustup-init"
curl --fail --silent --show-error --location --connect-timeout 15 --max-time 60 \
  "$rustup_url.sha256" -o "$bootstrap/rustup-init.sha256"
expected="$(awk 'NR == 1 {print $1}' "$bootstrap/rustup-init.sha256")"
[[ "$expected" =~ ^[[:xdigit:]]{64}$ ]]
test "$(digest "$bootstrap/rustup-init")" = "$expected"
chmod 700 "$bootstrap/rustup-init"
deadline 900 "$bootstrap/rustup-init" -y --profile minimal --no-modify-path --default-toolchain stable
deadline 2700 "$CARGO_HOME/bin/cargo" install --locked --force --root "$install_root" \
  --registry crates-io --version "$aegis_bootstrap_version" aegis-tool --bin aegis
test "$(deadline 10 "$install_root/bin/aegis" --version | awk '{print $NF}')" = "$aegis_bootstrap_version"
install -o root -g "$root_group" -m 0755 "$install_root/bin/aegis" "$system_stage"
test "$(deadline 10 "$system_stage" --version | awk '{print $NF}')" = "$aegis_bootstrap_version"
mv -f -- "$system_stage" "$system_aegis"
deadline 30 sync
