# Host platforms

Ubuntu and Arch Linux use kernel WireGuard, per-peer VXLAN, BIRD, and systemd.
Arch uses its current packages, `/etc/bird.conf`, `bird.service`, and
`sshd.service`. Enrollment performs a full `pacman -Syu`; partial upgrades are
not supported. AppArmor integration applies only when its profile exists.

macOS uses the same mesh: BoringTun on `utun`, per-peer VXLAN on `feth`, and
bundled upstream Babel. The agent owns the workers, interfaces, route filters,
and recovery journals. It advertises only the machine's stable IPv4/IPv6 addresses.
Route readiness checks the source address selected by an ordinary unbound socket.

| Capability | Ubuntu / Arch | macOS |
| --- | --- | --- |
| Enrollment, API keys, OAuth, SSH | Yes | Yes |
| Mesh leaf, stable IPv4/IPv6, managed upgrades | Yes | Implemented; native acceptance pending |
| Optional inbound certificate SSH | Yes | Remote Login must be enabled |
| Internet tunnel, egress gateway, hub, direct gateway | Yes | Unsupported |
| Managed SSH lockdown | Yes | Unsupported |

Mac enrollment does not manage DNS, Internet default routes, global forwarding,
or firewall rules. Unsupported operations fail before mutation. WireGuard keys
are generated in Rust; networking needs no Homebrew services or separately
configured daemons. The helper sources and licenses ship with the Cargo package.

Install the CLI with `cargo install --locked aegis-tool`, then enroll with the
invitation supplied by your administrator. Apple command-line developer tools
are needed to build it. If inbound SSH is selected, enrollment guides enabling
Remote Login and verifies that sshd actually reads the certificate configuration.
It does not enable unrestricted disk access or disable ordinary SSH authentication.

File transfers require rsync 3.2 or newer on both machines. Linux enrollment
installs it. On macOS, use `brew install rsync`; Aegis uses Homebrew's native
Intel or Apple Silicon path and reports a missing or outdated installation before
starting a transfer. The OS-supplied older rsync is not used.

Mac system files live under `/Library/PrivilegedHelperTools` and
`/Library/LaunchDaemons`; state lives under `/private/var/lib/aegis`.
`aegis-agent.plist` owns both local sockets. Capulus upgrades run in independent
launchd jobs and retain their status and installation journals across agent restarts.
Unenrollment stops the service and removes recorded Aegis resources. It retains
Remote Login, ordinary host SSH keys, unrelated interfaces, and shared Capulus state.

Intel is the first native acceptance target. Compilation does not establish a
minimum supported macOS version; record the actual model and OS during
[native validation](../aegis-tool/tests/PLATFORMS.md). No Mac release is claimed tested yet.

Package references: [BIRD](https://archlinux.org/packages/extra/x86_64/bird/files/),
[OpenSSH](https://archlinux.org/packages/core/x86_64/openssh/files/),
[iptables](https://archlinux.org/packages/core/x86_64/iptables/),
[Apple developer tools](https://developer.apple.com/documentation/xcode/installing-the-command-line-tools/).
