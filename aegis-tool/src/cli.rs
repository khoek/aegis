use std::path::PathBuf;

use crate::ui::UiArgs;
use aegis_dto::{HostAlias, HostId};
use capulus::managed::AgentLifecycleCommand;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
#[command(
    name = "aegis",
    version,
    about = "OAuth-backed SSH client and server management for the aegis ecosystem.",
    infer_subcommands = true
)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "NAME",
        help = "Select the Aegis namespace for this command"
    )]
    pub namespace: Option<aegis_dto::NamespaceId>,

    #[arg(
        long,
        global = true,
        value_name = "URL",
        help = "Override the saved or enrolled Aegis endpoint"
    )]
    pub api_base: Option<String>,

    #[command(flatten)]
    pub ui: UiArgs,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(hide = true)]
    Agent(AgentNamespaceArgs),

    #[command(
        name = "list",
        about = "Show cached hosts. Use --refresh to sync through the local aegis-agent first."
    )]
    List(ListArgs),

    #[command(
        name = "ssh",
        about = "Open SSH or run a command over WireGuard using an aegis-issued SSH certificate."
    )]
    Ssh(SshArgs),

    #[command(
        name = "push",
        about = "Copy local files or directories to a host with rsync over aegis SSH."
    )]
    Push(TransferArgs),

    #[command(
        name = "pull",
        about = "Copy remote files or directories from a host with rsync over aegis SSH."
    )]
    Pull(TransferArgs),

    #[command(
        name = "tunnel",
        about = "Route this machine's Internet traffic through one selected Aegis host."
    )]
    Tunnel(TunnelArgs),

    #[command(
        name = "manage",
        about = "Administrative aegis commands for login and host management."
    )]
    Manage(ManageArgs),

    #[command(
        name = "advanced",
        about = "Technical Aegis maintenance, recovery, and forced reconciliation commands."
    )]
    Advanced(AdvancedArgs),
}

#[derive(Debug, Args)]
#[command(infer_subcommands = true)]
pub struct PrincipalArgs {
    #[command(subcommand)]
    pub command: PrincipalCommands,
}

#[derive(Debug, Subcommand)]
pub enum PrincipalCommands {
    #[command(
        name = "allow",
        about = "Allow an Aegis user ID to log in as this Unix user."
    )]
    Allow(PrincipalGrantArgs),

    #[command(
        name = "revoke",
        about = "Revoke an Aegis user ID from this Unix user."
    )]
    Revoke(PrincipalGrantArgs),

    #[command(
        name = "list",
        about = "List Aegis user IDs allowed for this Unix user."
    )]
    List,
}

#[derive(Debug, Args)]
pub struct PrincipalGrantArgs {
    #[arg(value_name = "USER_ID")]
    pub user_id: String,
}

#[derive(Debug, Args)]
#[command(infer_subcommands = true)]
pub struct ManageArgs {
    #[command(subcommand)]
    pub command: ManageCommands,
}

#[derive(Debug, Subcommand)]
pub enum ManageCommands {
    #[command(about = "Select or inspect the current Aegis namespace.")]
    Namespace(NamespaceArgs),
    #[command(
        name = "host",
        about = "Manage host aliases without changing host identity."
    )]
    Host(HostArgs),

    #[command(
        name = "principal",
        about = "Grant or revoke Aegis users for the current local Unix login."
    )]
    Principal(PrincipalArgs),

    #[command(
        name = "login",
        about = "Authenticate via OAuth and store the login state in this Unix user's config."
    )]
    Login(LoginArgs),

    #[command(
        name = "agent-token",
        about = "Issue, rotate, or revoke Aegis agent credentials."
    )]
    AgentToken(AgentTokenArgs),

    #[command(
        name = "enrollment",
        about = "Create and manage reserved identities for machines that have not enrolled yet."
    )]
    Enrollment(EnrollmentAdminArgs),

    #[command(
        name = "sync-dns",
        about = "Reconcile Aegis-owned DNS records with current network membership."
    )]
    SyncDns(SyncDnsArgs),

    #[command(
        name = "sync-tls",
        about = "Reconcile the complete desired Aegis TLS certificate configuration."
    )]
    SyncTls(SyncTlsArgs),

    #[command(
        name = "satellite",
        about = "Pair persistent non-mesh devices with every Aegis hub."
    )]
    Satellite(SatelliteArgs),

    #[command(
        name = "enroll",
        about = "Convergently enroll the local machine or a remote host into Aegis."
    )]
    Enroll(EnrollArgs),

    #[command(
        name = "unenroll",
        about = "Remove aegis management from a local or remote host and delete its published host record."
    )]
    Unenroll(UnenrollArgs),

    #[command(
        name = "lockdown",
        about = "Enable, disable, or inspect cert-only SSH login restrictions on the WireGuard address."
    )]
    Lockdown(LockdownArgs),
}

#[derive(Debug, Args)]
pub struct NamespaceArgs {
    #[command(subcommand)]
    pub command: NamespaceCommands,
}

#[derive(Debug, Subcommand)]
pub enum NamespaceCommands {
    #[command(about = "Remember a namespace after checking membership.")]
    Use { namespace: aegis_dto::NamespaceId },
    #[command(about = "Show the selected API endpoint and namespace membership.")]
    Show,
}

#[derive(Debug, Args)]
#[command(infer_subcommands = true)]
pub struct AdvancedArgs {
    #[command(subcommand)]
    pub command: AdvancedCommands,
}

#[derive(Debug, Subcommand)]
pub enum AdvancedCommands {
    #[command(
        name = "install",
        about = "Install or repair Aegis-managed WireGuard and SSH authentication on this machine."
    )]
    Install(InstallArgs),

    #[command(
        name = "refresh-credentials",
        about = "Force-refresh local certificates, and CA material."
    )]
    RefreshCredentials(RefreshCredentialsArgs),

    #[command(
        name = "reconcile",
        about = "Force the local aegis-agent to reconcile control-plane and network state."
    )]
    Reconcile(ReconcileArgs),

    #[command(
        name = "redeploy",
        about = "Redeploy Aegis from crates.io through the local aegis-agent."
    )]
    Redeploy(RedeployArgs),

    #[command(name = "update-user", hide = true)]
    UpdateUser(UpdateUserArgs),

    #[command(
        name = "redeploy-status",
        about = "Query one local managed redeploy job."
    )]
    RedeployStatus(RedeployStatusArgs),

    #[command(
        name = "fleet",
        about = "Run fleet-wide technical maintenance across reachable hosts."
    )]
    Fleet(FleetArgs),
}

#[derive(Debug, Args)]
#[command(infer_subcommands = true)]
pub struct HostArgs {
    #[command(subcommand)]
    pub command: HostCommands,
}

#[derive(Debug, Subcommand)]
pub enum HostCommands {
    #[command(name = "list", about = "List host UUIDs and aliases.")]
    List(HostListArgs),
    #[command(
        name = "alias",
        about = "Add aliases, promote an alias to primary, or remove aliases."
    )]
    Alias(HostAliasesArgs),
}

#[derive(Debug, Args)]
pub struct HostListArgs {
    #[arg(long, help = "Print the host inventory as JSON")]
    pub json: bool,
}

#[derive(Debug, Args)]
#[command(infer_subcommands = true)]
pub struct HostAliasesArgs {
    #[command(subcommand)]
    pub command: HostAliasCommands,
}

#[derive(Debug, Subcommand)]
pub enum HostAliasCommands {
    #[command(
        name = "add",
        about = "Add an alias without changing the primary alias."
    )]
    Add(HostAliasAddArgs),
    #[command(name = "promote", about = "Promote an existing alias to primary.")]
    Promote(HostAliasPromoteArgs),
    #[command(name = "remove", about = "Remove a non-primary alias.")]
    Remove(HostAliasRemoveArgs),
}

#[derive(Debug, Args)]
pub struct HostAliasAddArgs {
    #[arg(value_name = "ALIAS")]
    pub alias: HostAlias,
    #[arg(value_name = "HOST")]
    pub host: String,
    #[command(flatten)]
    pub wait: HostAliasWaitArgs,
}

#[derive(Debug, Args)]
pub struct HostAliasPromoteArgs {
    #[arg(value_name = "ALIAS")]
    pub alias: HostAlias,
    #[command(flatten)]
    pub wait: HostAliasWaitArgs,
}

#[derive(Debug, Args)]
pub struct HostAliasRemoveArgs {
    #[arg(value_name = "ALIAS")]
    pub alias: HostAlias,
    #[command(flatten)]
    pub wait: HostAliasWaitArgs,
}

#[derive(Debug, Args)]
pub struct HostAliasWaitArgs {
    #[arg(
        long,
        default_value_t = 300,
        value_name = "SECONDS",
        help = "Minimum propagation wait after the agent reports the exact alias order"
    )]
    pub propagation_wait_secs: u64,
    #[arg(
        long,
        conflicts_with = "propagation_wait_secs",
        help = "Return after the control-plane change without waiting for the host agent"
    )]
    pub no_wait: bool,
}

#[derive(Debug, Args)]
#[command(infer_subcommands = true)]
pub struct AgentTokenArgs {
    #[command(subcommand)]
    pub command: AgentTokenCommands,
}

#[derive(Debug, Subcommand)]
pub enum AgentTokenCommands {
    #[command(
        name = "issue",
        about = "Issue an agent bootstrap credential for a host."
    )]
    Issue(AgentTokenIssueArgs),

    #[command(
        name = "rotate",
        about = "Issue and install a fresh credential for the local Aegis agent."
    )]
    Rotate(AgentTokenRotateArgs),

    #[command(
        name = "revoke",
        about = "Revoke one agent credential read from a file or standard input."
    )]
    Revoke(AgentTokenRevokeArgs),
}

#[derive(Debug, Args)]
pub struct AgentTokenIssueArgs {
    #[arg(value_name = "HOST")]
    pub host: String,

    #[arg(long, help = "Print the token response as JSON")]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct AgentTokenRevokeArgs {
    #[arg(
        long,
        value_name = "PATH",
        help = "Read the raw refresh token from PATH, or explicitly from standard input with `-`; omit to prompt securely"
    )]
    pub token_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(infer_subcommands = true)]
pub struct EnrollmentAdminArgs {
    #[command(subcommand)]
    pub command: EnrollmentAdminCommands,
}

#[derive(Debug, Subcommand)]
pub enum EnrollmentAdminCommands {
    #[command(
        name = "create",
        about = "Reserve a new host identity from a JSON request."
    )]
    Create(EnrollmentCreateArgs),
    #[command(name = "list", about = "List outstanding host identity reservations.")]
    List(EnrollmentListArgs),
    #[command(
        name = "get",
        about = "Show one outstanding host identity reservation."
    )]
    Get(EnrollmentHostArgs),
    #[command(
        name = "credential",
        about = "Issue or replace the bootstrap credential for an outstanding reservation."
    )]
    Credential(EnrollmentHostArgs),
    #[command(
        name = "cancel",
        about = "Cancel an outstanding reservation and its credential."
    )]
    Cancel(EnrollmentCancelArgs),
}

#[derive(Debug, Args)]
pub struct EnrollmentCreateArgs {
    #[arg(
        long,
        value_name = "PATH",
        help = "Read the enrollment create request from PATH, or from standard input with `-`"
    )]
    pub file: PathBuf,
    #[arg(long, help = "Print the created enrollment as JSON")]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct EnrollmentListArgs {
    #[arg(long, help = "Print the enrollment list response as JSON")]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct EnrollmentHostArgs {
    #[arg(value_name = "UUID")]
    pub host_id: HostId,
    #[arg(long, help = "Print the response as JSON")]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct EnrollmentCancelArgs {
    #[arg(value_name = "UUID")]
    pub host_id: HostId,
}

#[derive(Debug, Args)]
pub struct SyncDnsArgs {
    #[arg(long, help = "Report changes without applying them")]
    pub dry_run: bool,

    #[arg(long, help = "Print the reconciliation result as JSON")]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct SyncTlsArgs {
    #[arg(
        long,
        value_name = "PATH",
        help = "Read the desired TLS state JSON from PATH, or explicitly from standard input with `-`"
    )]
    pub file: PathBuf,

    #[arg(long, help = "Report changes without applying them")]
    pub dry_run: bool,

    #[arg(long, help = "Print the reconciliation result as JSON")]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    #[arg(
        long,
        default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(1..),
        value_name = "SECONDS",
        help = "How long to wait for a local browser callback"
    )]
    pub wait_timeout_secs: u64,

    #[arg(
        long,
        conflicts_with = "remote_auth_relay",
        help = "Complete login through a browser on another machine"
    )]
    pub remote_auth: bool,

    #[arg(
        long,
        value_name = "REQUEST",
        conflicts_with = "remote_auth",
        help = "Open a local browser for the supplied remote-auth request and print its response"
    )]
    pub remote_auth_relay: Option<String>,
}

#[derive(Debug, Args, Default)]
pub struct ListArgs {
    #[arg(long, default_value = "aegis", value_name = "NETWORK")]
    pub network: String,

    #[arg(long, help = "Include pending hosts in the output")]
    pub allow_pending: bool,

    #[arg(
        long,
        help = "Refresh the cached host inventory through the local aegis-agent"
    )]
    pub refresh: bool,
}

#[derive(Debug, Args, Clone)]
pub struct SshArgs {
    #[arg(value_name = "HOST")]
    pub host: Option<String>,

    #[arg(long, default_value = "aegis", value_name = "NETWORK")]
    pub network: String,

    #[arg(
        long,
        short = 'u',
        value_name = "USER",
        help = "Remote Unix principal to log in as"
    )]
    pub user: Option<String>,

    #[arg(long, help = "Allow connecting to a pending host record")]
    pub allow_pending: bool,

    #[arg(long, help = "Refresh host inventory before resolving the SSH target")]
    pub refresh: bool,

    #[arg(
        long,
        conflicts_with_all = ["ipv4", "ipv6"],
        help = "Connect using the published WireGuard endpoint instead of the mesh address"
    )]
    pub use_endpoint: bool,

    #[arg(
        long,
        conflicts_with = "ipv6",
        help = "Connect using only the mesh IPv4 address"
    )]
    pub ipv4: bool,

    #[arg(
        long,
        conflicts_with = "ipv4",
        help = "Connect using only the mesh IPv6 address"
    )]
    pub ipv6: bool,

    #[arg(
        long,
        help = "Allow connecting without a host certificate; still pins the raw host key"
    )]
    pub no_server_cert: bool,

    #[arg(
        long,
        value_name = "CMD",
        help = "Run a remote command instead of opening a shell"
    )]
    pub command: Option<String>,

    #[arg(
        trailing_var_arg = true,
        value_name = "SSH_ARG",
        help = "Additional ssh(1) arguments appended before the destination"
    )]
    pub ssh_args: Vec<String>,
}

#[derive(Debug, Args)]
pub struct TransferArgs {
    #[arg(value_name = "HOST")]
    pub host: String,

    #[arg(long, default_value = "aegis", value_name = "NETWORK")]
    pub network: String,

    #[arg(
        long,
        short = 'u',
        value_name = "USER",
        help = "Remote Unix principal to log in as"
    )]
    pub user: Option<String>,

    #[arg(
        value_name = "PATH",
        num_args = 1..,
        help = "Source path(s), optionally followed by a destination path. With one path, the destination defaults to `.`."
    )]
    pub paths: Vec<String>,

    #[arg(long, help = "Allow connecting to a pending host record")]
    pub allow_pending: bool,

    #[arg(
        long,
        conflicts_with_all = ["ipv4", "ipv6"],
        help = "Connect using the published WireGuard endpoint instead of the mesh address"
    )]
    pub use_endpoint: bool,

    #[arg(
        long,
        conflicts_with = "ipv6",
        help = "Connect using only the mesh IPv4 address"
    )]
    pub ipv4: bool,

    #[arg(
        long,
        conflicts_with = "ipv4",
        help = "Connect using only the mesh IPv6 address"
    )]
    pub ipv6: bool,

    #[arg(
        long,
        help = "Allow connecting without a host certificate; still pins the raw host key"
    )]
    pub no_server_cert: bool,

    #[arg(long, help = "Disable rsync compression")]
    pub no_compress: bool,

    #[arg(
        long,
        help = "Use rsync's default size/mtime quick check instead of --checksum"
    )]
    pub no_checksum: bool,

    #[arg(
        long,
        help = "Delete destination files that are absent from the source"
    )]
    pub delete: bool,

    #[arg(long, help = "Show what rsync would transfer without changing files")]
    pub dry_run: bool,

    #[arg(
        long,
        help = "Push only: abort before rsync if the remote destination path already exists"
    )]
    pub fail_if_exists: bool,

    #[arg(
        long = "rsync-arg",
        allow_hyphen_values = true,
        value_name = "ARG",
        help = "Additional rsync argument appended after aegis defaults. Repeat as needed."
    )]
    pub rsync_args: Vec<String>,
}

#[derive(Debug, Args, Clone)]
pub struct InstallArgs {
    #[arg(
        long,
        hide = true,
        conflicts_with_all = ["upgrade", "reinstall"],
        help = "Stage an enrollment install without starting the agent; activation starts it"
    )]
    pub staged_enrollment: bool,

    #[arg(
        long,
        conflicts_with = "reinstall",
        help = "Reuse the current local aegis install settings for any option not explicitly provided"
    )]
    pub upgrade: bool,

    #[arg(
        long,
        conflicts_with = "upgrade",
        help = "Reapply the current local aegis install settings and restart the local agent service"
    )]
    pub reinstall: bool,

    #[arg(long, value_name = "PATH", help = "HostKey path to present to clients")]
    pub key: Option<PathBuf>,

    #[arg(
        long,
        value_name = "PATH",
        help = "HostCertificate path to present to clients"
    )]
    pub cert: Option<PathBuf>,

    #[arg(
        long,
        value_name = "USER",
        help = "Login user that owns the cargo-installed aegis binary during root-driven reinstalls"
    )]
    pub user: Option<String>,

    #[arg(
        long,
        value_enum,
        value_name = "YES|NO",
        help = "Whether this machine accepts inbound aegis SSH; defaults to yes for normal installs"
    )]
    pub inbound_ssh: Option<Choice>,

    #[arg(long, hide = true, value_name = "UUID")]
    pub host_id: Option<HostId>,

    #[arg(long, hide = true, value_name = "PRINCIPAL")]
    pub initial_oauth_principal: Option<String>,
}

#[derive(Debug, Args, Default)]
pub struct RefreshCredentialsArgs {}

#[derive(Debug, Args, Default)]
pub struct ReconcileArgs {}

#[derive(Debug, Args, Default)]
pub struct AgentTokenRotateArgs {}

#[derive(Debug, Args, Default)]
pub struct RedeployArgs {
    #[arg(
        long,
        value_name = "VERSION",
        help = "Exact aegis-tool version to install; omit to use the latest non-yanked release in the public crates.io index"
    )]
    pub version: Option<String>,

    #[arg(long, help = "Wait for the managed system reinstall and agent restart")]
    pub wait: bool,

    #[arg(long, hide = true)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct UpdateUserArgs {
    #[arg(long, value_name = "VERSION")]
    pub version: String,

    #[arg(long, hide = true)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RedeployStatusArgs {
    #[arg(value_name = "JOB")]
    pub job: String,

    #[arg(long, help = "Print the complete job state as JSON")]
    pub json: bool,
}

#[derive(Debug, Args)]
#[command(infer_subcommands = true)]
pub struct FleetArgs {
    #[command(subcommand)]
    pub command: FleetCommands,
}

#[derive(Debug, Subcommand)]
pub enum FleetCommands {
    #[command(
        name = "redeploy",
        about = "Redeploy aegis across all reachable SSH-capable hosts in parallel."
    )]
    Redeploy(FleetRedeployArgs),
}

#[derive(Debug, Args, Default)]
pub struct FleetRedeployArgs {
    #[arg(
        long,
        value_name = "VERSION",
        help = "Exact aegis-tool version to install; omit to resolve the latest non-yanked release in the public crates.io index once for the fleet"
    )]
    pub version: Option<String>,

    #[arg(long, default_value = "aegis", value_name = "NETWORK")]
    pub network: String,

    #[arg(
        long,
        short = 'u',
        value_name = "USER",
        help = "Remote Unix principal to log in as"
    )]
    pub user: Option<String>,
}

#[derive(Debug, Args)]
#[command(infer_subcommands = true)]
pub struct TunnelArgs {
    #[command(subcommand)]
    pub command: TunnelCommands,
}

#[derive(Debug, Subcommand)]
pub enum TunnelCommands {
    #[command(
        name = "via",
        about = "Route Internet traffic through the selected Aegis host and fail closed if it is unavailable."
    )]
    Via(TunnelViaArgs),

    #[command(
        name = "disable",
        about = "Stop routing Internet traffic through another Aegis host."
    )]
    Disable,

    #[command(name = "status", about = "Show this machine's Internet tunnel status.")]
    Status(TunnelStatusArgs),
}

#[derive(Debug, Args)]
pub struct TunnelViaArgs {
    #[arg(value_name = "ALIAS")]
    pub alias: HostAlias,

    #[arg(
        long,
        help = "Test IPv4, IPv6 and DNS in a temporary network namespace; leave system routing and tunnel selection unchanged"
    )]
    pub isolated: bool,
}

#[derive(Debug, Args)]
pub struct TunnelStatusArgs {
    #[arg(long, help = "Print the complete tunnel status as JSON")]
    pub json: bool,
}

#[derive(Debug, Args)]
#[command(infer_subcommands = true)]
pub struct SatelliteArgs {
    #[command(subcommand)]
    pub command: SatelliteCommands,
}

#[derive(Debug, Subcommand)]
pub enum SatelliteCommands {
    #[command(
        name = "pair",
        about = "Create a persistent satellite identity and its import credentials."
    )]
    Pair(SatellitePairArgs),

    #[command(name = "list", about = "List paired satellites.")]
    List,

    #[command(name = "show", about = "Show a satellite's non-secret metadata.")]
    Show(SatelliteSlugArgs),

    #[command(name = "revoke", about = "Revoke a satellite globally.")]
    Revoke(SatelliteSlugArgs),
}

#[derive(Debug, Args)]
pub struct SatellitePairArgs {
    #[arg(value_name = "SLUG")]
    pub slug: String,

    #[arg(
        long,
        value_name = "DIRECTORY",
        help = "Persist the credential bundle to this directory; otherwise nothing is written to disk"
    )]
    pub out: Option<PathBuf>,

    #[arg(
        long,
        requires = "out",
        help = "Do not print import QR codes (requires --out)"
    )]
    pub no_qr: bool,
}

#[derive(Debug, Args)]
pub struct SatelliteSlugArgs {
    #[arg(value_name = "SLUG")]
    pub slug: String,
}

#[derive(Debug, Args)]
pub struct UnenrollArgs {
    #[arg(value_name = "HOST")]
    pub host: String,

    #[arg(
        long,
        value_name = "[USER@]HOST[:PORT]",
        conflicts_with_all = ["local", "orphan"],
        required_unless_present_any = ["local", "orphan"],
        help = "Remove aegis from a remote host over SSH"
    )]
    pub remote: Option<String>,

    #[arg(
        long,
        value_name = "TOKEN",
        help = "Use this API token to remove the host record when local agent auth is unavailable"
    )]
    pub api_token: Option<String>,

    #[arg(
        long,
        conflicts_with_all = ["remote", "orphan"],
        help = "Remove aegis from the current machine instead of connecting to a remote host"
    )]
    pub local: bool,

    #[arg(
        long,
        conflicts_with_all = ["remote", "local", "skip_api_delete"],
        help = "Remove a lost or unreachable host from the Aegis control plane without connecting to it"
    )]
    pub orphan: bool,

    #[arg(
        long,
        short = 'u',
        value_name = "USER",
        requires = "remote",
        help = "Remote SSH user when omitted from the target"
    )]
    pub user: Option<String>,

    #[arg(
        long,
        short = 'p',
        value_name = "PORT",
        requires = "remote",
        help = "Remote SSH port when omitted from the target"
    )]
    pub port: Option<u16>,

    #[arg(long, hide = true, conflicts_with = "orphan")]
    pub skip_api_delete: bool,
}

#[derive(Debug, Args)]
pub struct LockdownArgs {
    #[command(subcommand)]
    pub command: LockdownCommands,
}

#[derive(Debug, Subcommand)]
pub enum LockdownCommands {
    #[command(
        name = "enable",
        about = "Enable managed certificate-only SSH lockdown."
    )]
    Enable(LockdownEnableArgs),

    #[command(name = "disable", about = "Disable managed SSH lockdown.")]
    Disable,

    #[command(name = "status", about = "Inspect managed SSH lockdown without root.")]
    Status,
}

#[derive(Debug, Args)]
pub struct LockdownEnableArgs {
    #[arg(
        long,
        short = 'u',
        value_name = "USER",
        help = "Remote Unix principal to use for lockdown SSH preflight"
    )]
    pub user: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Choice {
    Yes,
    No,
}

impl Choice {
    pub const fn as_bool(self) -> bool {
        matches!(self, Self::Yes)
    }
}

#[derive(Debug, Args)]
pub struct EnrollArgs {
    /// Enrollment invitation; includes the API endpoint and namespace.
    #[arg(long, value_name = "FILE", conflicts_with = "name")]
    pub invitation: Option<PathBuf>,

    /// Host alias for an enrollment created using your signed-in administrator account.
    #[arg(long)]
    pub name: Option<HostAlias>,

    #[arg(
        long,
        value_name = "[USER@]HOST[:PORT]",
        conflicts_with = "local",
        required_unless_present = "local",
        help = "Bootstrap aegis onto a remote host over SSH"
    )]
    pub remote: Option<String>,

    #[arg(
        long,
        conflicts_with = "remote",
        help = "Enroll the current machine instead of connecting to a remote host"
    )]
    pub local: bool,

    #[arg(
        long,
        short = 'u',
        value_name = "USER",
        requires = "remote",
        help = "Remote SSH user when omitted from the target"
    )]
    pub user: Option<String>,

    #[arg(
        long,
        short = 'p',
        value_name = "PORT",
        requires = "remote",
        help = "Remote SSH port when omitted from the target"
    )]
    pub port: Option<u16>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum AgentMode {
    Leaf,
    Hub,
}

impl AgentMode {
    pub const fn is_hub(self) -> bool {
        matches!(self, Self::Hub)
    }
}

#[derive(Debug, Args)]
pub struct AgentArgs {
    #[arg(
        long,
        value_name = "PATH",
        default_value = aegis_dto::layout::AGENT_CONFIG_PATH,
        help = "Path to the aegis-agent configuration file"
    )]
    pub config: PathBuf,

    #[arg(long, hide = true)]
    pub once: bool,
}

#[derive(Debug, Args)]
pub struct AgentNamespaceArgs {
    #[command(subcommand)]
    pub command: AgentCommands,
}

#[derive(Debug, Subcommand)]
pub enum AgentCommands {
    Serve(AgentArgs),

    #[command(hide = true)]
    DirectSsh,

    #[command(flatten)]
    Lifecycle(AgentLifecycleCommand),

    #[command(hide = true)]
    EgressProbeWorker,
}

#[cfg(test)]
mod tests {
    use crate::ui::{UiColorMode, UiProgressMode};
    use std::path::PathBuf;

    use super::{
        AdvancedCommands, AgentTokenCommands, Cli, Commands, FleetCommands, HostAliasCommands,
        HostCommands, ManageCommands, PrincipalCommands, SatelliteCommands, TunnelCommands,
    };
    use clap::{CommandFactory, Parser};

    #[test]
    fn cli_infers_top_level_subcommands() {
        let cli = Cli::try_parse_from(["aegis", "ss", "alpha"])
            .expect("top-level ssh subcommand should infer");
        assert!(matches!(cli.command, Commands::Ssh(_)));
    }

    #[test]
    fn top_level_help_places_advanced_after_manage() {
        let help = Cli::command().render_long_help().to_string();
        assert!(!help.contains("\n  agent "));
        let manage = help.find("\n  manage ").expect("manage help entry");
        let advanced = help.find("\n  advanced ").expect("advanced help entry");
        let help_command = help.find("\n  help ").expect("help command entry");
        assert!(manage < advanced);
        assert!(advanced < help_command);
    }

    #[test]
    fn hidden_agent_endpoints_parse_under_the_single_binary() {
        let cli = Cli::try_parse_from(["aegis", "agent", "direct-ssh"])
            .expect("hidden direct SSH endpoint should parse");
        assert!(matches!(
            cli.command,
            Commands::Agent(super::AgentNamespaceArgs {
                command: super::AgentCommands::DirectSsh
            })
        ));

        Cli::try_parse_from(["aegis", "agent", "installation-manifest"])
            .expect("embedded Capulus lifecycle endpoint should parse");
    }

    #[test]
    fn cli_accepts_global_progress_and_color_modes() {
        let cli = Cli::try_parse_from(["aegis", "--progress", "plain", "--color", "never", "list"])
            .expect("global UI options should parse");
        assert_eq!(UiProgressMode::Plain, cli.ui.progress);
        assert_eq!(UiColorMode::Never, cli.ui.color);
    }

    #[test]
    fn cli_ui_handles_signals_for_interactive_commands() {
        let list = Cli::try_parse_from(["aegis", "list"]).expect("list command should parse");
        assert_eq!(
            capulus::ui::CancellationMode::Signal,
            list.ui.options().cancellation
        );
    }

    #[test]
    fn cli_rejects_removed_transitional_commands_and_options() {
        for command in [
            vec!["aegis", "agent"],
            vec!["aegis", "advanced", "finalize-systemd-cutover"],
            vec!["aegis", "advanced", "fleet", "finalize-systemd-cutover"],
            vec!["aegis", "advanced", "install", "--skip-rustup-update"],
            vec!["aegis", "advanced", "redeploy", "--skip-rustup-update"],
        ] {
            Cli::try_parse_from(command).expect_err("removed transitional CLI must be rejected");
        }
    }

    #[test]
    fn cli_requires_a_positive_browser_callback_timeout() {
        assert!(
            Cli::try_parse_from(["aegis", "manage", "login", "--wait-timeout-secs", "0",]).is_err()
        );
    }

    #[test]
    fn cli_parses_principal_allow_command() {
        let cli = Cli::try_parse_from(["aegis", "manage", "principal", "allow", "OpaqueUserID"])
            .expect("principal allow command should parse");

        let Commands::Manage(args) = cli.command else {
            panic!("expected manage command");
        };
        let ManageCommands::Principal(args) = args.command else {
            panic!("expected manage principal command");
        };
        let PrincipalCommands::Allow(args) = args.command else {
            panic!("expected principal allow command");
        };
        assert_eq!("OpaqueUserID", args.user_id);
    }

    #[test]
    fn cli_groups_agent_token_actions() {
        let cli = Cli::try_parse_from([
            "aegis",
            "manage",
            "agent-token",
            "issue",
            "host-a",
            "--json",
        ])
        .expect("agent-token issue should parse");
        let Commands::Manage(args) = cli.command else {
            panic!("expected manage command");
        };
        let ManageCommands::AgentToken(args) = args.command else {
            panic!("expected agent-token command");
        };
        let AgentTokenCommands::Issue(args) = args.command else {
            panic!("expected agent-token issue command");
        };
        assert_eq!("host-a", args.host);
        assert!(args.json);

        for action in ["rotate", "revoke"] {
            Cli::try_parse_from(["aegis", "manage", "agent-token", action])
                .unwrap_or_else(|error| panic!("agent-token {action} should parse: {error}"));
        }
    }

    #[test]
    fn cli_parses_json_host_inventory_command() {
        let cli = Cli::try_parse_from(["aegis", "manage", "host", "list", "--json"])
            .expect("host inventory command should parse");
        let Commands::Manage(args) = cli.command else {
            panic!("expected manage command");
        };
        let ManageCommands::Host(args) = args.command else {
            panic!("expected host command");
        };
        let HostCommands::List(args) = args.command else {
            panic!("expected host list command");
        };
        assert!(args.json);
    }

    #[test]
    fn cli_parses_host_alias_promotion() {
        let cli = Cli::try_parse_from([
            "aegis",
            "manage",
            "host",
            "alias",
            "promote",
            "new-name",
            "--propagation-wait-secs",
            "45",
        ])
        .expect("promote command should parse");
        let Commands::Manage(args) = cli.command else {
            panic!("expected manage command");
        };
        let ManageCommands::Host(args) = args.command else {
            panic!("expected host command");
        };
        let HostCommands::Alias(args) = args.command else {
            panic!("expected host alias command");
        };
        let HostAliasCommands::Promote(args) = args.command else {
            panic!("expected promote command");
        };
        assert_eq!("new-name", args.alias.as_str());
        assert_eq!(45, args.wait.propagation_wait_secs);
        assert!(!args.wait.no_wait);
    }

    #[test]
    fn cli_allows_alias_mutations_to_skip_convergence_wait_explicitly() {
        let cli = Cli::try_parse_from([
            "aegis",
            "manage",
            "host",
            "alias",
            "add",
            "new-name",
            "old-name",
            "--no-wait",
        ])
        .expect("--no-wait should override the default propagation wait");
        let Commands::Manage(args) = cli.command else {
            panic!("expected manage command");
        };
        let ManageCommands::Host(args) = args.command else {
            panic!("expected host command");
        };
        let HostCommands::Alias(args) = args.command else {
            panic!("expected host alias command");
        };
        let HostAliasCommands::Add(args) = args.command else {
            panic!("expected add command");
        };
        assert_eq!("new-name", args.alias.as_str());
        assert_eq!("old-name", args.host);
        assert!(args.wait.no_wait);
    }

    #[test]
    fn cli_parses_local_tunnel_commands() {
        let cli = Cli::try_parse_from(["aegis", "tunnel", "via", "leaf-a"])
            .expect("tunnel via command should parse");
        let Commands::Tunnel(args) = cli.command else {
            panic!("expected tunnel command");
        };
        let TunnelCommands::Via(args) = args.command else {
            panic!("expected tunnel via command");
        };
        assert_eq!("leaf-a", args.alias.as_str());

        let cli = Cli::try_parse_from(["aegis", "tunnel", "status", "--json"])
            .expect("tunnel status command should parse");
        let Commands::Tunnel(args) = cli.command else {
            panic!("expected tunnel command");
        };
        let TunnelCommands::Status(args) = args.command else {
            panic!("expected tunnel status command");
        };
        assert!(args.json);

        let cli = Cli::try_parse_from(["aegis", "tunnel", "disable"])
            .expect("tunnel disable command should parse");
        assert!(matches!(
            cli.command,
            Commands::Tunnel(super::TunnelArgs {
                command: TunnelCommands::Disable
            })
        ));

        assert!(Cli::try_parse_from(["aegis", "tunnel", "via"]).is_err());
        assert!(Cli::try_parse_from(["aegis", "manage", "egress", "enable", "leaf-a"]).is_err());
    }

    #[test]
    fn cli_parses_ssh_login_principal() {
        let cli = Cli::try_parse_from(["aegis", "ssh", "--user", "root", "alpha"])
            .expect("ssh --user should parse");

        let Commands::Ssh(args) = cli.command else {
            panic!("expected ssh command");
        };
        assert_eq!(Some("root".to_string()), args.user);
        assert_eq!(Some("alpha".to_string()), args.host);
    }

    #[test]
    fn cli_allows_interactive_ssh_without_a_host() {
        let cli = Cli::try_parse_from(["aegis", "ssh"]).expect("interactive SSH should parse");
        let Commands::Ssh(args) = cli.command else {
            panic!("expected ssh command");
        };
        assert!(args.host.is_none());
    }

    #[test]
    fn cli_pairs_a_global_satellite_without_a_hub_argument() {
        let cli = Cli::try_parse_from(["aegis", "manage", "satellite", "pair", "pocket-a"])
            .expect("global satellite pair should parse");
        let Commands::Manage(args) = cli.command else {
            panic!("expected manage command");
        };
        let ManageCommands::Satellite(args) = args.command else {
            panic!("expected satellite command");
        };
        let SatelliteCommands::Pair(args) = args.command else {
            panic!("expected satellite pair command");
        };
        assert_eq!(args.slug, "pocket-a");
        assert!(args.out.is_none());
        assert!(!args.no_qr);
    }

    #[test]
    fn cli_requires_explicit_output_when_satellite_qrs_are_disabled() {
        assert!(
            Cli::try_parse_from([
                "aegis",
                "manage",
                "satellite",
                "pair",
                "pocket-a",
                "--no-qr",
            ])
            .is_err()
        );

        let cli = Cli::try_parse_from([
            "aegis",
            "manage",
            "satellite",
            "pair",
            "pocket-a",
            "--out",
            "/tmp/pocket-a",
            "--no-qr",
        ])
        .expect("explicit satellite output should allow suppressing QR codes");
        let Commands::Manage(args) = cli.command else {
            panic!("expected manage command");
        };
        let ManageCommands::Satellite(args) = args.command else {
            panic!("expected satellite command");
        };
        let SatelliteCommands::Pair(args) = args.command else {
            panic!("expected satellite pair command");
        };
        assert_eq!(args.out, Some(PathBuf::from("/tmp/pocket-a")));
        assert!(args.no_qr);
    }

    #[test]
    fn cli_exposes_lockdown_actions_as_subcommands() {
        for action in ["enable", "disable", "status"] {
            Cli::try_parse_from(["aegis", "manage", "lockdown", action])
                .unwrap_or_else(|error| panic!("lockdown {action} should parse: {error}"));
        }
    }

    #[test]
    fn cli_parses_push_transfer_command() {
        let cli = Cli::try_parse_from([
            "aegis",
            "push",
            "--delete",
            "--fail-if-exists",
            "--rsync-arg",
            "--exclude=target",
            "alpha",
            "src/",
            "/srv/app",
        ])
        .expect("push command should parse");

        let Commands::Push(args) = cli.command else {
            panic!("expected push command");
        };
        assert_eq!("alpha", args.host);
        assert!(args.delete);
        assert!(args.fail_if_exists);
        assert_eq!(vec!["src/", "/srv/app"], args.paths);
        assert_eq!(vec!["--exclude=target"], args.rsync_args);
    }

    #[test]
    fn cli_parses_pull_transfer_command() {
        let cli = Cli::try_parse_from([
            "aegis",
            "pull",
            "--no-compress",
            "--no-checksum",
            "alpha",
            "/var/log/app/",
        ])
        .expect("pull command should parse");

        let Commands::Pull(args) = cli.command else {
            panic!("expected pull command");
        };
        assert_eq!("alpha", args.host);
        assert!(args.no_compress);
        assert!(args.no_checksum);
        assert_eq!(vec!["/var/log/app/"], args.paths);
    }

    #[test]
    fn cli_infers_advanced_subcommands() {
        let cli = Cli::try_parse_from(["aegis", "adv", "refresh-c"])
            .expect("nested advanced refresh-credentials subcommand should infer");
        assert!(matches!(
            cli.command,
            Commands::Advanced(crate::cli::AdvancedArgs {
                command: AdvancedCommands::RefreshCredentials(_)
            })
        ));

        let cli = Cli::try_parse_from(["aegis", "adv", "recon"])
            .expect("nested advanced reconcile subcommand should infer");
        assert!(matches!(
            cli.command,
            Commands::Advanced(crate::cli::AdvancedArgs {
                command: AdvancedCommands::Reconcile(_)
            })
        ));

        assert!(Cli::try_parse_from(["aegis", "manage", "install"]).is_err());
        assert!(Cli::try_parse_from(["aegis", "manage", "reconcile"]).is_err());
    }

    #[test]
    fn cli_parses_waiting_redeploy() {
        let cli = Cli::try_parse_from(["aegis", "advanced", "redeploy", "--wait"])
            .expect("waiting redeploy should parse");
        let Commands::Advanced(args) = cli.command else {
            panic!("expected advanced command");
        };
        let AdvancedCommands::Redeploy(args) = args.command else {
            panic!("expected redeploy command");
        };
        assert!(args.wait);
        assert!(args.version.is_none());
    }

    #[test]
    fn cli_allows_fleet_redeploy_without_a_version() {
        let cli = Cli::try_parse_from(["aegis", "advanced", "fleet", "redeploy"])
            .expect("fleet redeploy should default to the latest registry version");
        let Commands::Advanced(args) = cli.command else {
            panic!("expected advanced command");
        };
        let AdvancedCommands::Fleet(args) = args.command else {
            panic!("expected fleet command");
        };
        let FleetCommands::Redeploy(args) = args.command;
        assert!(args.version.is_none());

        let cli = Cli::try_parse_from([
            "aegis",
            "advanced",
            "fleet",
            "redeploy",
            "--version",
            "1.2.3",
        ])
        .expect("fleet redeploy should accept an exact version");
        let Commands::Advanced(args) = cli.command else {
            panic!("expected advanced command");
        };
        let AdvancedCommands::Fleet(args) = args.command else {
            panic!("expected fleet command");
        };
        let FleetCommands::Redeploy(args) = args.command;
        assert_eq!(Some("1.2.3"), args.version.as_deref());
    }

    #[test]
    fn cli_parses_remote_login_roles() {
        let cli = Cli::try_parse_from(["aegis", "manage", "login", "--remote-auth"])
            .expect("remote login initiator should parse");
        let Commands::Manage(args) = cli.command else {
            panic!("expected manage command");
        };
        let ManageCommands::Login(args) = args.command else {
            panic!("expected login command");
        };
        assert!(args.remote_auth);
        assert!(args.remote_auth_relay.is_none());

        let cli =
            Cli::try_parse_from(["aegis", "manage", "login", "--remote-auth-relay", "request"])
                .expect("remote login relay should parse");
        let Commands::Manage(args) = cli.command else {
            panic!("expected manage command");
        };
        let ManageCommands::Login(args) = args.command else {
            panic!("expected login command");
        };
        assert!(!args.remote_auth);
        assert_eq!(Some("request".to_string()), args.remote_auth_relay);
    }

    #[test]
    fn cli_rejects_ambiguous_manage_prefixes() {
        let error = Cli::try_parse_from(["aegis", "manage", "l"])
            .expect_err("ambiguous prefix should fail");
        assert!(
            error.to_string().contains("unrecognized subcommand")
                || error.to_string().contains("ambiguous"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn cli_parses_ssh_network() {
        let cli = Cli::try_parse_from(["aegis", "ssh", "--network", "deus", "alpha"])
            .expect("ssh --network should parse");

        let Commands::Ssh(args) = cli.command else {
            panic!("expected ssh command");
        };
        assert_eq!("deus", args.network);
        assert_eq!(Some("alpha".to_string()), args.host);
    }

    #[test]
    fn cli_parses_orphan_unenroll_without_remote_target() {
        let cli = Cli::try_parse_from(["aegis", "manage", "unenroll", "lost-host", "--orphan"])
            .expect("orphan unenroll should parse without a remote target");
        let Commands::Manage(args) = cli.command else {
            panic!("expected manage command");
        };
        let ManageCommands::Unenroll(args) = args.command else {
            panic!("expected unenroll command");
        };
        assert_eq!("lost-host", args.host);
        assert!(args.orphan);
        assert!(args.remote.is_none());
        assert!(!args.local);
    }

    #[test]
    fn cli_parses_control_plane_reconciliation_commands() {
        let cli = Cli::try_parse_from(["aegis", "manage", "sync-dns", "--dry-run", "--json"])
            .expect("DNS sync command should parse");
        let Commands::Manage(args) = cli.command else {
            panic!("expected manage command");
        };
        let ManageCommands::SyncDns(args) = args.command else {
            panic!("expected sync-dns command");
        };
        assert!(args.dry_run);
        assert!(args.json);

        let cli = Cli::try_parse_from([
            "aegis",
            "manage",
            "sync-tls",
            "--file",
            "desired.json",
            "--dry-run",
        ])
        .expect("TLS sync command should parse");
        let Commands::Manage(args) = cli.command else {
            panic!("expected manage command");
        };
        let ManageCommands::SyncTls(args) = args.command else {
            panic!("expected sync-tls command");
        };
        assert_eq!(std::path::Path::new("desired.json"), args.file);
        assert!(args.dry_run);
        assert!(!args.json);
    }

    #[test]
    fn cli_parses_agent_token_lifecycle_commands() {
        let cli = Cli::try_parse_from([
            "aegis",
            "manage",
            "agent-token",
            "issue",
            "new-host",
            "--json",
        ])
        .expect("agent token issue command should parse");
        let Commands::Manage(args) = cli.command else {
            panic!("expected manage command");
        };
        let ManageCommands::AgentToken(args) = args.command else {
            panic!("expected agent-token command");
        };
        let AgentTokenCommands::Issue(args) = args.command else {
            panic!("expected agent-token issue command");
        };
        assert_eq!("new-host", args.host);
        assert!(args.json);

        let cli = Cli::try_parse_from([
            "aegis",
            "manage",
            "agent-token",
            "revoke",
            "--token-file",
            "-",
        ])
        .expect("agent token revoke command should parse");
        let Commands::Manage(args) = cli.command else {
            panic!("expected manage command");
        };
        let ManageCommands::AgentToken(args) = args.command else {
            panic!("expected agent-token command");
        };
        let AgentTokenCommands::Revoke(args) = args.command else {
            panic!("expected agent-token revoke command");
        };
        assert_eq!(Some(std::path::Path::new("-")), args.token_file.as_deref());
    }

    #[test]
    fn cli_rejects_orphan_unenroll_with_host_cleanup_modes() {
        for mode in ["--local", "--remote"] {
            let mut argv = vec!["aegis", "manage", "unenroll", "lost-host", "--orphan", mode];
            if mode == "--remote" {
                argv.push("root@lost-host");
            }
            Cli::try_parse_from(argv)
                .expect_err("orphan unenroll must not connect to the target machine");
        }
    }
}
