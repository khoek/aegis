use aegis_dto::{
    AegisHostMode, HostAlias, HostAliases, HostId,
    protocol::{
        AegisAgentStatus, AegisDirectGatewayReport, AegisEnrollmentPhase, AegisEnrollmentSsh,
        AegisHostMessage, AegisNetworkConfig, AegisObservedPublicIps, AegisPrincipalGrant,
        AegisWireGuardAddressPool,
    },
};
use std::net::IpAddr;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AegisHostRecordSsh {
    pub port: Option<u16>,
    pub public_key: Option<String>,
    pub external_principals: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AegisHostRecord {
    pub platform: aegis_dto::platform::HostPlatform,
    pub host_id: HostId,
    pub aliases: HostAliases,
    pub ssh: Option<AegisHostRecordSsh>,
    pub egress_public_key: Option<String>,
    pub messages: Vec<AegisHostMessage>,
    pub agent: Option<AegisAgentStatus>,
    pub principal_grants: Vec<AegisPrincipalGrant>,
    pub ssh_lockdown_enabled: Option<bool>,
    pub direct_gateway_report: Option<AegisDirectGatewayReport>,
    pub observed_public_ips: AegisObservedPublicIps,
    pub transient: bool,
    pub pending: bool,
    pub created_unix: i64,
    pub updated_unix: i64,
    pub updated_by_principal: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AegisEnrollmentRecord {
    pub host_id: HostId,
    pub aliases: HostAliases,
    pub network: String,
    pub mode: AegisHostMode,
    pub ssh: Option<AegisEnrollmentSsh>,
    pub transient: bool,
    pub initial_user_id: String,
    pub phase: AegisEnrollmentPhase,
    pub credential_session_id: Option<String>,
    pub created_unix: i64,
    pub expires_unix: i64,
    pub updated_unix: i64,
    pub created_by_principal: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AegisEnrollmentPrepared {
    pub enrollment: AegisEnrollmentRecord,
    pub host: AegisHostRecord,
    pub member: AegisNetworkMemberRecord,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AegisEnrollmentPreparation<'a> {
    pub platform: aegis_dto::platform::HostPlatform,
    pub host_public_key: Option<&'a str>,
    pub wireguard_public_key: &'a str,
    pub wireguard_endpoints: &'a [String],
    pub network: &'a AegisNetworkConfig,
    pub updated_unix: i64,
}

pub(crate) fn enrollment_phase_rank(phase: AegisEnrollmentPhase) -> u8 {
    match phase {
        AegisEnrollmentPhase::AwaitingMachine => 0,
        AegisEnrollmentPhase::PreparingMachine => 1,
        AegisEnrollmentPhase::Prepared => 2,
        AegisEnrollmentPhase::InstallingAgent => 3,
        AegisEnrollmentPhase::Activating => 4,
    }
}

pub(crate) fn validate_current_enrollment(
    enrollment: &AegisEnrollmentRecord,
    credential_session_id: &str,
    now_unix: i64,
) -> Result<(), AegisEnrollmentWriteError> {
    if now_unix >= enrollment.expires_unix {
        return Err(AegisEnrollmentWriteError::Expired {
            host_id: enrollment.host_id,
            expires_unix: enrollment.expires_unix,
        });
    }
    match enrollment.credential_session_id.as_deref() {
        None => Err(AegisEnrollmentWriteError::CredentialMissing {
            host_id: enrollment.host_id,
        }),
        Some(current) if current != credential_session_id => {
            Err(AegisEnrollmentWriteError::CredentialMismatch {
                host_id: enrollment.host_id,
            })
        }
        Some(_) => Ok(()),
    }
}

pub(crate) fn prepared_host_matches_enrollment(
    enrollment: &AegisEnrollmentRecord,
    host: &AegisHostRecord,
    member: &AegisNetworkMemberRecord,
) -> bool {
    host.host_id == enrollment.host_id
        && host.aliases == enrollment.aliases
        && host.transient == enrollment.transient
        && member.host_id == enrollment.host_id
        && member.mode == enrollment.mode
        && match (&enrollment.ssh, &host.ssh) {
            (None, None) => true,
            (Some(expected), Some(actual)) => {
                actual.public_key.is_some()
                    && expected.port == actual.port
                    && expected.external_principals == actual.external_principals
            }
            _ => false,
        }
}

pub(crate) fn validate_enrollment_host_public_key(
    enrollment: &AegisEnrollmentRecord,
    host_public_key: Option<&str>,
) -> Result<(), AegisEnrollmentWriteError> {
    match (enrollment.ssh.is_some(), host_public_key.is_some()) {
        (true, false) => Err(AegisEnrollmentWriteError::SshHostPublicKeyRequired {
            host_id: enrollment.host_id,
        }),
        (false, true) => Err(AegisEnrollmentWriteError::SshHostPublicKeyUnexpected {
            host_id: enrollment.host_id,
        }),
        _ => Ok(()),
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AegisHostReportUpdate {
    pub messages: Vec<AegisHostMessage>,
    pub agent: AegisAgentStatus,
    pub principal_grants: Vec<AegisPrincipalGrant>,
    pub ssh_lockdown_enabled: bool,
    pub direct_gateway_report: AegisDirectGatewayReport,
    pub observed_public_ip: Option<(IpAddr, i64)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AegisUserIdentity {
    pub user_id: String,
    pub disabled: bool,
    pub admin: bool,
}

pub(crate) fn merge_direct_gateway_handshakes(
    previous: Option<&AegisDirectGatewayReport>,
    mut current: AegisDirectGatewayReport,
) -> AegisDirectGatewayReport {
    let previous_handshakes = previous
        .into_iter()
        .flat_map(|report| &report.peers)
        .filter_map(|peer| {
            peer.latest_handshake_unix
                .map(|handshake| (peer.public_key.as_str(), handshake))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    for peer in &mut current.peers {
        peer.latest_handshake_unix = peer
            .latest_handshake_unix
            .max(previous_handshakes.get(peer.public_key.as_str()).copied());
    }
    current
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AegisNetworkMemberRecord {
    pub host_id: HostId,
    pub mode: AegisHostMode,
    pub wireguard_public_key: Option<String>,
    pub wireguard_ipv4: Option<String>,
    pub wireguard_ipv6: Option<String>,
    pub wireguard_endpoints: Vec<String>,
    pub internal_ipv4: Option<String>,
    pub internal_ipv6: Option<String>,
    pub pending: bool,
    pub created_unix: i64,
    pub updated_unix: i64,
    pub updated_by_principal: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AegisDirectWireGuardRecord {
    pub public_key: String,
    pub ipv4: String,
    pub ipv6: String,
    pub endpoints: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AegisDirectGatewayRecord {
    pub host_id: HostId,
    pub wireguard: AegisDirectWireGuardRecord,
    pub created_unix: i64,
    pub updated_unix: i64,
    pub updated_by_principal: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AegisSatelliteRecord {
    pub slug: String,
    pub credential_id: String,
    pub owner_principal: String,
    pub wireguard: AegisDirectWireGuardRecord,
    pub ssh_public_key: String,
    pub created_unix: i64,
    pub created_by_principal: String,
    pub broker_uses: std::collections::BTreeMap<HostId, AegisSatelliteBrokerUseRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AegisSatelliteBrokerUseRecord {
    pub used_unix: i64,
    pub gateway_host_id: HostId,
    pub target_host_id: HostId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AegisDirectLeaseRecord {
    pub id: String,
    pub wireguard: AegisDirectWireGuardRecord,
}

#[derive(Debug, Error)]
pub(crate) enum AegisDirectWriteError {
    #[error("direct resource `{resource}` already exists")]
    AlreadyExists { resource: String },
    #[error("satellite name `{alias}` is already an alias of host `{host_id}`")]
    HostAliasExists { alias: HostAlias, host_id: HostId },
    #[error("WireGuard public key is already assigned to direct resource `{resource}`")]
    DuplicatePublicKey { resource: String },
    #[error("aegis direct-resource write conflicted with another concurrent write")]
    ConcurrentWrite,
    #[error("no direct addresses remain available in `{subnet_ipv4}` / `{subnet_ipv6}`")]
    NoAvailableAddress {
        subnet_ipv4: String,
        subnet_ipv6: String,
    },
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub(crate) enum AegisHostWriteError {
    #[error("host `{host_id}` does not exist")]
    NotFound { host_id: HostId },
    #[error("host `{host_id}` is controlled by an outstanding enrollment")]
    EnrollmentPending { host_id: HostId },
    #[error("aegis host write conflicted with another concurrent write")]
    ConcurrentWrite,
    #[error("host aliases must be changed through the add, promote, and remove alias operations")]
    AliasesChanged,
    #[error("{0}")]
    InvalidWireguardIdentity(String),
    #[error("wireguard_ipv4 `{wireguard_ipv4}` is already assigned to host `{host_id}`")]
    DuplicateWireguardIpv4 {
        host_id: HostId,
        wireguard_ipv4: String,
    },
    #[error("wireguard_ipv6 `{wireguard_ipv6}` is already assigned to host `{host_id}`")]
    DuplicateWireguardIpv6 {
        host_id: HostId,
        wireguard_ipv6: String,
    },
    #[error("egress public key is already assigned to host `{host_id}`")]
    DuplicateEgressPublicKey { host_id: HostId },
    #[error("internal_ipv4 `{internal_ipv4}` is already assigned to host `{host_id}`")]
    DuplicateInternalIpv4 {
        host_id: HostId,
        internal_ipv4: String,
    },
    #[error("internal_ipv6 `{internal_ipv6}` is already assigned to host `{host_id}`")]
    DuplicateInternalIpv6 {
        host_id: HostId,
        internal_ipv6: String,
    },
    #[error("no internal IP pairs remain available in `{subnet_ipv4}` / `{subnet_ipv6}`")]
    NoAvailableInternalIp {
        subnet_ipv4: String,
        subnet_ipv6: String,
    },
    #[error("no WireGuard host ids remain available in `{subnet_ipv4}` / `{subnet_ipv6}`")]
    NoAvailableWireguardHostId {
        subnet_ipv4: String,
        subnet_ipv6: String,
    },
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub(crate) enum AegisEgressWriteError {
    #[error("egress policy `{source_host_id}` does not exist")]
    NotFound { source_host_id: HostId },
    #[error("egress policy `{source_host_id}` changed concurrently")]
    ConcurrentWrite { source_host_id: HostId },
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Clone, Debug)]
pub(crate) struct AegisEgressSnapshot {
    pub generation: u64,
    pub policies: Vec<aegis_dto::protocol::AegisEgressPolicy>,
}

#[derive(Debug, Error)]
pub(crate) enum AegisHostDeleteError {
    #[error(
        "host `{host_id}` is controlled by an outstanding enrollment; cancel the enrollment instead"
    )]
    EnrollmentPending { host_id: HostId },
    #[error("host `{host_id}` is still selected as egress by: {source_host_ids:?}")]
    EgressTargetInUse {
        host_id: HostId,
        source_host_ids: Vec<HostId>,
    },
    #[error("host deletion changed concurrently")]
    ConcurrentWrite,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub(crate) enum AegisAliasWriteError {
    #[error("host `{host_id}` does not exist")]
    HostNotFound { host_id: HostId },
    #[error("host `{host_id}` aliases are controlled by an outstanding enrollment")]
    EnrollmentPending { host_id: HostId },
    #[error("host alias `{alias}` is already assigned to host `{host_id}`")]
    AlreadyAssigned { alias: HostAlias, host_id: HostId },
    #[error("host alias `{alias}` is already assigned to a satellite")]
    AssignedToSatellite { alias: HostAlias },
    #[error("host `{host_id}` does not have alias `{alias}`")]
    AliasNotFound { host_id: HostId, alias: HostAlias },
    #[error("{0}")]
    InvalidAliases(#[from] aegis_dto::InvalidHostAliases),
    #[error("host alias update changed concurrently")]
    ConcurrentWrite,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub(crate) enum AegisEnrollmentWriteError {
    #[error("enrollment for host `{host_id}` already exists")]
    AlreadyExists { host_id: HostId },
    #[error("enrollment for host `{host_id}` does not exist")]
    NotFound { host_id: HostId },
    #[error("host `{host_id}` is already enrolled")]
    HostAlreadyExists { host_id: HostId },
    #[error("enrollment for host `{host_id}` expired at {expires_unix}")]
    Expired { host_id: HostId, expires_unix: i64 },
    #[error("enrollment for host `{host_id}` has no issued credential")]
    CredentialMissing { host_id: HostId },
    #[error("the enrollment credential for host `{host_id}` is not the current credential")]
    CredentialMismatch { host_id: HostId },
    #[error("host alias `{alias}` is already assigned to host `{host_id}`")]
    AliasAlreadyAssigned { alias: HostAlias, host_id: HostId },
    #[error("host alias `{alias}` is already assigned to a satellite")]
    AliasAssignedToSatellite { alias: HostAlias },
    #[error("enrollment for host `{host_id}` has not prepared its machine identity")]
    NotPrepared { host_id: HostId },
    #[error("enrollment for host `{host_id}` requires an SSH host public key")]
    SshHostPublicKeyRequired { host_id: HostId },
    #[error("enrollment for host `{host_id}` does not permit an SSH host public key")]
    SshHostPublicKeyUnexpected { host_id: HostId },
    #[error("prepared host `{host_id}` is inconsistent with its enrollment")]
    InconsistentPreparedHost { host_id: HostId },
    #[error("aegis enrollment changed concurrently")]
    ConcurrentWrite,
    #[error(transparent)]
    Host(#[from] AegisHostWriteError),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[async_trait::async_trait]
pub(crate) trait AegisStore {
    async fn user_session_active(
        &self,
        claims: &phylax_core::AccessClaims,
        now: i64,
    ) -> anyhow::Result<bool>;

    async fn fetch_aegis_user_by_id(
        &self,
        user_id: &str,
    ) -> anyhow::Result<Option<AegisUserIdentity>>;

    async fn list_aegis_enrollments(&self) -> anyhow::Result<Vec<AegisEnrollmentRecord>>;
    async fn fetch_aegis_enrollment(
        &self,
        host_id: &HostId,
    ) -> anyhow::Result<Option<AegisEnrollmentRecord>>;
    async fn create_aegis_enrollment(
        &self,
        enrollment: &AegisEnrollmentRecord,
    ) -> Result<AegisEnrollmentRecord, AegisEnrollmentWriteError>;
    async fn replace_aegis_enrollment_credential(
        &self,
        host_id: &HostId,
        expected_session_id: Option<&str>,
        next_session_id: &str,
        updated_unix: i64,
    ) -> Result<AegisEnrollmentRecord, AegisEnrollmentWriteError>;
    async fn update_aegis_enrollment_phase(
        &self,
        host_id: &HostId,
        credential_session_id: &str,
        phase: AegisEnrollmentPhase,
        updated_unix: i64,
    ) -> Result<AegisEnrollmentRecord, AegisEnrollmentWriteError>;
    async fn prepare_aegis_enrollment(
        &self,
        host_id: &HostId,
        credential_session_id: &str,
        preparation: AegisEnrollmentPreparation<'_>,
    ) -> Result<AegisEnrollmentPrepared, AegisEnrollmentWriteError>;
    async fn activate_aegis_enrollment(
        &self,
        host_id: &HostId,
        credential_session_id: &str,
        updated_unix: i64,
    ) -> Result<AegisEnrollmentPrepared, AegisEnrollmentWriteError>;
    async fn cancel_aegis_enrollment(
        &self,
        host_id: &HostId,
    ) -> Result<Option<AegisEnrollmentRecord>, AegisEnrollmentWriteError>;

    async fn read_aegis_egress_snapshot(&self) -> anyhow::Result<AegisEgressSnapshot>;

    async fn fetch_aegis_egress_policy(
        &self,
        source_host_id: &HostId,
    ) -> anyhow::Result<Option<aegis_dto::protocol::AegisEgressPolicy>>;

    async fn compare_and_set_aegis_egress_policy(
        &self,
        source_host_id: &HostId,
        expected_generation: u64,
        expected_revision: Option<u64>,
        replacement: Option<&aegis_dto::protocol::AegisEgressPolicy>,
    ) -> Result<(), AegisEgressWriteError>;

    async fn list_aegis_direct_gateways(&self) -> anyhow::Result<Vec<AegisDirectGatewayRecord>>;
    async fn fetch_aegis_direct_gateway(
        &self,
        host_id: &HostId,
    ) -> anyhow::Result<Option<AegisDirectGatewayRecord>>;
    async fn put_aegis_direct_gateway(
        &self,
        gateway: &AegisDirectGatewayRecord,
    ) -> Result<AegisDirectGatewayRecord, AegisDirectWriteError>;
    async fn delete_aegis_direct_gateway(&self, host_id: &HostId) -> anyhow::Result<bool>;
    async fn list_aegis_satellites(&self) -> anyhow::Result<Vec<AegisSatelliteRecord>>;
    async fn create_aegis_satellite(
        &self,
        satellite: &AegisSatelliteRecord,
        pool: &AegisWireGuardAddressPool,
    ) -> Result<AegisSatelliteRecord, AegisDirectWriteError>;
    async fn fetch_aegis_satellite(
        &self,
        slug: &str,
    ) -> anyhow::Result<Option<AegisSatelliteRecord>>;
    async fn record_aegis_satellite_broker_use(
        &self,
        slug: &str,
        activity: &AegisSatelliteBrokerUseRecord,
    ) -> anyhow::Result<bool>;
    async fn delete_aegis_satellite(&self, slug: &str) -> anyhow::Result<bool>;
    async fn list_aegis_hosts(&self) -> anyhow::Result<Vec<AegisHostRecord>>;
    async fn fetch_aegis_host(&self, host_id: &HostId) -> anyhow::Result<Option<AegisHostRecord>>;
    async fn fetch_host_id_by_alias(&self, alias: &HostAlias) -> anyhow::Result<Option<HostId>>;
    async fn resolve_enrolled_host_alias(
        &self,
        alias: &HostAlias,
    ) -> anyhow::Result<Option<HostId>>;
    async fn add_host_alias(
        &self,
        host_id: &HostId,
        alias: &HostAlias,
        updated_by_principal: &str,
        updated_unix: i64,
    ) -> Result<AegisHostRecord, AegisAliasWriteError>;
    async fn promote_host_alias(
        &self,
        host_id: &HostId,
        alias: &HostAlias,
        updated_by_principal: &str,
        updated_unix: i64,
    ) -> Result<AegisHostRecord, AegisAliasWriteError>;
    async fn remove_host_alias(
        &self,
        host_id: &HostId,
        alias: &HostAlias,
        updated_by_principal: &str,
        updated_unix: i64,
    ) -> Result<AegisHostRecord, AegisAliasWriteError>;
    async fn list_aegis_network_members(
        &self,
        network: &str,
    ) -> anyhow::Result<Vec<AegisNetworkMemberRecord>>;
    async fn fetch_aegis_network_member(
        &self,
        network: &str,
        host_id: &HostId,
    ) -> anyhow::Result<Option<AegisNetworkMemberRecord>>;
    async fn update_aegis_host(
        &self,
        host: &AegisHostRecord,
    ) -> Result<AegisHostRecord, AegisHostWriteError>;
    async fn update_aegis_network_member(
        &self,
        network: &str,
        member: &AegisNetworkMemberRecord,
        config: &AegisNetworkConfig,
    ) -> Result<AegisNetworkMemberRecord, AegisHostWriteError>;
    async fn update_aegis_host_report(
        &self,
        host_id: &HostId,
        update: AegisHostReportUpdate,
    ) -> anyhow::Result<bool>;
    async fn delete_aegis_host(
        &self,
        host_id: &HostId,
        networks: &[String],
    ) -> Result<bool, AegisHostDeleteError>;
}

#[cfg(test)]
mod tests {
    use aegis_dto::protocol::{AegisDirectGatewayReport, AegisDirectPeerObservation};

    use super::merge_direct_gateway_handshakes;

    #[test]
    fn direct_gateway_handshakes_survive_restart_only_for_current_peers() {
        let previous = AegisDirectGatewayReport {
            observed_unix: 100,
            peers: vec![
                AegisDirectPeerObservation {
                    public_key: "retained".to_string(),
                    latest_handshake_unix: Some(90),
                },
                AegisDirectPeerObservation {
                    public_key: "removed".to_string(),
                    latest_handshake_unix: Some(80),
                },
            ],
        };
        let current = AegisDirectGatewayReport {
            observed_unix: 110,
            peers: vec![
                AegisDirectPeerObservation {
                    public_key: "retained".to_string(),
                    latest_handshake_unix: None,
                },
                AegisDirectPeerObservation {
                    public_key: "new".to_string(),
                    latest_handshake_unix: Some(105),
                },
            ],
        };

        let merged = merge_direct_gateway_handshakes(Some(&previous), current);

        assert_eq!(110, merged.observed_unix);
        assert_eq!(Some(90), merged.peers[0].latest_handshake_unix);
        assert_eq!(Some(105), merged.peers[1].latest_handshake_unix);
        assert!(merged.peers.iter().all(|peer| peer.public_key != "removed"));
    }
}
