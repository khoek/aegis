//! Source operations and durable recovery. Gateway membership is independent of selections.
use super::*;
use crate::tunnel_operation::{self as operation, Operation, Request, Snapshot};
use ssh_key::rand_core::{OsRng, RngCore};
use std::io::Write;

pub(super) const JOURNAL: &str = "/var/lib/aegis/egress-operation.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    source: HostId,
    revision: u64,
    previous: Option<HostId>,
    requested: Option<HostId>,
    outcome: AegisEgressOutcome,
}

impl Journal {
    fn load() -> Result<Option<Self>> {
        match fs::read(JOURNAL) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).context("invalid tunnel recovery journal")?,
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("failed to read tunnel recovery journal"),
        }
    }

    fn persist(&self) -> Result<()> {
        let parent = Path::new(JOURNAL).parent().expect("journal directory");
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(&serde_json::to_vec(self)?)?;
        file.as_file().sync_all()?;
        file.persist(JOURNAL)
            .context("failed to persist tunnel recovery journal")?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn via(&self) -> Option<HostId> {
        match self.outcome {
            AegisEgressOutcome::Applied => self.requested,
            AegisEgressOutcome::Rejected => self.previous,
        }
    }
}

pub(super) async fn start(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<AgentPeerCredentials>,
    headers: HeaderMap,
    Json(request): Json<Request>,
) -> Result<(StatusCode, Json<Snapshot>), AgentHttpError> {
    request.validate().map_err(AgentHttpError)?;
    state
        .platform
        .require(aegis_dto::platform::Capability::InternetTunnel)
        .map_err(AgentHttpError)?;
    let bearer = forwarded_user_bearer(&headers).map_err(AgentHttpError)?;
    let owner = peer
        .uid
        .ok_or_else(|| AgentHttpError(anyhow!("missing local caller identity")))?;
    let operation = {
        let mut current = state.tunnel_operations.lock().expect("tunnel operation");
        if current.last().is_some_and(|operation| operation.running()) {
            return Err(AgentHttpError(anyhow!(
                "a tunnel operation is already running"
            )));
        }
        // Keep completed results beyond the CLI deadline so a new invocation cannot
        // erase the result before the previous caller polls it.
        current.retain(|operation| operation.snapshot().elapsed_ms < 60_000);
        if current.len() >= 64 {
            return Err(AgentHttpError(anyhow!(
                "too many recent tunnel operations; retry shortly"
            )));
        }
        let operation = Operation::new(OsRng.next_u64(), owner);
        current.push(Arc::clone(&operation));
        operation
    };
    let snapshot = operation.snapshot();
    let worker_operation = Arc::clone(&operation);
    let worker = tokio::task::spawn_blocking(move || {
        worker_operation.run(|| execute(&state, &bearer, &request))
    });
    tokio::spawn(async move {
        let result = worker
            .await
            .context("tunnel worker stopped; recovery journal retained")
            .and_then(|result| result);
        operation.finish(result);
    });
    Ok((StatusCode::ACCEPTED, Json(snapshot)))
}

fn owned(state: &AppState, peer: &AgentPeerCredentials, id: u64) -> Result<Arc<Operation>> {
    let current = state.tunnel_operations.lock().expect("tunnel operation");
    let operation = current
        .iter()
        .find(|op| op.id == id)
        .ok_or_else(|| anyhow!("tunnel operation {id} is unavailable"))?;
    ensure!(
        peer.uid == Some(operation.owner) || peer.uid == Some(0),
        "tunnel operation belongs to another user"
    );
    Ok(Arc::clone(operation))
}

pub(super) async fn poll(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<AgentPeerCredentials>,
    axum::extract::Path(id): axum::extract::Path<u64>,
) -> Result<Json<Snapshot>, AgentHttpError> {
    let operation = owned(&state, &peer, id).map_err(AgentHttpError)?;
    operation.heartbeat();
    Ok(Json(operation.snapshot()))
}

pub(super) async fn cancel(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<AgentPeerCredentials>,
    axum::extract::Path(id): axum::extract::Path<u64>,
) -> Result<Json<Snapshot>, AgentHttpError> {
    let operation = owned(&state, &peer, id).map_err(AgentHttpError)?;
    operation.cancel();
    Ok(Json(operation.snapshot()))
}

pub(super) fn execute(state: &AppState, bearer: &str, request: &Request) -> Result<String> {
    request.validate()?;
    let _guard = operation::lock(&state.egress_lock)?;
    // This read authorizes the operator before any privileged or persistent work.
    let mut inventory = state.api.get_egress_inventory(bearer)?;
    let local_id = state.config.host.host_id;
    let target = request
        .via
        .as_ref()
        .map(|alias| {
            inventory
                .hosts
                .values()
                .find(|host| host.aliases.contains(alias))
                .cloned()
                .with_context(|| format!("unknown enrolled gateway `{alias}`"))
        })
        .transpose()?;
    ensure!(
        target.as_ref().is_none_or(|host| host.host_id != local_id),
        "cannot tunnel through this machine"
    );
    let local = inventory
        .hosts
        .get(&local_id)
        .cloned()
        .ok_or_else(|| anyhow!("local egress enrollment is incomplete"))?;
    let wireguard = managed_wireguard_config(&inventory.config.interface);
    verify_local_wireguard_public_key(&wireguard, &local.public_key)?;
    let private_key = load_private_key(&wireguard.private_key_path)?;

    if request.isolated {
        // No selection, journal, routes or persistent configuration are changed.
        let target = target.as_ref().expect("validated isolated request");
        ensure!(
            !inventory.policies.values().any(|policy| {
                (policy.source_host_id == local_id
                    && [policy.active_via, policy.desired_via].contains(&Some(target.host_id)))
                    || (policy.source_host_id == target.host_id
                        && [policy.active_via, policy.desired_via].contains(&Some(local_id)))
            }),
            "isolated testing would roam an active WireGuard peer; choose a gateway without an active relationship to this host"
        );
        operation::phase("Checking IPv4, IPv6 and DNS in isolation")?;
        crate::egress_probe::prove_candidate(CandidateProbe {
            config: &inventory.config,
            local: &local,
            target,
            private_key: &private_key,
            api_base: &state.config.api_base,
        })?;
        return Ok(format!(
            "Tunnel via {} passed IPv4, IPv6 and DNS checks; system routing unchanged",
            target.aliases.primary()
        ));
    }

    let token = access_token(state)?;
    recover_pending(state, &token, &mut inventory)?;
    operation::phase("Authorizing route")?;
    let before = inventory
        .policies
        .get(&local_id)
        .and_then(|policy| policy.active_via);
    let requested = target.as_ref().map(|host| host.host_id);
    let sources = gateway_members(&inventory, local_id);
    let transition = EgressSourceTransition {
        config: &inventory.config,
        local: &local,
        wireguard: &wireguard,
        private_key: &private_key,
        api_base: &state.config.api_base,
        active_target: egress_target(&inventory, before)?,
        desired_target: target.as_ref(),
        gateway_sources: &sources,
    };
    let previous_config = egress_wireguard_config_contents(
        &inventory.config,
        &local,
        &EgressWireGuardPeerPlan {
            default_target: transition.active_target,
            gateway_sources: &sources,
        },
        &private_key,
    )?;
    let status = if let Some(via) = requested {
        state
            .api
            .put_egress(bearer, &local_id, &AegisEgressEnableRequest { via })
            .context("route request failed; previous route unchanged; the agent will reject any unconfirmed reservation")?
    } else {
        state.api.delete_egress(bearer, &local_id)
            .context("disable request failed; previous route unchanged; the agent will reject any unconfirmed reservation")?;
        state.api.get_egress_status(bearer, &local_id)
            .context("disable reservation unconfirmed; previous route unchanged; the agent will recover the reservation")?
    };
    if before == requested {
        return Ok(target
            .map(|target| format!("Already connected via {}", target.aliases.primary()))
            .unwrap_or_else(|| "Tunnel already disabled".into()));
    }
    let policy = status
        .policy
        .as_ref()
        .ok_or_else(|| anyhow!("route request returned no pending policy"))?;
    let mut journal = Journal {
        source: local_id,
        revision: policy.revision,
        previous: before,
        requested,
        outcome: AegisEgressOutcome::Rejected,
    };
    // A crash anywhere before the durable Applied record restores the previous route.
    if let Err(error) = journal.persist() {
        return operation::recover("Cancelling route request", || {
            state
                .api
                .post_egress_result(
                    &token,
                    &local_id,
                    &AegisEgressResult {
                        revision: policy.revision,
                        outcome: AegisEgressOutcome::Rejected,
                    },
                )
                .context("request retained for repair; previous route unchanged")?;
            Err(error).context("route request cancelled; previous route unchanged")
        });
    }
    state.runtime.lock().expect("runtime").tunnel = agent_tunnel_status(Some(policy), &inventory);
    let result = reconcile_egress_source_transition(&transition).and_then(|()| {
        operation::check()?;
        journal.outcome = AegisEgressOutcome::Applied;
        journal.persist()
    });
    if let Err(error) = result {
        let recovery = operation::recover("Restoring previous route", || -> Result<()> {
            journal.outcome = AegisEgressOutcome::Rejected;
            journal.persist().context(
                "rollback decision could not be recorded; route and journal require repair",
            )?;
            restore_previous_egress_source_state(&transition, &previous_config).context(
                "previous route could not be restored; recovery journal retained for repair",
            )?;
            record_local_route(state, transition.active_target);
            report_journal(state, &token, &journal).context(
                "previous route restored; central rejection pending in recovery journal",
            )?;
            Ok(())
        });
        return match recovery {
            Ok(()) => {
                Err(error).context("previous Internet route restored; route request cancelled")
            }
            Err(recovery_error) => {
                state.runtime.lock().expect("runtime").tunnel = AgentTunnelStatus::Unknown;
                Err(error).context(format!("tunnel recovery incomplete: {recovery_error:#}"))
            }
        };
    }
    record_local_route(state, target.as_ref());
    // Once committed, acknowledgement is recoverable and must not undo a working route.
    let message = target
        .map(|target| format!("Connected via {}", target.aliases.primary()))
        .unwrap_or_else(|| "Tunnel disabled".into());
    match operation::recover("Reporting local result", || {
        report_journal(state, &token, &journal)
    }) {
        Ok(_) => Ok(message),
        Err(error) => Ok(format!("{message}; central reporting pending: {error:#}")),
    }
}

fn record_local_route(state: &AppState, target: Option<&AegisEgressHost>) {
    state.runtime.lock().expect("runtime").tunnel = target
        .map(|target| AgentTunnelStatus::Enabled {
            via: target.aliases.primary().to_string(),
        })
        .unwrap_or(AgentTunnelStatus::Disabled);
}

fn report_journal(state: &AppState, token: &str, journal: &Journal) -> Result<AegisEgressStatus> {
    let status = state.api.post_egress_result(
        token,
        &journal.source,
        &AegisEgressResult {
            revision: journal.revision,
            outcome: journal.outcome,
        },
    )?;
    fs::remove_file(JOURNAL).context("route reported; removing recovery journal failed")?;
    Ok(status)
}

/// Called only with the egress lock. Never starts an abandoned or failed selection.
pub(super) fn recover_pending(
    state: &AppState,
    token: &str,
    inventory: &mut AegisEgressInventory,
) -> Result<()> {
    let local_id = state.config.host.host_id;
    let policy = inventory.policies.get(&local_id).cloned();
    let journal = Journal::load()?;
    let pending = match (policy.as_ref(), journal) {
        (Some(policy), Some(journal)) if policy.revision == journal.revision => {
            ensure!(
                journal.source == local_id
                    && journal.previous == policy.active_via
                    && journal.requested == policy.desired_via,
                "tunnel journal disagrees with the reserved route"
            );
            Some(journal)
        }
        (Some(policy), None) if !policy.is_steady() => Some(Journal {
            source: local_id,
            revision: policy.revision,
            previous: policy.active_via,
            requested: policy.desired_via,
            outcome: AegisEgressOutcome::Rejected,
        }),
        (policy, Some(journal)) => {
            ensure!(
                policy.is_none_or(|policy| policy.is_steady())
                    && policy.and_then(|policy| policy.active_via) == journal.via(),
                "tunnel journal conflicts with central state; explicit repair required"
            );
            fs::remove_file(JOURNAL)?;
            None
        }
        _ => None,
    };
    if let Some(journal) = pending {
        // Re-establish the recorded route before acknowledging its result, including after a crash.
        let local = inventory
            .hosts
            .get(&local_id)
            .context("local egress identity missing")?;
        let wireguard = managed_wireguard_config(&inventory.config.interface);
        let private_key = load_private_key(&wireguard.private_key_path)?;
        let target = egress_target(inventory, journal.via())?;
        let sources = gateway_members(inventory, local_id);
        let config = egress_wireguard_config_contents(
            &inventory.config,
            local,
            &EgressWireGuardPeerPlan {
                default_target: target,
                gateway_sources: &sources,
            },
            &private_key,
        )?;
        restore_previous_egress_source_state(
            &EgressSourceTransition {
                config: &inventory.config,
                local,
                wireguard: &wireguard,
                private_key: &private_key,
                api_base: &state.config.api_base,
                active_target: target,
                desired_target: target,
                gateway_sources: &sources,
            },
            &config,
        )?;
        record_local_route(state, target);
        journal.persist()?;
        let status = report_journal(state, token, &journal)?;
        match status.policy {
            Some(policy) => {
                inventory.policies.insert(local_id, policy);
            }
            None => {
                inventory.policies.remove(&local_id);
            }
        }
    }
    Ok(())
}
