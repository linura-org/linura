//! Bounded same-invocation Keep/Revert/expiry first-frame observation.
//! Projection preserves the original gate deadlines; no mutation or retry.
use super::*;
use linura_core::DisplayOrdinaryReleaseScope;
use linura_observation::{
    DISPLAY_ORDINARY_HANDOFF_CAPABILITY, DisplayNativeHandoffOutput, DisplayNativeHandoffWindow,
    DisplayOrdinaryHandoffFacts, DisplayOrdinaryHandoffLineage, ObservationAuthority,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Handoff {
    schema: u32,
    topology: String,
    original_dispatch: String,
    checkpoint: String,
    original_transaction: String,
    original_effect: String,
    release_transaction: String,
    release_effect: String,
    release_dispatch: String,
    terminal_record: String,
    signed_binding: String,
    preparation_digest: String,
    outcome: String,
    source_guard: String,
    sampled_unix_ms: String,
    sampled_boot_ms: String,
    deadline_unix_ms: String,
    deadline_boot_ms: String,
    post_write_epoch: String,
    security_epoch: String,
    heads: Vec<Output>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    handle: String,
    generation: String,
    enabled: bool,
    connector: u32,
    crtc: u32,
    plane: u32,
    framebuffer: u32,
    spend_high_water: String,
    completed_commit: String,
}

#[allow(clippy::too_many_arguments)]
fn project(
    raw: &str,
    scope: &DisplayOrdinaryReleaseScope,
    start_boot: u64,
    end_boot: u64,
    start_unix: u64,
    end_unix: u64,
    sequence: u64,
) -> Result<ObservationEnvelope, String> {
    let invalid =
        || "ordinary terminal first-frame evidence is incomplete or unsupported".to_owned();
    if raw.is_empty()
        || raw.len() > 16 * 1024
        || sequence == 0
        || start_boot == 0
        || start_unix == 0
        || end_boot
            .checked_sub(start_boot)
            .is_none_or(|age| age >= 2000)
        || end_unix
            .checked_sub(start_unix)
            .is_none_or(|age| age >= 2000)
    {
        return Err(invalid());
    }
    let saved: Handoff = serde_json::from_str(raw).map_err(|_| invalid())?;
    let window = DisplayNativeHandoffWindow {
        observed_unix_ms: number(&saved.sampled_unix_ms)?,
        observed_boot_ms: number(&saved.sampled_boot_ms)?,
        deadline_unix_ms: number(&saved.deadline_unix_ms)?,
        deadline_boot_ms: number(&saved.deadline_boot_ms)?,
    };
    if saved.schema != 1
        || saved.topology
            != scope
                .topology()
                .resource_id()
                .map_err(|_| invalid())?
                .as_str()
        || saved.original_dispatch != scope.original_dispatch()
        || saved.heads.is_empty()
        || saved.heads.len() > 16
        || window.observed_boot_ms < start_boot
        || window.observed_boot_ms > end_boot
        || window.observed_unix_ms < start_unix
        || window.observed_unix_ms > end_unix
        || end_boot >= window.deadline_boot_ms
        || end_unix >= window.deadline_unix_ms
    {
        return Err(invalid());
    }
    let mut outputs = BTreeMap::new();
    let mut previous = None;
    for row in saved.heads {
        let id = DisplayOutputId::new(
            scope.topology().clone(),
            number(&row.handle)?,
            number(&row.generation)?,
        )
        .map_err(|_| invalid())?;
        if previous.as_ref().is_some_and(|last| last >= &id) {
            return Err(invalid());
        }
        previous = Some(id.clone());
        let output = DisplayNativeHandoffOutput {
            enabled: row.enabled,
            connector: row.connector,
            crtc: row.crtc,
            plane: row.plane,
            framebuffer: row.framebuffer,
            spend_high_water: number(&row.spend_high_water)?,
            completed_commit: number(&row.completed_commit)?,
        };
        if outputs.insert(id, output).is_some() {
            return Err(invalid());
        }
    }
    let lineage = DisplayOrdinaryHandoffLineage {
        checkpoint: saved.checkpoint,
        original_transaction: saved.original_transaction,
        original_effect: saved.original_effect,
        release_transaction: saved.release_transaction,
        release_effect: saved.release_effect,
        release_dispatch: saved.release_dispatch,
        terminal_record: saved.terminal_record,
        signed_binding: saved.signed_binding,
        preparation_digest: saved.preparation_digest,
        outcome: saved.outcome,
        source_guard: saved.source_guard,
        post_write_epoch: number(&saved.post_write_epoch)?,
        security_epoch: number(&saved.security_epoch)?,
    };
    let facts = DisplayOrdinaryHandoffFacts::new(scope.clone(), lineage, window, outputs)
        .map_err(|_| invalid())?;
    let envelope = ObservationEnvelope {
        provider: ProviderId::new(DISPLAY_PROVIDER).map_err(|_| invalid())?,
        capability: CapabilityId::new(DISPLAY_ORDINARY_HANDOFF_CAPABILITY)
            .map_err(|_| invalid())?,
        resource: scope.resource_id().map_err(|_| invalid())?,
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms: window.observed_unix_ms,
        valid_for_ms: window.valid_for_ms().map_err(|_| invalid())?,
        sequence,
        attributes: facts.attributes(),
    };
    DisplayOrdinaryHandoffFacts::from_envelope(&envelope, scope, end_unix)
        .map_err(|_| invalid())?;
    Ok(envelope)
}

impl NativeSessionChannel {
    pub fn observe_ordinary_display_handoff(
        &self,
        scope: &DisplayOrdinaryReleaseScope,
        sequence: u64,
    ) -> Result<ObservationEnvelope, String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        let start_boot = boot_ms()?;
        let start_unix = unix_ms()?;
        let boot = current_boot()?;
        let owner = self.discover(scope.topology().session().uid(), started)?;
        let reply = self.call_with_budget(
            &owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "ObserveOrdinaryDisplayHandoff",
            &(),
            owner_reply_budget(started.elapsed())?,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != owner.unique_name)
            || reply.body().signature().to_string() != "s"
            || reply.body().len() > 16 * 1024 + 8
        {
            return Err("ordinary terminal-frame reply identity/shape differs".into());
        }
        let (raw,): (String,) = reply
            .body()
            .deserialize()
            .map_err(|_| "ordinary terminal-frame codec differs")?;
        self.revalidate_observation(&owner, &boot, started)?;
        let result = project(
            &raw,
            scope,
            start_boot,
            boot_ms()?,
            start_unix,
            unix_ms()?,
            sequence,
        )?;
        let finished_boot = boot_ms()?;
        let facts = DisplayOrdinaryHandoffFacts::from_envelope(&result, scope, unix_ms()?)
            .map_err(|_| "ordinary terminal-frame evidence expired")?;
        if started.elapsed() >= crate::bus::PROBE_BUDGET
            || finished_boot >= facts.window().deadline_boot_ms
        {
            return Err("ordinary terminal-frame evidence exceeded its original budget".into());
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
