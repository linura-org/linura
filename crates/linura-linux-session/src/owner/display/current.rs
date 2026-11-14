//! Bounded current post-handoff observation from the attested native owner.
//! Producer read deadlines remain fixed across the transport. No mutation or
//! retry, and no reconstruction of current state from a first-frame receipt.
use super::*;
use linura_core::DisplayRecoveryScope;
use linura_observation::{
    DISPLAY_NATIVE_CURRENT_CAPABILITY, DisplayNativeCurrentFacts, DisplayNativeCurrentOutput,
    DisplayNativeHandoffLineage, DisplayNativeHandoffWindow, ObservationAuthority,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Current {
    schema: u32,
    completion_digest: String,
    current_commit_digest: String,
    final_retirement_digest: String,
    input_retired: bool,
    power_fence_held: bool,
    topology: String,
    original_dispatch: String,
    checkpoint: String,
    restoration_transaction: String,
    restoration_effect: String,
    restoration_dispatch: String,
    terminal_transaction: String,
    terminal_effect: String,
    terminal_dispatch: String,
    terminal_link: String,
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
    handoff_commit: String,
    completed_commit: String,
}

#[allow(clippy::too_many_arguments)]
fn project(
    raw: &str,
    scope: &DisplayRecoveryScope,
    start_boot: u64,
    end_boot: u64,
    start_unix: u64,
    end_unix: u64,
    sequence: u64,
) -> Result<ObservationEnvelope, String> {
    let invalid = || "native current post-handoff evidence is incomplete or unsupported".to_owned();
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
    let saved: Current = serde_json::from_str(raw).map_err(|_| invalid())?;
    let window = DisplayNativeHandoffWindow {
        observed_unix_ms: number(&saved.sampled_unix_ms)?,
        observed_boot_ms: number(&saved.sampled_boot_ms)?,
        deadline_unix_ms: number(&saved.deadline_unix_ms)?,
        deadline_boot_ms: number(&saved.deadline_boot_ms)?,
    };
    if saved.schema != 3
        || saved.topology
            != scope
                .replacement()
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
            scope.replacement().clone(),
            number(&row.handle)?,
            number(&row.generation)?,
        )
        .map_err(|_| invalid())?;
        if previous.as_ref().is_some_and(|last| last >= &id) {
            return Err(invalid());
        }
        previous = Some(id.clone());
        let output = DisplayNativeCurrentOutput {
            enabled: row.enabled,
            connector: row.connector,
            crtc: row.crtc,
            plane: row.plane,
            framebuffer: row.framebuffer,
            handoff_commit: number(&row.handoff_commit)?,
            completed_commit: number(&row.completed_commit)?,
        };
        if outputs.insert(id, output).is_some() {
            return Err(invalid());
        }
    }
    let lineage = DisplayNativeHandoffLineage {
        checkpoint: saved.checkpoint,
        restoration_transaction: saved.restoration_transaction,
        restoration_effect: saved.restoration_effect,
        restoration_dispatch: saved.restoration_dispatch,
        terminal_transaction: saved.terminal_transaction,
        terminal_effect: saved.terminal_effect,
        terminal_dispatch: saved.terminal_dispatch,
        terminal_link: saved.terminal_link,
        source_guard: saved.source_guard,
        post_write_epoch: number(&saved.post_write_epoch)?,
        security_epoch: number(&saved.security_epoch)?,
    };
    let facts = DisplayNativeCurrentFacts::new(
        scope.clone(),
        lineage,
        window,
        outputs,
        saved.completion_digest,
        saved.input_retired,
        saved.power_fence_held,
        match saved.current_commit_digest.as_str() {
            raw if raw == "0".repeat(64) => None,
            raw => Some(raw.into()),
        },
        match saved.final_retirement_digest.as_str() {
            raw if raw == "0".repeat(64) => None,
            raw => Some(raw.into()),
        },
    )
    .map_err(|_| invalid())?;
    let envelope = ObservationEnvelope {
        provider: ProviderId::new(DISPLAY_PROVIDER).map_err(|_| invalid())?,
        capability: CapabilityId::new(DISPLAY_NATIVE_CURRENT_CAPABILITY).map_err(|_| invalid())?,
        resource: scope.resource_id().map_err(|_| invalid())?,
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms: window.observed_unix_ms,
        valid_for_ms: window.valid_for_ms().map_err(|_| invalid())?,
        sequence,
        attributes: facts.attributes(),
    };
    DisplayNativeCurrentFacts::from_envelope(&envelope, scope, end_unix).map_err(|_| invalid())?;
    Ok(envelope)
}

impl NativeSessionChannel {
    pub fn observe_native_display_current(
        &self,
        scope: &DisplayRecoveryScope,
        sequence: u64,
    ) -> Result<ObservationEnvelope, String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        let start_boot = boot_ms()?;
        let start_unix = unix_ms()?;
        let boot = current_boot()?;
        let owner = self.discover(scope.replacement().session().uid(), started)?;
        let reply = self.call_with_budget(
            &owner.unique_name,
            ENDPOINT,
            INTERFACE,
            "ObserveNativeDisplayCurrent",
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
            return Err("native current-frame reply identity/shape differs".into());
        }
        let (raw,): (String,) = reply
            .body()
            .deserialize()
            .map_err(|_| "native current-frame codec differs")?;
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
        let facts = DisplayNativeCurrentFacts::from_envelope(&result, scope, unix_ms()?)
            .map_err(|_| "native current-frame evidence expired")?;
        if started.elapsed() >= crate::bus::PROBE_BUDGET
            || finished_boot >= facts.window().deadline_boot_ms
        {
            return Err("native current-frame evidence exceeded its original budget".into());
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
