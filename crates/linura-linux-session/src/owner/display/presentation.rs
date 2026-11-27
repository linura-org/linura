//! One bounded read of original-restoration KMS/frame facts from the same
//! independently attested protected owner. No mutation, retry or finalization.
use super::*;
use linura_core::DisplayRecoveryScope;
use linura_observation::{
    DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY, DisplayOriginalPresentationFacts,
    DisplayPostWriteFrame, ObservationAuthority,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Presentation {
    schema: u32,
    topology: String,
    original_dispatch: String,
    checkpoint: String,
    transaction: String,
    effect: String,
    dispatch: String,
    source_guard: String,
    sampled_boot_ms: String,
    post_write_epoch: String,
    heads: Vec<Frame>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    handle: String,
    generation: String,
    enabled: bool,
    crtc: u32,
    framebuffer: u32,
    commit: String,
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
    let invalid =
        || "native original-restoration presentation is incomplete or unsupported".to_owned();
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
    let saved: Presentation = serde_json::from_str(raw).map_err(|_| invalid())?;
    let sampled = number(&saved.sampled_boot_ms)?;
    if saved.schema != 1
        || saved.topology
            != scope
                .replacement()
                .resource_id()
                .map_err(|_| invalid())?
                .as_str()
        || saved.original_dispatch != scope.original_dispatch()
        || saved.heads.is_empty()
        || saved.heads.len() > 16
        || sampled < start_boot
        || sampled > end_boot
        || end_boot - sampled >= 2000
    {
        return Err(invalid());
    }
    let mut frames = BTreeMap::new();
    let mut previous = None;
    for row in saved.heads {
        let output = DisplayOutputId::new(
            scope.replacement().clone(),
            number(&row.handle)?,
            number(&row.generation)?,
        )
        .map_err(|_| invalid())?;
        if previous.as_ref().is_some_and(|last| last >= &output) {
            return Err(invalid());
        }
        previous = Some(output.clone());
        let commit = number(&row.commit)?;
        let frame = if row.enabled {
            DisplayPostWriteFrame::Presented {
                crtc: row.crtc,
                framebuffer: row.framebuffer,
                commit,
            }
        } else if row.crtc == 0 && row.framebuffer == 0 && commit == 0 {
            DisplayPostWriteFrame::Disabled
        } else {
            return Err(invalid());
        };
        if frames.insert(output, frame).is_some() {
            return Err(invalid());
        }
    }
    let facts = DisplayOriginalPresentationFacts::new(
        scope.clone(),
        saved.checkpoint,
        saved.transaction,
        saved.effect,
        saved.dispatch,
        saved.source_guard,
        number(&saved.post_write_epoch)?,
        frames,
    )
    .map_err(|_| invalid())?;
    let envelope = ObservationEnvelope {
        provider: ProviderId::new(DISPLAY_PROVIDER).map_err(|_| invalid())?,
        capability: CapabilityId::new(DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY)
            .map_err(|_| invalid())?,
        resource: scope.resource_id().map_err(|_| invalid())?,
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms: start_unix,
        valid_for_ms: 2000,
        sequence,
        attributes: facts.attributes(),
    };
    DisplayOriginalPresentationFacts::from_envelope(&envelope, scope, end_unix)
        .map_err(|_| invalid())?;
    Ok(envelope)
}

impl NativeSessionChannel {
    pub fn observe_original_display_presentation(
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
            "ObserveOriginalDisplayPresentation",
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
            return Err(
                "native original-restoration presentation reply identity/shape differs".into(),
            );
        }
        let (raw,): (String,) = reply
            .body()
            .deserialize()
            .map_err(|_| "native restoration presentation codec differs")?;
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
        if started.elapsed() >= crate::bus::PROBE_BUDGET {
            return Err(
                "native original-restoration presentation exceeded its original budget".into(),
            );
        }
        result
            .require_current(unix_ms()?)
            .map_err(|e| e.to_string())?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
