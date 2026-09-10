use linura_core::{IntentId, PrincipalId, RequestId};
use linura_intent::ProposalDigest;
use rusqlite::{OptionalExtension, params};

use crate::proposal_acceptance::ProposalAcceptanceAuthority;
use crate::{
    AuthorityTimeSeal, LocalLibrary, ProposalAcceptanceError, ProposalAcceptanceMaterial,
    ProposalAcceptanceRecord, ProposalAcceptanceTarget,
};

const ACCEPTANCE_RESULT_KIND: &str = "intent-proposal-acceptance";
const ACCEPTANCE_RECORD_PREFIX: &str = "v08:acceptance:";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalAcceptanceReplayKey {
    pub principal: PrincipalId,
    pub proposal_id: RequestId,
    pub proposal_digest: ProposalDigest,
    pub decision_id: RequestId,
    pub operation_id: RequestId,
    pub target: ProposalAcceptanceTarget,
    pub resulting_intent_digest: ProposalDigest,
}

impl ProposalAcceptanceAuthority {
    /// Resolve an already committed exact acceptance before consulting fresh
    /// policy/observation state. This is the lost-response/restart path: a
    /// completed transaction remains replayable even after the authority that
    /// authorized it has subsequently expired or changed.
    pub fn replay_request(
        &self,
        library: &LocalLibrary,
        key: &ProposalAcceptanceReplayKey,
    ) -> Result<Option<ProposalAcceptanceRecord>, ProposalAcceptanceError> {
        let operation = library
            .connection
            .query_row(
                "SELECT semantic_digest, result_kind, result_id, result_revision FROM library_operations WHERE operation_id = ?1",
                params![key.operation_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((semantic_digest, result_kind, result_id, result_revision)) = operation else {
            return Ok(None);
        };
        if result_kind != ACCEPTANCE_RESULT_KIND {
            return Err(ProposalAcceptanceError::IdentityConflict {
                kind: "operation",
                id: key.operation_id.as_str().into(),
            });
        }
        let payload = library
            .connection
            .query_row(
                "SELECT payload FROM lifecycle_records WHERE entity_id = ?1 AND content_digest = ?2 ORDER BY sequence DESC LIMIT 1",
                params![
                    format!("{ACCEPTANCE_RECORD_PREFIX}{}", key.operation_id.as_str()),
                    semantic_digest,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ProposalAcceptanceError::Corrupt(
                    "operation exists without durable v0.8 acceptance record".into(),
                )
            })?;

        if field(&payload, "principal")? != key.principal.as_str()
            || field(&payload, "proposal_id")? != key.proposal_id.as_str()
            || parse_digest(&payload, "proposal_digest")? != key.proposal_digest
            || field(&payload, "decision_id")? != key.decision_id.as_str()
            || field(&payload, "operation_id")? != key.operation_id.as_str()
            || !target_matches(&payload, &key.target)?
            || parse_digest(&payload, "resulting_intent_digest")? != key.resulting_intent_digest
        {
            return Err(ProposalAcceptanceError::IdentityConflict {
                kind: "operation",
                id: key.operation_id.as_str().into(),
            });
        }

        let target = parse_target(&payload)?;
        let material = ProposalAcceptanceMaterial {
            principal: PrincipalId::new(field(&payload, "principal")?)
                .map_err(|error| ProposalAcceptanceError::Corrupt(error.to_string()))?,
            decision_id: RequestId::new(field(&payload, "decision_id")?)
                .map_err(|error| ProposalAcceptanceError::Corrupt(error.to_string()))?,
            decision_binding_digest: parse_digest(&payload, "decision_binding_digest")?,
            proposal_id: RequestId::new(field(&payload, "proposal_id")?)
                .map_err(|error| ProposalAcceptanceError::Corrupt(error.to_string()))?,
            proposal_digest: parse_digest(&payload, "proposal_digest")?,
            accepted_context_digest: parse_digest(&payload, "accepted_context_digest")?,
            operation_id: RequestId::new(field(&payload, "operation_id")?)
                .map_err(|error| ProposalAcceptanceError::Corrupt(error.to_string()))?,
            target,
            authority_generation: parse_u64(&payload, "authority_generation")?,
            authority_evidence_digest: parse_digest(&payload, "authority_evidence_digest")?,
            decision_validity_digest: parse_digest(&payload, "decision_validity_digest")?,
            resulting_intent_digest: parse_digest(&payload, "resulting_intent_digest")?,
        };
        if material.semantic_digest().to_hex() != semantic_digest {
            return Err(ProposalAcceptanceError::Corrupt(
                "durable acceptance material digest does not match operation record".into(),
            ));
        }

        let resulting_intent_id = IntentId::new(result_id)
            .map_err(|error| ProposalAcceptanceError::Corrupt(error.to_string()))?;
        let resulting_revision = u64::try_from(result_revision)
            .map_err(|_| ProposalAcceptanceError::Corrupt("invalid result revision".into()))?;
        if field(&payload, "resulting_intent_id")? != resulting_intent_id.as_str()
            || parse_u64(&payload, "resulting_revision")? != resulting_revision
        {
            return Err(ProposalAcceptanceError::Corrupt(
                "durable acceptance result disagrees with operation record".into(),
            ));
        }
        Ok(Some(ProposalAcceptanceRecord {
            material,
            time_seal: AuthorityTimeSeal {
                time_floor_unix_ms: parse_u64(&payload, "time_floor_unix_ms")?,
                exclusive_deadline_unix_ms: parse_u64(&payload, "exclusive_deadline_unix_ms")?,
                continuity_generation: parse_u64(&payload, "continuity_generation")?,
                normalization_evidence_digest: parse_digest(
                    &payload,
                    "normalization_evidence_digest",
                )?,
            },
            resulting_intent_id,
            resulting_revision,
            linearized_at_unix_ms: parse_u64(&payload, "linearized_at_unix_ms")?,
        }))
    }
}

fn target_matches(
    payload: &str,
    target: &ProposalAcceptanceTarget,
) -> Result<bool, ProposalAcceptanceError> {
    if field(payload, "action")? != target.action().as_str()
        || field(payload, "target_intent_id")? != target.intent_id().as_str()
    {
        return Ok(false);
    }
    let stored_expected = field(payload, "expected_revision")?;
    Ok(match target.expected_revision() {
        None => stored_expected == "none",
        Some(expected) => stored_expected == expected.to_string(),
    })
}

fn parse_target(payload: &str) -> Result<ProposalAcceptanceTarget, ProposalAcceptanceError> {
    let intent_id = IntentId::new(field(payload, "target_intent_id")?)
        .map_err(|error| ProposalAcceptanceError::Corrupt(error.to_string()))?;
    match field(payload, "action")? {
        "create" => {
            if field(payload, "expected_revision")? != "none" {
                return Err(ProposalAcceptanceError::Corrupt(
                    "create acceptance unexpectedly has target revision".into(),
                ));
            }
            Ok(ProposalAcceptanceTarget::Create { intent_id })
        }
        "revise-proposed" => Ok(ProposalAcceptanceTarget::ReviseProposed {
            intent_id,
            expected_revision: parse_u64(payload, "expected_revision")?,
        }),
        other => Err(ProposalAcceptanceError::Corrupt(format!(
            "unknown durable proposal acceptance action {other}"
        ))),
    }
}

fn parse_u64(payload: &str, name: &'static str) -> Result<u64, ProposalAcceptanceError> {
    field(payload, name)?.parse::<u64>().map_err(|_| {
        ProposalAcceptanceError::Corrupt(format!(
            "invalid {name} in durable proposal acceptance record"
        ))
    })
}

fn parse_digest(
    payload: &str,
    name: &'static str,
) -> Result<ProposalDigest, ProposalAcceptanceError> {
    ProposalDigest::parse_hex(field(payload, name)?)
        .map_err(|error| ProposalAcceptanceError::Corrupt(error.to_string()))
}

fn field<'a>(payload: &'a str, name: &'static str) -> Result<&'a str, ProposalAcceptanceError> {
    let prefix = format!("{name}=");
    payload
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or_else(|| {
            ProposalAcceptanceError::Corrupt(format!(
                "missing {name} in durable proposal acceptance record"
            ))
        })
}
