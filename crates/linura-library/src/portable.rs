use std::collections::{BTreeMap, BTreeSet};

use linura_core::{Actor, ActorId, ActorKind, IntentId, ProfileId, RequirementId, SetupId};
use linura_intent::{
    Intent, IntentStatus, MachineClass, MachineProfile, Requirement, RequirementKind, Setup,
};
use sha2::{Digest, Sha256};

use crate::{
    IntentRevisionRef, LibraryError, SetupRevisionRef, StoredIntent, StoredProfile, StoredSetup,
};

pub const PORTABLE_FORMAT_VERSION: u16 = 1;
const MAX_PORTABLE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RECORDS: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableSetupBundle {
    pub format_version: u16,
    pub root: SetupRevisionRef,
    pub setups: Vec<StoredSetup>,
    pub intents: Vec<StoredIntent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableProfileBundle {
    pub format_version: u16,
    pub profile: StoredProfile,
    pub setups: Vec<StoredSetup>,
    pub intents: Vec<StoredIntent>,
}

pub fn encode_setup_bundle(bundle: &PortableSetupBundle) -> Result<Vec<u8>, LibraryError> {
    validate_setup_bundle(bundle)?;
    let mut body = String::new();
    push_line(
        &mut body,
        &[
            "LINURA-LIBRARY",
            &bundle.format_version.to_string(),
            "setup",
        ],
    );
    push_line(
        &mut body,
        &[
            "root-setup",
            &hex_text(bundle.root.id.as_str()),
            &bundle.root.revision.to_string(),
        ],
    );
    encode_intents(&mut body, &bundle.intents);
    encode_setups(&mut body, &bundle.setups);
    finish_artifact(body)
}

pub fn encode_profile_bundle(bundle: &PortableProfileBundle) -> Result<Vec<u8>, LibraryError> {
    validate_profile_bundle(bundle)?;
    let mut body = String::new();
    push_line(
        &mut body,
        &[
            "LINURA-LIBRARY",
            &bundle.format_version.to_string(),
            "profile",
        ],
    );
    let profile = &bundle.profile;
    push_line(
        &mut body,
        &[
            "profile",
            &hex_text(profile.profile.id.as_str()),
            &profile.revision.to_string(),
            &hex_text(&profile.profile.name),
            profile.profile.machine_class.as_str(),
        ],
    );
    let mut intent_refs = profile.intent_revisions.clone();
    intent_refs.sort_by(|left, right| {
        (left.id.as_str(), left.revision).cmp(&(right.id.as_str(), right.revision))
    });
    for reference in intent_refs {
        push_line(
            &mut body,
            &[
                "profile-intent",
                &hex_text(profile.profile.id.as_str()),
                &profile.revision.to_string(),
                &hex_text(reference.id.as_str()),
                &reference.revision.to_string(),
            ],
        );
    }
    let mut setup_refs = profile.setup_revisions.clone();
    setup_refs.sort_by(|left, right| {
        (left.id.as_str(), left.revision).cmp(&(right.id.as_str(), right.revision))
    });
    for reference in setup_refs {
        push_line(
            &mut body,
            &[
                "profile-setup",
                &hex_text(profile.profile.id.as_str()),
                &profile.revision.to_string(),
                &hex_text(reference.id.as_str()),
                &reference.revision.to_string(),
            ],
        );
    }
    for (ordinal, value) in profile.profile.portable_constraints.iter().enumerate() {
        push_line(
            &mut body,
            &[
                "profile-constraint",
                &hex_text(profile.profile.id.as_str()),
                &profile.revision.to_string(),
                &ordinal.to_string(),
                &hex_text(value),
            ],
        );
    }
    for (ordinal, value) in profile.profile.hardware_hints.iter().enumerate() {
        push_line(
            &mut body,
            &[
                "profile-hardware",
                &hex_text(profile.profile.id.as_str()),
                &profile.revision.to_string(),
                &ordinal.to_string(),
                &hex_text(value),
            ],
        );
    }
    encode_intents(&mut body, &bundle.intents);
    encode_setups(&mut body, &bundle.setups);
    finish_artifact(body)
}

pub fn decode_setup_bundle(bytes: &[u8]) -> Result<PortableSetupBundle, LibraryError> {
    let parsed = parse_artifact(bytes, "setup")?;
    let root = parsed.root.ok_or_else(|| {
        LibraryError::PortableFormat("setup artifact is missing root-setup record".into())
    })?;
    if parsed.profile.is_some() {
        return Err(LibraryError::PortableFormat(
            "setup artifact unexpectedly contains a profile".into(),
        ));
    }
    let bundle = PortableSetupBundle {
        format_version: parsed.version,
        root,
        setups: finalize_setups(parsed.setups)?,
        intents: finalize_intents(parsed.intents)?,
    };
    validate_setup_bundle(&bundle)?;
    Ok(bundle)
}

pub fn decode_profile_bundle(bytes: &[u8]) -> Result<PortableProfileBundle, LibraryError> {
    let parsed = parse_artifact(bytes, "profile")?;
    if parsed.root.is_some() {
        return Err(LibraryError::PortableFormat(
            "profile artifact unexpectedly contains root-setup record".into(),
        ));
    }
    let profile = finalize_profile(parsed.profile.ok_or_else(|| {
        LibraryError::PortableFormat("profile artifact is missing profile record".into())
    })?)?;
    let bundle = PortableProfileBundle {
        format_version: parsed.version,
        profile,
        setups: finalize_setups(parsed.setups)?,
        intents: finalize_intents(parsed.intents)?,
    };
    validate_profile_bundle(&bundle)?;
    Ok(bundle)
}

fn encode_intents(body: &mut String, intents: &[StoredIntent]) {
    let mut intents = intents.to_vec();
    intents.sort_by(|left, right| {
        (left.intent.id.as_str(), left.revision).cmp(&(right.intent.id.as_str(), right.revision))
    });
    for stored in intents {
        let intent = &stored.intent;
        push_line(
            body,
            &[
                "intent",
                &hex_text(intent.id.as_str()),
                &stored.revision.to_string(),
                &hex_text(intent.actor.id.as_str()),
                actor_kind_str(intent.actor.kind),
                if intent.actor.interactive { "1" } else { "0" },
                intent_status_str(intent.status),
                &hex_text(&intent.statement),
            ],
        );
        let mut requirements = intent.requirements.clone();
        requirements.sort_by(|left, right| left.id.cmp(&right.id));
        for requirement in requirements {
            push_line(
                body,
                &[
                    "requirement",
                    &hex_text(intent.id.as_str()),
                    &stored.revision.to_string(),
                    &hex_text(requirement.id.as_str()),
                    requirement_kind_str(requirement.kind),
                    &hex_text(&requirement.statement),
                ],
            );
        }
        let mut supersedes = intent.supersedes.clone();
        supersedes.sort();
        for predecessor in supersedes {
            push_line(
                body,
                &[
                    "supersedes",
                    &hex_text(intent.id.as_str()),
                    &stored.revision.to_string(),
                    &hex_text(predecessor.as_str()),
                ],
            );
        }
    }
}

fn encode_setups(body: &mut String, setups: &[StoredSetup]) {
    let mut setups = setups.to_vec();
    setups.sort_by(|left, right| {
        (left.setup.id.as_str(), left.setup.revision)
            .cmp(&(right.setup.id.as_str(), right.setup.revision))
    });
    for stored in setups {
        let setup = &stored.setup;
        push_line(
            body,
            &[
                "setup",
                &hex_text(setup.id.as_str()),
                &setup.revision.to_string(),
                &hex_text(&setup.name),
                &hex_text(&setup.description),
            ],
        );
        let mut intent_refs = stored.intent_revisions.clone();
        intent_refs.sort_by(|left, right| {
            (left.id.as_str(), left.revision).cmp(&(right.id.as_str(), right.revision))
        });
        for reference in intent_refs {
            push_line(
                body,
                &[
                    "setup-intent",
                    &hex_text(setup.id.as_str()),
                    &setup.revision.to_string(),
                    &hex_text(reference.id.as_str()),
                    &reference.revision.to_string(),
                ],
            );
        }
        let mut setup_refs = stored.included_revisions.clone();
        setup_refs.sort_by(|left, right| {
            (left.id.as_str(), left.revision).cmp(&(right.id.as_str(), right.revision))
        });
        for reference in setup_refs {
            push_line(
                body,
                &[
                    "setup-include",
                    &hex_text(setup.id.as_str()),
                    &setup.revision.to_string(),
                    &hex_text(reference.id.as_str()),
                    &reference.revision.to_string(),
                ],
            );
        }
        for (ordinal, value) in setup.portable_constraints.iter().enumerate() {
            push_line(
                body,
                &[
                    "setup-constraint",
                    &hex_text(setup.id.as_str()),
                    &setup.revision.to_string(),
                    &ordinal.to_string(),
                    &hex_text(value),
                ],
            );
        }
        for (ordinal, value) in setup.required_secret_refs.iter().enumerate() {
            push_line(
                body,
                &[
                    "setup-secret-ref",
                    &hex_text(setup.id.as_str()),
                    &setup.revision.to_string(),
                    &ordinal.to_string(),
                    &hex_text(value),
                ],
            );
        }
        for (ordinal, value) in setup.hardware_hints.iter().enumerate() {
            push_line(
                body,
                &[
                    "setup-hardware",
                    &hex_text(setup.id.as_str()),
                    &setup.revision.to_string(),
                    &ordinal.to_string(),
                    &hex_text(value),
                ],
            );
        }
    }
}

fn finish_artifact(mut body: String) -> Result<Vec<u8>, LibraryError> {
    if body.len() > MAX_PORTABLE_BYTES {
        return Err(LibraryError::PortableFormat(
            "portable artifact exceeds maximum size".into(),
        ));
    }
    let digest = sha256_hex(body.as_bytes());
    body.push_str("sha256\t");
    body.push_str(&digest);
    body.push('\n');
    if body.len() > MAX_PORTABLE_BYTES {
        return Err(LibraryError::PortableFormat(
            "portable artifact exceeds maximum size".into(),
        ));
    }
    Ok(body.into_bytes())
}

#[derive(Default)]
struct IntentBuilder {
    base: Option<IntentBase>,
    requirements: Vec<(String, String, String)>,
    supersedes: Vec<String>,
}

struct IntentBase {
    actor_id: String,
    actor_kind: String,
    actor_interactive: bool,
    status: String,
    statement: String,
}

#[derive(Default)]
struct SetupBuilder {
    base: Option<(String, String)>,
    intents: Vec<(String, u64)>,
    includes: Vec<(String, u32)>,
    constraints: BTreeMap<usize, String>,
    secret_refs: BTreeMap<usize, String>,
    hardware_hints: BTreeMap<usize, String>,
}

#[derive(Default)]
struct ProfileBuilder {
    key: Option<(String, u32)>,
    name: Option<String>,
    machine_class: Option<String>,
    intents: Vec<(String, u64)>,
    setups: Vec<(String, u32)>,
    constraints: BTreeMap<usize, String>,
    hardware_hints: BTreeMap<usize, String>,
}

struct ParsedArtifact {
    version: u16,
    root: Option<SetupRevisionRef>,
    profile: Option<ProfileBuilder>,
    intents: BTreeMap<(String, u64), IntentBuilder>,
    setups: BTreeMap<(String, u32), SetupBuilder>,
}

fn parse_artifact(bytes: &[u8], expected_kind: &str) -> Result<ParsedArtifact, LibraryError> {
    if bytes.len() > MAX_PORTABLE_BYTES {
        return Err(LibraryError::PortableFormat(
            "portable artifact exceeds maximum size".into(),
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| LibraryError::PortableFormat("artifact is not UTF-8".into()))?;
    let marker = "\nsha256\t";
    let (body_without_final_newline, digest_tail) = text
        .rsplit_once(marker)
        .ok_or_else(|| LibraryError::PortableFormat("missing terminal digest".into()))?;
    if !digest_tail.ends_with('\n') || digest_tail[..digest_tail.len() - 1].contains('\n') {
        return Err(LibraryError::PortableFormat(
            "terminal digest record is malformed".into(),
        ));
    }
    let declared_digest = &digest_tail[..digest_tail.len() - 1];
    if declared_digest.len() != 64 || !declared_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(LibraryError::PortableFormat(
            "terminal digest is not a SHA-256 hexadecimal value".into(),
        ));
    }
    let mut hashed_body = body_without_final_newline.as_bytes().to_vec();
    hashed_body.push(b'\n');
    if sha256_hex(&hashed_body) != declared_digest.to_ascii_lowercase() {
        return Err(LibraryError::PortableDigestMismatch);
    }
    let body = std::str::from_utf8(&hashed_body)
        .map_err(|_| LibraryError::PortableFormat("artifact body is not UTF-8".into()))?;
    let mut lines = body.lines();
    let header = lines
        .next()
        .ok_or_else(|| LibraryError::PortableFormat("missing header".into()))?;
    let header_fields = header.split('\t').collect::<Vec<_>>();
    if header_fields.len() != 3 || header_fields[0] != "LINURA-LIBRARY" {
        return Err(LibraryError::PortableFormat(
            "invalid artifact header".into(),
        ));
    }
    let version = parse_u16(header_fields[1], "portable format version")?;
    if version > PORTABLE_FORMAT_VERSION {
        return Err(LibraryError::UnsupportedPortableFormat {
            found: version,
            supported: PORTABLE_FORMAT_VERSION,
        });
    }
    if version != PORTABLE_FORMAT_VERSION {
        return Err(LibraryError::PortableFormat(format!(
            "unsupported legacy portable format {version}"
        )));
    }
    if header_fields[2] != expected_kind {
        return Err(LibraryError::PortableFormat(format!(
            "expected {expected_kind} artifact, found {}",
            header_fields[2]
        )));
    }
    let mut parsed = ParsedArtifact {
        version,
        root: None,
        profile: None,
        intents: BTreeMap::new(),
        setups: BTreeMap::new(),
    };
    for (index, line) in lines.enumerate() {
        if index >= MAX_RECORDS {
            return Err(LibraryError::PortableFormat(
                "portable artifact exceeds record bound".into(),
            ));
        }
        if line.is_empty() {
            return Err(LibraryError::PortableFormat(
                "empty records are not permitted".into(),
            ));
        }
        parse_record(&mut parsed, line)?;
    }
    Ok(parsed)
}

fn parse_record(parsed: &mut ParsedArtifact, line: &str) -> Result<(), LibraryError> {
    let fields = line.split('\t').collect::<Vec<_>>();
    let kind = fields
        .first()
        .copied()
        .ok_or_else(|| LibraryError::PortableFormat("empty record".into()))?;
    match kind {
        "root-setup" => {
            require_fields(&fields, 3)?;
            if parsed.root.is_some() {
                return Err(LibraryError::PortableFormat(
                    "duplicate root-setup record".into(),
                ));
            }
            parsed.root = Some(SetupRevisionRef {
                id: SetupId::new(decode_text(fields[1])?).map_err(portable_validation)?,
                revision: parse_u32(fields[2], "setup revision")?,
            });
        }
        "intent" => parse_intent_base(parsed, &fields)?,
        "requirement" => parse_requirement(parsed, &fields)?,
        "supersedes" => parse_supersedes(parsed, &fields)?,
        "setup" => parse_setup_base(parsed, &fields)?,
        "setup-intent" => parse_setup_intent(parsed, &fields)?,
        "setup-include" => parse_setup_include(parsed, &fields)?,
        "setup-constraint" => parse_setup_value(parsed, &fields, SetupValueKind::Constraint)?,
        "setup-secret-ref" => parse_setup_value(parsed, &fields, SetupValueKind::SecretRef)?,
        "setup-hardware" => parse_setup_value(parsed, &fields, SetupValueKind::Hardware)?,
        "profile" => parse_profile_base(parsed, &fields)?,
        "profile-intent" => parse_profile_intent(parsed, &fields)?,
        "profile-setup" => parse_profile_setup(parsed, &fields)?,
        "profile-constraint" => parse_profile_value(parsed, &fields, ProfileValueKind::Constraint)?,
        "profile-hardware" => parse_profile_value(parsed, &fields, ProfileValueKind::Hardware)?,
        _ => {
            return Err(LibraryError::PortableFormat(format!(
                "unknown portable record {kind:?}"
            )));
        }
    }
    Ok(())
}

fn parse_intent_base(parsed: &mut ParsedArtifact, fields: &[&str]) -> Result<(), LibraryError> {
    require_fields(fields, 8)?;
    let id = decode_text(fields[1])?;
    let revision = parse_u64(fields[2], "intent revision")?;
    let entry = parsed.intents.entry((id, revision)).or_default();
    if entry.base.is_some() {
        return Err(LibraryError::PortableFormat(
            "duplicate intent base record".into(),
        ));
    }
    entry.base = Some(IntentBase {
        actor_id: decode_text(fields[3])?,
        actor_kind: fields[4].into(),
        actor_interactive: parse_bool(fields[5])?,
        status: fields[6].into(),
        statement: decode_text(fields[7])?,
    });
    Ok(())
}

fn parse_requirement(parsed: &mut ParsedArtifact, fields: &[&str]) -> Result<(), LibraryError> {
    require_fields(fields, 6)?;
    let id = decode_text(fields[1])?;
    let revision = parse_u64(fields[2], "intent revision")?;
    parsed
        .intents
        .entry((id, revision))
        .or_default()
        .requirements
        .push((
            decode_text(fields[3])?,
            fields[4].into(),
            decode_text(fields[5])?,
        ));
    Ok(())
}

fn parse_supersedes(parsed: &mut ParsedArtifact, fields: &[&str]) -> Result<(), LibraryError> {
    require_fields(fields, 4)?;
    let id = decode_text(fields[1])?;
    let revision = parse_u64(fields[2], "intent revision")?;
    parsed
        .intents
        .entry((id, revision))
        .or_default()
        .supersedes
        .push(decode_text(fields[3])?);
    Ok(())
}

fn parse_setup_base(parsed: &mut ParsedArtifact, fields: &[&str]) -> Result<(), LibraryError> {
    require_fields(fields, 5)?;
    let id = decode_text(fields[1])?;
    let revision = parse_u32(fields[2], "setup revision")?;
    let entry = parsed.setups.entry((id, revision)).or_default();
    if entry.base.is_some() {
        return Err(LibraryError::PortableFormat(
            "duplicate setup base record".into(),
        ));
    }
    entry.base = Some((decode_text(fields[3])?, decode_text(fields[4])?));
    Ok(())
}

fn parse_setup_intent(parsed: &mut ParsedArtifact, fields: &[&str]) -> Result<(), LibraryError> {
    require_fields(fields, 5)?;
    let id = decode_text(fields[1])?;
    let revision = parse_u32(fields[2], "setup revision")?;
    parsed
        .setups
        .entry((id, revision))
        .or_default()
        .intents
        .push((
            decode_text(fields[3])?,
            parse_u64(fields[4], "intent revision")?,
        ));
    Ok(())
}

fn parse_setup_include(parsed: &mut ParsedArtifact, fields: &[&str]) -> Result<(), LibraryError> {
    require_fields(fields, 5)?;
    let id = decode_text(fields[1])?;
    let revision = parse_u32(fields[2], "setup revision")?;
    parsed
        .setups
        .entry((id, revision))
        .or_default()
        .includes
        .push((
            decode_text(fields[3])?,
            parse_u32(fields[4], "setup revision")?,
        ));
    Ok(())
}

enum SetupValueKind {
    Constraint,
    SecretRef,
    Hardware,
}

fn parse_setup_value(
    parsed: &mut ParsedArtifact,
    fields: &[&str],
    kind: SetupValueKind,
) -> Result<(), LibraryError> {
    require_fields(fields, 5)?;
    let id = decode_text(fields[1])?;
    let revision = parse_u32(fields[2], "setup revision")?;
    let ordinal = parse_usize(fields[3], "setup value ordinal")?;
    let value = decode_text(fields[4])?;
    let entry = parsed.setups.entry((id, revision)).or_default();
    let target = match kind {
        SetupValueKind::Constraint => &mut entry.constraints,
        SetupValueKind::SecretRef => &mut entry.secret_refs,
        SetupValueKind::Hardware => &mut entry.hardware_hints,
    };
    if target.insert(ordinal, value).is_some() {
        return Err(LibraryError::PortableFormat(
            "duplicate setup ordinal".into(),
        ));
    }
    Ok(())
}

fn parse_profile_base(parsed: &mut ParsedArtifact, fields: &[&str]) -> Result<(), LibraryError> {
    require_fields(fields, 5)?;
    if parsed.profile.is_some() {
        return Err(LibraryError::PortableFormat(
            "duplicate profile base record".into(),
        ));
    }
    parsed.profile = Some(ProfileBuilder {
        key: Some((
            decode_text(fields[1])?,
            parse_u32(fields[2], "profile revision")?,
        )),
        name: Some(decode_text(fields[3])?),
        machine_class: Some(fields[4].into()),
        ..ProfileBuilder::default()
    });
    Ok(())
}

fn parse_profile_intent(parsed: &mut ParsedArtifact, fields: &[&str]) -> Result<(), LibraryError> {
    require_fields(fields, 5)?;
    require_profile_key(parsed, fields)?;
    parsed
        .profile
        .as_mut()
        .ok_or_else(|| LibraryError::PortableFormat("profile base must appear first".into()))?
        .intents
        .push((
            decode_text(fields[3])?,
            parse_u64(fields[4], "intent revision")?,
        ));
    Ok(())
}

fn parse_profile_setup(parsed: &mut ParsedArtifact, fields: &[&str]) -> Result<(), LibraryError> {
    require_fields(fields, 5)?;
    require_profile_key(parsed, fields)?;
    parsed
        .profile
        .as_mut()
        .ok_or_else(|| LibraryError::PortableFormat("profile base must appear first".into()))?
        .setups
        .push((
            decode_text(fields[3])?,
            parse_u32(fields[4], "setup revision")?,
        ));
    Ok(())
}

enum ProfileValueKind {
    Constraint,
    Hardware,
}

fn parse_profile_value(
    parsed: &mut ParsedArtifact,
    fields: &[&str],
    kind: ProfileValueKind,
) -> Result<(), LibraryError> {
    require_fields(fields, 5)?;
    require_profile_key(parsed, fields)?;
    let ordinal = parse_usize(fields[3], "profile value ordinal")?;
    let value = decode_text(fields[4])?;
    let profile = parsed
        .profile
        .as_mut()
        .ok_or_else(|| LibraryError::PortableFormat("profile base must appear first".into()))?;
    let target = match kind {
        ProfileValueKind::Constraint => &mut profile.constraints,
        ProfileValueKind::Hardware => &mut profile.hardware_hints,
    };
    if target.insert(ordinal, value).is_some() {
        return Err(LibraryError::PortableFormat(
            "duplicate profile ordinal".into(),
        ));
    }
    Ok(())
}

fn require_profile_key(parsed: &ParsedArtifact, fields: &[&str]) -> Result<(), LibraryError> {
    let profile = parsed
        .profile
        .as_ref()
        .and_then(|profile| profile.key.as_ref())
        .ok_or_else(|| LibraryError::PortableFormat("profile base must appear first".into()))?;
    let id = decode_text(fields[1])?;
    let revision = parse_u32(fields[2], "profile revision")?;
    if profile.0 != id || profile.1 != revision {
        return Err(LibraryError::PortableFormat(
            "profile child record does not match profile identity".into(),
        ));
    }
    Ok(())
}

fn finalize_intents(
    builders: BTreeMap<(String, u64), IntentBuilder>,
) -> Result<Vec<StoredIntent>, LibraryError> {
    builders
        .into_iter()
        .map(|((id, revision), builder)| {
            let base = builder.base.ok_or_else(|| {
                LibraryError::PortableFormat(format!("intent {id}@{revision} has no base record"))
            })?;
            let id = IntentId::new(id).map_err(portable_validation)?;
            let mut requirement_ids = BTreeSet::new();
            let requirements = builder
                .requirements
                .into_iter()
                .map(|(requirement_id, kind, statement)| {
                    let requirement_id =
                        RequirementId::new(requirement_id).map_err(portable_validation)?;
                    if !requirement_ids.insert(requirement_id.clone()) {
                        return Err(LibraryError::PortableFormat(
                            "duplicate requirement identity".into(),
                        ));
                    }
                    Ok(Requirement {
                        id: requirement_id,
                        kind: parse_requirement_kind(&kind)?,
                        statement,
                    })
                })
                .collect::<Result<Vec<_>, LibraryError>>()?;
            let mut supersedes = builder
                .supersedes
                .into_iter()
                .map(|value| IntentId::new(value).map_err(portable_validation))
                .collect::<Result<Vec<_>, _>>()?;
            supersedes.sort();
            if supersedes.windows(2).any(|window| window[0] == window[1]) {
                return Err(LibraryError::PortableFormat(
                    "duplicate intent supersession lineage".into(),
                ));
            }
            Ok(StoredIntent {
                intent: Intent {
                    id,
                    actor: Actor {
                        id: ActorId::new(base.actor_id).map_err(portable_validation)?,
                        kind: parse_actor_kind(&base.actor_kind)?,
                        interactive: base.actor_interactive,
                    },
                    statement: base.statement,
                    status: parse_intent_status(&base.status)?,
                    requirements,
                    supersedes,
                },
                revision,
            })
        })
        .collect()
}

fn finalize_setups(
    builders: BTreeMap<(String, u32), SetupBuilder>,
) -> Result<Vec<StoredSetup>, LibraryError> {
    builders
        .into_iter()
        .map(|((id, revision), builder)| {
            let (name, description) = builder.base.ok_or_else(|| {
                LibraryError::PortableFormat(format!("setup {id}@{revision} has no base record"))
            })?;
            let id = SetupId::new(id).map_err(portable_validation)?;
            let mut intent_revisions = builder
                .intents
                .into_iter()
                .map(|(intent_id, intent_revision)| {
                    Ok(IntentRevisionRef {
                        id: IntentId::new(intent_id).map_err(portable_validation)?,
                        revision: intent_revision,
                    })
                })
                .collect::<Result<Vec<_>, LibraryError>>()?;
            intent_revisions.sort_by(|left, right| {
                (left.id.as_str(), left.revision).cmp(&(right.id.as_str(), right.revision))
            });
            ensure_unique_intent_refs(&intent_revisions)?;
            let mut included_revisions = builder
                .includes
                .into_iter()
                .map(|(setup_id, setup_revision)| {
                    Ok(SetupRevisionRef {
                        id: SetupId::new(setup_id).map_err(portable_validation)?,
                        revision: setup_revision,
                    })
                })
                .collect::<Result<Vec<_>, LibraryError>>()?;
            included_revisions.sort_by(|left, right| {
                (left.id.as_str(), left.revision).cmp(&(right.id.as_str(), right.revision))
            });
            ensure_unique_setup_refs(&included_revisions)?;
            let setup = Setup {
                id,
                name,
                description,
                revision,
                intent_ids: intent_revisions
                    .iter()
                    .map(|value| value.id.clone())
                    .collect(),
                included_setup_ids: included_revisions
                    .iter()
                    .map(|value| value.id.clone())
                    .collect(),
                portable_constraints: ordered_values(builder.constraints)?,
                required_secret_refs: ordered_values(builder.secret_refs)?,
                hardware_hints: ordered_values(builder.hardware_hints)?,
            };
            setup.validate().map_err(|error| {
                LibraryError::PortableFormat(format!("invalid setup: {error:?}"))
            })?;
            Ok(StoredSetup {
                setup,
                intent_revisions,
                included_revisions,
            })
        })
        .collect()
}

fn finalize_profile(builder: ProfileBuilder) -> Result<StoredProfile, LibraryError> {
    let (id, revision) = builder
        .key
        .ok_or_else(|| LibraryError::PortableFormat("profile identity missing".into()))?;
    let id = ProfileId::new(id).map_err(portable_validation)?;
    let mut intent_revisions = builder
        .intents
        .into_iter()
        .map(|(intent_id, intent_revision)| {
            Ok(IntentRevisionRef {
                id: IntentId::new(intent_id).map_err(portable_validation)?,
                revision: intent_revision,
            })
        })
        .collect::<Result<Vec<_>, LibraryError>>()?;
    intent_revisions.sort_by(|left, right| {
        (left.id.as_str(), left.revision).cmp(&(right.id.as_str(), right.revision))
    });
    ensure_unique_intent_refs(&intent_revisions)?;
    let mut setup_revisions = builder
        .setups
        .into_iter()
        .map(|(setup_id, setup_revision)| {
            Ok(SetupRevisionRef {
                id: SetupId::new(setup_id).map_err(portable_validation)?,
                revision: setup_revision,
            })
        })
        .collect::<Result<Vec<_>, LibraryError>>()?;
    setup_revisions.sort_by(|left, right| {
        (left.id.as_str(), left.revision).cmp(&(right.id.as_str(), right.revision))
    });
    ensure_unique_setup_refs(&setup_revisions)?;
    Ok(StoredProfile {
        profile: MachineProfile {
            id,
            name: builder
                .name
                .ok_or_else(|| LibraryError::PortableFormat("profile name missing".into()))?,
            machine_class: parse_machine_class(
                builder
                    .machine_class
                    .as_deref()
                    .ok_or_else(|| LibraryError::PortableFormat("machine class missing".into()))?,
            )?,
            setup_ids: setup_revisions
                .iter()
                .map(|value| value.id.clone())
                .collect(),
            intent_ids: intent_revisions
                .iter()
                .map(|value| value.id.clone())
                .collect(),
            portable_constraints: ordered_values(builder.constraints)?,
            hardware_hints: ordered_values(builder.hardware_hints)?,
        },
        revision,
        intent_revisions,
        setup_revisions,
    })
}

fn validate_setup_bundle(bundle: &PortableSetupBundle) -> Result<(), LibraryError> {
    validate_version(bundle.format_version)?;
    let setup_map = setup_map(&bundle.setups)?;
    let intent_map = intent_map(&bundle.intents)?;
    let root_key = (bundle.root.id.as_str().to_owned(), bundle.root.revision);
    if !setup_map.contains_key(&root_key) {
        return Err(LibraryError::PortableFormat(
            "root setup revision is not present in bundle".into(),
        ));
    }
    validate_composition(&setup_map, &intent_map)?;
    validate_reachable_setup_closure(&root_key, &setup_map, &intent_map)
}

fn validate_profile_bundle(bundle: &PortableProfileBundle) -> Result<(), LibraryError> {
    validate_version(bundle.format_version)?;
    if bundle.profile.revision == 0 {
        return Err(LibraryError::PortableFormat(
            "profile revision must be positive".into(),
        ));
    }
    let setup_map = setup_map(&bundle.setups)?;
    let intent_map = intent_map(&bundle.intents)?;
    validate_composition(&setup_map, &intent_map)?;
    for reference in &bundle.profile.intent_revisions {
        if !intent_map.contains_key(&(reference.id.as_str().to_owned(), reference.revision)) {
            return Err(LibraryError::PortableFormat(format!(
                "profile references missing intent {}@{}",
                reference.id.as_str(),
                reference.revision
            )));
        }
    }
    for reference in &bundle.profile.setup_revisions {
        let key = (reference.id.as_str().to_owned(), reference.revision);
        if !setup_map.contains_key(&key) {
            return Err(LibraryError::PortableFormat(format!(
                "profile references missing setup {}@{}",
                reference.id.as_str(),
                reference.revision
            )));
        }
    }
    validate_profile_closure(&bundle.profile, &setup_map, &intent_map)
}

fn validate_version(version: u16) -> Result<(), LibraryError> {
    if version > PORTABLE_FORMAT_VERSION {
        return Err(LibraryError::UnsupportedPortableFormat {
            found: version,
            supported: PORTABLE_FORMAT_VERSION,
        });
    }
    if version != PORTABLE_FORMAT_VERSION {
        return Err(LibraryError::PortableFormat(format!(
            "unsupported legacy portable format {version}"
        )));
    }
    Ok(())
}

fn setup_map(
    setups: &[StoredSetup],
) -> Result<BTreeMap<(String, u32), &StoredSetup>, LibraryError> {
    let mut map = BTreeMap::new();
    for setup in setups {
        let key = (setup.setup.id.as_str().to_owned(), setup.setup.revision);
        if map.insert(key, setup).is_some() {
            return Err(LibraryError::PortableFormat(
                "duplicate setup revision in bundle".into(),
            ));
        }
    }
    Ok(map)
}

fn intent_map(
    intents: &[StoredIntent],
) -> Result<BTreeMap<(String, u64), &StoredIntent>, LibraryError> {
    let mut map = BTreeMap::new();
    for intent in intents {
        let key = (intent.intent.id.as_str().to_owned(), intent.revision);
        if map.insert(key, intent).is_some() {
            return Err(LibraryError::PortableFormat(
                "duplicate intent revision in bundle".into(),
            ));
        }
    }
    Ok(map)
}

fn validate_composition(
    setups: &BTreeMap<(String, u32), &StoredSetup>,
    intents: &BTreeMap<(String, u64), &StoredIntent>,
) -> Result<(), LibraryError> {
    for ((setup_id, setup_revision), setup) in setups {
        for reference in &setup.intent_revisions {
            if !intents.contains_key(&(reference.id.as_str().to_owned(), reference.revision)) {
                return Err(LibraryError::PortableFormat(format!(
                    "setup {setup_id}@{setup_revision} references missing intent {}@{}",
                    reference.id.as_str(),
                    reference.revision
                )));
            }
        }
        for reference in &setup.included_revisions {
            if !setups.contains_key(&(reference.id.as_str().to_owned(), reference.revision)) {
                return Err(LibraryError::PortableFormat(format!(
                    "setup {setup_id}@{setup_revision} references missing setup {}@{}",
                    reference.id.as_str(),
                    reference.revision
                )));
            }
        }
    }
    detect_setup_cycles(setups)
}

fn validate_reachable_setup_closure(
    root: &(String, u32),
    setups: &BTreeMap<(String, u32), &StoredSetup>,
    intents: &BTreeMap<(String, u64), &StoredIntent>,
) -> Result<(), LibraryError> {
    let mut pending = vec![root.clone()];
    let mut visited = BTreeSet::new();
    let mut referenced_intents = BTreeSet::new();
    while let Some(key) = pending.pop() {
        if !visited.insert(key.clone()) {
            continue;
        }
        let setup = setups.get(&key).ok_or_else(|| {
            LibraryError::PortableFormat("setup closure contains missing revision".into())
        })?;
        for reference in &setup.intent_revisions {
            referenced_intents.insert((reference.id.as_str().to_owned(), reference.revision));
        }
        for reference in &setup.included_revisions {
            pending.push((reference.id.as_str().to_owned(), reference.revision));
        }
    }
    if visited.len() != setups.len() {
        return Err(LibraryError::PortableFormat(
            "setup bundle contains unrelated setup revisions outside the root closure".into(),
        ));
    }
    if referenced_intents.len() != intents.len()
        || referenced_intents
            .iter()
            .any(|key| !intents.contains_key(key))
    {
        return Err(LibraryError::PortableFormat(
            "setup bundle contains missing or unrelated intent revisions".into(),
        ));
    }
    Ok(())
}

fn validate_profile_closure(
    profile: &StoredProfile,
    setups: &BTreeMap<(String, u32), &StoredSetup>,
    intents: &BTreeMap<(String, u64), &StoredIntent>,
) -> Result<(), LibraryError> {
    let mut pending = profile
        .setup_revisions
        .iter()
        .map(|reference| (reference.id.as_str().to_owned(), reference.revision))
        .collect::<Vec<_>>();
    let mut visited = BTreeSet::new();
    let mut referenced_intents = profile
        .intent_revisions
        .iter()
        .map(|reference| (reference.id.as_str().to_owned(), reference.revision))
        .collect::<BTreeSet<_>>();

    while let Some(key) = pending.pop() {
        if !visited.insert(key.clone()) {
            continue;
        }
        let setup = setups.get(&key).ok_or_else(|| {
            LibraryError::PortableFormat("profile closure contains missing setup revision".into())
        })?;
        for reference in &setup.intent_revisions {
            referenced_intents.insert((reference.id.as_str().to_owned(), reference.revision));
        }
        for reference in &setup.included_revisions {
            pending.push((reference.id.as_str().to_owned(), reference.revision));
        }
    }

    if visited.len() != setups.len() {
        return Err(LibraryError::PortableFormat(
            "profile bundle contains unrelated setup revisions outside the profile closure".into(),
        ));
    }
    if referenced_intents.len() != intents.len()
        || referenced_intents
            .iter()
            .any(|key| !intents.contains_key(key))
    {
        return Err(LibraryError::PortableFormat(
            "profile bundle contains missing or unrelated intent revisions".into(),
        ));
    }
    Ok(())
}

fn detect_setup_cycles(setups: &BTreeMap<(String, u32), &StoredSetup>) -> Result<(), LibraryError> {
    let mut permanent = BTreeSet::new();
    let mut temporary = BTreeSet::new();
    for key in setups.keys() {
        visit_setup(key, setups, &mut temporary, &mut permanent)?;
    }
    Ok(())
}

fn visit_setup(
    key: &(String, u32),
    setups: &BTreeMap<(String, u32), &StoredSetup>,
    temporary: &mut BTreeSet<(String, u32)>,
    permanent: &mut BTreeSet<(String, u32)>,
) -> Result<(), LibraryError> {
    if permanent.contains(key) {
        return Ok(());
    }
    if !temporary.insert(key.clone()) {
        return Err(LibraryError::PortableFormat(format!(
            "setup composition cycle detected at {}@{}",
            key.0, key.1
        )));
    }
    let setup = setups.get(key).ok_or_else(|| {
        LibraryError::PortableFormat("cycle traversal encountered missing setup".into())
    })?;
    for reference in &setup.included_revisions {
        let child = (reference.id.as_str().to_owned(), reference.revision);
        visit_setup(&child, setups, temporary, permanent)?;
    }
    temporary.remove(key);
    permanent.insert(key.clone());
    Ok(())
}

fn ordered_values(values: BTreeMap<usize, String>) -> Result<Vec<String>, LibraryError> {
    let mut output = Vec::with_capacity(values.len());
    for (expected, (ordinal, value)) in values.into_iter().enumerate() {
        if ordinal != expected {
            return Err(LibraryError::PortableFormat(
                "portable ordinal sequence contains a gap".into(),
            ));
        }
        output.push(value);
    }
    Ok(output)
}

fn ensure_unique_intent_refs(values: &[IntentRevisionRef]) -> Result<(), LibraryError> {
    if values
        .windows(2)
        .any(|window| window[0].id == window[1].id && window[0].revision == window[1].revision)
    {
        Err(LibraryError::PortableFormat(
            "duplicate intent revision reference".into(),
        ))
    } else {
        Ok(())
    }
}

fn ensure_unique_setup_refs(values: &[SetupRevisionRef]) -> Result<(), LibraryError> {
    if values
        .windows(2)
        .any(|window| window[0].id == window[1].id && window[0].revision == window[1].revision)
    {
        Err(LibraryError::PortableFormat(
            "duplicate setup revision reference".into(),
        ))
    } else {
        Ok(())
    }
}

fn push_line(output: &mut String, fields: &[&str]) {
    output.push_str(&fields.join("\t"));
    output.push('\n');
}

fn require_fields(fields: &[&str], expected: usize) -> Result<(), LibraryError> {
    if fields.len() == expected {
        Ok(())
    } else {
        Err(LibraryError::PortableFormat(format!(
            "record {} has {} fields; expected {expected}",
            fields.first().copied().unwrap_or("<empty>"),
            fields.len()
        )))
    }
}

fn hex_text(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value.as_bytes() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_text(value: &str) -> Result<String, LibraryError> {
    if value.len() % 2 != 0 {
        return Err(LibraryError::PortableFormat(
            "hex text contains odd byte count".into(),
        ));
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let high = hex_nibble(bytes[index])?;
        let low = hex_nibble(bytes[index + 1])?;
        decoded.push((high << 4) | low);
        index += 2;
    }
    String::from_utf8(decoded)
        .map_err(|_| LibraryError::PortableFormat("hex text is not valid UTF-8".into()))
}

fn hex_nibble(value: u8) -> Result<u8, LibraryError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(LibraryError::PortableFormat(
            "invalid hexadecimal text".into(),
        )),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn parse_u16(value: &str, label: &str) -> Result<u16, LibraryError> {
    value
        .parse::<u16>()
        .map_err(|_| LibraryError::PortableFormat(format!("invalid {label}")))
}

fn parse_u32(value: &str, label: &str) -> Result<u32, LibraryError> {
    let value = value
        .parse::<u32>()
        .map_err(|_| LibraryError::PortableFormat(format!("invalid {label}")))?;
    if value == 0 {
        return Err(LibraryError::PortableFormat(format!(
            "{label} must be positive"
        )));
    }
    Ok(value)
}

fn parse_u64(value: &str, label: &str) -> Result<u64, LibraryError> {
    let value = value
        .parse::<u64>()
        .map_err(|_| LibraryError::PortableFormat(format!("invalid {label}")))?;
    if value == 0 {
        return Err(LibraryError::PortableFormat(format!(
            "{label} must be positive"
        )));
    }
    Ok(value)
}

fn parse_usize(value: &str, label: &str) -> Result<usize, LibraryError> {
    value
        .parse::<usize>()
        .map_err(|_| LibraryError::PortableFormat(format!("invalid {label}")))
}

fn parse_bool(value: &str) -> Result<bool, LibraryError> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(LibraryError::PortableFormat(
            "boolean field must be 0 or 1".into(),
        )),
    }
}

fn actor_kind_str(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Human => "human",
        ActorKind::Service => "service",
        ActorKind::Agent => "agent",
        ActorKind::Remote => "remote",
    }
}

fn parse_actor_kind(value: &str) -> Result<ActorKind, LibraryError> {
    match value {
        "human" => Ok(ActorKind::Human),
        "service" => Ok(ActorKind::Service),
        "agent" => Ok(ActorKind::Agent),
        "remote" => Ok(ActorKind::Remote),
        _ => Err(LibraryError::PortableFormat(format!(
            "unknown actor kind {value:?}"
        ))),
    }
}

fn intent_status_str(status: IntentStatus) -> &'static str {
    match status {
        IntentStatus::Proposed => "proposed",
        IntentStatus::Active => "active",
        IntentStatus::Suspended => "suspended",
        IntentStatus::Superseded => "superseded",
        IntentStatus::Retired => "retired",
    }
}

fn parse_intent_status(value: &str) -> Result<IntentStatus, LibraryError> {
    match value {
        "proposed" => Ok(IntentStatus::Proposed),
        "active" => Ok(IntentStatus::Active),
        "suspended" => Ok(IntentStatus::Suspended),
        "superseded" => Ok(IntentStatus::Superseded),
        "retired" => Ok(IntentStatus::Retired),
        _ => Err(LibraryError::PortableFormat(format!(
            "unknown intent status {value:?}"
        ))),
    }
}

fn requirement_kind_str(kind: RequirementKind) -> &'static str {
    match kind {
        RequirementKind::Goal => "goal",
        RequirementKind::Constraint => "constraint",
        RequirementKind::Preference => "preference",
        RequirementKind::Prohibition => "prohibition",
    }
}

fn parse_requirement_kind(value: &str) -> Result<RequirementKind, LibraryError> {
    match value {
        "goal" => Ok(RequirementKind::Goal),
        "constraint" => Ok(RequirementKind::Constraint),
        "preference" => Ok(RequirementKind::Preference),
        "prohibition" => Ok(RequirementKind::Prohibition),
        _ => Err(LibraryError::PortableFormat(format!(
            "unknown requirement kind {value:?}"
        ))),
    }
}

fn parse_machine_class(value: &str) -> Result<MachineClass, LibraryError> {
    match value {
        "workstation" => Ok(MachineClass::Workstation),
        "server" => Ok(MachineClass::Server),
        "edge" => Ok(MachineClass::Edge),
        _ => Err(LibraryError::PortableFormat(format!(
            "unknown machine class {value:?}"
        ))),
    }
}

fn portable_validation(error: linura_core::ValidationError) -> LibraryError {
    LibraryError::PortableFormat(error.to_string())
}
