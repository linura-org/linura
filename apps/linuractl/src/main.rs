#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

use linura_sdk::{
    ActorKind, CapabilityId, IntentId, LocalLibrary, MAX_CATALOG_PAGE_SIZE,
    LocalAuthorityClient, LocalControlClient,
    LocalSessionClient, LocalSessionEffectReceipt, PlanDesiredStateRequest, PlanId, PlanPreview,
    PlanReview, ProtectiveLockSettingReceipt, ProtectiveLockSettingRequest, ProtocolVersion,
    ProfileId, ProviderId, RequestId, RequirementId, ResourceId, RiskClass, SemanticReason,
    SetupId, SessionEpoch,
    SessionLockId, SessionLockReceipt, SessionLockRequest, SessionTransitionCompletion,
    SessionTransitionReceipt, SessionTransitionRequest,
};

#[derive(Clone, Copy)]
struct CommandInfo {
    name: &'static str,
    summary: &'static str,
    offline: bool,
}

const COMMANDS: &[CommandInfo] = &[
    CommandInfo {
        name: "native-sleep-gate-status",
        summary: "Read own-login sleep diagnostics, never current protection or successful sleep",
        offline: false,
    },
    CommandInfo {
        name: "configure-protective-lock",
        summary: "Authenticate exact login-scoped protective-lock consent; does not lock or sleep",
        offline: false,
    },
    CommandInfo {
        name: "protective-lock-setting",
        summary: "Read retained consent for an exact own-login epoch, not native protection",
        offline: false,
    },
    CommandInfo {
        name: "protective-lock-setting-status",
        summary: "Inspect a lost-reply consent request without reapplying or reenabling it",
        offline: false,
    },
    CommandInfo {
        name: "own-session-transition",
        summary: "Query an exact power target with a native suspend baseline",
        offline: false,
    },
    CommandInfo {
        name: "transition-session",
        summary: "Request a managed suspend/logout/reboot/power-off from a secure lock",
        offline: false,
    },
    CommandInfo {
        name: "session-transition-status",
        summary: "Read historical durable power status, not current machine state",
        offline: false,
    },
    CommandInfo {
        name: "recover-session-transition",
        summary: "Observe-only power recovery; never replay a transition",
        offline: false,
    },
    CommandInfo {
        name: "acknowledge-session-transition",
        summary: "Acknowledge a committed suspend without another effect or unlock",
        offline: false,
    },
    CommandInfo {
        name: "own-session-lock",
        summary: "Query the exact native own-session lock generation",
        offline: false,
    },
    CommandInfo {
        name: "lock-session",
        summary: "Request a managed lock after native purpose-bound confirmation",
        offline: false,
    },
    CommandInfo {
        name: "unlock-session",
        summary: "Request a managed release after native owner authentication",
        offline: false,
    },
    CommandInfo {
        name: "session-lock-status",
        summary: "Read historical durable request status, not current coverage",
        offline: false,
    },
    CommandInfo {
        name: "recover-session-lock",
        summary: "Observe-only managed recovery; never replay the effect",
        offline: false,
    },
    CommandInfo {
        name: "acknowledge-session-release",
        summary: "Acknowledge a committed verified release without another effect",
        offline: false,
    },
    CommandInfo {
        name: "library-list",
        summary: "Offline read-only bounded exact Library catalog; does not verify machine state",
        offline: true,
    },
    CommandInfo {
        name: "version",
        summary: "Show Linura and protocol version",
        offline: true,
    },
    CommandInfo {
        name: "commands",
        summary: "List machine-readable CLI command metadata",
        offline: true,
    },
    CommandInfo {
        name: "whoami",
        summary: "Show the authenticated local D-Bus caller identity",
        offline: false,
    },
    CommandInfo {
        name: "capabilities",
        summary: "List observation providers, health, and capabilities",
        offline: false,
    },
    CommandInfo {
        name: "observe",
        summary: "Read authoritative current state for one resource",
        offline: false,
    },
    CommandInfo {
        name: "graph",
        summary: "Show the current observed causal system graph",
        offline: false,
    },
    CommandInfo {
        name: "explain",
        summary: "Explain the authoritative evidence for one resource",
        offline: false,
    },
    CommandInfo {
        name: "plan-preview",
        summary: "Create an evidence-bound non-executable desired-state preview",
        offline: false,
    },
    CommandInfo {
        name: "get-plan-preview",
        summary: "Read one retained non-executable preview",
        offline: false,
    },
    CommandInfo {
        name: "explain-plan-preview",
        summary: "Explain one retained non-executable preview",
        offline: false,
    },
    CommandInfo {
        name: "review-plan",
        summary: "Review one retained canonical plan through trusted policy",
        offline: false,
    },
    CommandInfo {
        name: "set-audio-output-volume",
        summary: "Set one exact PipeWire output node volume through Session1 Control",
        offline: false,
    },
    CommandInfo {
        name: "explain-plan-review",
        summary: "Explain the trusted review of one retained canonical plan",
        offline: false,
    },
    CommandInfo {
        name: "help",
        summary: "Show CLI help",
        offline: true,
    },
];

fn main() {
    if let Err(error) = run() {
        eprintln!("linuractl: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("native-sleep-gate-status") => {
            require_arity(&args, 1, "native-sleep-gate-status")?;
            let status = LocalAuthorityClient::connect()?.own_native_sleep_gate_status()?;
            field("own_login", status.epoch.resource_id()?.as_str());
            field("process_retained_native_sleep_gate", status.state.as_str());
            field("current_native_protection", "not-queried");
            field("successful_sleep", "not-claimed");
        }
        Some("configure-protective-lock") => {
            require_arity(
                &args,
                4,
                "configure-protective-lock <enable|revoke> <operation-id> <exact-lock-resource>",
            )?;
            let enabled = protective_lock_decision(&args[1])?;
            let lock = SessionLockId::from_resource(&ResourceId::new(&args[3])?)?;
            let receipt = LocalAuthorityClient::connect()?.configure_protective_lock(
                &ProtectiveLockSettingRequest {
                    operation_id: args[2].clone(),
                    lock,
                    enabled,
                },
            )?;
            print_protective_lock_setting(&receipt)?;
        }
        Some("protective-lock-setting") => {
            require_arity(
                &args,
                2,
                "protective-lock-setting <exact-session-epoch-resource>",
            )?;
            let epoch = SessionEpoch::from_resource(&ResourceId::new(&args[1])?)?;
            let receipt =
                LocalAuthorityClient::connect()?.recorded_protective_lock_setting(&epoch)?;
            if let Some(receipt) = receipt {
                print_protective_lock_setting(&receipt)?;
            } else {
                field("retained_consent", "absent-default-deny");
                field("current_native_protection", "not-queried");
            }
        }
        Some("protective-lock-setting-status") => {
            require_arity(&args, 2, "protective-lock-setting-status <request-id>")?;
            let receipt = LocalAuthorityClient::connect()?
                .protective_lock_setting_request_status(&RequestId::new(&args[1])?)?;
            print_protective_lock_setting(&receipt)?;
        }
        Some("own-session-transition") => {
            require_arity(
                &args,
                2,
                "own-session-transition <suspend|logout|reboot|power-off>",
            )?;
            let action = transition_action(&args[1])?;
            let target = LocalAuthorityClient::connect()?.own_session_transition(action)?;
            field("resource", target.resource_id()?.as_str());
        }
        Some("transition-session") => {
            require_arity(
                &args,
                4,
                "transition-session <suspend|logout|reboot|power-off> <operation-id> <reason>",
            )?;
            let action = transition_action(&args[1])?;
            let client = LocalAuthorityClient::connect()?;
            let receipt = client.converge_session_transition(&SessionTransitionRequest {
                operation_id: args[2].clone(),
                target: client.own_session_transition(action)?,
                reason: args[3].clone(),
            })?;
            print_transition_receipt(&receipt)?;
        }
        Some("session-transition-status") => {
            require_arity(&args, 2, "session-transition-status <request-id>")?;
            let status = LocalAuthorityClient::connect()?
                .session_transition_request_status(&RequestId::new(&args[1])?)?;
            field("request_id", status.request_id.as_str());
            field("transaction_id", &status.transaction_id);
            field("resource", status.target.resource_id()?.as_str());
            field("historical_transaction_state", &status.state);
            field("current_native_power_state", "not-queried");
        }
        Some("recover-session-transition") => {
            require_arity(&args, 2, "recover-session-transition <request-id>")?;
            let receipt = LocalAuthorityClient::connect()?
                .recover_session_transition(&RequestId::new(&args[1])?)?;
            print_transition_receipt(&receipt)?;
        }
        Some("acknowledge-session-transition") => {
            require_arity(&args, 2, "acknowledge-session-transition <request-id>")?;
            let acknowledged = LocalAuthorityClient::connect()?
                .acknowledge_session_transition(&RequestId::new(&args[1])?)?;
            field(
                "native_transition_acknowledged",
                if acknowledged { "true" } else { "false" },
            );
            field("effect_replayed", "false");
        }
        Some("own-session-lock") => {
            require_arity(&args, 1, "own-session-lock")?;
            let lock = LocalAuthorityClient::connect()?.own_session_lock()?;
            field("resource", lock.resource_id()?.as_str());
        }
        Some("lock-session" | "unlock-session") => {
            require_arity(
                &args,
                3,
                "lock-session|unlock-session <operation-id> <reason>",
            )?;
            let client = LocalAuthorityClient::connect()?;
            let request = SessionLockRequest {
                operation_id: args[1].clone(),
                lock: client.own_session_lock()?,
                secure: args[0] == "lock-session",
                reason: args[2].clone(),
            };
            let receipt = client.converge_session_lock(&request)?;
            print_lock_receipt(&receipt)?;
        }
        Some("session-lock-status") => {
            require_arity(&args, 2, "session-lock-status <request-id>")?;
            let request = RequestId::new(&args[1])?;
            let status = LocalAuthorityClient::connect()?.session_lock_request_status(&request)?;
            field("request_id", status.request_id.as_str());
            field("transaction_id", &status.transaction_id);
            field("resource", status.lock.resource_id()?.as_str());
            field(
                "desired_secure",
                if status.secure { "true" } else { "false" },
            );
            field("historical_transaction_state", &status.state);
            field("current_native_coverage", "not-queried");
        }
        Some("recover-session-lock") => {
            require_arity(&args, 2, "recover-session-lock <request-id>")?;
            let receipt = LocalAuthorityClient::connect()?
                .recover_session_lock(&RequestId::new(&args[1])?)?;
            print_lock_receipt(&receipt)?;
        }
        Some("acknowledge-session-release") => {
            require_arity(&args, 2, "acknowledge-session-release <request-id>")?;
            let acknowledged = LocalAuthorityClient::connect()?
                .acknowledge_session_lock_release(&RequestId::new(&args[1])?)?;
            field(
                "native_release_acknowledged",
                if acknowledged { "true" } else { "false" },
            );
            field("effect_replayed", "false");
        }
        Some("library-list") => library_list(&args)?,
        Some("version") => {
            require_arity(&args, 1, "version")?;
            let version = ProtocolVersion::default();
            println!(
                "linuractl {} (protocol {})",
                version.product_version, version.major
            );
        }
        Some("commands") if args.get(1).map(String::as_str) == Some("--json") => {
            require_arity(&args, 2, "commands [--json]")?;
            println!("{}", commands_json());
        }
        Some("commands") => {
            require_arity(&args, 1, "commands [--json]")?;
            print_commands();
        }
        Some("whoami") => {
            require_arity(&args, 1, "whoami")?;
            let (actor_id, kind, interactive, uid, pid, sender) =
                LocalControlClient::connect()?.who_am_i()?;
            field("actor_id", &actor_id);
            field("actor_kind", &kind);
            field("interactive", if interactive { "true" } else { "false" });
            field("uid", &uid.to_string());
            field("pid", &pid.to_string());
            field("dbus_sender", &sender);
        }
        Some("capabilities") => {
            require_arity(&args, 1, "capabilities")?;
            let (providers, capabilities) = LocalControlClient::connect()?.capabilities()?;
            for (index, (provider, availability, reason)) in providers.iter().enumerate() {
                if index > 0 {
                    println!();
                }
                field("provider", provider);
                field("availability", availability);
                if !reason.is_empty() {
                    field("reason", reason);
                }
            }
            for (id, provider, support, reason) in capabilities {
                println!();
                field("capability", &id);
                field("provider", &provider);
                field("support", &support);
                if !reason.is_empty() {
                    field("reason", &reason);
                }
            }
        }
        Some("observe") => {
            let (provider, capability, resource) = parse_observe_args(&args)?;
            let observation =
                LocalControlClient::connect()?.observe(provider, resource, capability)?;
            let (
                provider,
                resource,
                capability,
                authority,
                freshness,
                observed_at,
                valid_for,
                sequence,
                attributes,
            ) = observation;
            field("provider", &provider);
            field("resource", &resource);
            field("capability", &capability);
            field("authority", &authority);
            field("freshness", &freshness);
            field("observed_at_unix_ms", &observed_at.to_string());
            field("valid_for_ms", &valid_for.to_string());
            field("sequence", &sequence.to_string());
            for (key, value) in attributes {
                field(&format!("attribute.{key}"), &value);
            }
        }
        Some("graph") => {
            require_arity(&args, 1, "graph")?;
            let (nodes, edges) = LocalControlClient::connect()?.graph()?;
            for (index, (node, attributes)) in nodes.into_iter().enumerate() {
                if index > 0 {
                    println!();
                }
                field("node", &node);
                for (key, value) in attributes {
                    field(&format!("attribute.{key}"), &value);
                }
            }
            for (from, to, kind, reason) in edges {
                println!();
                field("edge_from", &from);
                field("edge_to", &to);
                field("edge_kind", &kind);
                field("reason", &reason);
            }
        }
        Some("explain") => {
            require_arity(&args, 2, "explain <resource>")?;
            let (resource, provider, capability, freshness, evidence_id, authority) =
                LocalControlClient::connect()?.explain(&args[1])?;
            field("resource", &resource);
            field("provider", &provider);
            field("capability", &capability);
            field("freshness", &freshness);
            field("evidence_id", &evidence_id);
            field("authority", &authority);
        }
        Some("plan-preview") => {
            let request = parse_plan_preview_args(&args)?;
            let preview = LocalControlClient::connect()?.plan_desired_state(&request)?;
            print_plan_preview(&preview);
        }
        Some("get-plan-preview") => {
            require_arity(&args, 2, "get-plan-preview <plan-id>")?;
            let plan_id = PlanId::new(args[1].clone())?;
            let preview = LocalControlClient::connect()?.get_plan_preview(&plan_id)?;
            print_plan_preview(&preview);
        }
        Some("explain-plan-preview") => {
            require_arity(&args, 2, "explain-plan-preview <plan-id>")?;
            let plan_id = PlanId::new(args[1].clone())?;
            let preview = LocalControlClient::connect()?.explain_plan_preview(&plan_id)?;
            print_plan_preview(&preview);
        }
        Some("review-plan") => {
            require_arity(&args, 2, "review-plan <plan-id>")?;
            let plan_id = PlanId::new(args[1].clone())?;
            let review = LocalControlClient::connect()?.review_plan(&plan_id)?;
            print_plan_review(&review);
        }
        Some("explain-plan-review") => {
            require_arity(&args, 2, "explain-plan-review <plan-id>")?;
            let plan_id = PlanId::new(args[1].clone())?;
            let review = LocalControlClient::connect()?.explain_plan_review(&plan_id)?;
            print_plan_review(&review);
        }
        Some("set-audio-output-volume") => {
            require_arity(
                &args,
                5,
                "set-audio-output-volume <request-id> <node-id> <volume-percent> <reason>",
            )?;
            let request_id = RequestId::new(args[1].clone())?;
            let node_id = parse_canonical_u32(&args[2], "node-id")?;
            let volume_percent = parse_canonical_u16(&args[3], "volume-percent")?;
            if volume_percent > 100 {
                return Err(Box::new(CliError(
                    "volume-percent must be in the inclusive range 0..100".into(),
                )));
            }
            let receipt = LocalSessionClient::connect()?.set_audio_output_volume(
                request_id.as_str(),
                node_id,
                volume_percent,
                &args[4],
            )?;
            print_session_effect_receipt(&receipt);
        }
        Some("help") | Some("--help") | Some("-h") | None => print_help(),
        Some(other) => {
            return Err(Box::new(CliError(format!(
                "unknown command {other:?}; run `linuractl help`"
            ))));
        }
    }
    Ok(())
}

fn library_list(args: &[String]) -> Result<(), Box<dyn Error>> {
    if args.len() < 3 || args.len() > 5 {
        return Err(Box::new(CliError(
            "usage: linuractl library-list <existing-db-path> <intents|setups|profiles> [page-size] [after-id]".into(),
        )));
    }
    let page_size = match args.get(3) {
        Some(size) => size.parse::<usize>()?,
        None => 32,
    };
    if !(1..=MAX_CATALOG_PAGE_SIZE).contains(&page_size) {
        return Err(Box::new(CliError(format!(
            "library page size must be between 1 and {MAX_CATALOG_PAGE_SIZE}"
        ))));
    }
    let mut library = LocalLibrary::open_existing_read_only(&args[1])?;
    field("schema_version", &library.schema_version()?.to_string());
    field("source", "existing-local-sqlite");
    field("machine_verified", "false");
    match args[2].as_str() {
        "intents" => {
            let after = args.get(4).map(|id| IntentId::new(id)).transpose()?;
            let page = library.catalog_intents_page(after.as_ref(), page_size)?;
            for value in &page.items {
                println!();
                field("kind", "intent");
                field("id", value.intent.id.as_str());
                field("revision", &value.revision.to_string());
                field("status", &format!("{:?}", value.intent.status));
            }
            if let Some(next) = &page.next_after {
                println!();
                field("next_after", next.as_str());
            }
        }
        "setups" => {
            let after = args.get(4).map(|id| SetupId::new(id)).transpose()?;
            let page = library.catalog_setups_page(after.as_ref(), page_size)?;
            for value in &page.items {
                println!();
                field("kind", "setup");
                field("id", value.setup.id.as_str());
                field("revision", &value.setup.revision.to_string());
                field("name", &value.setup.name);
                field("local_state", "stored-only");
            }
            if let Some(next) = &page.next_after {
                println!();
                field("next_after", next.as_str());
            }
        }
        "profiles" => {
            let after = args.get(4).map(|id| ProfileId::new(id)).transpose()?;
            let page = library.catalog_profiles_page(after.as_ref(), page_size)?;
            for value in &page.items {
                println!();
                field("kind", "profile");
                field("id", value.profile.id.as_str());
                field("revision", &value.revision.to_string());
                field("name", &value.profile.name);
                field("local_state", "stored-only");
            }
            if let Some(next) = &page.next_after {
                println!();
                field("next_after", next.as_str());
            }
        }
        _ => {
            return Err(Box::new(CliError(
                "library kind must be intents, setups, or profiles".into(),
            )));
        }
    }
    Ok(())
}

fn parse_observe_args(args: &[String]) -> Result<(&str, &str, &str), Box<dyn Error>> {
    match args {
        [_, resource] => {
            let (provider, capability) = infer_route(resource)?;
            Ok((provider, capability, resource))
        }
        [_, provider, capability, resource] => Ok((provider, capability, resource)),
        _ => Err(Box::new(CliError(
            "usage: linuractl observe <resource> OR linuractl observe <provider> <capability> <resource>"
                .into(),
        ))),
    }
}

fn protective_lock_decision(value: &str) -> Result<bool, Box<dyn Error>> {
    match value {
        "enable" => Ok(true),
        "revoke" => Ok(false),
        _ => Err("protective-lock decision must be enable or revoke".into()),
    }
}

fn print_protective_lock_setting(
    receipt: &ProtectiveLockSettingReceipt,
) -> Result<(), Box<dyn Error>> {
    field("request_id", receipt.request_id.as_str());
    field(
        "confirmation_lock",
        receipt.confirmed_lock.resource_id()?.as_str(),
    );
    field(
        "recorded_consent",
        if receipt.enabled {
            "enabled"
        } else {
            "revoked"
        },
    );
    field("intent_id", receipt.intent_id.as_str());
    field("revision_id", receipt.revision_id.as_str());
    field(
        "confirmed_at_unix_ms",
        &receipt.confirmed_at_unix_ms.to_string(),
    );
    field(
        "latest_for_recorded_epoch",
        &receipt.latest_for_epoch.to_string(),
    );
    field("current_native_protection", "not-queried");
    Ok(())
}

fn print_lock_receipt(receipt: &SessionLockReceipt) -> Result<(), Box<dyn Error>> {
    field("request_id", receipt.request_id.as_str());
    field("transaction_id", &receipt.transaction_id);
    field("resource", receipt.lock.resource_id()?.as_str());
    field(
        "desired_secure",
        if receipt.secure { "true" } else { "false" },
    );
    field("completion", "verified-committed-reconciled");
    field(
        "recovered",
        if receipt.recovered { "true" } else { "false" },
    );
    field("effect_digest", &receipt.effect_digest);
    field("stages", &receipt.stages.join(","));
    Ok(())
}

fn transition_action(action: &str) -> Result<&str, CliError> {
    match action {
        "suspend" | "logout" | "reboot" | "power-off" => Ok(action),
        _ => Err(CliError(
            "unsupported session transition; no force/skip/ambient action is accepted".into(),
        )),
    }
}

fn print_transition_receipt(receipt: &SessionTransitionReceipt) -> Result<(), Box<dyn Error>> {
    field("request_id", receipt.request_id.as_str());
    field("transaction_id", &receipt.transaction_id);
    field("resource", receipt.target.resource_id()?.as_str());
    field("completion", "verified-committed-reconciled");
    field(
        "postcondition",
        match receipt.completion {
            SessionTransitionCompletion::ResumedSecurely => "resumed-securely",
            SessionTransitionCompletion::OriginalSessionEnded => "original-session-ended",
            SessionTransitionCompletion::OriginalBootEnded => "original-boot-ended",
        },
    );
    field("current_native_power_state", "not-inferred");
    field(
        "recovered",
        if receipt.recovered { "true" } else { "false" },
    );
    field("effect_digest", &receipt.effect_digest);
    field("stages", &receipt.stages.join(","));
    Ok(())
}

fn parse_plan_preview_args(args: &[String]) -> Result<PlanDesiredStateRequest, Box<dyn Error>> {
    if args.len() < 6 {
        return Err(Box::new(CliError(plan_preview_usage().into())));
    }
    let request_id = RequestId::new(args[1].clone())?;
    let resource = ResourceId::new(args[2].clone())?;
    let (provider_name, capability_name) = infer_route(resource.as_str())?;
    let provider = ProviderId::new(provider_name)?;
    let observation_capability = CapabilityId::new(capability_name)?;
    let summary = args[3].clone();

    let mut intent_ids = Vec::new();
    let mut requirement_ids = Vec::new();
    let mut capability_ids = Vec::new();
    let mut desired_state = BTreeMap::new();
    let mut index = 4;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = args
            .get(index + 1)
            .ok_or_else(|| Box::new(CliError(plan_preview_usage().into())) as Box<dyn Error>)?;
        match flag {
            "--intent" => intent_ids.push(IntentId::new(value.clone())?),
            "--requirement" => requirement_ids.push(RequirementId::new(value.clone())?),
            "--capability-origin" => capability_ids.push(CapabilityId::new(value.clone())?),
            "--set" => {
                let (key, desired) = value.split_once('=').ok_or_else(|| {
                    Box::new(CliError(format!(
                        "invalid --set value {value:?}; expected key=value"
                    ))) as Box<dyn Error>
                })?;
                if key.is_empty() {
                    return Err(Box::new(CliError(
                        "desired-state attribute key cannot be empty".into(),
                    )));
                }
                if desired_state
                    .insert(key.to_string(), desired.to_string())
                    .is_some()
                {
                    return Err(Box::new(CliError(format!(
                        "duplicate desired-state attribute {key:?}"
                    ))));
                }
            }
            _ => {
                return Err(Box::new(CliError(format!(
                    "unknown plan-preview option {flag:?}; {}",
                    plan_preview_usage()
                ))));
            }
        }
        index += 2;
    }

    let reason = SemanticReason {
        summary,
        intent_ids,
        requirement_ids,
        capability_ids,
    };
    reason.validate()?;
    if desired_state.is_empty() {
        return Err(Box::new(CliError(
            "plan-preview requires at least one --set key=value".into(),
        )));
    }

    Ok(PlanDesiredStateRequest {
        request_id,
        provider,
        resource,
        observation_capability,
        reason,
        desired_state,
    })
}

fn plan_preview_usage() -> &'static str {
    "usage: linuractl plan-preview <request-id> <resource> <summary> [--intent <id>] [--requirement <id>] [--capability-origin <id>] --set <key=value> [--set <key=value> ...]"
}

fn infer_route(resource: &str) -> Result<(&'static str, &'static str), Box<dyn Error>> {
    if resource.starts_with("systemd:unit:") {
        return Ok(("systemd", "systemd.unit.observe"));
    }
    if resource == "networkmanager:manager" {
        return Ok(("networkmanager", "networkmanager.manager.observe"));
    }
    if resource.starts_with("networkmanager:device:") {
        return Ok(("networkmanager", "networkmanager.device.observe"));
    }
    if resource == "audio:session:default-output" || resource.starts_with("audio:session:output:") {
        return Ok(("pipewire", "audio.session.observe"));
    }
    Err(Box::new(CliError(format!(
        "cannot infer an observation provider for {resource:?}; use `linuractl observe <provider> <capability> <resource>`"
    ))))
}

fn parse_canonical_u32(value: &str, label: &str) -> Result<u32, Box<dyn Error>> {
    if value.is_empty()
        || value.len() > 10
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Box::new(CliError(format!(
            "{label} must be a canonical non-negative integer"
        ))));
    }
    value
        .parse::<u32>()
        .map_err(|_| Box::new(CliError(format!("{label} exceeds the u32 range"))) as Box<dyn Error>)
}

fn parse_canonical_u16(value: &str, label: &str) -> Result<u16, Box<dyn Error>> {
    if value.is_empty()
        || value.len() > 5
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Box::new(CliError(format!(
            "{label} must be a canonical non-negative integer"
        ))));
    }
    value
        .parse::<u16>()
        .map_err(|_| Box::new(CliError(format!("{label} exceeds the u16 range"))) as Box<dyn Error>)
}

fn print_session_effect_receipt(receipt: &LocalSessionEffectReceipt) {
    field("operation_id", &receipt.operation_id);
    field("plan_id", &receipt.plan_id);
    field("request_id", &receipt.request_id);
    field("risk", &receipt.risk);
    field("pre_effect_evidence_id", &receipt.pre_effect_evidence_id);
    if let Some(post) = &receipt.post_effect_evidence_id {
        field("post_effect_evidence_id", post);
    }
    field("status", &receipt.status);
}

fn require_arity(args: &[String], expected: usize, usage: &str) -> Result<(), Box<dyn Error>> {
    if args.len() == expected {
        Ok(())
    } else {
        Err(Box::new(CliError(format!("usage: linuractl {usage}"))))
    }
}

fn print_plan_preview(preview: &PlanPreview) {
    field("plan_id", preview.plan_id.as_str());
    field("request_id", preview.request_id.as_str());
    field("actor_id", preview.actor.id.as_str());
    field("actor_kind", actor_kind_name(preview.actor.kind));
    field(
        "actor_interactive",
        if preview.actor.interactive {
            "true"
        } else {
            "false"
        },
    );
    field("provider", preview.provider.as_str());
    field("resource", preview.resource.as_str());
    field("capability", preview.observation_capability.as_str());
    field("evidence_id", &preview.observed_evidence_id);
    field("prospective_risk", risk_name(preview.prospective_risk));
    field("status", preview.status.as_str());
    field(
        "execution_authorized",
        if preview.execution_authorized {
            "true"
        } else {
            "false"
        },
    );
    field("reason.summary", &preview.reason.summary);
    for (index, id) in preview.reason.intent_ids.iter().enumerate() {
        field(&format!("reason.intent.{index}"), id.as_str());
    }
    for (index, id) in preview.reason.requirement_ids.iter().enumerate() {
        field(&format!("reason.requirement.{index}"), id.as_str());
    }
    for (index, id) in preview.reason.capability_ids.iter().enumerate() {
        field(&format!("reason.capability.{index}"), id.as_str());
    }
    for (index, change) in preview.changes.iter().enumerate() {
        field(&format!("change.{index}.key"), &change.key);
        field(
            &format!("change.{index}.current_present"),
            if change.current.is_some() {
                "true"
            } else {
                "false"
            },
        );
        if let Some(current) = &change.current {
            field(&format!("change.{index}.current"), current);
        }
        field(&format!("change.{index}.desired"), &change.desired);
    }
    for (index, finding) in preview.findings.iter().enumerate() {
        field(&format!("finding.{index}.code"), &finding.code);
        field(&format!("finding.{index}.level"), finding.level.as_str());
        field(&format!("finding.{index}.message"), &finding.message);
    }
}

fn print_plan_review(review: &PlanReview) {
    field("plan_id", review.plan_id.as_str());
    field("request_id", review.request_id.as_str());
    field("principal", review.principal.as_str());
    field("actor_id", review.actor.id.as_str());
    field("actor_kind", actor_kind_name(review.actor.kind));
    field("provider", review.provider.as_str());
    field("resource", review.resource.as_str());
    field("capability", review.observation_capability.as_str());
    field("evidence_id", &review.observed_evidence_id);
    field("planner_risk_floor", risk_name(review.planner_risk_floor));
    field("reviewed_risk", risk_name(review.reviewed_risk));
    field("status", review.status.as_str());
    field("policy_id", review.policy_id.as_str());
    field("policy_revision_id", review.policy_revision_id.as_str());
    field("decision", review.decision.as_str());
    field(
        "approval_required",
        if review.approval_class.is_some() {
            "true"
        } else {
            "false"
        },
    );
    if let Some(class) = review.approval_class {
        field("approval_class", class.as_str());
    }
    if !review.decision_reason.is_empty() {
        field("decision_reason", &review.decision_reason);
    }
    field(
        "execution_authorized",
        if review.execution_authorized {
            "true"
        } else {
            "false"
        },
    );
    field("reason.summary", &review.reason.summary);
    for (index, id) in review.reason.intent_ids.iter().enumerate() {
        field(&format!("reason.intent.{index}"), id.as_str());
    }
    for (index, id) in review.reason.requirement_ids.iter().enumerate() {
        field(&format!("reason.requirement.{index}"), id.as_str());
    }
    for (index, id) in review.reason.capability_ids.iter().enumerate() {
        field(&format!("reason.capability.{index}"), id.as_str());
    }
    for (index, change) in review.changes.iter().enumerate() {
        field(&format!("change.{index}.key"), &change.key);
        if let Some(current) = &change.current {
            field(&format!("change.{index}.current"), current);
        }
        field(&format!("change.{index}.desired"), &change.desired);
    }
    for (index, finding) in review.findings.iter().enumerate() {
        field(&format!("finding.{index}.code"), &finding.code);
        field(&format!("finding.{index}.level"), finding.level.as_str());
        field(&format!("finding.{index}.message"), &finding.message);
    }
}

const fn actor_kind_name(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Human => "human",
        ActorKind::Service => "service",
        ActorKind::Agent => "agent",
        ActorKind::Remote => "remote",
    }
}

const fn risk_name(risk: RiskClass) -> &'static str {
    match risk {
        RiskClass::ReadOnly => "read-only",
        RiskClass::UserState => "user-state",
        RiskClass::SystemMutation => "system-mutation",
        RiskClass::SecuritySensitive => "security-sensitive",
        RiskClass::Destructive => "destructive",
    }
}

fn print_commands() {
    for command in COMMANDS {
        println!("{:<22} {}", command.name, command.summary);
    }
}

fn commands_json() -> String {
    let mut output = String::from("[");
    for (index, command) in COMMANDS.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"name\":");
        output.push_str(&json_string(command.name));
        output.push_str(",\"summary\":");
        output.push_str(&json_string(command.summary));
        output.push_str(",\"offline\":");
        output.push_str(if command.offline { "true" } else { "false" });
        output.push('}');
    }
    output.push(']');
    output
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character <= '\u{1f}' => {
                use std::fmt::Write as _;
                write!(&mut output, "\\u{:04x}", u32::from(character))
                    .unwrap_or_else(|_| unreachable!("writing to String cannot fail"));
            }
            other => output.push(other),
        }
    }
    output.push('"');
    output
}

fn field(key: &str, value: &str) {
    println!("{}={}", escaped(key), escaped(value));
}

fn escaped(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            other => output.push(other),
        }
    }
    output
}

fn print_help() {
    println!("linuractl {}", env!("CARGO_PKG_VERSION"));
    println!(
        "Authenticated Linura control client; sensitive effects require native managed authority."
    );
    println!();
    println!("Commands:");
    println!("  version");
    println!("  commands [--json]");
    println!("  library-list <existing-db-path> <intents|setups|profiles> [page-size] [after-id]");
    println!("  whoami");
    println!("  capabilities");
    println!("  observe <resource>");
    println!("  observe <provider> <capability> <resource>");
    println!("  graph");
    println!("  explain <resource>");
    println!(
        "  plan-preview <request-id> <resource> <summary> [origin flags] --set <key=value> ..."
    );
    println!("  get-plan-preview <plan-id>");
    println!("  explain-plan-preview <plan-id>");
    println!("  review-plan <plan-id>");
    println!("  explain-plan-review <plan-id>");
    println!("  set-audio-output-volume <request-id> <node-id> <volume-percent> <reason>");
    println!("  own-session-lock");
    println!("  native-sleep-gate-status");
    println!("  configure-protective-lock <enable|revoke> <operation-id> <exact-lock-resource>");
    println!("  protective-lock-setting <exact-session-epoch-resource>");
    println!("  protective-lock-setting-status <request-id>");
    println!("  lock-session <operation-id> <reason>");
    println!("  unlock-session <operation-id> <reason>");
    println!("  session-lock-status <request-id>");
    println!("  recover-session-lock <request-id>");
    println!("  acknowledge-session-release <request-id>");
    println!("  own-session-transition <suspend|logout|reboot|power-off>");
    println!("  transition-session <suspend|logout|reboot|power-off> <operation-id> <reason>");
    println!("  session-transition-status <request-id>");
    println!("  recover-session-transition <request-id>");
    println!("  acknowledge-session-transition <request-id>");
    println!("  help");
    println!();
    println!("Plan preview origin flags: --intent, --requirement, --capability-origin");
    println!(
        "Session operation IDs are stable lowercase slugs. Never put credentials in arguments or reasons."
    );
    println!(
        "After an uncertain session result, inspect request:v010:session-lock:<operation-id> status; recovery never replays the effect."
    );
    println!(
        "Power requires a verified secure lock first. Track request:v010:session-transition:<operation-id>; a dispatch reply never proves completion."
    );
}

#[derive(Debug)]
struct CliError(String);

impl Display for CliError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for CliError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn built_in_resource_routes_are_deterministic() {
        assert_eq!(
            infer_route("systemd:unit:sshd.service")
                .unwrap_or_else(|error| unreachable!("{error}")),
            ("systemd", "systemd.unit.observe")
        );
        assert_eq!(
            infer_route("networkmanager:manager").unwrap_or_else(|error| unreachable!("{error}")),
            ("networkmanager", "networkmanager.manager.observe")
        );
    }

    #[test]
    fn audio_resource_routes_are_read_only_discovery_capable() {
        assert_eq!(
            infer_route("audio:session:default-output")
                .unwrap_or_else(|error| unreachable!("{error}")),
            ("pipewire", "audio.session.observe")
        );
        assert_eq!(
            infer_route("audio:session:output:42").unwrap_or_else(|error| unreachable!("{error}")),
            ("pipewire", "audio.session.observe")
        );
    }

    #[test]
    fn audio_cli_numeric_inputs_are_canonical_and_bounded() {
        assert_eq!(
            parse_canonical_u32("42", "node-id").unwrap_or_else(|error| unreachable!("{error}")),
            42
        );
        assert_eq!(
            parse_canonical_u16("100", "volume-percent")
                .unwrap_or_else(|error| unreachable!("{error}")),
            100
        );
        for value in ["", "042", "+42", "-1", "42.0"] {
            assert!(parse_canonical_u32(value, "node-id").is_err(), "{value}");
        }
    }

    #[test]
    fn plan_preview_parser_is_typed_and_deterministic() {
        let args = strings(&[
            "plan-preview",
            "request:test",
            "systemd:unit:sshd.service",
            "keep SSH active",
            "--intent",
            "intent:ssh",
            "--capability-origin",
            "remote.ssh",
            "--set",
            "active_state=active",
        ]);
        let request =
            parse_plan_preview_args(&args).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(request.request_id.as_str(), "request:test");
        assert_eq!(request.provider.as_str(), "systemd");
        assert_eq!(
            request
                .desired_state
                .get("active_state")
                .map(String::as_str),
            Some("active")
        );
        assert_eq!(request.reason.intent_ids[0].as_str(), "intent:ssh");
    }

    #[test]
    fn plan_preview_parser_rejects_duplicate_desired_keys() {
        let args = strings(&[
            "plan-preview",
            "request:test",
            "systemd:unit:sshd.service",
            "keep SSH active",
            "--intent",
            "intent:ssh",
            "--set",
            "active_state=active",
            "--set",
            "active_state=inactive",
        ]);
        assert!(parse_plan_preview_args(&args).is_err());
    }

    #[test]
    fn output_escaping_is_line_safe() {
        assert_eq!(escaped("a\nb\\c\t"), "a\\nb\\\\c\\t");
    }

    #[test]
    fn protective_consent_parser_has_no_automatic_or_force_mode() {
        assert!(protective_lock_decision("enable").unwrap_or_else(|e| unreachable!("{e}")));
        assert!(!protective_lock_decision("revoke").unwrap_or_else(|e| unreachable!("{e}")));
        for value in [
            "",
            "true",
            "false",
            "Enable",
            "force",
            "automatic",
            "sleep",
            "unlock",
        ] {
            assert!(protective_lock_decision(value).is_err());
        }
    }

    #[test]
    fn command_catalog_is_unique_and_keeps_json_introspection() {
        let names: BTreeSet<_> = COMMANDS.iter().map(|command| command.name).collect();
        assert_eq!(names.len(), COMMANDS.len());
        assert!(names.contains("commands"));
        assert!(names.contains("observe"));
        assert!(names.contains("plan-preview"));
        assert!(names.contains("get-plan-preview"));
        assert!(names.contains("explain-plan-preview"));
        assert!(names.contains("set-audio-output-volume"));
        for name in [
            "native-sleep-gate-status",
            "configure-protective-lock",
            "protective-lock-setting",
            "protective-lock-setting-status",
            "own-session-lock",
            "lock-session",
            "unlock-session",
            "session-lock-status",
            "recover-session-lock",
            "acknowledge-session-release",
            "own-session-transition",
            "transition-session",
            "session-transition-status",
            "recover-session-transition",
            "acknowledge-session-transition",
        ] {
            assert!(names.contains(name));
            assert!(
                COMMANDS
                    .iter()
                    .any(|command| command.name == name && !command.offline)
            );
        }

        let json = commands_json();
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
        assert!(json.contains("\"name\":\"commands\""));
        assert!(json.contains("\"name\":\"observe\""));
        assert!(json.contains("\"name\":\"plan-preview\""));
        assert!(json.contains("\"name\":\"set-audio-output-volume\""));
        assert!(json.contains("\"offline\":true"));
        assert!(json.contains("\"offline\":false"));
    }

    #[test]
    fn json_strings_escape_control_characters() {
        assert_eq!(json_string("a\n\"b\\c\t"), "\"a\\n\\\"b\\\\c\\t\"");
    }

    #[test]
    fn transition_actions_are_fixed_without_shell_aliases_or_force_modes() {
        for action in ["suspend", "logout", "reboot", "power-off"] {
            assert_eq!(transition_action(action).ok(), Some(action));
        }
        for action in [
            "",
            "shutdown",
            "hibernate",
            "force",
            "--force",
            "reboot --force",
            "suspend\n",
            "poweroff",
            "Reboot",
        ] {
            assert!(transition_action(action).is_err());
        }
    }
}
