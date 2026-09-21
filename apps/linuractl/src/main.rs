#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

use linura_sdk::{
    ActorKind, CapabilityId, IntentId, LocalControlClient, LocalSessionClient,
    LocalSessionEffectReceipt, PlanDesiredStateRequest, PlanId, PlanPreview, PlanReview,
    ProtocolVersion, ProviderId, RequestId, RequirementId, ResourceId, RiskClass, SemanticReason,
};

#[derive(Clone, Copy)]
struct CommandInfo {
    name: &'static str,
    summary: &'static str,
    offline: bool,
}

const COMMANDS: &[CommandInfo] = &[
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
    println!("Authenticated Linura observation and non-executable planning client.");
    println!();
    println!("Commands:");
    println!("  version");
    println!("  commands [--json]");
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
    println!("  help");
    println!();
    println!("Plan preview origin flags: --intent, --requirement, --capability-origin");
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
    fn command_catalog_is_unique_and_keeps_json_introspection() {
        let names: BTreeSet<_> = COMMANDS.iter().map(|command| command.name).collect();
        assert_eq!(names.len(), COMMANDS.len());
        assert!(names.contains("commands"));
        assert!(names.contains("observe"));
        assert!(names.contains("plan-preview"));
        assert!(names.contains("get-plan-preview"));
        assert!(names.contains("explain-plan-preview"));
        assert!(names.contains("set-audio-output-volume"));

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
}
