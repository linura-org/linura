"""Fail-closed path-impact classification for v0.9's exact-source PR lanes."""
from __future__ import annotations


class RoutingError(ValueError):
    pass


def requires_full_qualification(changed: list[str], contract: dict) -> bool:
    if (contract.get("schema_version") != 1 or
            contract.get("pull_request_default_lane") != "exact-source-regression" or
            contract.get("workflow_call_lane") != "full-qualification" or
            contract.get("workflow_dispatch_lane") != "full-qualification"):
        raise RoutingError("invalid v0.9 routing contract identity")
    exact = contract.get("full_exact")
    prefixes = contract.get("full_prefixes")
    guidance = contract.get("guidance_only_basenames")
    if (not isinstance(exact, list) or not exact or
            any(not isinstance(p, str) or not p or p.startswith("/")
                for p in exact) or len(exact) != len(set(exact)) or
            not isinstance(prefixes, list) or not prefixes or
            any(not isinstance(p, str) or not p.endswith("/") or p.startswith("/")
                for p in prefixes) or len(prefixes) != len(set(prefixes)) or
            guidance != ["AGENTS.md", "README.md"]):
        raise RoutingError("invalid full-qualification route contract")
    if not changed:
        return True  # Unknown or empty impact is not a valid fast-lane exemption.
    for path in changed:
        if (not isinstance(path, str) or not path or path.startswith("/") or
                path.endswith("/") or ".." in path.split("/")):
            raise RoutingError("unsafe or ambiguous changed path")
        if path in exact:
            return True
        if path.startswith(tuple(prefixes)) and path.rsplit("/", 1)[-1] not in guidance:
            return True
    return False
