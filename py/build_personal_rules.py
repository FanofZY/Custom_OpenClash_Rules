#!/usr/bin/env python3
"""Build personal rule providers and templates on top of the upstream branch."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


UPSTREAM_REPOSITORY = "Aethersailor/Custom_OpenClash_Rules"
CUSTOM_FILES = {
    "direct": Path("custom/Custom_Direct.list"),
    "proxy": Path("custom/Custom_Proxy.list"),
    "reject": Path("custom/Custom_Reject.list"),
}
PREPEND_FILE = Path("custom/Custom_Prepend.list")
UPSTREAM_RULES = {
    "direct": "rule/Custom_Direct.list",
    "proxy": "rule/Custom_Proxy.list",
}
TEMPLATES = (
    "Custom_Clash.ini",
    "Custom_Clash_Fallback.ini",
    "Custom_Clash_Lite.ini",
    "Custom_Clash_Lite_Fallback.ini",
    "Custom_Clash_GFW.ini",
    "Custom_Clash_GFW_Fallback.ini",
    "Custom_Clash_Full.ini",
    "Custom_Clash_Full_Fallback.ini",
)
SUPPORTED_RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "IP-CIDR",
    "IP-CIDR6",
    "SRC-PORT",
    "DST-PORT",
}


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str
    rendered: str

    @property
    def key(self) -> tuple[str, str]:
        return self.kind, self.value.casefold()


@dataclass(frozen=True)
class PolicyRule:
    kind: str
    value: str
    rendered: str
    policy: str

    @property
    def key(self) -> tuple[str, str]:
        return self.kind, self.value.casefold()


def git_output(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout


def git_file(root: Path, revision: str, path: str) -> str:
    return git_output(root, "show", f"{revision}:{path}")


def parse_rules(content: str, source: str) -> list[Rule]:
    rules: list[Rule] = []
    seen: set[tuple[str, str]] = set()
    for line_number, raw_line in enumerate(content.splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue

        parts = [part.strip() for part in stripped.split(",")]
        if len(parts) < 2:
            raise ValueError(f"{source}:{line_number}: malformed rule: {stripped}")
        kind, value = parts[0].upper(), parts[1]
        if kind not in SUPPORTED_RULE_TYPES:
            raise ValueError(
                f"{source}:{line_number}: unsupported rule type {kind}"
            )
        if not value:
            raise ValueError(f"{source}:{line_number}: empty rule value")

        if kind in {"IP-CIDR", "IP-CIDR6"}:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"{source}:{line_number}: invalid CIDR: {value}"
                ) from exc
            expected = "IP-CIDR6" if network.version == 6 else "IP-CIDR"
            if kind != expected:
                raise ValueError(
                    f"{source}:{line_number}: {value} must use {expected}"
                )
            value = str(network)
            rendered = f"{kind},{value},no-resolve"
        else:
            if len(parts) > 2:
                raise ValueError(
                    f"{source}:{line_number}: policy/options are not allowed; "
                    "the custom filename selects the policy"
                )
            rendered = f"{kind},{value}"

        rule = Rule(kind=kind, value=value, rendered=rendered)
        if rule.key in seen:
            raise ValueError(
                f"{source}:{line_number}: duplicate rule key: {kind},{value}"
            )
        seen.add(rule.key)
        rules.append(rule)
    return rules


def parse_prepend_rules(
    content: str, source: str
) -> tuple[list[PolicyRule], int]:
    """Parse full Clash rules, preserving their third-column policy."""
    rules: list[PolicyRule] = []
    owners: dict[tuple[str, str], str] = {}
    duplicates_removed = 0
    for line_number, raw_line in enumerate(content.splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue

        parts = [part.strip() for part in stripped.split(",")]
        has_no_resolve = (
            len(parts) == 4 and parts[3].casefold() == "no-resolve"
        )
        if len(parts) != 3 and not has_no_resolve:
            raise ValueError(
                f"{source}:{line_number}: expected KIND,VALUE,POLICY: "
                f"{stripped}"
            )
        base = parse_rules(
            f"{parts[0]},{parts[1]}\n", f"{source}:{line_number}"
        )[0]
        if has_no_resolve and base.kind not in {"IP-CIDR", "IP-CIDR6"}:
            raise ValueError(
                f"{source}:{line_number}: no-resolve is only valid for CIDR rules"
            )
        policy = parts[2]
        if not policy:
            raise ValueError(f"{source}:{line_number}: empty policy")

        previous = owners.get(base.key)
        if previous is not None:
            if previous == policy:
                duplicates_removed += 1
                continue
            raise ValueError(
                f"{source}:{line_number}: {base.kind},{base.value} already "
                f"uses policy {previous}"
            )
        owners[base.key] = policy
        rules.append(
            PolicyRule(
                kind=base.kind,
                value=base.value,
                rendered=base.rendered,
                policy=policy,
            )
        )
    return rules, duplicates_removed


def load_custom_rules(root: Path) -> dict[str, list[Rule]]:
    result: dict[str, list[Rule]] = {}
    owners: dict[tuple[str, str], str] = {}
    for policy, relative in CUSTOM_FILES.items():
        rules = parse_rules(
            (root / relative).read_text(encoding="utf-8-sig"),
            relative.as_posix(),
        )
        for rule in rules:
            previous = owners.get(rule.key)
            if previous is not None:
                raise ValueError(
                    f"{relative}: {rule.kind},{rule.value} also exists in "
                    f"personal {previous} rules"
                )
            owners[rule.key] = policy
        result[policy] = rules
    return result


def merge_rules(
    upstream: list[Rule], personal: list[Rule], claimed: set[tuple[str, str]]
) -> list[Rule]:
    merged = list(personal)
    seen = {rule.key for rule in personal}
    for rule in upstream:
        if rule.key in claimed or rule.key in seen:
            continue
        merged.append(rule)
        seen.add(rule.key)
    return merged


def render_provider(
    policy: str, upstream_sha: str, rules: list[Rule]
) -> str:
    lines = [
        "# Generated by py/build_personal_rules.py; do not edit.",
        f"# Upstream: {UPSTREAM_REPOSITORY}@{upstream_sha}",
        f"# Policy: {policy}",
        f"# Total: {len(rules)}",
        "",
    ]
    if not rules:
        lines.append("payload: []")
    else:
        lines.append("payload:")
        for rule in rules:
            escaped = rule.rendered.replace("'", "''")
            lines.append(f"  - '{escaped}'")
    return "\n".join(lines) + "\n"


def provider_url(repository: str, branch: str, filename: str) -> str:
    return (
        f"https://raw.githubusercontent.com/{repository}/{branch}/"
        f"dist/rule/{filename}"
    )


def proxy_groups(lines: list[str]) -> set[str]:
    groups: set[str] = set()
    for line in lines:
        if not line.startswith("custom_proxy_group="):
            continue
        definition = line.split("=", 1)[1]
        groups.add(definition.split("`", 1)[0])
    return groups


def resolve_policy(policy: str, groups: set[str]) -> str:
    main_proxy = next(
        (name for name in ("🚀 手动选择", "🚀 故障转移") if name in groups),
        None,
    )
    if policy == "DIRECT":
        return "🎯 全球直连"
    if policy == "REJECT":
        return "REJECT"
    if policy == "PROXY":
        if main_proxy is None:
            raise ValueError("template has no main proxy group")
        return main_proxy
    if policy in groups:
        return policy
    if policy in {
        "🚀 手动选择",
        "🚀 故障转移",
        "🇯🇵 日本节点",
        "🇺🇸 美国节点",
    } and main_proxy is not None:
        return main_proxy
    raise ValueError(f"template does not define policy group: {policy}")


def patch_template(
    content: str,
    repository: str,
    branch: str,
    include_reject: bool,
    prepend_rules: list[PolicyRule] | None = None,
) -> str:
    lines = [line.rstrip() for line in content.splitlines()]
    groups = proxy_groups(lines)
    main_proxy = resolve_policy("PROXY", groups) if groups else "🚀 手动选择"
    replacements = {
        "direct": (
            "Custom_Direct_Domain.mrs",
            "Custom_Direct_Classical_IP.yaml",
            "Personal_Direct_Classical.yaml",
        ),
        "proxy": (
            "Custom_Proxy_Domain.mrs",
            "Custom_Proxy_Classical_IP.yaml",
            "Personal_Proxy_Classical.yaml",
        ),
    }

    for policy, (domain_name, ip_name, output_name) in replacements.items():
        indexes = [
            index
            for index, line in enumerate(lines)
            if domain_name in line or ip_name in line
        ]
        url = provider_url(repository, branch, output_name)
        if not indexes:
            if policy == "direct":
                private_indexes = [
                    index
                    for index, line in enumerate(lines)
                    if line.startswith("ruleset=")
                    and "[]GEOIP,private" in line
                ]
                if private_indexes:
                    insert_at = private_indexes[-1] + 1
                else:
                    insert_at = next(
                        index
                        for index, line in enumerate(lines)
                        if line.startswith("ruleset=")
                    )
                group = "ruleset=🎯 全球直连"
            else:
                anchor = next(
                    index
                    for index, line in enumerate(lines)
                    if "Personal_Direct_Classical.yaml" in line
                )
                insert_at = anchor + 1
                group = f"ruleset={main_proxy}"
            lines.insert(insert_at, f"{group},clash-classic:{url},28800")
            continue
        if len(indexes) != 2:
            raise ValueError(
                f"upstream template anchor changed for {domain_name}: "
                f"expected 2 lines, found {len(indexes)}"
            )
        first, second = indexes
        group_match = re.match(r"^(ruleset=[^,]+),", lines[first])
        if group_match is None:
            raise ValueError(f"cannot read ruleset group from: {lines[first]}")
        lines[first] = f"{group_match.group(1)},clash-classic:{url},28800"
        del lines[second]

    if include_reject:
        direct_index = next(
            index
            for index, line in enumerate(lines)
            if "Personal_Direct_Classical.yaml" in line
        )
        reject_url = provider_url(
            repository, branch, "Personal_Reject_Classical.yaml"
        )
        lines.insert(
            direct_index,
            f"ruleset=REJECT,clash-classic:{reject_url},28800",
        )

    if prepend_rules:
        first_ruleset = next(
            index
            for index, line in enumerate(lines)
            if line.startswith("ruleset=")
        )
        rendered = [
            f"ruleset={resolve_policy(rule.policy, groups)},[]{rule.rendered}"
            for rule in prepend_rules
        ]
        lines[first_ruleset:first_ruleset] = [
            "; Personal prepend rules (kept ahead of upstream rules).",
            *rendered,
            "",
        ]

    banner = (
        "; Personal build generated from the current upstream template.\n"
        f"; Repository: https://github.com/{repository}/tree/{branch}\n"
    )
    return banner + "\n".join(lines).rstrip() + "\n"


def expected_outputs(
    root: Path,
    upstream_ref: str,
    repository: str,
    branch: str,
) -> dict[Path, str]:
    upstream_sha = git_output(root, "rev-parse", upstream_ref).strip()
    personal = load_custom_rules(root)
    prepend_rules, duplicates_removed = parse_prepend_rules(
        (root / PREPEND_FILE).read_text(encoding="utf-8-sig"),
        PREPEND_FILE.as_posix(),
    )
    claimed = {rule.key for rules in personal.values() for rule in rules}
    upstream_rules = {
        policy: parse_rules(
            git_file(root, upstream_ref, path), f"{upstream_ref}:{path}"
        )
        for policy, path in UPSTREAM_RULES.items()
    }

    merged = {
        "direct": merge_rules(
            upstream_rules["direct"], personal["direct"], claimed
        ),
        "proxy": merge_rules(
            upstream_rules["proxy"], personal["proxy"], claimed
        ),
        "reject": personal["reject"],
    }
    outputs = {
        Path(f"dist/rule/Personal_{policy.title()}_Classical.yaml"):
            render_provider(policy, upstream_sha, rules)
        for policy, rules in merged.items()
    }

    for template in TEMPLATES:
        source = git_file(root, upstream_ref, f"cfg/{template}")
        outputs[Path("dist/cfg") / template] = patch_template(
            source,
            repository,
            branch,
            include_reject=bool(personal["reject"]),
            prepend_rules=prepend_rules,
        )

    manifest = {
        "repository": repository,
        "branch": branch,
        "upstream_repository": UPSTREAM_REPOSITORY,
        "upstream_revision": upstream_sha,
        "counts": {
            policy: {
                "personal": len(personal[policy]),
                "published": len(merged[policy]),
            }
            for policy in ("direct", "proxy", "reject")
        },
        "prepend": {
            "published": len(prepend_rules),
            "duplicates_removed": duplicates_removed,
        },
    }
    outputs[Path("dist/manifest.json")] = (
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    )
    return outputs


def write_outputs(root: Path, outputs: dict[Path, str]) -> None:
    for relative, content in outputs.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8", newline="\n")


def check_outputs(root: Path, outputs: dict[Path, str]) -> int:
    failures: list[str] = []
    expected_paths = set(outputs)
    dist = root / "dist"
    if dist.exists():
        for path in dist.rglob("*"):
            if path.is_file() and path.relative_to(root) not in expected_paths:
                failures.append(f"unexpected generated file: {path.relative_to(root)}")
    for relative, expected in outputs.items():
        destination = root / relative
        if not destination.exists():
            failures.append(f"missing generated file: {relative}")
        elif destination.read_text(encoding="utf-8-sig") != expected:
            failures.append(f"stale generated file: {relative}")
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}")
        return 1
    print("Personal generated files are up to date.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parent.parent
    )
    parser.add_argument("--upstream-ref", default="upstream/main")
    parser.add_argument("--repository", default="FanofZY/Custom_OpenClash_Rules")
    parser.add_argument("--branch", default="personal")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    root = args.root.resolve()
    outputs = expected_outputs(
        root, args.upstream_ref, args.repository, args.branch
    )
    if args.check:
        return check_outputs(root, outputs)
    write_outputs(root, outputs)
    print(f"Generated {len(outputs)} personal files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
