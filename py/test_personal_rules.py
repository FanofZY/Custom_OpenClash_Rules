#!/usr/bin/env python3
"""Tests for the personal rule overlay builder."""

from __future__ import annotations

import unittest

from build_personal_rules import merge_rules, parse_rules, patch_template


class PersonalRulesTest(unittest.TestCase):
    def test_personal_rule_replaces_claimed_upstream_policy(self) -> None:
        upstream = parse_rules(
            "DOMAIN-SUFFIX,example.com\nDOMAIN,keep.example\n", "upstream"
        )
        personal = parse_rules("DOMAIN-SUFFIX,example.com\n", "personal")
        claimed = {rule.key for rule in personal}

        self.assertEqual(
            [rule.rendered for rule in merge_rules(upstream, personal, claimed)],
            ["DOMAIN-SUFFIX,example.com", "DOMAIN,keep.example"],
        )

    def test_cidr_is_normalized_and_marked_no_resolve(self) -> None:
        rule = parse_rules("IP-CIDR,192.0.2.9/24\n", "custom")[0]
        self.assertEqual(rule.value, "192.0.2.0/24")
        self.assertEqual(rule.rendered, "IP-CIDR,192.0.2.0/24,no-resolve")

    def test_patch_replaces_standard_upstream_providers(self) -> None:
        source = "\n".join(
            (
                "[custom]",
                "ruleset=直连,clash-domain:https://x/Custom_Direct_Domain.mrs,1",
                "ruleset=直连,clash-classic:https://x/Custom_Direct_Classical_IP.yaml,1",
                "ruleset=代理,clash-domain:https://x/Custom_Proxy_Domain.mrs,1",
                "ruleset=代理,clash-classic:https://x/Custom_Proxy_Classical_IP.yaml,1",
            )
        )
        result = patch_template(source, "owner/repo", "personal", True)

        self.assertEqual(result.count("Personal_Direct_Classical.yaml"), 1)
        self.assertEqual(result.count("Personal_Proxy_Classical.yaml"), 1)
        self.assertEqual(result.count("Personal_Reject_Classical.yaml"), 1)

    def test_patch_inserts_providers_into_minimal_gfw_template(self) -> None:
        source = "\n".join(
            (
                "[custom]",
                "ruleset=代理,[]GEOSITE,gfw",
                "ruleset=直连,[]FINAL",
            )
        )
        result = patch_template(source, "owner/repo", "personal", False)

        direct = result.index("Personal_Direct_Classical.yaml")
        proxy = result.index("Personal_Proxy_Classical.yaml")
        gfw = result.index("[]GEOSITE,gfw")
        self.assertLess(direct, proxy)
        self.assertLess(proxy, gfw)


if __name__ == "__main__":
    unittest.main()
