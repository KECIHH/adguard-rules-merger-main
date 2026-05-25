#!/usr/bin/env python3
"""Build a lighter rule set from the merged full rule output."""

from __future__ import annotations

import re
import shutil
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from common import load_config, repo_path, setup_logging
else:
    from .common import load_config, repo_path, setup_logging

INPUT_FILE = repo_path("rules", "merged_all.txt")
OUTPUT_FILE = repo_path("rules", "merged_lite.txt")
STATS_FILE = repo_path("rules", "optimization_stats.txt")
LOGGER = setup_logging("optimize_rules")

IMPORTANT_KEYWORDS = [
    "doubleclick",
    "google-analytics",
    "facebook",
    "tracking",
    "adsystem",
    "adservice",
    "adserver",
    "analytics",
    "cookie",
    "beacon",
    "pixel",
    "metrics",
    "telemetry",
    "spyware",
    "malware",
    "phishing",
    "malicious",
]

COMMON_DOMAINS = [
    "google",
    "youtube",
    "facebook",
    "twitter",
    "instagram",
    "amazon",
    "microsoft",
    "apple",
    "cloudflare",
    "akamai",
]

SCORE_WEIGHTS = {
    "domain_rule": -50,
    "important_keyword": -30,
    "common_domain": 20,
    "short_rule": -10,
    "long_rule": 15,
    "wildcard": 5,
    "third_party_option": -5,
    "important_option": -20,
    "regex_rule": 10,
}
MAX_IMPORTANT_KEYWORD_HITS = 3
MAX_COMMON_DOMAIN_HITS = 2

LEVEL_PRESETS: dict[int, tuple[int, int, int]] = {
    0: (200000, 180000, 250000),
    1: (180000, 140000, 220000),
    2: (150000, 100000, 200000),
    3: (120000, 80000, 160000),
}

IMPORTANT_REGEX = re.compile(r"(?:%s)" % "|".join(map(re.escape, IMPORTANT_KEYWORDS)), re.IGNORECASE)
COMMON_REGEX = re.compile(r"(?:%s)" % "|".join(map(re.escape, COMMON_DOMAINS)), re.IGNORECASE)


def config_int(optimization: dict, key: str, default: int) -> int:
    value = optimization.get(key, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        LOGGER.warning("Invalid optimization.%s=%r; using %s", key, value, default)
        return default


def safe_ratio(selected: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return 1 - (selected / total)


def resolve_limits(config: dict) -> tuple[bool, int, int, int]:
    optimization = config.get("optimization", {})
    enabled = bool(optimization.get("enable", True))

    try:
        level = int(optimization.get("level", 2))
    except (TypeError, ValueError):
        level = 2

    target, minimum, maximum = LEVEL_PRESETS.get(level, LEVEL_PRESETS[2])
    target = config_int(optimization, "target_rules", target)
    minimum = config_int(optimization, "min_rules", minimum)
    maximum = config_int(optimization, "max_rules", maximum)

    target = max(0, target)
    minimum = max(0, min(minimum, target))
    maximum = max(target, maximum, 0)
    return enabled, target, minimum, maximum


class RuleOptimizer:
    def __init__(self, target_rules: int, min_rules: int, max_rules: int):
        self.target_rules = target_rules
        self.min_rules = min_rules
        self.max_rules = max_rules
        self.allow_rules: list[str] = []
        self.block_rules: list[str] = []
        self.stats = {
            "total": 0,
            "allow": 0,
            "block": 0,
            "selected": 0,
        }

    def load_rules(self, input_file: Path) -> None:
        LOGGER.info("Loading merged rules from %s", input_file)

        with open(input_file, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith("!"):
                    continue

                self.stats["total"] += 1
                if line.startswith("@@"):
                    self.allow_rules.append(line)
                    self.stats["allow"] += 1
                else:
                    self.block_rules.append(line)
                    self.stats["block"] += 1

        LOGGER.info("Loaded %s total rules", f"{self.stats['total']:,}")
        LOGGER.info("Allow rules: %s", f"{self.stats['allow']:,}")
        LOGGER.info("Block rules: %s", f"{self.stats['block']:,}")

    @staticmethod
    def calculate_rule_score(rule: str) -> int:
        score = 0

        if rule.startswith("||") and rule.endswith("^"):
            score += SCORE_WEIGHTS["domain_rule"]

        important_hits = len(IMPORTANT_REGEX.findall(rule))
        if important_hits > 0:
            score += SCORE_WEIGHTS["important_keyword"] * min(important_hits, MAX_IMPORTANT_KEYWORD_HITS)

        common_hits = len(COMMON_REGEX.findall(rule))
        if common_hits > 0:
            score += SCORE_WEIGHTS["common_domain"] * min(common_hits, MAX_COMMON_DOMAIN_HITS)

        rule_length = len(rule)
        if rule_length < 20:
            score += SCORE_WEIGHTS["short_rule"]
        elif rule_length > 100:
            score += SCORE_WEIGHTS["long_rule"]

        if "*" in rule:
            score += SCORE_WEIGHTS["wildcard"]

        if "$" in rule:
            if "third-party" in rule:
                score += SCORE_WEIGHTS["third_party_option"]
            if "important" in rule:
                score += SCORE_WEIGHTS["important_option"]

        if rule.startswith("/") and rule.endswith("/"):
            score += SCORE_WEIGHTS["regex_rule"]

        return score

    @staticmethod
    def is_rule_effective(rule: str) -> bool:
        if rule.count("*") > 3:
            return False

        clean = rule.replace("*", "").replace(".", "").replace("^", "").replace("/", "").strip()
        if len(clean) < 3:
            return False

        return rule not in {"*.*", "*", ".*", "/*/"}

    def select_top_rules(self, rules: list[str], target_count: int) -> list[str]:
        if target_count <= 0:
            return []
        if len(rules) <= target_count:
            return sorted(rules)

        scored: list[tuple[int, str]] = []
        for rule in rules:
            if not self.is_rule_effective(rule):
                continue
            scored.append((self.calculate_rule_score(rule), rule))

        scored.sort(key=lambda item: (item[0], item[1]))
        selected = [rule for _, rule in scored[:target_count]]
        selected.sort()
        return selected

    def optimize(self) -> tuple[list[str], int]:
        LOGGER.info("Optimizing merged rules")

        if self.stats["total"] == 0:
            return [], 0

        selected_allow = sorted(self.allow_rules)
        max_block_rules = max(0, self.max_rules - len(selected_allow))
        desired_block_rules = max(0, self.target_rules - len(selected_allow))
        minimum_block_rules = max(0, self.min_rules - len(selected_allow))

        target_block_rules = min(
            max(desired_block_rules, minimum_block_rules),
            max_block_rules,
            len(self.block_rules),
        )

        if len(selected_allow) > self.max_rules:
            LOGGER.warning(
                "Allow rules already exceed max_rules (%s > %s); keeping allow rules only",
                len(selected_allow),
                self.max_rules,
            )

        LOGGER.info("Target total rules: %s", f"{self.target_rules:,}")
        LOGGER.info("Selected block rules: %s", f"{target_block_rules:,}")

        selected_block = self.select_top_rules(self.block_rules, target_block_rules)
        final_rules = selected_allow + selected_block
        self.stats["selected"] = len(final_rules)
        return final_rules, len(selected_block)

    def save_rules(self, rules: list[str], output_file: Path) -> None:
        LOGGER.info("Writing optimized rules to %s", output_file)
        ratio = safe_ratio(self.stats["selected"], self.stats["total"])

        with open(output_file, "w", encoding="utf-8", newline="\n") as file:
            file.write("! Optimized AdGuard rules\n")
            file.write(f"! Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            file.write(f"! Original rules: {self.stats['total']:,}\n")
            file.write(f"! Optimized rules: {self.stats['selected']:,}\n")
            file.write(f"! Reduction ratio: {ratio:.1%}\n")
            file.write("!\n\n")

            if self.stats["allow"] > 0:
                file.write("! === ALLOW RULES ===\n")
                for rule in rules:
                    if rule.startswith("@@"):
                        file.write(f"{rule}\n")
                file.write("\n")

            file.write("! === BLOCK RULES ===\n")
            for rule in rules:
                if not rule.startswith("@@"):
                    file.write(f"{rule}\n")

    def save_stats(self, selected_block_count: int) -> None:
        ratio = safe_ratio(self.stats["selected"], self.stats["total"])
        with open(STATS_FILE, "w", encoding="utf-8") as file:
            file.write(f"Optimized at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            file.write(f"Target rules: {self.target_rules:,}\n")
            file.write(f"Original rules: {self.stats['total']:,}\n")
            file.write(f"Allow rules: {self.stats['allow']:,}\n")
            file.write(f"Block rules: {self.stats['block']:,}\n")
            file.write(f"Selected block rules: {selected_block_count:,}\n")
            file.write(f"Final rules: {self.stats['selected']:,}\n")
            file.write(f"Reduction ratio: {ratio:.1%}\n")

    def log_stats(self, selected_block_count: int) -> None:
        ratio = safe_ratio(self.stats["selected"], self.stats["total"])
        LOGGER.info("=" * 60)
        LOGGER.info("Original rules: %s", f"{self.stats['total']:,}")
        LOGGER.info("Allow rules kept: %s", f"{self.stats['allow']:,}")
        LOGGER.info("Block rules available: %s", f"{self.stats['block']:,}")
        LOGGER.info("Block rules selected: %s", f"{selected_block_count:,}")
        LOGGER.info("Final rules: %s", f"{self.stats['selected']:,}")
        LOGGER.info("Reduction ratio: %.1f%%", ratio * 100)
        LOGGER.info("=" * 60)


def main() -> int:
    start_time = time.time()

    if not INPUT_FILE.exists():
        LOGGER.error("Input file does not exist: %s", INPUT_FILE)
        return 1

    enabled, target_rules, min_rules, max_rules = resolve_limits(load_config())
    if not enabled:
        shutil.copyfile(INPUT_FILE, OUTPUT_FILE)
        with open(STATS_FILE, "w", encoding="utf-8") as file:
            file.write(f"Optimization skipped at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            file.write("Reason: optimization.enable=false\n")
        LOGGER.info("Optimization disabled; copied %s to %s", INPUT_FILE, OUTPUT_FILE)
        return 0

    optimizer = RuleOptimizer(target_rules, min_rules, max_rules)
    optimizer.load_rules(INPUT_FILE)
    if optimizer.stats["total"] == 0:
        LOGGER.error("No rules available for optimization")
        return 1

    final_rules, selected_block_count = optimizer.optimize()
    if len(final_rules) < min_rules:
        LOGGER.error(
            "Optimized output has %s rules, below min_rules=%s; refusing to publish a likely incomplete rule set",
            f"{len(final_rules):,}",
            f"{min_rules:,}",
        )
        return 1

    optimizer.save_rules(final_rules, OUTPUT_FILE)
    optimizer.save_stats(selected_block_count)
    optimizer.log_stats(selected_block_count)

    LOGGER.info("Finished in %.1f seconds", time.time() - start_time)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
