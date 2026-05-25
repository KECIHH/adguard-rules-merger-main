#!/usr/bin/env python3
"""Merge downloaded rule lists into a single deterministic output file."""

from __future__ import annotations

import re
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from common import ensure_dir, repo_path, setup_logging
else:
    from .common import ensure_dir, repo_path, setup_logging

TEMP_DIR = repo_path("temp")
OUTPUT_DIR = ensure_dir(repo_path("rules"))
LOCAL_RULE_FILE = OUTPUT_DIR / "my_rules.txt"
MERGED_FILE = OUTPUT_DIR / "merged_all.txt"
STATS_FILE = OUTPUT_DIR / "merge_stats.txt"
DOWNLOADED_RULE_PATTERN = "[0-9][0-9][0-9][0-9]_*.txt"
LOGGER = setup_logging("merge_rules")

COMMENT_PREFIX_EXCEPTIONS = ("##", "#@#", "#?#", "#@?#", "#$#", "#@$#", "#%#", "#@%#")
HOSTS_PATTERN = re.compile(r"^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+(\S+)")
NON_NETWORK_MARKERS = ("##", "#@#", "#?#", "#@?#", "#$#", "#@$#", "#%#", "#@%#", "$$", "$@$")


class RuleProcessor:
    def __init__(self):
        self.rules: set[str] = set()
        self.stats = {
            "total_lines": 0,
            "duplicates": 0,
            "invalid_lines": 0,
            "local_rules": 0,
        }
        self.category_counts: defaultdict[str, int] = defaultdict(int)

    @staticmethod
    def get_rule_category(rule: str) -> str:
        if rule.startswith("@@"):
            return "allow"
        if rule.startswith("/") and rule.endswith("/"):
            return "regex"
        if rule.startswith("||") and rule.endswith("^"):
            return "domain"
        if rule.startswith(("0.0.0.0 ", "127.0.0.1 ", "::1 ")):
            return "hosts"
        return "other"

    @staticmethod
    def _is_comment_or_metadata(line: str) -> bool:
        if line.startswith("!"):
            return True
        if line.startswith("#") and not line.startswith(COMMENT_PREFIX_EXCEPTIONS):
            return True
        if line.startswith("[") and line.endswith("]") and "adblock" in line.lower():
            return True
        return False

    @staticmethod
    def _can_normalize_network_options(line: str) -> bool:
        if "$" not in line:
            return False
        if line.startswith("/"):
            return False
        return not any(marker in line for marker in NON_NETWORK_MARKERS)

    def normalize_rule(self, line: str) -> Optional[str]:
        line = line.lstrip("\ufeff").strip()
        if not line or self._is_comment_or_metadata(line):
            return None

        hosts_match = HOSTS_PATTERN.match(line)
        if hosts_match:
            return f"{hosts_match.group(1)} {hosts_match.group(2)}"

        if self._can_normalize_network_options(line):
            main, options = line.split("$", 1)
            normalized_options = sorted({option.strip() for option in options.split(",") if option.strip()})
            if not normalized_options:
                return main.strip() or None
            return f"{main.strip()}${','.join(normalized_options)}"

        return line

    def process_file(self, file_path: Path, is_local: bool = False) -> None:
        if not file_path.exists():
            return

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                self._read_lines(file, is_local)
        except UnicodeDecodeError:
            try:
                with open(file_path, "r", encoding="latin-1") as file:
                    self._read_lines(file, is_local)
            except Exception as exc:
                LOGGER.error("Unable to decode %s: %s", file_path.name, exc)

    def _read_lines(self, lines, is_local: bool) -> None:
        for line in lines:
            self.stats["total_lines"] += 1
            rule = self.normalize_rule(line)

            if not rule:
                self.stats["invalid_lines"] += 1
                continue

            if rule in self.rules:
                self.stats["duplicates"] += 1
                continue

            self.rules.add(rule)
            self.category_counts[self.get_rule_category(rule)] += 1
            if is_local:
                self.stats["local_rules"] += 1

    def save_rules(self, output_path: Path) -> None:
        LOGGER.info("Sorting %s unique rules", f"{len(self.rules):,}")

        def sort_key(rule: str) -> tuple[int, str]:
            category = self.get_rule_category(rule)
            priority = {"allow": 0, "regex": 1, "domain": 2, "hosts": 3, "other": 4}.get(category, 5)
            return (priority, rule)

        sorted_rules = sorted(self.rules, key=sort_key)

        with open(output_path, "w", encoding="utf-8", newline="\n") as file:
            file.write("! Merged AdGuard rules\n")
            file.write(f"! Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            file.write(f"! Total rules: {len(sorted_rules):,}\n")
            file.write("!\n")

            current_category = None
            for rule in sorted_rules:
                category = self.get_rule_category(rule)
                if category != current_category:
                    file.write(f"\n! === {category.upper()} RULES ({self.category_counts[category]:,}) ===\n")
                    current_category = category
                file.write(f"{rule}\n")

    def save_stats(self, output_path: Path) -> None:
        with open(output_path, "w", encoding="utf-8") as file:
            file.write(f"Merged at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            file.write(f"Processed lines: {self.stats['total_lines']:,}\n")
            file.write(f"Invalid/skipped lines: {self.stats['invalid_lines']:,}\n")
            file.write(f"Duplicate rules: {self.stats['duplicates']:,}\n")
            file.write(f"Local rules: {self.stats['local_rules']:,}\n")
            file.write(f"Final unique rules: {len(self.rules):,}\n")
            for category, count in sorted(self.category_counts.items()):
                file.write(f"{category}: {count}\n")

    def log_stats(self) -> None:
        LOGGER.info("=" * 60)
        LOGGER.info("Processed lines: %s", f"{self.stats['total_lines']:,}")
        LOGGER.info("Invalid/skipped lines: %s", f"{self.stats['invalid_lines']:,}")
        LOGGER.info("Duplicate rules: %s", f"{self.stats['duplicates']:,}")
        LOGGER.info("Local rules: %s", f"{self.stats['local_rules']:,}")
        LOGGER.info("Final unique rules: %s", f"{len(self.rules):,}")
        LOGGER.info("=" * 60)


def main() -> int:
    start_time = time.time()
    processor = RuleProcessor()

    if LOCAL_RULE_FILE.exists():
        LOGGER.info("Loading local rules from %s", LOCAL_RULE_FILE)
        processor.process_file(LOCAL_RULE_FILE, is_local=True)

    downloaded_files = sorted(TEMP_DIR.glob(DOWNLOADED_RULE_PATTERN))
    if downloaded_files:
        LOGGER.info("Merging %d downloaded source files", len(downloaded_files))
        for file_path in downloaded_files:
            processor.process_file(file_path)
    else:
        LOGGER.warning("No downloaded files matched %s in %s", DOWNLOADED_RULE_PATTERN, TEMP_DIR)

    if not processor.rules:
        LOGGER.error("No valid rules were found to merge")
        return 1

    processor.log_stats()
    processor.save_rules(MERGED_FILE)
    processor.save_stats(STATS_FILE)
    LOGGER.info("Merged rules saved to %s", MERGED_FILE)
    LOGGER.info("Finished in %.1f seconds", time.time() - start_time)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
