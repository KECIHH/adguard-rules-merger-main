from pathlib import Path

import scripts.merge_rules as merge_rules


def test_normalize_rule_keeps_inline_bang_and_skips_metadata():
    processor = merge_rules.RuleProcessor()

    assert processor.normalize_rule("[Adblock Plus 2.0]") is None
    assert processor.normalize_rule("||example.com/path!important^") == "||example.com/path!important^"


def test_normalize_rule_does_not_corrupt_cosmetic_or_regex_rules():
    processor = merge_rules.RuleProcessor()

    cosmetic_rule = "example.com#$#.ad { display: none !important; }"
    extended_css_exception = "#@?#.ad"
    regex_rule = r"/^(\S+\.)?example\.com$/$dnstype=A"

    assert processor.normalize_rule(cosmetic_rule) == cosmetic_rule
    assert processor.normalize_rule(extended_css_exception) == extended_css_exception
    assert processor.normalize_rule(regex_rule) == regex_rule


def test_normalize_rule_sorts_network_options_only():
    processor = merge_rules.RuleProcessor()

    assert processor.normalize_rule("||example.com^$script,third-party,script") == (
        "||example.com^$script,third-party"
    )


def test_normalize_rule_compacts_hosts_comment():
    processor = merge_rules.RuleProcessor()

    assert processor.normalize_rule("0.0.0.0 ads.example.com # comment") == "0.0.0.0 ads.example.com"


def test_main_merges_only_downloaded_rule_files(workspace_tmp_path: Path, monkeypatch):
    temp_dir = workspace_tmp_path / "temp"
    rules_dir = workspace_tmp_path / "rules"
    temp_dir.mkdir()
    rules_dir.mkdir()

    (temp_dir / "0001_example.txt").write_text("[Adblock Plus 2.0]\n||good.example^\n", encoding="utf-8")
    (temp_dir / "failed_sources.txt").write_text("bad.example.com\n", encoding="utf-8")

    monkeypatch.setattr(merge_rules, "TEMP_DIR", temp_dir)
    monkeypatch.setattr(merge_rules, "OUTPUT_DIR", rules_dir)
    monkeypatch.setattr(merge_rules, "LOCAL_RULE_FILE", rules_dir / "my_rules.txt")
    monkeypatch.setattr(merge_rules, "MERGED_FILE", rules_dir / "merged_all.txt")
    monkeypatch.setattr(merge_rules, "STATS_FILE", rules_dir / "merge_stats.txt")

    assert merge_rules.main() == 0

    merged_text = (rules_dir / "merged_all.txt").read_text(encoding="utf-8")
    assert "||good.example^" in merged_text
    assert "bad.example.com" not in merged_text
    assert "[Adblock Plus 2.0]" not in merged_text
