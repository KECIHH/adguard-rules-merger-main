from pathlib import Path

from scripts.optimize_rules import RuleOptimizer, resolve_limits, safe_ratio


def test_safe_ratio_handles_zero_total():
    assert safe_ratio(0, 0) == 0.0


def test_optimize_clamps_negative_block_target():
    optimizer = RuleOptimizer(target_rules=10, min_rules=8, max_rules=12)
    optimizer.allow_rules = [f"@@||allow{i}.example^" for i in range(15)]
    optimizer.block_rules = [f"||block{i}.example^" for i in range(5)]
    optimizer.stats["total"] = len(optimizer.allow_rules) + len(optimizer.block_rules)
    optimizer.stats["allow"] = len(optimizer.allow_rules)
    optimizer.stats["block"] = len(optimizer.block_rules)

    final_rules, selected_block_count = optimizer.optimize()

    assert selected_block_count == 0
    assert len(final_rules) == len(optimizer.allow_rules)


def test_save_rules_does_not_crash_on_zero_total(workspace_tmp_path: Path):
    optimizer = RuleOptimizer(target_rules=10, min_rules=8, max_rules=12)
    optimizer.stats["selected"] = 0

    output_file = workspace_tmp_path / "merged_lite.txt"
    optimizer.save_rules([], output_file)

    text = output_file.read_text(encoding="utf-8")
    assert "Reduction ratio: 0.0%" in text


def test_resolve_limits_handles_invalid_and_negative_values():
    enabled, target, minimum, maximum = resolve_limits(
        {
            "optimization": {
                "enable": True,
                "level": "bad",
                "target_rules": -1,
                "min_rules": "bad",
                "max_rules": None,
            }
        }
    )

    assert enabled is True
    assert (target, minimum, maximum) == (0, 0, 200000)
