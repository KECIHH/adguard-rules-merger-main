from pathlib import Path

from scripts.fetch_rules import Downloader, config_float, config_int, is_rule_candidate, read_sources


def test_read_sources_skips_comments_invalid_and_duplicates(workspace_tmp_path: Path):
    source_file = workspace_tmp_path / "sources.txt"
    source_file.write_text(
        "\n".join(
            [
                "# comment",
                "https://example.com/a.txt",
                "invalid-url",
                "https://example.com/a.txt",
                "https://example.org/b.txt # trailing comment",
            ]
        ),
        encoding="utf-8",
    )

    sources = read_sources(source_file)

    assert sources == [
        ("https://example.com/a.txt", "example.com"),
        ("https://example.org/b.txt", "example.org"),
    ]


def test_read_sources_keeps_url_fragments(workspace_tmp_path: Path):
    source_file = workspace_tmp_path / "sources.txt"
    source_file.write_text("https://example.com/filter.txt#section\n", encoding="utf-8")

    assert read_sources(source_file) == [("https://example.com/filter.txt#section", "example.com")]


def test_read_sources_uses_hostname_not_raw_netloc(workspace_tmp_path: Path):
    source_file = workspace_tmp_path / "sources.txt"
    source_file.write_text("https://user:pass@example.com:443/filter.txt\n", encoding="utf-8")

    assert read_sources(source_file) == [("https://user:pass@example.com:443/filter.txt", "example.com")]


def test_is_rule_candidate_filters_comments_and_metadata():
    assert not is_rule_candidate(b"! comment")
    assert not is_rule_candidate(b"# hosts comment")
    assert not is_rule_candidate(b"[Adblock Plus 2.0]")
    assert is_rule_candidate(b"##.ad-banner")
    assert is_rule_candidate(b"#@?#.ad-banner")
    assert is_rule_candidate(b"||example.com^")


def test_download_config_helpers_fall_back_and_clamp():
    assert config_int({"timeout": "bad"}, "timeout", 30, minimum=1) == 30
    assert config_int({"timeout": -5}, "timeout", 30, minimum=1) == 1
    assert config_float({"min_success_rate": 2}, "min_success_rate", 0.8, 0.0, 1.0) == 1.0


def test_downloader_filename_sanitizes_domain():
    downloader = Downloader(connect_timeout=1, read_timeout=1, max_workers=1, max_retries=0)

    filename = downloader.get_filename(1, "../evil.com:443").name

    assert filename == "0001_evil.com_443.txt"


def test_downloader_close_closes_registered_sessions(monkeypatch):
    downloader = Downloader(connect_timeout=1, read_timeout=1, max_workers=1, max_retries=0)
    session = downloader.get_session()
    closed: list[bool] = []
    monkeypatch.setattr(session, "close", lambda: closed.append(True))

    downloader.close()

    assert closed == [True]
    assert downloader._sessions == []
