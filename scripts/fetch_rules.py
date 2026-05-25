#!/usr/bin/env python3
"""Download upstream AdGuard rule sources into the local temp directory."""

from __future__ import annotations

import os
import re
import shutil
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from common import ensure_dir, load_config, repo_path, setup_logging
else:
    from .common import ensure_dir, load_config, repo_path, setup_logging

TEMP_DIR = repo_path("temp")
FAILED_SOURCES_FILE = TEMP_DIR / "failed_sources.log"
SOURCES_FILE = repo_path("sources", "sources.txt")
LOGGER = setup_logging("fetch_rules")
SAFE_DOMAIN_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")


def is_rule_candidate(line: bytes) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith(b"!"):
        return False
    if stripped.startswith(b"#") and not stripped.startswith(
        (b"##", b"#@#", b"#?#", b"#@?#", b"#$#", b"#@$#", b"#%#", b"#@%#")
    ):
        return False
    if stripped.startswith(b"[") and stripped.endswith(b"]") and b"adblock" in stripped.lower():
        return False
    return True


class Downloader:
    def __init__(self, connect_timeout: int, read_timeout: int, max_workers: int, max_retries: int):
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.max_workers = max_workers
        self.max_retries = max_retries
        self._thread_local = threading.local()
        self._sessions: list[requests.Session] = []
        self._session_lock = threading.Lock()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (compatible; AdGuardRulesFetcher/5.1; +https://github.com)",
                "Accept-Encoding": "gzip, deflate",
            }
        )

        adapter = HTTPAdapter(
            pool_connections=self.max_workers,
            pool_maxsize=self.max_workers,
            max_retries=Retry(
                total=self.max_retries,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=frozenset(["GET"]),
            ),
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def get_session(self) -> requests.Session:
        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = self._create_session()
            self._thread_local.session = session
            with self._session_lock:
                self._sessions.append(session)
        return session

    def close(self) -> None:
        with self._session_lock:
            sessions = self._sessions
            self._sessions = []

        if hasattr(self._thread_local, "session"):
            delattr(self._thread_local, "session")

        for session in sessions:
            session.close()

    def get_filename(self, idx: int, domain: str) -> Path:
        safe_domain = SAFE_DOMAIN_PATTERN.sub("_", domain.strip().lower())[:50].strip("._-") or "source"
        return TEMP_DIR / f"{idx:04d}_{safe_domain}.txt"

    @staticmethod
    def get_source_label(idx: int, url: str, domain: str) -> str:
        file_name = Path(urlparse(url).path).name or domain
        return f"{idx:04d}:{file_name}"

    def download_source(self, idx: int, url: str, domain: str) -> Optional[tuple[int, int]]:
        output_file = self.get_filename(idx, domain)
        temp_file = output_file.with_suffix(f"{output_file.suffix}.tmp")
        source_label = self.get_source_label(idx, url, domain)

        def remove_temp_file() -> None:
            if temp_file.exists():
                temp_file.unlink()

        try:
            LOGGER.info("Downloading [%s] %s", source_label, url)
            with self.get_session().get(
                url,
                timeout=(self.connect_timeout, self.read_timeout),
                stream=True,
            ) as response:
                response.raise_for_status()

                rule_count = 0
                total_size = 0

                with open(temp_file, "wb") as file:
                    for line in response.iter_lines():
                        if not line:
                            continue

                        if is_rule_candidate(line):
                            rule_count += 1

                        file.write(line + b"\n")
                        total_size += len(line) + 1

            if total_size < 10:
                raise ValueError(f"downloaded file is too small ({total_size} bytes)")

            os.replace(temp_file, output_file)
            LOGGER.info("[%s] %8d rules %8.1f KB", source_label, rule_count, total_size / 1024)
            return rule_count, total_size
        except requests.RequestException as exc:
            LOGGER.error("[%s] network error: %s", source_label, exc)
            remove_temp_file()
            return None
        except (OSError, ValueError) as exc:
            LOGGER.error("[%s] file or data error: %s", source_label, exc)
            remove_temp_file()
            return None
        except Exception as exc:
            LOGGER.error("[%s] unexpected download error: %s", source_label, exc)
            remove_temp_file()
            return None


def read_sources(path: Path = SOURCES_FILE) -> list[tuple[str, str]]:
    sources: list[tuple[str, str]] = []
    seen: set[str] = set()

    if not path.exists():
        raise FileNotFoundError(f"source file does not exist: {path}")

    with open(path, "r", encoding="utf-8") as file:
        for line_num, raw_line in enumerate(file, 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            comment_start = next(
                (index for index, char in enumerate(line) if char == "#" and line[index - 1].isspace()),
                -1,
            )
            url = line[:comment_start].strip() if comment_start >= 0 else line
            if url in seen:
                continue
            if not url.startswith(("http://", "https://")):
                LOGGER.warning("Skipping invalid URL on line %d: %s", line_num, url)
                continue

            parsed = urlparse(url)
            domain = (parsed.hostname or "").strip()
            if not domain:
                LOGGER.warning("Skipping URL without domain on line %d: %s", line_num, url)
                continue

            seen.add(url)
            sources.append((url, domain))

    LOGGER.info("Loaded %d sources from %s", len(sources), path)
    return sources


def config_int(section: dict, key: str, default: int, minimum: Optional[int] = None) -> int:
    value = section.get(key, default)
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        LOGGER.warning("Invalid download.%s=%r; using %s", key, value, default)
        parsed = default

    if minimum is not None:
        parsed = max(minimum, parsed)
    return parsed


def config_float(section: dict, key: str, default: float, minimum: float, maximum: float) -> float:
    value = section.get(key, default)
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        LOGGER.warning("Invalid download.%s=%r; using %s", key, value, default)
        parsed = default

    return min(maximum, max(minimum, parsed))


def rebuild_temp_dir() -> None:
    if TEMP_DIR.exists():
        shutil.rmtree(TEMP_DIR)
    ensure_dir(TEMP_DIR)


def main() -> int:
    start_time = time.time()
    config = load_config()

    download_config = config.get("download", {})
    workers_config = config.get("workers", {})

    default_read_timeout = config_int(download_config, "timeout", 30, minimum=1)
    read_timeout = config_int(download_config, "read_timeout", default_read_timeout, minimum=1)
    connect_timeout = config_int(download_config, "connect_timeout", min(read_timeout, 10), minimum=1)
    max_retries = config_int(download_config, "retries", 3, minimum=0)
    min_success_rate = config_float(download_config, "min_success_rate", 0.8, 0.0, 1.0)
    max_workers = config_int(workers_config, "threads", min(16, (os.cpu_count() or 2) * 2), minimum=1)

    rebuild_temp_dir()
    sources = read_sources()
    if not sources:
        LOGGER.error("No valid sources found in %s", SOURCES_FILE)
        return 1
    max_workers = min(max_workers, len(sources))

    downloader = Downloader(connect_timeout, read_timeout, max_workers, max_retries)
    total_rules = 0
    total_size = 0
    failed_sources: list[str] = []

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_source = {
                executor.submit(downloader.download_source, index, url, domain): (url, domain)
                for index, (url, domain) in enumerate(sources, 1)
            }

            for future in as_completed(future_to_source):
                url, domain = future_to_source[future]
                try:
                    result = future.result()
                except requests.RequestException as exc:
                    LOGGER.error("%s: network error: %s", domain, exc)
                    result = None
                except (OSError, ValueError) as exc:
                    LOGGER.error("%s: file or data error: %s", domain, exc)
                    result = None
                except Exception as exc:
                    LOGGER.error("%s: unexpected worker exception: %s", domain, exc)
                    result = None

                if result is None:
                    failed_sources.append(url)
                    continue

                rules, size = result
                total_rules += rules
                total_size += size
    finally:
        downloader.close()

    LOGGER.info("=" * 60)
    LOGGER.info("Total rules: %s", f"{total_rules:,}")
    LOGGER.info("Total size: %.2f MB", total_size / 1024 / 1024)
    LOGGER.info("Succeeded: %d/%d", len(sources) - len(failed_sources), len(sources))

    if failed_sources:
        with open(FAILED_SOURCES_FILE, "w", encoding="utf-8") as file:
            file.write("\n".join(failed_sources))
        LOGGER.warning("Failed source list saved to %s", FAILED_SOURCES_FILE)

    if len(failed_sources) == len(sources):
        LOGGER.error("All downloads failed; refusing to continue with an empty rule set")
        return 1

    success_rate = (len(sources) - len(failed_sources)) / len(sources)
    if success_rate < min_success_rate:
        LOGGER.error(
            "Download success rate %.1f%% is below min_success_rate %.1f%%; refusing to publish a partial rule set",
            success_rate * 100,
            min_success_rate * 100,
        )
        return 1

    LOGGER.info("Finished in %.1f seconds", time.time() - start_time)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
