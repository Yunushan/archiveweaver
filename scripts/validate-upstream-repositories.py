#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "src" / "archiveweaver" / "data" / "solutions.json"
GITHUB_API = "https://api.github.com"
Fetcher = Callable[[str], dict[str, Any]]


def github_slug(url: object) -> str | None:
    if not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if (
        parsed.scheme != "https"
        or hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or len(parts) != 2
    ):
        return None
    owner, repository = parts
    if repository.endswith(".git"):
        repository = repository[:-4]
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", owner):
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", repository) or repository in {".", ".."}:
        return None
    return f"{owner}/{repository}"


def github_fetcher(token: str | None) -> Fetcher:
    def fetch(slug: str) -> dict[str, Any]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "archiveweaver-upstream-audit/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(f"{GITHUB_API}/repos/{slug}", headers=headers)
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                # The request origin is the fixed HTTPS GITHUB_API constant and
                # ``slug`` is constrained to a canonical owner/repository pair.
                with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
                    result = json.load(response)
                if not isinstance(result, dict):
                    raise ValueError(f"GitHub returned a non-object for {slug}")
                return result
            except urllib.error.HTTPError as exc:
                last_error = exc
                if exc.code < 500 or attempt == 2:
                    raise
            except urllib.error.URLError as exc:
                last_error = exc
                if attempt == 2:
                    raise
            time.sleep(attempt + 1)
        raise RuntimeError(f"GitHub request failed for {slug}: {last_error}")

    return fetch


def audit(
    solutions: Iterable[dict[str, Any]],
    fetch: Fetcher,
) -> tuple[list[str], list[str], int, int]:
    errors: list[str] = []
    warnings: list[str] = []
    repositories: dict[str, set[str]] = {}
    archived_notes: dict[str, bool] = {}
    non_github_urls: set[str] = set()

    for solution in solutions:
        solution_id = solution.get("id", "<missing>")
        urls = (solution.get("upstream_repo"), solution.get("source_repo"))
        seen_urls: set[str] = set()
        for url in urls:
            if isinstance(url, str) and url in seen_urls:
                continue
            if isinstance(url, str):
                seen_urls.add(url)
            slug = github_slug(url)
            if slug is None:
                if isinstance(url, str):
                    try:
                        github_host = urlparse(url).hostname == "github.com"
                    except ValueError:
                        github_host = False
                    if github_host:
                        errors.append(
                            f"{solution_id} uses a non-canonical GitHub repository URL: {url!r}"
                        )
                    else:
                        non_github_urls.add(url)
                continue
            repositories.setdefault(slug, set()).add(str(solution_id))
            notes = solution.get("notes", [])
            archived_notes[slug] = archived_notes.get(slug, False) or (
                isinstance(notes, list)
                and any(isinstance(note, str) and "archiv" in note.casefold() for note in notes)
            )
    for slug in sorted(repositories, key=str.casefold):
        owners = ", ".join(sorted(repositories[slug]))
        try:
            metadata = fetch(slug)
        except (OSError, ValueError, urllib.error.URLError) as exc:
            errors.append(f"{slug} ({owners}) could not be verified: {exc}")
            continue
        canonical = metadata.get("full_name")
        if not isinstance(canonical, str) or canonical.casefold() != slug.casefold():
            errors.append(f"{slug} ({owners}) resolves to unexpected repository {canonical!r}")
        if metadata.get("disabled") is not False:
            errors.append(f"{slug} ({owners}) is disabled or returned an invalid disabled state")
        if metadata.get("archived") is True:
            if not archived_notes.get(slug, False):
                errors.append(f"{slug} ({owners}) is archived but the catalog does not disclose it")
            else:
                warnings.append(f"{slug} ({owners}) is archived and disclosed as maintenance-only")
        pushed_at = metadata.get("pushed_at")
        if isinstance(pushed_at, str):
            try:
                pushed = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
            except ValueError:
                errors.append(f"{slug} ({owners}) returned an invalid pushed_at timestamp")
            else:
                age = datetime.now(timezone.utc) - pushed.astimezone(timezone.utc)
                if age.days > 730:
                    warnings.append(f"{slug} ({owners}) has had no push for {age.days} days")

    return errors, warnings, len(repositories), len(non_github_urls)


def main() -> int:
    try:
        solutions = json.loads(CATALOG.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"upstream audit failed to load catalog: {exc}", file=sys.stderr)
        return 2
    if not isinstance(solutions, list) or not all(
        isinstance(solution, dict) for solution in solutions
    ):
        print("upstream audit requires a list of solution objects", file=sys.stderr)
        return 2

    token = os.environ.get("GITHUB_TOKEN") or None
    errors, warnings, checked, non_github = audit(solutions, github_fetcher(token))
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    print(
        f"GitHub upstream audit: checked={checked}, non_github_urls={non_github}, "
        f"warnings={len(warnings)}, errors={len(errors)}"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
