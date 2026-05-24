#!/usr/bin/env python3
"""Check the production GitHub App against the versioned manifest.

This intentionally uses GitHub's unauthenticated public app endpoint. A private
or owner-only app should fail this check even if a maintainer token could see it.
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_MANIFEST = Path("deploy/connectors/github/app-manifest.json")
APP_SLUG_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$")
SYSTEM_CA_FILES = (
    "/etc/ssl/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def app_slug(manifest: dict[str, Any], explicit: str) -> str:
    if explicit:
        slug = explicit.strip().lower()
    else:
        name = str(manifest.get("name", "")).strip().lower()
        slug = re.sub(r"[^a-z0-9]+", "-", name).strip("-")
    if not APP_SLUG_PATTERN.fullmatch(slug):
        raise ValueError(f"invalid GitHub App slug: {slug!r}")
    return slug


def ssl_context() -> ssl.SSLContext:
    paths = ssl.get_default_verify_paths()
    if paths.cafile:
        return ssl.create_default_context()
    for candidate in SYSTEM_CA_FILES:
        path = Path(candidate)
        if path.exists():
            return ssl.create_default_context(cafile=str(path))
    return ssl.create_default_context()


def fetch_public_app(slug: str) -> dict[str, Any]:
    request = urllib.request.Request(
        f"https://api.github.com/apps/{slug}",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "identrail-github-app-manifest-check",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15, context=ssl_context()) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise RuntimeError(
                f"GitHub App {slug!r} is not visible from the public app endpoint. "
                "Check that the production app slug is correct and that the app is public / installable on Any account."
            ) from error
        raise
    if not isinstance(payload, dict):
        raise RuntimeError("GitHub returned an unexpected app payload")
    return payload


def sorted_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted(str(item).strip() for item in value if str(item).strip())


def string_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def compare(manifest: dict[str, Any], live: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    warnings: list[str] = []

    if manifest.get("public") is not True:
        failures.append("manifest public must be true so GitHub can show personal and organization install targets")

    setup_url = str(manifest.get("setup_url", "")).strip()
    callback_urls = sorted_strings(manifest.get("callback_urls"))
    if not setup_url:
        failures.append("manifest setup_url is required so GitHub can return users after install")
    if setup_url and setup_url not in callback_urls:
        failures.append("manifest callback_urls must include setup_url")
    if manifest.get("setup_on_update") is not False:
        failures.append(
            "manifest setup_on_update must be false: update redirects arrive without an install "
            "state token, and the callback requires one, so enabling it sends users to an error "
            "page. Repository selection changes already sync via the installation_repositories webhook."
        )

    expected_name = str(manifest.get("name", "")).strip()
    live_name = str(live.get("name", "")).strip()
    if expected_name and live_name and expected_name != live_name:
        failures.append(f"app name mismatch: manifest={expected_name!r} live={live_name!r}")

    expected_url = str(manifest.get("url", "")).strip().rstrip("/")
    live_url = str(live.get("external_url", "")).strip().rstrip("/")
    if expected_url and live_url and expected_url != live_url:
        failures.append(f"homepage URL mismatch: manifest={expected_url!r} live={live_url!r}")

    expected_permissions = string_map(manifest.get("default_permissions"))
    live_permissions = string_map(live.get("permissions"))
    if expected_permissions != live_permissions:
        failures.append(
            "permission mismatch:\n"
            f"  manifest={json.dumps(expected_permissions, sort_keys=True)}\n"
            f"  live={json.dumps(live_permissions, sort_keys=True)}"
        )

    expected_events = sorted_strings(manifest.get("default_events"))
    live_events = sorted_strings(live.get("events"))
    if expected_events != live_events:
        failures.append(
            "event subscription mismatch:\n"
            f"  manifest={json.dumps(expected_events)}\n"
            f"  live={json.dumps(live_events)}"
        )

    if setup_url:
        warnings.append("GitHub's public app endpoint does not expose setup_url; confirm it in GitHub App settings.")

    return failures + [f"warning: {warning}" for warning in warnings]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--slug", default="", help="GitHub App slug. Defaults to the manifest name slug.")
    args = parser.parse_args()

    try:
        manifest = load_json(args.manifest)
        slug = app_slug(manifest, args.slug)
        live = fetch_public_app(slug)
        messages = compare(manifest, live)
    except Exception as error:  # noqa: BLE001 - command-line diagnostics should be direct.
        print(f"GitHub App manifest check failed: {error}", file=sys.stderr)
        return 1

    failures = [message for message in messages if not message.startswith("warning: ")]
    warnings = [message for message in messages if message.startswith("warning: ")]
    for warning in warnings:
        print(warning, file=sys.stderr)
    if failures:
        print("GitHub App manifest check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"GitHub App {slug!r} matches {args.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
