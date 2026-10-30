#!/usr/bin/env python3
"""Verify a build's input IPA, signed program hashes, and app signature.

This is a read-only integrity check. It does not launch the game or update the
build report, and it makes no claim about runtime compatibility.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent


class VerificationError(Exception):
    pass


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def expected_hash(value: object, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise VerificationError(f"Missing or invalid SHA-256 in report: {label}")
    return value.lower()


def recorded_path(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise VerificationError(f"Missing or invalid path in report: {label}")
    path = Path(value)
    if not path.is_absolute():
        raise VerificationError(f"Report path must be absolute: {label}")
    return path.resolve(strict=True)


def verify(report_path: Path) -> int:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise VerificationError("Build report must contain a JSON object")
    if report.get("status") != "built-and-signature-verified":
        raise VerificationError("Report does not describe a successfully signed build")
    app = recorded_path(report.get("output"), "output")
    if not app.is_dir() or app.suffix != ".app":
        raise VerificationError("Reported output is not an application bundle")
    ipa = recorded_path(report.get("ipa"), "ipa")
    if not ipa.is_file():
        raise VerificationError("Reported input IPA is not a file")
    ipa_hash = expected_hash(report.get("ipa_sha256"), "ipa_sha256")
    images = report.get("images")
    if not isinstance(images, list) or not images:
        raise VerificationError("Build report has no program hashes")
    programs: list[tuple[Path, str, str]] = []
    seen: set[str] = set()
    for image in images:
        if not isinstance(image, dict):
            raise VerificationError("Malformed program entry in report")
        name = image.get("path")
        if not isinstance(name, str) or not name or "\x00" in name or "\\" in name:
            raise VerificationError("Invalid program path in report")
        relative = PurePosixPath(name)
        if relative.is_absolute() or any(part in ("", ".", "..") for part in name.split("/")):
            raise VerificationError(f"Unsafe program path in report: {name}")
        if name in seen:
            raise VerificationError(f"Duplicate program path in report: {name}")
        seen.add(name)
        path = app.joinpath(*relative.parts).resolve(strict=True)
        if not path.is_relative_to(app) or not path.is_file():
            raise VerificationError(f"Program escapes the app or is not a file: {name}")
        programs.append((path, expected_hash(image.get("final_sha256"), name), name))
    codesign = shutil.which("codesign")
    if not codesign:
        raise VerificationError("Apple codesign is unavailable; run this check on macOS")
    if digest(ipa) != ipa_hash:
        raise VerificationError("Input IPA SHA-256 does not match the build report")
    for path, expected, name in programs:
        if digest(path) != expected:
            raise VerificationError(f"Signed program SHA-256 does not match the report: {name}")
    checked = subprocess.run(
        [codesign, "--verify", "--deep", "--strict", str(app)],
        text=True, capture_output=True, check=False,
    )
    if checked.returncode:
        diagnostic = checked.stderr.strip() or checked.stdout.strip()
        raise VerificationError(f"App signature verification failed: {diagnostic}")
    return len(programs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=ROOT / "build/report.json")
    args = parser.parse_args()
    try:
        count = verify(args.report.expanduser().resolve(strict=True))
    except (VerificationError, OSError, ValueError, UnicodeError) as error:
        print(f"Verification failed: {error}", file=sys.stderr)
        return 1
    print(f"Verified input IPA, {count} signed programs, and app signature.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
