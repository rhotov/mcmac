#!/usr/bin/env python3
"""Build a local Apple Silicon compatibility bundle from an unencrypted IPA.

This changes binary platform metadata and system-library paths; it does not
recover source code, decrypt executables, or recompile Minecraft.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zipfile


ROOT = Path(__file__).resolve().parent.parent
MH_MAGIC_64 = b"\xcf\xfa\xed\xfe"
MACHO_MAGICS = {
    MH_MAGIC_64, b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}
LC_BUILD_VERSION = 0x32
LC_VERSION_MIN_IPHONEOS = 0x25
LC_ENCRYPTION_INFO = {0x21, 0x2C}
DYLIB_COMMANDS = {0xC, 0x18, 0x20, 0x80000018, 0x8000001F, 0x80000023}
LC_ID_DYLIB = 0xD
CATALYST_PLATFORM = 6
MINIMUM_OS = 13 << 16
SHIM_LOAD_PATH = "@executable_path/Frameworks/libmcmac.dylib"


class PortError(Exception):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], operations: list[dict]) -> str:
    result = subprocess.run(command, text=True, capture_output=True)
    operations.append({"command": command, "exit_code": result.returncode,
                       "stdout": result.stdout.strip(), "stderr": result.stderr.strip()})
    if result.returncode:
        raise PortError(f"Command failed ({result.returncode}): {' '.join(command)}\n"
                        f"{result.stderr.strip()}")
    return result.stdout.strip()


def extract_ipa(ipa: Path, destination: Path) -> tuple[Path, dict]:
    """Validate the entire central directory before writing selected app files."""
    with zipfile.ZipFile(ipa) as archive:
        infos = archive.infolist()
        seen: dict[str, bool] = {}
        app_names: set[str] = set()
        total_size = 0
        for entry in infos:
            name = entry.filename
            if not name or "\x00" in name or "\\" in name or name.startswith("/"):
                raise PortError(f"Unsafe ZIP member: {name!r}")
            bare = name[:-1] if name.endswith("/") else name
            parts = bare.split("/")
            if not bare or any(part in ("", ".", "..") for part in parts):
                raise PortError(f"Unsafe ZIP member: {name!r}")
            if bare in seen:
                raise PortError(f"Duplicate ZIP member: {bare}")
            seen[bare] = entry.is_dir()
            unix_mode = entry.external_attr >> 16
            kind = stat.S_IFMT(unix_mode)
            if stat.S_ISLNK(unix_mode) or kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise PortError(f"Unsupported ZIP special file or symlink: {name}")
            if kind == stat.S_IFDIR and not entry.is_dir():
                raise PortError(f"Inconsistent ZIP directory metadata: {name}")
            if entry.flag_bits & 1:
                raise PortError(f"Encrypted ZIP member is unsupported: {name}")
            total_size += entry.file_size
            if total_size > 8 * 1024 ** 3:
                raise PortError("IPA expands beyond the 8 GiB build limit")
            if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
                app_names.add(parts[1])
        for name in seen:
            for ancestor in PurePosixPath(name).parents:
                if str(ancestor) in seen and not seen[str(ancestor)]:
                    raise PortError(f"ZIP file shadows a directory: {ancestor}")
        if len(app_names) != 1:
            raise PortError(f"Expected exactly one Payload/*.app, found {sorted(app_names)}")
        app_name = next(iter(app_names))
        prefix = f"Payload/{app_name}/"
        if prefix + "Info.plist" not in seen:
            raise PortError("The app has no root Info.plist")
        destination.mkdir()
        for entry in infos:
            if not entry.filename.startswith(prefix):
                continue
            relative = entry.filename[len(prefix):].rstrip("/")
            if not relative:
                continue
            target = destination.joinpath(*PurePosixPath(relative).parts)
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                target.chmod(0o755 if (entry.external_attr >> 16) & 0o111 else 0o644)
        info = plistlib.loads((destination / "Info.plist").read_bytes())
        if not isinstance(info, dict):
            raise PortError("Info.plist is not a dictionary")
        executable = info.get("CFBundleExecutable")
        if not isinstance(executable, str) or not executable or "/" in executable or executable in (".", ".."):
            raise PortError("Invalid CFBundleExecutable")
        if not (destination / executable).is_file():
            raise PortError("CFBundleExecutable is missing")
        return destination, info


def read_commands(data: bytes) -> tuple[tuple[int, ...], list[tuple[int, bytes]]]:
    if data[:4] != MH_MAGIC_64 or len(data) < 32:
        raise PortError("Only little-endian, thin arm64 Mach-O files are supported")
    header = struct.unpack_from("<IiiIIIII", data)
    if header[1] != 0x0100000C or header[2] != 0:
        raise PortError("Only plain arm64 is supported; arm64e and other CPUs are rejected")
    if header[3] not in (2, 6, 8):
        raise PortError(f"Unsupported Mach-O file type: {header[3]}")
    ncmds, size = header[4:6]
    if ncmds > 4096 or size > len(data) - 32:
        raise PortError("Invalid Mach-O load-command range")
    commands = []
    offset = 32
    for _ in range(ncmds):
        if offset + 8 > 32 + size:
            raise PortError("Truncated Mach-O command header")
        command, command_size = struct.unpack_from("<II", data, offset)
        if command_size < 8 or command_size % 8 or offset + command_size > 32 + size:
            raise PortError("Invalid Mach-O load-command size")
        commands.append((command, data[offset:offset + command_size]))
        offset += command_size
    if offset != 32 + size:
        raise PortError("Mach-O sizeofcmds does not match its commands")
    return header, commands


def command_string(command: bytes, field_offset: int = 8) -> str:
    if len(command) < field_offset + 4:
        raise PortError("Truncated command string offset")
    offset = struct.unpack_from("<I", command, field_offset)[0]
    if offset < 12 or offset >= len(command) or b"\0" not in command[offset:]:
        raise PortError("Invalid Mach-O command string")
    return command[offset:].split(b"\0", 1)[0].decode("utf-8", errors="strict")


def dylib_command(kind: int, name: str, original: bytes | None = None) -> bytes:
    encoded = name.encode("utf-8") + b"\0"
    size = (24 + len(encoded) + 7) & ~7
    tail = original[12:24] if original is not None else struct.pack("<III", 0, 0x10000, 0x10000)
    if len(tail) != 12:
        raise PortError("Truncated dylib command")
    return struct.pack("<III", kind, size, 24) + tail + encoded + bytes(size - 24 - len(encoded))


def library_path(original: str, sdk: Path) -> str:
    if original == "@rpath/libswift_Concurrency.dylib":
        return "/usr/lib/swift/libswift_Concurrency.dylib"
    match = re.fullmatch(r"/System/Library/Frameworks/([^/]+)\.framework/(.+)", original)
    if match:
        framework, remainder = match.groups()
        support = Path("/System/iOSSupport/System/Library/Frameworks") / f"{framework}.framework"
        if support.is_dir() or (sdk / str(support).lstrip("/")).is_dir():
            return f"{support}/{remainder}"
    if original.startswith("/usr/lib/swift/"):
        support = Path("/System/iOSSupport") / original.lstrip("/")
        stub = (sdk / str(support).lstrip("/")).with_suffix(".tbd")
        if support.exists() or stub.is_file():
            return str(support)
    return original


def first_file_payload(data: bytes, commands: list[tuple[int, bytes]], old_end: int) -> int:
    """Find the first section/file segment byte after the existing commands."""
    candidates = [len(data)]
    for kind, command in commands:
        if kind != 0x19:  # LC_SEGMENT_64
            continue
        if len(command) < 72:
            raise PortError("Truncated LC_SEGMENT_64")
        file_offset, file_size = struct.unpack_from("<QQ", command, 40)
        section_count = struct.unpack_from("<I", command, 64)[0]
        if len(command) != 72 + section_count * 80:
            raise PortError("Invalid LC_SEGMENT_64 section table")
        if file_offset and file_size:
            if file_offset < old_end:
                raise PortError("A file segment overlaps Mach-O load commands")
            candidates.append(file_offset)
        for index in range(section_count):
            section = command[72 + index * 80:72 + (index + 1) * 80]
            section_size = struct.unpack_from("<Q", section, 40)[0]
            section_offset = struct.unpack_from("<I", section, 48)[0]
            section_type = struct.unpack_from("<I", section, 64)[0] & 0xFF
            if section_size and section_type not in (1, 0xC, 0x12):  # zero-fill has no file bytes
                if section_offset < old_end or section_offset + section_size > len(data):
                    raise PortError("Invalid or overlapping file-backed Mach-O section")
                candidates.append(section_offset)
    return min(candidates)


def patch_image(path: Path, sdk: Path, inject: bool = False) -> dict:
    data = path.read_bytes()
    header, commands = read_commands(data)
    original_hash = hashlib.sha256(data).hexdigest()
    changes: list[dict] = []
    rewritten: list[bytes] = []
    platform_count = 0
    load_paths = []
    encryption = []
    for kind, command in commands:
        if kind in LC_ENCRYPTION_INFO:
            if len(command) < 20:
                raise PortError(f"Truncated encryption command: {path}")
            cryptoff, cryptsize, cryptid = struct.unpack_from("<III", command, 8)
            encryption.append({"offset": cryptoff, "size": cryptsize, "cryptid": cryptid})
            if cryptid:
                raise PortError(f"Encrypted executable cannot be converted: {path} (cryptid={cryptid})")
        if kind == LC_BUILD_VERSION:
            if len(command) < 24:
                raise PortError("Truncated LC_BUILD_VERSION")
            platform, minos, sdk_version, tool_count = struct.unpack_from("<IIII", command, 8)
            if platform not in (2, 6):
                raise PortError(f"Expected iOS/Catalyst image, found platform {platform}: {path}")
            if len(command) != 24 + tool_count * 8:
                raise PortError("Invalid LC_BUILD_VERSION tool table")
            command = command[:8] + struct.pack("<IIII", CATALYST_PLATFORM, MINIMUM_OS,
                                               max(sdk_version, MINIMUM_OS), tool_count) + command[24:]
            changes.append({"kind": "platform", "from": platform, "to": CATALYST_PLATFORM,
                            "original_minimum_os": minos, "minimum_os": MINIMUM_OS})
            platform_count += 1
        elif kind == LC_VERSION_MIN_IPHONEOS:
            if len(command) != 16:
                raise PortError("Invalid LC_VERSION_MIN_IPHONEOS")
            minos, sdk_version = struct.unpack_from("<II", command, 8)
            command = struct.pack("<IIIIII", LC_BUILD_VERSION, 24, CATALYST_PLATFORM,
                                  MINIMUM_OS, max(sdk_version, MINIMUM_OS), 0)
            changes.append({"kind": "legacy_platform", "from": "LC_VERSION_MIN_IPHONEOS",
                            "to": CATALYST_PLATFORM, "original_minimum_os": minos,
                            "minimum_os": MINIMUM_OS})
            platform_count += 1
        elif kind in DYLIB_COMMANDS:
            name = command_string(command)
            replacement = library_path(name, sdk)
            if replacement != name:
                command = dylib_command(kind, replacement, command)
                changes.append({"kind": "library", "from": name, "to": replacement})
            load_paths.append(replacement)
        rewritten.append(command)
    if platform_count != 1:
        raise PortError(f"Expected one platform command, found {platform_count}: {path}")
    if inject and SHIM_LOAD_PATH not in load_paths:
        rewritten.append(dylib_command(0xC, SHIM_LOAD_PATH))
        changes.append({"kind": "inject", "path": SHIM_LOAD_PATH})
    old_end = 32 + header[5]
    new_commands = b"".join(rewritten)
    new_end = 32 + len(new_commands)
    payload_start = first_file_payload(data, commands, old_end)
    if new_end > payload_start:
        raise PortError(f"Insufficient load-command padding in {path}")
    if new_end > old_end and any(data[old_end:new_end]):
        raise PortError(f"Refusing to overwrite nonzero load-command padding in {path}")
    output = bytearray(data)
    output[32:max(old_end, new_end)] = new_commands + bytes(max(old_end, new_end) - new_end)
    struct.pack_into("<II", output, 16, len(rewritten), len(new_commands))
    # No bytes beyond the reserved header area may move or change here.
    if output[max(old_end, new_end):] != data[max(old_end, new_end):]:
        raise PortError("Internal error: file payload changed during metadata patching")
    read_commands(output)
    path.write_bytes(output)
    path.chmod(0o755)
    return {"source_sha256": original_hash, "patched_sha256": sha256(path),
            "architecture": "arm64", "encryption": encryption, "changes": changes,
            "old_load_commands_end": old_end, "new_load_commands_end": new_end,
            "first_payload_offset": payload_start}


def remove_mobile_signatures(app: Path) -> list[str]:
    removed = []
    candidates = [p for p in app.rglob("*") if p.name in
                  ("_CodeSignature", "embedded.mobileprovision", "embedded.provisionprofile")]
    for path in sorted(candidates, key=lambda p: len(p.parts), reverse=True):
        if not path.exists():
            continue
        removed.append(str(path.relative_to(app)))
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    return removed


def update_plists(app: Path, original: dict) -> None:
    for path in [app / "Info.plist", *sorted((app / "Frameworks").glob("*.framework/Info.plist"))]:
        if not path.exists():
            continue
        value = plistlib.loads(path.read_bytes())
        for key in list(value):
            if key.startswith("DT") or key == "BuildMachineOSBuild":
                value.pop(key, None)
        value["MinimumOSVersion"] = "13.0"
        if path == app / "Info.plist":
            value["CFBundleName"] = "Minecraft"
            value["CFBundleDisplayName"] = "Minecraft"
            value["LSMinimumSystemVersion"] = "13.0"
            value["LSApplicationCategoryType"] = "public.app-category.games"
            value["LSSupportsGameMode"] = True
            value["GCSupportsGameMode"] = True
            for key in ("CFBundleSupportedPlatforms", "LSRequiresIPhoneOS", "UIDeviceFamily", "UIRequiresFullScreen"):
                if key in original:
                    value[key] = original[key]
                else:
                    value.pop(key, None)
            value["UIStatusBarHidden"] = True
            # Preserve identity and executable exactly; Xbox callback names depend on them.
            value["CFBundleIdentifier"] = original["CFBundleIdentifier"]
            value["CFBundleExecutable"] = original["CFBundleExecutable"]
        path.write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=False))


def build(args: argparse.Namespace, report: dict) -> None:
    ipa = args.ipa.expanduser().resolve(strict=True)
    output = args.output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise PortError(f"Output already exists; select a new --output: {output}")
    if output.suffix != ".app":
        raise PortError("--output must end in .app")
    if sys.platform != "darwin":
        raise PortError("This builder needs macOS and Apple's command-line developer tools")
    if os.uname().machine != "arm64":
        raise PortError("This build target requires an Apple Silicon Mac")
    for tool in ("codesign", "xcrun"):
        if shutil.which(tool) is None:
            raise PortError(f"Required tool is missing: {tool}")
    shim = args.shim.expanduser().resolve(strict=True) if args.shim else None
    report.update({"ipa": str(ipa), "ipa_sha256": sha256(ipa), "output": str(output),
                   "host": {"machine": os.uname().machine, "release": os.uname().release},
                   "method": "Binary compatibility adaptation; no source recompilation or decryption",
                   "images": [], "operations": [], "excluded": []})
    sdk = Path(run(["xcrun", "--show-sdk-path"], report["operations"]))
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".mcmac-", dir=output.parent) as temporary:
        staging = Path(temporary) / output.name
        app, original = extract_ipa(ipa, staging)
        report["original_bundle"] = original
        if not isinstance(original.get("CFBundleIdentifier"), str):
            raise PortError("Missing CFBundleIdentifier")
        report["removed"] = remove_mobile_signatures(app)
        concurrency = app / "Frameworks/libswift_Concurrency.dylib"
        if concurrency.exists():
            # Inspect even excluded images: encrypted inputs must never be silently accepted.
            data = concurrency.read_bytes()
            _, commands = read_commands(data)
            for kind, command in commands:
                if kind in LC_ENCRYPTION_INFO and (len(command) < 20 or struct.unpack_from("<I", command, 16)[0]):
                    raise PortError("Bundled Swift concurrency runtime is encrypted or malformed")
            report["excluded"].append({"path": str(concurrency.relative_to(app)),
                                       "sha256": sha256(concurrency),
                                       "reason": "Use macOS system Swift concurrency runtime"})
            concurrency.unlink()
        if shim:
            shim_target = app / "Frameworks/libmcmac.dylib"
            shim_target.parent.mkdir(parents=True, exist_ok=True)
            if shim_target.exists():
                raise PortError("IPA already contains Frameworks/libmcmac.dylib")
            shutil.copyfile(shim, shim_target)
            report["shim"] = {"source": str(shim), "sha256": sha256(shim)}
        images: list[Path] = []
        for path in sorted(app.rglob("*")):
            if path.is_file():
                with path.open("rb") as handle:
                    magic = handle.read(4)
                if magic in MACHO_MAGICS:
                    images.append(path)
        main = app / original["CFBundleExecutable"]
        if main not in images:
            raise PortError("The main executable is not a supported Mach-O")
        for image in images:
            try:
                item = patch_image(image, sdk, inject=bool(shim) and image == main)
            except (ValueError, struct.error, UnicodeError) as error:
                raise PortError(f"Malformed Mach-O {image.relative_to(app)}: {error}") from error
            item["path"] = str(image.relative_to(app))
            report["images"].append(item)
        update_plists(app, original)
        entitlements = {
            "com.apple.security.app-sandbox": True,
            "com.apple.security.files.user-selected.read-write": True,
            "com.apple.security.device.audio-input": True,
        }
        if not args.offline:
            entitlements["com.apple.security.network.client"] = True
            entitlements["com.apple.security.network.server"] = True
        report["network_enabled"] = not args.offline
        entitlement_file = Path(temporary) / "entitlements.plist"
        entitlement_file.write_bytes(plistlib.dumps(entitlements))
        report["entitlements"] = entitlements
        for image in sorted((p for p in images if p != main), key=lambda p: len(p.parts), reverse=True):
            run(["codesign", "--force", "--sign", "-", "--timestamp=none", str(image)], report["operations"])
        frameworks = sorted(app.rglob("*.framework"), key=lambda p: len(p.parts), reverse=True)
        for framework in frameworks:
            run(["codesign", "--force", "--sign", "-", "--timestamp=none", str(framework)], report["operations"])
        run(["codesign", "--force", "--sign", "-", "--timestamp=none", "--entitlements",
             str(entitlement_file), str(app)], report["operations"])
        run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)], report["operations"])
        for item in report["images"]:
            item["final_sha256"] = sha256(app / item["path"])
        if output.exists() or output.is_symlink():
            raise PortError(f"Output appeared during build; refusing replacement: {output}")
        app.rename(output)
    report["status"] = "built-and-signature-verified"
    report["runtime_verified"] = False


def json_safe(value):
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if hasattr(value, "isoformat"):
        return value.isoformat()
    raise TypeError(f"Unsupported report value: {type(value).__name__}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipa", nargs="?", type=Path, default=ROOT / "Minecraft_ipa_ios_1.26.13.0.ipa")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/Minecraft.app")
    parser.add_argument("--shim", type=Path, help="Optional Catalyst dylib to inject as libmcmac.dylib")
    parser.add_argument("--offline", action="store_true", help="Build without any network entitlements for offline validation")
    parser.add_argument("--report", type=Path, default=ROOT / "build/report.json")
    args = parser.parse_args()
    report_path = args.report.expanduser().resolve()
    protected = [args.ipa.expanduser().resolve()]
    if args.shim:
        protected.append(args.shim.expanduser().resolve())
    output_path = args.output.expanduser().resolve()
    if report_path in protected or report_path == output_path or output_path in report_path.parents:
        parser.error("--report must not overwrite the input IPA, shim, or any file inside the output app")
    args.report = report_path
    report = {"started_at_unix": time.time(), "status": "building"}
    code = 0
    try:
        build(args, report)
    except (PortError, OSError, zipfile.BadZipFile, plistlib.InvalidFileException) as error:
        report["status"] = "failed"
        report["error"] = str(error)
        print(f"Build failed: {error}", file=sys.stderr)
        code = 1
    finally:
        report["finished_at_unix"] = time.time()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=json_safe) + "\n")
    if not code:
        print(f"Built: {report['output']}")
        print(f"Signature verified. Runtime testing remains required. Report: {args.report.absolute()}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
