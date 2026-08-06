#!/usr/bin/env python3
"""
General-purpose APK build / repackaging tool.

Takes an ``.apk`` / ``.xapk`` / ``.apks`` / ``.apkm`` file, optionally injects a
Frida gadget (or any user-supplied native library) into the app's native
libraries, then rebuilds, zipaligns, signs and verifies the result.

The tool is deliberately *not* tied to any specific application: the injection
target is chosen automatically and the optional interaction script is supplied
by the user, not hardcoded.

Intended for authorized security testing / research only.

Usage examples
--------------
    # Inject the latest Frida gadget, auto-detect ABIs, sign with a throwaway key
    python patch.py -i app.apk

    # Provide a Frida script for the gadget to run on load
    python patch.py -i app.xapk --script bypass.js

    # Just repackage + sign, no injection (pure packaging tool)
    python patch.py -i app.apk --no-gadget

    # Use a local gadget and your own keystore
    python patch.py -i app.apk --gadget ./frida-gadget-arm64.so \
        --keystore my.jks --keyalias mykey --storepass secret
"""
from __future__ import annotations

import argparse
import json
import logging
import lzma
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from shutil import which
from typing import Iterable, Optional

import config

# Third-party imports are wrapped so a missing dependency produces a clear
# message instead of a raw traceback.
try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

try:
    import lief
except ImportError:  # pragma: no cover
    lief = None  # type: ignore


log = logging.getLogger("patchapk")

#: Directory containing this script (used for the persistent tools cache).
SCRIPT_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class PatchError(Exception):
    """Any recoverable, user-facing failure raised by this tool."""


class ToolError(PatchError):
    """An external command failed; carries the captured output for context."""


# ---------------------------------------------------------------------------
# Logging / progress
# ---------------------------------------------------------------------------
class StepLogger:
    """Emits ``[n/total] message`` progress lines."""

    def __init__(self, total: int) -> None:
        self.total = total
        self.current = 0

    def step(self, message: str) -> None:
        self.current += 1
        log.info("[%d/%d] %s", self.current, self.total, message)


def setup_logging(verbose: bool) -> None:
    """Configure UTF-8 friendly logging that works on Windows consoles."""
    for stream in (sys.stdout, sys.stderr):
        # Python 3.7+; make console output UTF-8 so Korean paths etc. print.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )


# ---------------------------------------------------------------------------
# Subprocess helper (no shell, unicode-safe)
# ---------------------------------------------------------------------------
def run_command(cmd: list[str], *, what: str) -> subprocess.CompletedProcess:
    """
    Run ``cmd`` (a list, never a shell string) and return the completed process.

    Raises :class:`ToolError` with captured output on non-zero exit. Output is
    decoded as UTF-8 with replacement so mixed-codepage tool output never
    crashes the run.
    """
    printable = " ".join(str(c) for c in cmd)
    log.debug("$ %s", printable)
    try:
        result = subprocess.run(
            [str(c) for c in cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise ToolError(f"{what}: executable not found ({cmd[0]})") from exc
    except OSError as exc:
        raise ToolError(f"{what}: failed to launch {cmd[0]}: {exc}") from exc

    output = (result.stdout or "").strip()
    if result.returncode != 0:
        detail = output if output else "(no output captured)"
        raise ToolError(
            f"{what} failed (exit {result.returncode}).\n"
            f"  command: {printable}\n"
            f"  output : {detail}"
        )
    if output:
        log.debug("%s output:\n%s", what, output)
    return result


# ---------------------------------------------------------------------------
# External tool discovery
# ---------------------------------------------------------------------------
def _find_in_sdk(exe_names: list[str]) -> Optional[Path]:
    """Search Android SDK build-tools dirs for one of ``exe_names``."""
    for root in config.android_sdk_roots():
        build_tools = root / "build-tools"
        if not build_tools.is_dir():
            continue
        # Newest build-tools version first.
        for version_dir in sorted(build_tools.iterdir(), reverse=True):
            for name in exe_names:
                candidate = version_dir / name
                if candidate.is_file():
                    return candidate
    return None


def _find_in_jdk(exe_names: list[str]) -> Optional[Path]:
    for root in config.jdk_bin_roots():
        for name in exe_names:
            candidate = root / name
            if candidate.is_file():
                return candidate
    return None


def find_tool(logical: str) -> Optional[Path]:
    """
    Locate an external tool by logical name
    (``apksigner``/``zipalign``/``keytool``/``java``).

    Search order: PATH (all known exe variants) → Android SDK build-tools (for
    build tools) or JDK bin dirs (for keytool/java). Returns the path or ``None``.
    """
    exe_names = config.TOOL_EXECUTABLES[logical]

    for name in exe_names:
        found = which(name)
        if found:
            return Path(found)

    if logical in config.JDK_TOOLS:
        return _find_in_jdk(exe_names)
    return _find_in_sdk(exe_names)


def resolve_tools(need_signing: bool) -> dict[str, Path]:
    """
    Resolve every external tool we need and fail early with guidance if any
    are missing.
    """
    required = ["zipalign", "apksigner", "keytool"] if need_signing else []
    resolved: dict[str, Path] = {}
    missing: list[str] = []

    for logical in required:
        path = find_tool(logical)
        if path is None:
            missing.append(logical)
        else:
            resolved[logical] = path
            log.debug("Found %-9s -> %s", logical, path)

    if missing:
        _report_missing_tools(missing)
        raise PatchError(f"Missing required tool(s): {', '.join(missing)}")
    return resolved


def _report_missing_tools(missing: Iterable[str]) -> None:
    log.error("Could not locate the following tool(s): %s", ", ".join(missing))
    log.error("Searched PATH and these Android SDK roots:")
    for root in config.android_sdk_roots():
        marker = "ok " if root.exists() else "-- "
        log.error("  [%s] %s", marker, root)
    log.error("Hints:")
    log.error("  * apksigner / zipalign live in <SDK>/build-tools/<version>/")
    log.error("  * keytool ships with any JDK (set JAVA_HOME)")
    log.error("  * or add the directories above to your PATH")


# ---------------------------------------------------------------------------
# Filesystem / workspace helpers
# ---------------------------------------------------------------------------
def _is_ascii(text: str) -> bool:
    try:
        text.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def make_workspace(explicit: Optional[Path]) -> Path:
    """
    Create a temporary workspace.

    Prefers an ASCII-only path because some external tools and older LIEF builds
    misbehave with non-ASCII (e.g. Korean) directory names on Windows.
    """
    if explicit is not None:
        explicit.mkdir(parents=True, exist_ok=True)
        return explicit

    base = Path(tempfile.gettempdir())
    if not _is_ascii(str(base)):
        # Fall back to a guaranteed-ASCII location.
        if os.name == "nt":
            base = Path(os.environ.get("SystemDrive", "C:") + "\\") / "apk_patch_tmp"
        else:
            base = Path("/tmp")
        base.mkdir(parents=True, exist_ok=True)

    return Path(tempfile.mkdtemp(prefix="apkpatch_", dir=str(base)))


def safe_rmtree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def default_output_for(input_path: Path) -> Path:
    """Derive an output path that keeps the input's extension/format."""
    return input_path.with_name(
        input_path.stem + config.DEFAULT_OUTPUT_SUFFIX + input_path.suffix
    )


# ---------------------------------------------------------------------------
# Input format detection
# ---------------------------------------------------------------------------
@dataclass
class InputInfo:
    path: Path
    suffix: str          # normalized lower-case extension
    is_bundle: bool


def detect_input(path: Path) -> InputInfo:
    if not path.is_file():
        raise PatchError(f"Input file not found: {path}")
    suffix = path.suffix.lower()
    if suffix not in config.SUPPORTED_INPUT_EXTS:
        raise PatchError(
            f"Unsupported input '{suffix}'. "
            f"Supported: {', '.join(sorted(config.SUPPORTED_INPUT_EXTS))}"
        )
    if not zipfile.is_zipfile(path):
        raise PatchError(f"Input is not a valid zip/apk container: {path}")
    return InputInfo(path=path, suffix=suffix, is_bundle=suffix in config.BUNDLE_EXTS)


# ---------------------------------------------------------------------------
# Bundle (xapk/apks/apkm) handling
# ---------------------------------------------------------------------------
def extract_zip(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(dest)


def find_apks(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.apk") if p.is_file())


def apk_has_native_libs(apk: Path) -> bool:
    with zipfile.ZipFile(apk) as zf:
        return any(
            n.startswith("lib/") and n.endswith(".so") for n in zf.namelist()
        )


def select_primary_apk(apks: list[Path]) -> Path:
    """
    Choose which APK inside a bundle carries the native libraries to patch.

    Preference: an APK that both is named ``base.apk`` *and* contains native
    libs → any APK that contains native libs (largest wins) → ``base.apk`` →
    largest APK overall.
    """
    if not apks:
        raise PatchError("No .apk files found inside the bundle")

    with_libs = [a for a in apks if apk_has_native_libs(a)]

    base_with_libs = [a for a in with_libs if a.name == "base.apk"]
    if base_with_libs:
        return base_with_libs[0]
    if with_libs:
        return max(with_libs, key=lambda p: p.stat().st_size)

    base = [a for a in apks if a.name == "base.apk"]
    if base:
        log.warning("No native libraries found in any split; using base.apk")
        return base[0]

    log.warning("No native libraries and no base.apk; using largest APK")
    return max(apks, key=lambda p: p.stat().st_size)


def repackage_bundle(extract_dir: Path, output: Path) -> None:
    """Zip a previously-extracted bundle directory back into ``output``."""
    tmp_out = output.with_suffix(output.suffix + ".tmp")
    if tmp_out.exists():
        tmp_out.unlink()
    with zipfile.ZipFile(tmp_out, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in sorted(extract_dir.rglob("*")):
            if file.is_file():
                arcname = file.relative_to(extract_dir).as_posix()
                zf.write(file, arcname)
    shutil.move(str(tmp_out), str(output))


def _split_id(apk_name: str) -> str:
    """Derive an XAPK ``split_apks`` id from an apk file name."""
    stem = apk_name[:-4] if apk_name.lower().endswith(".apk") else apk_name
    if stem == "base":
        return "base"
    return stem[len("split_"):] if stem.startswith("split_") else stem


def write_xapk_manifest(extract_dir: Path, apks: list[Path]) -> None:
    """
    Write a minimal ``manifest.json`` so the repackaged bundle is a valid XAPK.

    Package / version fields are taken from an existing ``info.json`` (present in
    APKM bundles) when available; the split list is always rebuilt from the real
    files so it matches what we actually ship.
    """
    info: dict = {}
    info_json = extract_dir / "info.json"
    if info_json.exists():
        try:
            info = json.loads(info_json.read_text(encoding="utf-8", errors="replace"))
        except (ValueError, OSError):
            info = {}

    manifest = {
        "xapk_version": 2,
        "package_name": info.get("pname", ""),
        "name": info.get("app_name") or info.get("apk_title") or "app",
        "version_code": str(info.get("versioncode", "")),
        "version_name": info.get("release_version", ""),
        "min_sdk_version": str(info.get("min_api", "")),
        "target_sdk_version": "",
        "split_apks": [
            {"file": a.relative_to(extract_dir).as_posix(), "id": _split_id(a.name)}
            for a in apks
        ],
    }
    (extract_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    log.info("Wrote XAPK manifest.json (%d split(s))", len(apks))


# ---------------------------------------------------------------------------
# APKEditor: merge a split bundle into a single universal APK
# ---------------------------------------------------------------------------
def ensure_apkeditor(local_jar: Optional[Path]) -> Path:
    """
    Return a path to the APKEditor jar, downloading it once into a persistent
    cache (``<script dir>/.tools/``) if necessary.
    """
    if local_jar is not None:
        if not local_jar.is_file():
            raise PatchError(f"--apkeditor jar not found: {local_jar}")
        return local_jar

    cache_dir = SCRIPT_DIR / config.TOOLS_CACHE_DIRNAME
    cached = cache_dir / config.APKEDITOR_JAR_NAME
    if cached.is_file() and cached.stat().st_size > 0:
        log.debug("Using cached APKEditor: %s", cached)
        return cached

    log.info("Fetching APKEditor (one-time download) ...")
    release = http_get_json(config.APKEDITOR_LATEST_API)
    asset = next(
        (a for a in release.get("assets", [])
         if a.get("name", "").endswith(".jar")),
        None,
    )
    if asset is None:
        raise PatchError("Could not find an APKEditor .jar in the latest release")
    download_file(asset["browser_download_url"], cached)
    log.info("APKEditor %s cached at %s", release.get("tag_name", "?"), cached)
    return cached


def merge_bundle_to_apk(java: Path, jar: Path, bundle: Path, out_apk: Path) -> None:
    """Merge a split bundle (apkm/xapk/apks) into a single APK via APKEditor."""
    if out_apk.exists():
        out_apk.unlink()
    log.info("Merging splits into a single APK (APKEditor) ...")
    run_command(
        [java, "-jar", str(jar), "m", "-i", str(bundle), "-o", str(out_apk), "-f"],
        what="APKEditor merge",
    )
    if not out_apk.is_file():
        raise PatchError("APKEditor did not produce a merged APK")


def _res_xml_dir(decoded: Path) -> Path:
    for res in decoded.glob("resources/*/res"):
        return res / "xml"
    return decoded / "resources" / "package_1" / "res" / "xml"


def patch_nsc(java: Path, jar: Path, apk: Path, workspace: Path) -> Path:
    """
    Return a new (unsigned) APK whose network-security-config trusts user CAs.

    Decodes with APKEditor, overwrites the app's existing NSC resource (or adds
    one if absent), and rebuilds. Lets you intercept TLS with a proxy + a
    user-installed CA certificate — the robust bypass for hardened apps (e.g.
    SoLoader/Superpack apps that defeat Frida-gadget injection).
    """
    decoded = workspace / "nsc_decode"
    safe_rmtree(decoded)
    log.info("Decoding APK for NSC patch (APKEditor, raw dex) ...")
    # '-dex' keeps dex files raw (skips smali disassembly) — we only touch
    # resources/manifest, so this is dramatically faster on large apps.
    run_command([java, "-jar", str(jar), "d", "-i", str(apk), "-o", str(decoded),
                 "-dex", "-f"],
                what="APKEditor decode")

    manifest = decoded / "AndroidManifest.xml"
    text = manifest.read_text(encoding="utf-8", errors="replace")
    xml_dir = _res_xml_dir(decoded)
    xml_dir.mkdir(parents=True, exist_ok=True)

    match = re.search(r'android:networkSecurityConfig="@xml/([^"]+)"', text)
    if match:
        name = match.group(1)
        log.info("Overwriting existing NSC resource '%s'", name)
    else:
        name = config.NSC_RESOURCE_NAME
        new_text, n = re.subn(r'<application(\s)',
                              f'<application android:networkSecurityConfig="@xml/{name}"\\1',
                              text, count=1)
        if n == 0:
            raise PatchError("Could not find <application> tag to add networkSecurityConfig")
        manifest.write_text(new_text, encoding="utf-8")
        log.info("App declared no NSC; adding resource '%s'", name)

    (xml_dir / f"{name}.xml").write_text(config.PERMISSIVE_NSC_XML, encoding="utf-8")

    out = workspace / "nsc_patched.apk"
    if out.exists():
        out.unlink()
    log.info("Rebuilding APK with permissive NSC (APKEditor) ...")
    run_command([java, "-jar", str(jar), "b", "-i", str(decoded), "-o", str(out), "-f"],
                what="APKEditor build")
    if not out.is_file():
        raise PatchError("APKEditor did not produce an NSC-patched APK")
    safe_rmtree(decoded)
    return out


# ---------------------------------------------------------------------------
# Native library discovery & selection
# ---------------------------------------------------------------------------
@dataclass
class LibCandidate:
    arcname: str          # e.g. lib/arm64-v8a/libfoo.so
    abi: str
    name: str             # libfoo.so
    size: int


def list_abis(apk: Path) -> list[str]:
    """Return the ABIs present in the APK, in configured preference order."""
    present: set[str] = set()
    with zipfile.ZipFile(apk) as zf:
        for entry in zf.namelist():
            parts = entry.split("/")
            if len(parts) >= 3 and parts[0] == "lib" and entry.endswith(".so"):
                present.add(parts[1])
    ordered = [abi for abi in config.SUPPORTED_ABIS if abi in present]
    # Include any exotic ABI we do not rank explicitly, so nothing is silently lost.
    ordered += sorted(present - set(ordered))
    return ordered


def uses_soloader_superpack(apk: Path) -> bool:
    """
    Detect Facebook SoLoader + Superpack packaging (Instagram, Facebook,
    Messenger, WhatsApp, Threads, ...).

    These apps ship their native libraries as a compressed ``assets/lib/libs.spo``
    blob and load them through a custom loader, so a gadget added as a NEEDED
    dependency of a ``lib/<abi>/*.so`` is never loaded — and rewriting one of
    those libs can break the app's native start-up entirely.
    """
    with zipfile.ZipFile(apk) as zf:
        for name in zf.namelist():
            base = name.rsplit("/", 1)[-1]
            if base == "libs.spo" or base.startswith("libsuperpack"):
                return True
    return False


def warn_if_soloader(apk: Path) -> None:
    if not uses_soloader_superpack(apk):
        return
    bar = "=" * 66
    log.warning(bar)
    log.warning("This app uses Facebook SoLoader + Superpack (assets/lib/libs.spo).")
    log.warning("Frida-gadget injection via a NEEDED dependency will NOT be loaded")
    log.warning("(the app loads libs from Superpack, not from lib/<abi>/), and")
    log.warning("modifying one of those libs can break native start-up (the app")
    log.warning("hangs/closes on launch). For these apps prefer:")
    log.warning("  * frida-server on a rooted device/emulator (no repackaging), or")
    log.warning("  * a network-security-config + proxy (user-CA) approach.")
    log.warning("Continuing anyway because you asked to inject ...")
    log.warning(bar)


def candidate_libs_for_abi(apk: Path, abi: str) -> list[LibCandidate]:
    """
    Return injection-host candidates for ``abi``, best (largest) first.

    Skips excluded names, zero-byte files and non-ELF entries. Deeper checks
    (LIEF parseability, already-patched) happen when a candidate is actually
    tried, so a single corrupt library never removes the rest from the running.
    """
    candidates: list[LibCandidate] = []
    prefix = f"lib/{abi}/"
    with zipfile.ZipFile(apk) as zf:
        for info in zf.infolist():
            name = info.filename
            if not name.startswith(prefix) or not name.endswith(".so"):
                continue
            basename = name.rsplit("/", 1)[-1]
            if basename in config.EXCLUDED_LIB_NAMES:
                continue
            if info.file_size == 0:
                log.debug("skip %s (zero-byte)", name)
                continue
            with zf.open(info) as fh:
                if fh.read(4) != config.ELF_MAGIC:
                    log.debug("skip %s (not an ELF)", name)
                    continue
            candidates.append(
                LibCandidate(arcname=name, abi=abi, name=basename, size=info.file_size)
            )
    candidates.sort(key=lambda c: c.size, reverse=True)
    return candidates


# ---------------------------------------------------------------------------
# LIEF injection (with fallback across candidates)
# ---------------------------------------------------------------------------
def _lief_needed_libs(binary) -> list[str]:
    """Return NEEDED library names across LIEF versions."""
    libs = getattr(binary, "libraries", [])
    result = []
    for item in libs:
        result.append(item if isinstance(item, str) else getattr(item, "name", str(item)))
    return result


def inject_gadget_into(so_path: Path) -> bool:
    """
    Add ``libgadget.so`` as a NEEDED dependency of ``so_path`` using LIEF.

    Returns ``True`` on success, ``False`` if LIEF cannot parse/patch this file
    (so the caller can try the next candidate). Already-patched libraries are
    treated as success.
    """
    if lief is None:
        raise PatchError("LIEF is not installed. Run: pip install -r requirements.txt")

    binary = lief.parse(str(so_path))
    if binary is None:
        log.warning("LIEF could not parse %s", so_path.name)
        return False

    if config.GADGET_LIB_NAME in _lief_needed_libs(binary):
        log.info("%s already references %s (already patched)",
                 so_path.name, config.GADGET_LIB_NAME)
        return True

    try:
        binary.add_library(config.GADGET_LIB_NAME)
        binary.write(str(so_path))
    except Exception as exc:  # LIEF raises assorted exception types
        log.warning("LIEF failed to patch %s: %s", so_path.name, exc)
        return False
    return True


def patch_host_library(
    apk: Path, candidates: list[LibCandidate], scratch: Path
) -> Optional[LibCandidate]:
    """
    Try each candidate (best first) until one is successfully patched.

    Returns the patched candidate (its file left at ``scratch/<arcname>``) or
    ``None`` if every candidate failed.
    """
    last_error: Optional[str] = None
    for cand in candidates:
        target = scratch / cand.arcname
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(apk) as zf, zf.open(cand.arcname) as src, \
                open(target, "wb") as dst:
            shutil.copyfileobj(src, dst)

        log.info("Trying injection host: %s (%d bytes)", cand.arcname, cand.size)
        try:
            if inject_gadget_into(target):
                log.info("Patched host library: %s", cand.arcname)
                return cand
        except PatchError:
            raise
        except Exception as exc:  # be defensive: never abort the whole run here
            last_error = f"{cand.arcname}: {exc}"
            log.warning("Unexpected error patching %s: %s", cand.arcname, exc)
        target.unlink(missing_ok=True)

    log.error("All injection candidates failed for this ABI.")
    if last_error:
        log.error("Last error: %s", last_error)
    return None


# ---------------------------------------------------------------------------
# Downloads (timeout + retry + optional checksum)
# ---------------------------------------------------------------------------
def _require_requests():
    if requests is None:
        raise PatchError("'requests' is not installed. Run: pip install -r requirements.txt")


def http_get_json(url: str):
    _require_requests()
    last: Optional[Exception] = None
    for attempt in range(1, config.DOWNLOAD_RETRIES + 1):
        try:
            resp = requests.get(url, timeout=config.DOWNLOAD_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:  # network/JSON errors
            last = exc
            log.warning("GET %s failed (attempt %d/%d): %s",
                        url, attempt, config.DOWNLOAD_RETRIES, exc)
    raise PatchError(f"Could not fetch {url}: {last}")


def download_file(url: str, dest: Path, *, sha256: Optional[str] = None) -> Path:
    """Download ``url`` to ``dest`` with retry, timeout and optional checksum."""
    import hashlib
    import time

    _require_requests()
    dest.parent.mkdir(parents=True, exist_ok=True)
    last: Optional[Exception] = None

    for attempt in range(1, config.DOWNLOAD_RETRIES + 1):
        digest = hashlib.sha256()
        try:
            with requests.get(url, stream=True, timeout=config.DOWNLOAD_TIMEOUT) as resp:
                resp.raise_for_status()
                total = int(resp.headers.get("content-length") or 0)
                done = 0
                with open(dest, "wb") as fh:
                    for chunk in resp.iter_content(chunk_size=config.DOWNLOAD_CHUNK):
                        if not chunk:
                            continue
                        fh.write(chunk)
                        digest.update(chunk)
                        done += len(chunk)
                        _print_progress(done, total)
            if total:
                sys.stdout.write("\n")

            if sha256 and digest.hexdigest().lower() != sha256.lower():
                raise PatchError(
                    f"Checksum mismatch for {url}\n"
                    f"  expected {sha256}\n  got      {digest.hexdigest()}"
                )
            return dest
        except PatchError:
            raise
        except Exception as exc:
            last = exc
            log.warning("Download failed (attempt %d/%d): %s",
                        attempt, config.DOWNLOAD_RETRIES, exc)
            if attempt < config.DOWNLOAD_RETRIES:
                time.sleep(config.DOWNLOAD_BACKOFF * attempt)

    raise PatchError(f"Failed to download {url}: {last}")


def _print_progress(done: int, total: int) -> None:
    if not total:
        return
    filled = int(50 * done / total)
    sys.stdout.write("\r  [%s%s] %d%%" % ("=" * filled, " " * (50 - filled),
                                          int(100 * done / total)))
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Frida gadget acquisition
# ---------------------------------------------------------------------------
def resolve_gadget_for_abi(
    abi: str, version: Optional[str], scratch: Path,
    local_gadget: Optional[Path], checksum: Optional[str],
) -> Path:
    """
    Return a path to an uncompressed gadget ``.so`` for ``abi``.

    Uses ``local_gadget`` if provided (decompressing ``.xz`` if needed),
    otherwise downloads the matching asset from the Frida GitHub releases.
    """
    out = scratch / f"gadget-{abi}.so"

    if local_gadget is not None:
        if not local_gadget.is_file():
            raise PatchError(f"--gadget path not found: {local_gadget}")
        _materialize_gadget(local_gadget, out)
        return out

    arch = config.ABI_TO_FRIDA_ARCH.get(abi)
    if arch is None:
        raise PatchError(f"No Frida gadget architecture mapping for ABI '{abi}'")

    url = _find_gadget_asset_url(arch, version)
    archive = scratch / f"gadget-{abi}.so.xz"
    log.info("Downloading Frida gadget for %s ...", abi)
    download_file(url, archive, sha256=checksum)
    _materialize_gadget(archive, out)
    archive.unlink(missing_ok=True)
    return out


def _materialize_gadget(source: Path, dest: Path) -> None:
    """Copy ``source`` to ``dest``, transparently decompressing ``.xz``."""
    is_xz = source.suffix == ".xz" or _looks_like_xz(source)
    if is_xz:
        with lzma.open(source, "rb") as fin, open(dest, "wb") as fout:
            shutil.copyfileobj(fin, fout)
    else:
        shutil.copy(source, dest)


def _looks_like_xz(path: Path) -> bool:
    with open(path, "rb") as fh:
        return fh.read(6) == b"\xfd7zXZ\x00"


def _find_gadget_asset_url(arch: str, version: Optional[str]) -> str:
    releases = http_get_json(config.FRIDA_RELEASES_API)
    for release in releases:
        tag = release.get("tag_name", "")
        if version and tag != version:
            continue
        wanted = config.FRIDA_GADGET_ASSET_TEMPLATE.format(version=tag, arch=arch)
        for asset in release.get("assets", []):
            if asset.get("name") == wanted:
                return asset["browser_download_url"]
        if version:
            break
    target = f"version {version}" if version else "the latest release"
    raise PatchError(f"No Frida gadget asset for arch '{arch}' in {target}")


# ---------------------------------------------------------------------------
# Gadget config / interaction script
# ---------------------------------------------------------------------------
def build_gadget_config(script_name: Optional[str], scratch: Path) -> Optional[Path]:
    """
    Create ``libgadget.config.so`` when a script is supplied.

    With no script the gadget uses its default (listen) interaction, so no
    config file is written.
    """
    if script_name is None:
        return None
    cfg = {
        "interaction": {
            "type": "script",
            "path": f"./{script_name}",
        }
    }
    path = scratch / config.GADGET_CONFIG_NAME
    path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return path


def script_lib_name(script: Path) -> str:
    """
    Derive the on-device file name for a user script.

    Android only extracts files named ``lib*.so`` from the APK's lib dir, so the
    script is stored under that pattern.
    """
    safe = script.stem.replace(" ", "_")
    return f"lib{safe}.js.so"


# ---------------------------------------------------------------------------
# APK rebuild (preserve compression, drop old signatures)
# ---------------------------------------------------------------------------
_SIGNATURE_PREFIXES = ("META-INF/",)
_SIGNATURE_SUFFIXES = (".SF", ".RSA", ".DSA", ".EC")


def _is_old_signature(name: str) -> bool:
    if name == "META-INF/MANIFEST.MF":
        return True
    if name.startswith(_SIGNATURE_PREFIXES):
        return name.upper().endswith(_SIGNATURE_SUFFIXES)
    return False


def rebuild_apk(
    original: Path,
    output: Path,
    modified: dict[str, bytes],
    added: dict[str, bytes],
) -> None:
    """
    Rewrite ``original`` into ``output``.

    * Existing entries are copied verbatim, preserving their compression so the
      resources / manifest are never re-encoded (avoids corruption on modern
      APKs where ``resources.arsc`` must stay stored).
    * ``modified`` entries replace the original bytes but keep the original
      compression type.
    * ``added`` entries are appended STORED (uncompressed) so ``zipalign -p``
      can page-align native libraries.
    * Old v1 signature files are dropped so re-signing starts clean.
    """
    tmp_out = output.with_suffix(output.suffix + ".building")
    if tmp_out.exists():
        tmp_out.unlink()

    with zipfile.ZipFile(original, "r") as zin, \
            zipfile.ZipFile(tmp_out, "w") as zout:
        for info in zin.infolist():
            name = info.filename
            if _is_old_signature(name):
                continue
            if name in added:
                continue  # will be (re)written below
            data = modified.get(name)
            if data is None:
                data = zin.read(name)
            # Preserve the original entry's compression choice.
            new_info = zipfile.ZipInfo(filename=name, date_time=info.date_time)
            new_info.compress_type = info.compress_type
            new_info.external_attr = info.external_attr
            new_info.internal_attr = info.internal_attr
            new_info.create_system = info.create_system
            zout.writestr(new_info, data)

        for name, data in added.items():
            zinfo = zipfile.ZipInfo(filename=name)
            zinfo.compress_type = zipfile.ZIP_STORED
            zinfo.external_attr = 0o644 << 16
            zout.writestr(zinfo, data)

    shutil.move(str(tmp_out), str(output))
    log.info("Rebuilt APK: %s (%d bytes)", output.name, output.stat().st_size)


# ---------------------------------------------------------------------------
# zipalign / sign / verify
# ---------------------------------------------------------------------------
def zipalign_apk(tools: dict[str, Path], apk: Path) -> None:
    aligned = apk.with_suffix(apk.suffix + ".aligned")
    run_command(
        [tools["zipalign"], "-p", "-f", "4", str(apk), str(aligned)],
        what="zipalign",
    )
    aligned.replace(apk)


def create_keystore(tools: dict[str, Path], keystore: Path,
                    alias: str, store_pass: str) -> None:
    log.info("Generating throwaway keystore ...")
    run_command(
        [
            tools["keytool"], "-genkeypair", "-v",
            "-keystore", str(keystore),
            "-alias", alias,
            "-keyalg", config.KEYSTORE_KEYALG,
            "-keysize", config.KEYSTORE_KEYSIZE,
            "-validity", config.KEYSTORE_VALIDITY,
            "-storepass", store_pass,
            "-keypass", store_pass,
            "-dname", config.KEYSTORE_DNAME,
            "-noprompt",
        ],
        what="keytool (create keystore)",
    )


def sign_apk(tools: dict[str, Path], apk: Path, keystore: Path,
             alias: str, store_pass: str, min_sdk: Optional[str] = None) -> None:
    log.info("Signing %s ...", apk.name)
    cmd = [
        tools["apksigner"], "sign",
        "--ks", str(keystore),
        "--ks-key-alias", alias,
        "--ks-pass", f"pass:{store_pass}",
        "--key-pass", f"pass:{store_pass}",
    ]
    if min_sdk:
        cmd += ["--min-sdk-version", str(min_sdk)]
    cmd.append(str(apk))
    run_command(cmd, what="apksigner sign")


def verify_apk(tools: dict[str, Path], apk: Path, min_sdk: Optional[str] = None) -> bool:
    """
    Best-effort signature verification.

    Signing (``sign_apk``) is authoritative and fatal; verification is only a
    sanity check. ``apksigner verify`` legitimately fails on config splits that
    carry a minimal manifest (no ``<uses-sdk>``), so a verify failure here is
    downgraded to a warning instead of discarding a correctly-signed APK.
    Returns ``True`` if verification passed.
    """
    log.info("Verifying signature of %s ...", apk.name)
    cmd = [tools["apksigner"], "verify", "--verbose"]
    if min_sdk:
        cmd += ["--min-sdk-version", str(min_sdk)]
    cmd.append(str(apk))
    try:
        result = run_command(cmd, what="apksigner verify")
    except ToolError as exc:
        log.warning("Could not verify %s (it was still SIGNED successfully). "
                    "This is normal for config splits with a minimal manifest.",
                    apk.name)
        log.debug("verify detail: %s", exc)
        return False
    if result.stdout:
        log.debug(result.stdout.strip())
    log.info("  %s: signature OK", apk.name)
    return True


def align_and_sign(tools: dict[str, Path], apk: Path, keystore: Path,
                   alias: str, store_pass: str, min_sdk: Optional[str] = None) -> None:
    zipalign_apk(tools, apk)
    sign_apk(tools, apk, keystore, alias, store_pass, min_sdk)
    verify_apk(tools, apk, min_sdk)


# ---------------------------------------------------------------------------
# Core: injection planning
# ---------------------------------------------------------------------------
@dataclass
class PatchOptions:
    inject: bool = True
    frida_version: Optional[str] = None
    local_gadget: Optional[Path] = None
    gadget_checksum: Optional[str] = None
    script: Optional[Path] = None
    forced_target_lib: Optional[str] = None


def _filter_candidates(cands: list[LibCandidate], forced: Optional[str]) -> list[LibCandidate]:
    if forced is None:
        return cands
    exact = [c for c in cands if c.name == forced]
    if not exact:
        log.warning("Forced target lib '%s' not found; falling back to auto-select", forced)
        return cands
    return exact


def plan_injection(apk: Path, abis: list[str], scratch: Path,
                   opts: PatchOptions) -> tuple[dict[str, bytes], dict[str, bytes], list[str]]:
    """
    Work out the zip entries needed to inject the gadget into ``apk``.

    Returns ``(modified, added, patched_abis)`` without touching ``apk``. The
    caller feeds these dicts to :func:`rebuild_apk`.
    """
    modified: dict[str, bytes] = {}
    added: dict[str, bytes] = {}
    patched_abis: list[str] = []

    # Optional interaction script (shared across ABIs).
    script_name: Optional[str] = None
    script_bytes: Optional[bytes] = None
    if opts.script is not None:
        if not opts.script.is_file():
            raise PatchError(f"--script file not found: {opts.script}")
        script_name = script_lib_name(opts.script)
        script_bytes = opts.script.read_bytes()

    gadget_config = build_gadget_config(script_name, scratch)

    for abi in abis:
        log.info("  ABI %s: selecting host library", abi)
        candidates = _filter_candidates(candidate_libs_for_abi(apk, abi),
                                        opts.forced_target_lib)
        if not candidates:
            log.warning("  no usable ELF libraries for %s; skipping", abi)
            continue

        patched = patch_host_library(apk, candidates, scratch)
        if patched is None:
            log.warning("  could not patch any library for %s; skipping", abi)
            continue

        modified[patched.arcname] = (scratch / patched.arcname).read_bytes()

        gadget_so = resolve_gadget_for_abi(
            abi, opts.frida_version, scratch, opts.local_gadget, opts.gadget_checksum
        )
        added[f"lib/{abi}/{config.GADGET_LIB_NAME}"] = gadget_so.read_bytes()
        if gadget_config is not None:
            added[f"lib/{abi}/{config.GADGET_CONFIG_NAME}"] = gadget_config.read_bytes()
        if script_name is not None and script_bytes is not None:
            added[f"lib/{abi}/{script_name}"] = script_bytes

        patched_abis.append(abi)

    return modified, added, patched_abis


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def process(args: argparse.Namespace) -> Path:
    input_path = Path(args.input).expanduser().resolve()
    info = detect_input(input_path)

    fmt = args.format
    if fmt == "xapk" and not info.is_bundle:
        log.warning("--format xapk ignored for a single-APK input")
        fmt = "auto"

    patch_nsc_mode = args.patch_nsc
    if patch_nsc_mode and info.is_bundle and fmt != "apk":
        log.info("--patch-nsc on a bundle: merging to a single APK first")
        fmt = "apk"

    merge_mode = info.is_bundle and fmt == "apk"    # bundle -> single APK
    xapk_mode = info.is_bundle and fmt == "xapk"    # bundle -> XAPK

    out_ext = ".apk" if merge_mode else (".xapk" if xapk_mode else info.suffix)
    output_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else input_path.with_name(input_path.stem + config.DEFAULT_OUTPUT_SUFFIX + out_ext)
    )

    opts = PatchOptions(
        inject=not args.no_gadget,
        frida_version=args.frida_version,
        local_gadget=Path(args.gadget).expanduser().resolve() if args.gadget else None,
        gadget_checksum=args.gadget_sha256,
        script=Path(args.script).expanduser().resolve() if args.script else None,
        forced_target_lib=args.target_lib,
    )

    total = (9 if merge_mode else 8) + (1 if patch_nsc_mode else 0)
    steps = StepLogger(total=total)
    steps.step("Detect input format")
    log.info("Input: %s (%s%s) -> output '%s'", input_path.name, info.suffix,
             ", bundle" if info.is_bundle else "", out_ext)

    need_signing = not args.no_sign
    tools = resolve_tools(need_signing)

    java: Optional[Path] = None
    if merge_mode or patch_nsc_mode:
        java = find_tool("java")
        if java is None:
            _report_missing_tools(["java"])
            raise PatchError("Missing required tool: java (needed for --format apk / --patch-nsc)")

    keystore = _resolve_existing_keystore(args)
    workspace = make_workspace(Path(args.work_dir).resolve() if args.work_dir else None)
    log.debug("Workspace: %s", workspace)

    tmp_output = workspace / ("out" + out_ext)
    try:
        ctx = _Ctx(info=info, workspace=workspace, tmp_output=tmp_output, opts=opts,
                   steps=steps, tools=tools, keystore=keystore,
                   alias=args.keyalias, store_pass=args.storepass,
                   need_signing=need_signing, min_sdk=args.min_sdk_version,
                   java=java, xapk_mode=xapk_mode, patch_nsc=patch_nsc_mode,
                   apkeditor_local=(Path(args.apkeditor).expanduser().resolve()
                                    if args.apkeditor else None))
        if merge_mode:
            _process_merge(ctx)
        elif info.is_bundle:
            _process_bundle(ctx)
        else:
            _process_single(ctx)

        # Only now, after full success, publish the final artifact. This keeps a
        # failed run from leaving a bogus output file behind.
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists():
            output_path.unlink()
        shutil.move(str(tmp_output), str(output_path))
        steps.step("Finalize output")
        return output_path
    finally:
        safe_rmtree(workspace)


@dataclass
class _Ctx:
    info: InputInfo
    workspace: Path
    tmp_output: Path
    opts: PatchOptions
    steps: StepLogger
    tools: dict[str, Path]
    keystore: Optional[Path]
    alias: str
    store_pass: str
    need_signing: bool
    min_sdk: Optional[str] = None
    java: Optional[Path] = None
    apkeditor_local: Optional[Path] = None
    xapk_mode: bool = False
    patch_nsc: bool = False
    source_apk: Optional[Path] = None   # overrides info.path for the single pipeline


def _resolve_existing_keystore(args) -> Optional[Path]:
    if args.no_sign or not args.keystore:
        return None
    ks = Path(args.keystore).expanduser().resolve()
    if not ks.is_file():
        raise PatchError(f"Keystore not found: {ks}")
    return ks


def _ensure_keystore(ctx: _Ctx) -> Path:
    if ctx.keystore is not None:
        return ctx.keystore
    generated = ctx.workspace / config.KEYSTORE_FILENAME
    create_keystore(ctx.tools, generated, ctx.alias, ctx.store_pass)
    ctx.keystore = generated  # reuse the same key across bundle splits
    return generated


def _log_tools(tools: dict[str, Path]) -> None:
    for name, path in tools.items():
        log.info("  %-9s : %s", name, path)


def _inject_apk_inplace(apk: Path, ctx: _Ctx) -> list[str]:
    """Plan + rebuild one APK in place; returns the ABIs actually patched."""
    abis = list_abis(apk)
    if not abis:
        log.warning("  %s has no native libraries; left unchanged", apk.name)
        return []
    log.info("  %s ABIs: %s", apk.name, ", ".join(abis))
    modified, added, patched = plan_injection(apk, abis, ctx.workspace, ctx.opts)
    if patched:
        rebuild_apk(apk, apk, modified, added)
    return patched


def _process_merge(ctx: _Ctx) -> None:
    """Bundle -> single universal APK (APKEditor), then run the single pipeline."""
    ctx.steps.step("Merge splits into single APK (APKEditor)")
    jar = ensure_apkeditor(ctx.apkeditor_local)
    merged = ctx.workspace / "merged.apk"
    merge_bundle_to_apk(ctx.java, jar, ctx.info.path, merged)
    log.info("Merged APK: %.1f MB", merged.stat().st_size / 1048576)
    ctx.source_apk = merged
    _process_single(ctx)


def _process_single(ctx: _Ctx) -> None:
    steps = ctx.steps
    steps.step("Copy package into workspace")
    work_apk = ctx.workspace / "app.apk"
    shutil.copy(ctx.source_apk or ctx.info.path, work_apk)

    steps.step("Discover / verify build tools")
    _log_tools(ctx.tools)

    if ctx.patch_nsc:
        steps.step("Patch network-security-config (trust user CAs)")
        jar = ensure_apkeditor(ctx.apkeditor_local)
        patched = patch_nsc(ctx.java, jar, work_apk, ctx.workspace)
        shutil.move(str(patched), str(work_apk))

    if ctx.opts.inject:
        steps.step("Locate native libraries and ABIs")
        warn_if_soloader(work_apk)
        abis = list_abis(work_apk)
        if not abis:
            raise PatchError("APK contains no native libraries (lib/<abi>/*.so) to patch")
        log.info("ABIs present: %s", ", ".join(abis))

        steps.step("Process libraries (download gadget + inject)")
        modified, added, patched = plan_injection(work_apk, abis, ctx.workspace, ctx.opts)
        if not patched:
            raise PatchError("Injection failed for every ABI; nothing was patched")
        log.info("Injected into ABIs: %s", ", ".join(patched))

        steps.step("Rebuild APK")
        rebuild_apk(work_apk, work_apk, modified, added)
    else:
        steps.step("Locate native libraries (skipped: --no-gadget)")
        steps.step("Repackage only (drop old signatures)")
        steps.step("Rebuild APK")
        rebuild_apk(work_apk, work_apk, modified={}, added={})

    _finish_single(ctx, work_apk)


def _finish_single(ctx: _Ctx, work_apk: Path) -> None:
    if ctx.need_signing:
        ks = _ensure_keystore(ctx)
        ctx.steps.step("Zipalign + sign + verify")
        align_and_sign(ctx.tools, work_apk, ks, ctx.alias, ctx.store_pass, ctx.min_sdk)
    else:
        ctx.steps.step("Zipalign / sign (skipped: --no-sign)")
    shutil.move(str(work_apk), str(ctx.tmp_output))


def _process_bundle(ctx: _Ctx) -> None:
    steps = ctx.steps
    steps.step("Extract package")
    extract_dir = ctx.workspace / "bundle"
    extract_zip(ctx.info.path, extract_dir)

    apks = find_apks(extract_dir)
    log.info("Bundle contains %d APK(s)", len(apks))

    steps.step("Discover / verify build tools")
    _log_tools(ctx.tools)

    if ctx.opts.inject:
        _inject_bundle(ctx, extract_dir, apks)
    else:
        steps.step("Locate native libraries (skipped: --no-gadget)")
        steps.step("Repackage only (drop old signatures)")
        steps.step("Rebuild APK(s)")
        for apk in apks:
            rebuild_apk(apk, apk, modified={}, added={})

    if ctx.need_signing:
        ks = _ensure_keystore(ctx)
        steps.step("Zipalign + sign + verify all splits")
        for apk in apks:
            align_and_sign(ctx.tools, apk, ks, ctx.alias, ctx.store_pass, ctx.min_sdk)
    else:
        steps.step("Zipalign / sign (skipped: --no-sign)")

    if ctx.xapk_mode:
        write_xapk_manifest(extract_dir, apks)

    log.info("Repackaging bundle -> %s", ctx.tmp_output.name)
    repackage_bundle(extract_dir, ctx.tmp_output)


def _inject_bundle(ctx: _Ctx, extract_dir: Path, apks: list[Path]) -> None:
    """Inject into every split that carries native libraries."""
    steps = ctx.steps
    targets = [a for a in apks if apk_has_native_libs(a)]
    if not targets:
        raise PatchError("No native libraries found in any APK inside the bundle")

    steps.step("Locate native libraries and ABIs")
    for apk in targets:
        log.info("  target split: %s", apk.relative_to(extract_dir).as_posix())
        warn_if_soloader(apk)

    steps.step("Process libraries (download gadget + inject)")
    all_patched: list[str] = []
    for apk in targets:
        patched = _inject_apk_inplace(apk, ctx)
        all_patched += patched
    if not all_patched:
        raise PatchError("Injection failed for every split; nothing was patched")

    steps.step("Rebuild APK(s)")
    log.info("Patched ABIs across splits: %s", ", ".join(sorted(set(all_patched))))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="patch.py",
        description="General-purpose APK/XAPK/APKS/APKM patch & repackaging tool "
                    "(authorized security testing only).",
    )
    p.add_argument("-i", "--input", required=True,
                   help="Input .apk/.xapk/.apks/.apkm file")
    p.add_argument("-o", "--output",
                   help="Output path (default: <name>_patched<ext>)")

    grp = p.add_argument_group("injection")
    grp.add_argument("--no-gadget", action="store_true",
                     help="Do not inject anything; just repackage + sign")
    grp.add_argument("--gadget",
                     help="Local Frida gadget .so (or .so.xz) instead of downloading")
    grp.add_argument("--gadget-sha256",
                     help="Expected SHA-256 of the downloaded gadget (optional)")
    grp.add_argument("--frida-version", dest="frida_version",
                     help="Pin a specific Frida release tag (default: latest)")
    grp.add_argument("--script",
                     help="JS script for the gadget to run on load (optional)")
    grp.add_argument("--target-lib",
                     help="Force a specific host library name (e.g. libfoo.so)")
    grp.add_argument("--patch-nsc", action="store_true",
                     help="Patch network-security-config to trust user CAs (MITM via "
                          "proxy + user cert). Best for SoLoader/hardened apps; "
                          "combine with --no-gadget. Needs java + APKEditor.")

    grp2 = p.add_argument_group("signing")
    grp2.add_argument("--no-sign", action="store_true",
                      help="Skip zipalign/sign/verify (needs no external tools)")
    grp2.add_argument("--keystore", help="Use an existing keystore instead of generating one")
    grp2.add_argument("--keyalias", default=config.DEFAULT_KEY_ALIAS, help="Key alias")
    grp2.add_argument("--storepass", default=config.DEFAULT_STORE_PASS,
                      help="Keystore/key password")
    grp2.add_argument("--min-sdk-version", dest="min_sdk_version",
                      help="Pass an explicit minSdkVersion to apksigner "
                           "(use if it cannot read AndroidManifest.xml)")

    grp3 = p.add_argument_group("output format")
    grp3.add_argument("--format", choices=["auto", "apk", "xapk"], default="auto",
                      help="auto: keep input format; apk: merge a bundle into ONE "
                           "universal APK (via APKEditor); xapk: repackage a bundle "
                           "as .xapk")
    grp3.add_argument("--apkeditor",
                      help="Path to APKEditor.jar (otherwise auto-downloaded & cached)")

    p.add_argument("--work-dir", help="Explicit workspace dir (default: system temp)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)
    try:
        output = process(args)
    except PatchError as exc:
        log.error("ERROR: %s", exc)
        return 1
    except KeyboardInterrupt:
        log.error("Interrupted")
        return 130
    log.info("Done. Output: %s", output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
