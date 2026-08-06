"""
Central configuration for the APK patch/packaging tool.

All values that a user might reasonably want to tune live here so the main
logic in ``patch.py`` stays readable. Nothing in this file is specific to any
single application or service.
"""
from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

#: Extensions we accept as input.
APK_EXT = ".apk"
BUNDLE_EXTS = {".xapk", ".apks", ".apkm"}
SUPPORTED_INPUT_EXTS = {APK_EXT} | BUNDLE_EXTS

#: Default suffix appended to the input stem when the user gives no output path.
DEFAULT_OUTPUT_SUFFIX = "_patched"

# ---------------------------------------------------------------------------
# ABI / architecture handling
# ---------------------------------------------------------------------------

#: ABIs we know how to patch, in *preference* order (best first). When an APK
#: ships several ABIs we still patch all of them, but this order decides which
#: one is reported/selected first.
SUPPORTED_ABIS = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]

#: Maps an Android ABI to the architecture token used in Frida gadget asset
#: names (e.g. ``frida-gadget-<ver>-android-arm64.so.xz``).
ABI_TO_FRIDA_ARCH = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}

# ---------------------------------------------------------------------------
# Native library selection
# ---------------------------------------------------------------------------

#: Library file names that must never be chosen as an injection host.
EXCLUDED_LIB_NAMES = {"libgadget.so", "libgadget.config.so"}

#: Name of the injected gadget library (added as a NEEDED dependency).
GADGET_LIB_NAME = "libgadget.so"
GADGET_CONFIG_NAME = "libgadget.config.so"

#: ELF magic used for a cheap "is this a shared object" pre-check.
ELF_MAGIC = b"\x7fELF"

# ---------------------------------------------------------------------------
# Frida gadget download
# ---------------------------------------------------------------------------

FRIDA_RELEASES_API = "https://api.github.com/repos/frida/frida/releases"
FRIDA_GADGET_ASSET_TEMPLATE = "frida-gadget-{version}-android-{arch}.so.xz"

# ---------------------------------------------------------------------------
# APKEditor (merge split APKs / bundles into a single universal APK)
# ---------------------------------------------------------------------------

APKEDITOR_LATEST_API = "https://api.github.com/repos/REAndroid/APKEditor/releases/latest"
#: Cached jar file name (stored under <script dir>/.tools/).
APKEDITOR_JAR_NAME = "APKEditor.jar"
TOOLS_CACHE_DIRNAME = ".tools"

# ---------------------------------------------------------------------------
# Network security config (SSL-pinning bypass via user-CA trust)
# ---------------------------------------------------------------------------

#: A permissive network-security-config: trust system + user CAs and permit
#: cleartext, so traffic can be intercepted with a proxy + user-installed CA.
#: Overriding the app's config also drops any pin-sets it declared.
PERMISSIVE_NSC_XML = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
"""

#: Resource name used when the app declares no networkSecurityConfig of its own.
NSC_RESOURCE_NAME = "nsc_bypass"

# ---------------------------------------------------------------------------
# Networking (download) behaviour
# ---------------------------------------------------------------------------

DOWNLOAD_TIMEOUT = 30          # seconds, per request
DOWNLOAD_RETRIES = 3           # total attempts before giving up
DOWNLOAD_BACKOFF = 2.0         # base seconds for exponential backoff
DOWNLOAD_CHUNK = 64 * 1024     # streaming chunk size

# ---------------------------------------------------------------------------
# Signing / keystore defaults
# ---------------------------------------------------------------------------

KEYSTORE_FILENAME = "release.keystore"
DEFAULT_KEY_ALIAS = "patchkey"
DEFAULT_STORE_PASS = "password"
KEYSTORE_KEYALG = "RSA"
KEYSTORE_KEYSIZE = "2048"
KEYSTORE_VALIDITY = "10000"
KEYSTORE_DNAME = "CN=APK Patcher, OU=Dev, O=APK, L=Unknown, S=Unknown, C=US"

# ---------------------------------------------------------------------------
# External tool discovery
# ---------------------------------------------------------------------------

#: Logical tool name -> candidate executable file names (platform variants).
#: ``shutil.which`` is tried for each name first; SDK search comes after.
TOOL_EXECUTABLES = {
    "apksigner": ["apksigner.bat", "apksigner"],
    "zipalign": ["zipalign.exe", "zipalign"],
    "keytool": ["keytool.exe", "keytool"],
    "java": ["java.exe", "java"],
}

#: Tools that live in a JDK's ``bin`` directory (searched via jdk_bin_roots).
JDK_TOOLS = {"keytool", "java"}


def _expand(*parts: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(os.path.join(*parts))))


def android_sdk_roots() -> list[Path]:
    """Return likely Android SDK root directories for the current machine."""
    roots: list[Path] = []
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        val = os.environ.get(env)
        if val:
            roots.append(Path(val))

    if os.name == "nt":
        roots += [
            _expand("%LOCALAPPDATA%", "Android", "Sdk"),
            _expand("%USERPROFILE%", "AppData", "Local", "Android", "Sdk"),
            _expand("%ProgramFiles%", "Android", "android-sdk"),
            _expand("%ProgramFiles(x86)%", "Android", "android-sdk"),
        ]
    else:
        roots += [
            _expand("~", "Android", "Sdk"),
            _expand("~", "Library", "Android", "sdk"),   # macOS
            Path("/usr/lib/android-sdk"),
            Path("/opt/android-sdk"),
        ]
    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique: list[Path] = []
    for r in roots:
        key = str(r).lower()
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def jdk_bin_roots() -> list[Path]:
    """Return likely directories that contain ``keytool``."""
    roots: list[Path] = []
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        roots.append(Path(java_home) / "bin")

    if os.name == "nt":
        for base in (
            _expand("%ProgramFiles%", "Java"),
            _expand("%ProgramFiles%", "Eclipse Adoptium"),
            _expand("%ProgramFiles%", "Android", "Android Studio", "jbr", "bin"),
            _expand("%ProgramFiles%", "Android", "Android Studio", "jre", "bin"),
            _expand("%LOCALAPPDATA%", "Programs", "Android Studio", "jbr", "bin"),
        ):
            if base.name == "bin":
                roots.append(base)
            elif base.exists():
                # e.g. C:\Program Files\Java\jdk-17\bin
                roots += [p / "bin" for p in base.iterdir() if p.is_dir()]
    else:
        roots += [
            Path("/usr/lib/jvm"),
            Path("/usr/local/opt/openjdk/bin"),
        ]
    return roots
