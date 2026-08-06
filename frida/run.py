#!/usr/bin/env python3
"""
Spawn an app and inject one or more Frida scripts AT STARTUP, then keep the
session alive.

Use this when `frida -U -f <pkg> -l script.js` fails with
    "Failed to spawn: unexpectedly timed out while waiting for app to launch"
on some apps/emulators (Instagram is a common one). The frida CLI's spawn flow
hangs, but the low-level spawn+attach+resume used here does not — and it gives the
same startup timing needed for the Tigon hook.

Usage (from the repo root):
    py -3.13 frida\\run.py                                   # IG + tigon_bypass.js
    py -3.13 frida\\run.py <package>                         # <package> + tigon_bypass.js
    py -3.13 frida\\run.py <package> a.js b.js c.js          # multiple scripts (like -l -l -l)

Example (bypass + auth probe):
    py -3.13 frida\\run.py com.instagram.android frida\\tigon_bypass.js ig-auth-probe.js

Requires: Python 3.11+, `pip install frida frida-tools` (version matching your
frida-server), a rooted device with frida-server running.
"""
import os
import sys
import time

import frida
import frida_tools

HERE = os.path.dirname(os.path.abspath(__file__))
pkg = sys.argv[1] if len(sys.argv) > 1 else "com.instagram.android"
script_paths = sys.argv[2:] or [os.path.join(HERE, "tigon_bypass.js")]
# frida 17 doesn't expose the Java bridge to raw scripts — bundle the one shipped
# with frida-tools so `Java.*` works in every script.
bridge_path = os.path.join(os.path.dirname(frida_tools.__file__), "bridges", "java.js")
BRIDGE = open(bridge_path, encoding="utf-8").read() + "\n;globalThis.Java = bridge;\n"


def make_handler(tag):
    def on_message(message, data):
        if message.get("type") == "error":
            print(f"[{tag}][error]", message.get("description"))
        else:
            payload = message.get("payload")
            if payload is not None:
                print(f"[{tag}]", payload)
    return on_message


def main():
    dev = frida.get_usb_device(timeout=10)
    print(f"[*] spawning {pkg} ...")
    pid = dev.spawn([pkg])                        # low-level spawn (avoids the CLI hang)
    session = dev.attach(pid)

    scripts = []                                  # keep references alive
    for path in script_paths:
        tag = os.path.basename(path)
        script = session.create_script(BRIDGE + open(path, encoding="utf-8").read())
        script.on("message", make_handler(tag))
        script.load()                             # each script loaded BEFORE resume
        scripts.append(script)
        print(f"[*] loaded {tag}")

    dev.resume(pid)
    print(f"[*] resumed pid {pid}. Use the app now; Ctrl-C to detach.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] detaching")
        try:
            session.detach()
        except Exception:
            pass


if __name__ == "__main__":
    main()
