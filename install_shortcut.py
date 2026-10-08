#!/usr/bin/env python3
"""Create a desktop launcher for Security Studio on any OS.

    python install_shortcut.py            # create it
    python install_shortcut.py --remove   # take it away again

Windows gets a .lnk, Linux a .desktop entry (registered in the applications
menu as well as on the desktop), and macOS a double-clickable .command file.
Nothing is installed system-wide and nothing needs elevation.
"""
from __future__ import annotations

import argparse
import os
# Used only for the fixed Windows PowerShell path in install_windows().
import subprocess  # nosec B404
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NAME = "Security Studio"
ICON_ICO = ROOT / "assets" / "security-studio.ico"
ICON_PNG = ROOT / "assets" / "security-studio-icon.png"
ICON_SVG = ROOT / "assets" / "securitysuite.svg"


def desktop_dir() -> Path:
    """Best effort at the user's desktop, including localised Linux names."""
    if os.name == "nt":
        try:
            import winreg
            key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
                return Path(winreg.QueryValueEx(handle, "Desktop")[0])
        except Exception:
            return Path.home() / "Desktop"

    config = Path.home() / ".config" / "user-dirs.dirs"
    if config.exists():
        try:
            for line in config.read_text(encoding="utf-8").splitlines():
                if line.startswith("XDG_DESKTOP_DIR"):
                    value = line.split("=", 1)[1].strip().strip('"')
                    return Path(os.path.expandvars(value.replace("$HOME", str(Path.home()))))
        except OSError:
            pass
    return Path.home() / "Desktop"


def best_icon() -> Path | None:
    for candidate in (ICON_PNG, ICON_SVG, ICON_ICO):
        if candidate.exists():
            return candidate
    return None


# ------------------------------------------------------------------ windows
def windowless_python() -> str:
    """pythonw.exe beside the running interpreter, or python.exe if absent.

    python.exe is a console program, so a shortcut to it holds a terminal
    window open for as long as the suite runs. pythonw.exe is the same
    interpreter without a console; the suite then logs to
    data/securitysuite.log instead.
    """
    candidate = Path(sys.executable).with_name("pythonw.exe")
    return str(candidate) if candidate.exists() else sys.executable


def install_windows(remove: bool) -> Path:
    target = desktop_dir() / (NAME + ".lnk")
    if remove:
        target.unlink(missing_ok=True)
        return target
    icon = ICON_ICO if ICON_ICO.exists() else None   # .lnk needs a real .ico
    script = (
        "$ws = New-Object -ComObject WScript.Shell; "
        "$l = $ws.CreateShortcut(%s); "
        "$l.TargetPath = %s; "
        "$l.Arguments = 'run.py'; "
        "$l.WorkingDirectory = %s; "
        "$l.Description = 'Security Studio - local defensive tool arena'; "
        % (ps_quote(str(target)), ps_quote(windowless_python()), ps_quote(str(ROOT)))
    )
    if icon:
        script += "$l.IconLocation = %s; " % ps_quote(str(icon) + ",0")
    script += "$l.Save()"
    powershell = (Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" /
                  "WindowsPowerShell" / "v1.0" / "powershell.exe")
    # Every interpolated value is derived from this script's resolved path or
    # the interpreter's own path and escaped as a PowerShell single-quoted literal.
    subprocess.run([str(powershell), "-NoProfile", "-Command", script], check=True,
                   capture_output=True)  # nosec B603
    return target


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


# -------------------------------------------------------------------- linux
def install_linux(remove: bool) -> Path:
    entry = NAME.lower().replace(" ", "-") + ".desktop"
    apps_dir = Path.home() / ".local" / "share" / "applications"
    targets = [apps_dir / entry, desktop_dir() / entry]
    if remove:
        for target in targets:
            target.unlink(missing_ok=True)
        return targets[0]

    icon = best_icon()
    content = "\n".join([
        "[Desktop Entry]",
        "Type=Application",
        "Name=" + NAME,
        "Comment=Local defensive tool arena with YARA detection",
        "Exec=" + shell_quote(sys.executable) + " run.py",
        "Path=" + str(ROOT),
        "Icon=" + (str(icon) if icon else "security-high"),
        "Terminal=true",
        "Categories=Security;System;Monitor;",
        "StartupNotify=false",
        "",
    ])
    for target in targets:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            target.chmod(0o755)          # GNOME refuses to launch a non-executable entry
        except OSError as exc:
            print("  could not write " + str(target) + ": " + str(exc))
    return targets[0]


def shell_quote(value: str) -> str:
    return '"' + value.replace('"', '\\"') + '"' if " " in value else value


# -------------------------------------------------------------------- macOS
def install_macos(remove: bool) -> Path:
    target = desktop_dir() / (NAME + ".command")
    if remove:
        target.unlink(missing_ok=True)
        return target
    script = "\n".join([
        "#!/bin/bash",
        "# Double-click to start Security Studio.",
        "cd " + shell_quote(str(ROOT)),
        "exec " + shell_quote(sys.executable) + " run.py",
        "",
    ])
    target.write_text(script, encoding="utf-8")
    target.chmod(0o755)
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a desktop launcher.")
    parser.add_argument("--remove", action="store_true", help="remove the launcher")
    args = parser.parse_args()

    if os.name == "nt":
        platform, install = "Windows", install_windows
    elif sys.platform == "darwin":
        platform, install = "macOS", install_macos
    else:
        platform, install = "Linux", install_linux

    try:
        target = install(args.remove)
    except subprocess.CalledProcessError as exc:
        print("[-] Launcher creation failed: " + (exc.stderr or b"").decode("utf-8", "replace")[:200])
        return 1
    except OSError as exc:
        print("[-] Launcher creation failed: " + str(exc))
        return 1

    verb = "Removed" if args.remove else "Created"
    print("[*] " + platform + " launcher")
    print("[*] " + verb + ": " + str(target))
    if not args.remove:
        # Windows shortcuts need a genuine .ico; the others take PNG or SVG.
        if platform == "Windows":
            icon = ICON_ICO if ICON_ICO.exists() else None
        else:
            icon = best_icon()
        print("[*] Icon    : " + (str(icon) if icon else "system default"))
        runs = windowless_python() if platform == "Windows" else sys.executable
        print("[*] Runs    : " + runs + " run.py")
        if platform == "Windows" and runs != sys.executable:
            print("[*] No console window; output goes to data/securitysuite.log")
        print("[*] From    : " + str(ROOT))
        if platform == "macOS":
            print("[*] macOS may ask for confirmation the first time it is opened.")
        if platform == "Linux":
            print("[*] Some desktops require 'Allow Launching' from the file's context menu.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
