#!/usr/bin/env python3
"""
NetWitness PoC Analysis — Interactive Launcher
Guides the user through all options and runs nw_poc_v2_7.py. (PoC Analysis Tool v0.9)

Usage:
    python3 nw_poc_launcher.py
"""

import os
import subprocess
import sys
from getpass import getpass

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def _c(code, text):
    """ANSI colour wrapper."""
    return f"\033[{code}m{text}\033[0m"

def header(text):
    print()
    print(_c("1;36", "─" * 60))
    print(_c("1;36", f"  {text}"))
    print(_c("1;36", "─" * 60))

def ask(prompt, default=None, secret=False):
    hint = f" [{default}]" if default else ""
    full_prompt = _c("1;33", f"  {prompt}{hint}: ")
    if secret:
        val = getpass(full_prompt)
    else:
        val = input(full_prompt).strip()
    return val if val else (default or "")

def choose(prompt, options, default=None):
    """Present a numbered menu, return chosen value."""
    print(_c("1;33", f"\n  {prompt}"))
    for i, (label, val) in enumerate(options, 1):
        marker = " ◀  (default)" if val == default else ""
        print(f"    {_c('33', str(i))}) {label}{_c('90', marker)}")
    while True:
        raw = input(_c("1;33", "  Enter number: ")).strip()
        if not raw and default:
            return default
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return options[idx][1]
        except ValueError:
            pass
        print(_c("31", "  Invalid — enter a number from the list."))

def confirm(prompt, default=True):
    hint = "[Y/n]" if default else "[y/N]"
    raw = input(_c("1;33", f"  {prompt} {hint}: ")).strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")

# ─────────────────────────────────────────────────────────────
# LAUNCHER
# ─────────────────────────────────────────────────────────────

def main():
    os.system("clear" if os.name == "posix" else "cls")

    print()
    print(_c("1;37", "  ╔══════════════════════════════════════════════════╗"))
    print(_c("1;37", "  ║   NetWitness PoC Analysis — Interactive Launcher  ║"))
    print(_c("1;37", "  ║   v0.9                                            ║"))
    print(_c("1;37", "  ╚══════════════════════════════════════════════════╝"))
    print()
    print(_c("90", "  This wizard builds and runs nw_poc_v2_7.py  [v0.9]"))
    print(_c("90", "  Press Enter to accept defaults shown in [brackets]."))

    # ── 1. Connection ─────────────────────────────────────────
    header("1 / 6  Connection")
    concentrator = ask("Concentrator IP or hostname", default="192.168.1.112")
    conc_port    = ask("Concentrator port", default="50105")
    user         = ask("Username", default="admin")
    password     = ask("Password", secret=True) or "netwitness"

    session_size = ask(
        "Max sessions to fetch (current limit)",
        default="50000"
    )
    try:
        session_size = int(session_size)
        if session_size < 1000:
            session_size = 1000
        if session_size > 500000:
            session_size = 500000
    except ValueError:
        session_size = 50000
    print(_c("90", f"  → Will fetch up to {session_size:,} sessions. "
             f"Estimated time: ~{max(1, session_size // 35000 * 2)}-{max(2, session_size // 20000 * 2)}s"))

    # ── 2. Client ─────────────────────────────────────────────
    header("2 / 6  Client")
    client = ask("Client / customer name (shown in report header)", default="Client")

    # ── 3. Time range ─────────────────────────────────────────
    header("3 / 6  Analysis time range")
    time_mode = choose(
        "How much data to analyse?",
        [
            ("Last 24 hours  — minimal, quick test",              "24h"),
            ("Last 72 hours  — 3 days, basic patterns",           "72h"),
            ("Last 7 days    — recommended minimum",              "7d"),
            ("Last 14 days   — recommended for PoC",              "14d"),
            ("Last 30 days   — full baseline (max)",              "30d"),
            ("All available data (use with caution on large envs)", "all"),
        ],
        default="14d",
    )

    hours_arg = None
    all_time  = False

    if time_mode == "24h":
        hours_arg = 24
    elif time_mode == "72h":
        hours_arg = 72
    elif time_mode == "7d":
        hours_arg = 168
    elif time_mode == "14d":
        hours_arg = 336
    elif time_mode == "30d":
        hours_arg = 720
    elif time_mode == "all":
        all_time = True

    # ── 4. Report type ────────────────────────────────────────
    header("4 / 6  Report type")
    report = choose(
        "Which report do you want to generate?",
        [
            ("Threat Hunting  — tactical finding cards for SOC (recommended for POC)", "threathunting"),
            ("Engineer        — traffic breakdown, parser health, SE notes",           "engineer"),
            ("NIS2            — Art.21 compliance capability mapping",                 "nis2"),
            ("All three       — generate all reports in one run (data fetched once)",  "all"),
        ],
        default="threathunting",
    )

    # ── 5. Output & cache ─────────────────────────────────────
    header("5 / 6  Theme")
    theme = choose(
        "Report colour theme?",
        [
            ("Light  — white background, Slate + Teal (default)", "light"),
            ("Dark   — dark background, optimised for screen sharing / demos", "dark"),
        ],
        default="light",
    )

    header("6 / 6  Output")
    safe_client = client.replace(" ", "_").replace("/", "-")
    if report == "all":
        default_out = f"{safe_client}.html"
        print(_c("90", f"  All three reports: {safe_client}_threathunting.html, {safe_client}_engineer.html, {safe_client}_nis2.html"))
    else:
        default_out = f"{safe_client}_{report}.html"
    output = ask("Output HTML base filename", default=default_out)

    use_cache = confirm("Save/load session cache (for offline re-render)?", default=False)
    cache_arg = None
    if use_cache:
        default_cache = f"{safe_client}_cache.json"
        cache_arg = ask("Cache file path", default=default_cache)

    # ── Build command ─────────────────────────────────────────
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nw_poc_v2_7.py")

    cmd = [
        sys.executable, script,
        "--concentrator", concentrator,
        "--concentrator-port", str(conc_port),
        "--user", user,
        "--password", password,
        "--client", client,
        "--report", report,
        "--theme", theme,
        "--output", output,
    ]

    if all_time:
        cmd.append("--all-time")
    elif hours_arg:
        cmd += ["--hours", str(hours_arg)]

    if cache_arg:
        cmd += ["--cache", cache_arg]

    cmd += ["--session-size", str(session_size)]

    # ── Preview & confirm ─────────────────────────────────────
    print()
    print(_c("1;36", "  ─" * 30))
    print(_c("1;37", "  Command to run:"))
    safe_cmd = [c if c != password else "***" for c in cmd]
    print(_c("90", "  " + " \\\n    ".join(safe_cmd)))
    print(_c("1;36", "  ─" * 30))
    print()

    if not confirm("Run now?", default=True):
        print(_c("90", "\n  Aborted. You can copy the command above and run it manually."))
        sys.exit(0)

    print()
    print(_c("1;32", "  Starting analysis…"))
    print()

    result = subprocess.run(cmd)

    if result.returncode == 0:
        print()
        print(_c("1;32", f"  ✓ Done. Report saved → {output}"))
        if cache_arg and os.path.exists(cache_arg):
            print(_c("90", f"    Cache saved → {cache_arg}"))
        print()
        print(_c("90", "  Tip: open the report directly in a browser — it's self-contained, no login required."))
    else:
        print()
        print(_c("1;31", f"  ✗ Script exited with code {result.returncode}. Check the output above."))

    print()


if __name__ == "__main__":
    main()
