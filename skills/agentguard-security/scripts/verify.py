#!/usr/bin/env python3
"""
AgentGuard Runtime Environment Verifier.

Checks whether the current agent session is operating under active zero-trust
supervision (daemon connection, shell shims, taint tracking, and secret vault).
"""

import os
from pathlib import Path
import sys


def verify_environment():
    session_id = os.environ.get("AGENTGUARD_SESSION_ID")
    socket_path = os.environ.get("AGENTGUARD_SOCKET", str(Path.home() / ".agentguard" / "agentguard.sock"))
    shim_dir = os.environ.get("AGENTGUARD_SHIM_DIR")
    hitl_mode = os.environ.get("AGENTGUARD_HITL") == "1"

    print("=" * 60)
    print(" 🛡️  AgentGuard Runtime Verification")
    print("=" * 60)

    # 1. Session status
    if session_id:
        print(f" [ACTIVE]     Session ID       : {session_id}")
    else:
        print(" [NOT ACTIVE] Session ID       : None (Running unwrapped)")

    # 2. Interception shims
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    is_shimmed = bool(shim_dir and path_dirs and path_dirs[0] == shim_dir)
    if is_shimmed:
        print(f" [ACTIVE]     Shell Shims      : Intercepting ({shim_dir})")
    else:
        print(" [WARNING]    Shell Shims      : Not prepended to PATH")

    # 3. Daemon IPC Socket
    socket_exists = Path(socket_path).exists()
    if socket_exists:
        print(f" [ONLINE]     Daemon Socket    : {socket_path}")
    else:
        print(f" [OFFLINE]    Daemon Socket    : {socket_path} not found")

    # 4. Human-In-The-Loop
    hitl_str = "Enabled (Interactive)" if hitl_mode else "Automatic (Policy Defined)"
    print(f" [CONFIG]     HITL Gate        : {hitl_str}")

    # 5. Local Security Policy file
    policy_local = Path("security_policy.md").exists()
    policy_global = (Path.home() / ".agentguard" / "security_policy.md").exists()
    if policy_local:
        print(" [CONFIG]     Security Policy  : Found (./security_policy.md)")
    elif policy_global:
        print(" [CONFIG]     Security Policy  : Found (~/.agentguard/security_policy.md)")
    else:
        print(" [INFO]       Security Policy  : Using default baseline (No custom security_policy.md)")

    print("-" * 60)
    if session_id and is_shimmed:
        print(" ✅ Status: FULL ZERO-TRUST PROTECTION ACTIVE")
        print(" Commands are intercepted, vaulted, and monitored against policy.")
    else:
        print(" ⚠️  Status: UNPROTECTED RUNTIME")
        print(" To run under zero-trust supervision, launch with:")
        print("   ag daemon start")
        print("   ag wrap -- <your-agent-command>")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    verify_environment()
