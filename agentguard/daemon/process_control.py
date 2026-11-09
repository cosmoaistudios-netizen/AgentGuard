"""
AgentGuard Process Tree Control & Signal Management.
Re-exports process control functions from agentguard.kernel.process.
"""

from agentguard.kernel.process import (
    ProcessTreeController,
    get_process_tree_info,
    get_tree_info,
    handle_shim_hitl_cycle,
    inspect_tree,
    kill_tree,
    notify_daemon_hitl_decision,
    pause_process_tree,
    pause_tree,
    prompt_interactive_terminal_fallback,
    resume_process_tree,
    resume_tree,
    terminate_process_tree,
)

__all__ = [
    "pause_process_tree",
    "resume_process_tree",
    "terminate_process_tree",
    "get_process_tree_info",
    "pause_tree",
    "resume_tree",
    "kill_tree",
    "inspect_tree",
    "get_tree_info",
    "ProcessTreeController",
    "prompt_interactive_terminal_fallback",
    "notify_daemon_hitl_decision",
    "handle_shim_hitl_cycle",
]
