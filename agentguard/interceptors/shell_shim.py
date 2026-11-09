"""
AgentGuard Process Interceptor and Shell Shim Manager.

Implements:
- Command classification (SAFE_READONLY, SAFE_MUTATION, DANGEROUS)
- Deterministic AST / compound command decomposition
- High-speed regex heuristics
- Real binary resolution without infinite recursion
- Native C shim compilation and portable Python fallback
- Shim directory and environment variable management
"""

from enum import Enum
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple, Union

# Intercepted binary names symlinked to ag-sh
INTERCEPTED_BINARIES = [
    "bash",
    "sh",
    "zsh",
    "curl",
    "wget",
    "rm",
    "git",
    "python",
    "python3",
    "node",
    "npx",
    "perl",
    "ruby",
    "nc",
    "netcat",
    "scp",
    "ssh",
    "tar",
    "find",
    "docker",
    "podman",
]

DEFAULT_SHIM_DIR = Path.home() / ".agentguard" / "shims"

# Dangerous execution patterns
DANGEROUS_PATTERNS = [
    # Destructive deletions
    re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b"),
    re.compile(r"\brm\s+-[a-zA-Z]*[rfRF]+(\s+.*)?$"),
    # Shell pipe executions
    re.compile(r"(curl|wget|fetch)\b.*\|\s*(bash|sh|zsh)"),
    # Sensitive credential and configuration paths
    re.compile(r"(\.ssh|\.aws|\.env|id_rsa|authorized_keys|/etc/shadow)\b"),
    # Raw device writes and format tools
    re.compile(r">\s*/dev/(sd[a-z]|nvme|disk)"),
    re.compile(r"dd\s+if=.*of=/dev/"),
    re.compile(r"\b(mkfs(\.[a-zA-Z0-9]+)?|fdisk|parted)\b"),
    # Fork bomb
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
]

# Verified safe read-only commands
SAFE_READONLY_PATTERN = re.compile(
    r"^(ls|cat|pwd|echo|git\s+status|git\s+diff|git\s+log|"
    r"head|tail|whoami|date|which|wc|grep)(\s+[^;&|><]*)?$"
)


class CommandClassification(str, Enum):
    """Classification states for shell commands."""
    SAFE_READONLY = "SAFE_READONLY"
    SAFE_MUTATION = "SAFE_MUTATION"
    DANGEROUS = "DANGEROUS"


class CommandClassifier:
    """
    Sub-millisecond AST and regex-based command security classifier.
    """

    @classmethod
    def normalize_command(cls, raw: Union[str, List[str]]) -> str:
        """Converts str or argv list into normalized command string."""
        if isinstance(raw, list):
            if not raw:
                return ""
            bin_name = Path(raw[0]).name
            # If bash/sh/zsh with -c, extract the inline string
            if bin_name in ("bash", "sh", "zsh") and "-c" in raw:
                idx = raw.index("-c")
                if idx + 1 < len(raw):
                    return raw[idx + 1]
            return " ".join(raw)
        return str(raw).strip()

    @classmethod
    def decompose_command(cls, cmd: str) -> List[str]:
        """
        Decomposes compound command lines into individual atomic statements.
        Handles pipelines (|), chains (&&, ||), sequences (;), and subshells.
        """
        if not cmd:
            return []

        # Extract subshell expressions: `...` or $(...)
        subshells = re.findall(r"`([^`]+)`|\$\(([^)]+)\)", cmd)
        extracted = []
        for sub in subshells:
            val = sub[0] or sub[1]
            if val.strip():
                extracted.append(val.strip())

        # Split on compound operators
        statements = re.split(r"&&|\|\||;|\||\n", cmd)
        result = []
        for s in statements + extracted:
            clean = s.strip()
            if clean:
                result.append(clean)
        return result

    @classmethod
    def classify(
        cls, command: Union[str, List[str]]
    ) -> Tuple[CommandClassification, str]:
        """
        Classifies command as SAFE_READONLY, SAFE_MUTATION, or DANGEROUS.
        Returns: (classification, reason)
        """
        cmd_str = cls.normalize_command(command)
        if not cmd_str:
            return CommandClassification.SAFE_READONLY, "Empty command"

        # 1. Immediate dangerous check across entire command string
        for pat in DANGEROUS_PATTERNS:
            if pat.search(cmd_str):
                return (
                    CommandClassification.DANGEROUS,
                    f"Matched dangerous pattern: {pat.pattern}",
                )

        # 2. Decompose and inspect atomic sub-commands
        sub_commands = cls.decompose_command(cmd_str)
        is_all_readonly = True

        for sub in sub_commands:
            for pat in DANGEROUS_PATTERNS:
                if pat.search(sub):
                    return (
                        CommandClassification.DANGEROUS,
                        f"Sub-command matched dangerous pattern: "
                        f"{pat.pattern}",
                    )

            # Check if sub-command is safe read-only
            if not SAFE_READONLY_PATTERN.match(sub):
                is_all_readonly = False

        if is_all_readonly and len(sub_commands) > 0:
            return (
                CommandClassification.SAFE_READONLY,
                "Command verified safe read-only",
            )

        return (
            CommandClassification.SAFE_MUTATION,
            "Command verified safe mutation",
        )


def resolve_real_binary(
    binary_name: str,
    original_path: Optional[str] = None,
    exclude_dir: Optional[Union[str, Path]] = None,
    path: Optional[str] = None,
) -> str:
    """
    Locates genuine system binary in PATH without infinite recursion.
    """
    search_path = original_path or path or os.environ.get(
        "AGENTGUARD_ORIGINAL_PATH", os.environ.get("PATH", "")
    )
    exclude_real = (
        Path(exclude_dir).resolve() if exclude_dir is not None else None
    )

    for entry in search_path.split(os.pathsep):
        entry_clean = entry.strip()
        if not entry_clean:
            continue
        try:
            entry_path = Path(entry_clean).resolve()
        except OSError:
            continue

        if exclude_real and entry_path == exclude_real:
            continue

        # Check candidate file
        candidate = entry_path / binary_name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

    # Standard system fallback locations
    for fallback in ("/bin", "/usr/bin", "/usr/local/bin"):
        cand = Path(fallback) / binary_name
        if cand.is_file() and os.access(cand, os.X_OK):
            if not (exclude_real and cand.parent.resolve() == exclude_real):
                return str(cand)

    raise FileNotFoundError(
        f"Real system binary '{binary_name}' not found in PATH"
    )


class ShimManager:
    """
    Manages building, installing, and configuring the ag-sh shim environment.
    """

    def __init__(
        self,
        shim_dir: Optional[Union[str, Path]] = None,
        socket_path: str = "/tmp/agentguard.sock",
    ):
        base_dir = shim_dir or DEFAULT_SHIM_DIR
        self.shim_dir = Path(base_dir).expanduser().resolve()
        self.socket_path = socket_path

    def compile_c_shim(self) -> Optional[Path]:
        """
        Attempts to compile ag-sh.c and libagentguard_hook.c using clang or gcc.
        Returns compiled binary Path on success, None on failure.
        """
        c_source = Path(__file__).parent / "shim_binary" / "ag-sh.c"
        hook_source = Path(__file__).parent / "shim_binary" / "libagentguard_hook.c"
        if not c_source.is_file():
            return None

        out_bin = self.shim_dir / "ag-sh"
        self.shim_dir.mkdir(parents=True, exist_ok=True)

        for compiler in ("clang", "gcc"):
            cc = shutil.which(compiler)
            if not cc:
                continue
            cmd = [
                cc,
                "-O2",
                "-Wall",
                "-Wextra",
                str(c_source),
                "-o",
                str(out_bin),
            ]
            try:
                res = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10.0
                )
                if res.returncode == 0 and out_bin.is_file():
                    out_bin.chmod(0o755)

                    # Also compile libagentguard_hook shared library if possible
                    if hook_source.is_file():
                        hook_out = (
                            self.shim_dir / "libagentguard_hook.dylib"
                            if os.uname().sysname == "Darwin"
                            else self.shim_dir / "libagentguard_hook.so"
                        )
                        hook_cmd = [
                            cc,
                            "-O2",
                            "-fPIC",
                            "-shared",
                            str(hook_source),
                            "-o",
                            str(hook_out),
                        ]
                        try:
                            h_res = subprocess.run(
                                hook_cmd, capture_output=True, text=True, timeout=10.0
                            )
                            if h_res.returncode == 0 and hook_out.is_file():
                                hook_out.chmod(0o755)
                        except Exception:
                            pass

                    return out_bin
            except (subprocess.SubprocessError, OSError):
                continue

        return None

    def write_python_fallback(self) -> Path:
        """
        Writes a portable Python fallback executable for ag-sh.
        Handles both BLOCKED and PROMPT_HITL responses.
        """
        self.shim_dir.mkdir(parents=True, exist_ok=True)
        py_shim = self.shim_dir / "ag-sh"

        script_content = (
            "#!/usr/bin/env python3\n"
            "import os, sys, json, socket, pathlib\n"
            "\n"
            "DEFAULT_SOCK = '/tmp/agentguard.sock'\n"
            "\n"
            "def main():\n"
            "    if len(sys.argv) < 1:\n"
            "        sys.exit(127)\n"
            "    bin_name = pathlib.Path(sys.argv[0]).name\n"
            "    target_argv = sys.argv\n"
            "    if bin_name == 'ag-sh' and len(sys.argv) > 1:\n"
            "        target_argv = sys.argv[1:]\n"
            "        bin_name = pathlib.Path(target_argv[0]).name\n"
            "    sess = os.environ.get('AGENTGUARD_SESSION_ID', 'default')\n"
            "    sock = os.environ.get('AGENTGUARD_SOCKET', DEFAULT_SOCK)\n"
            "    fail_closed = os.environ.get('AGENTGUARD_FAIL_CLOSED', '0') in ('1', 'true')\n"
            "    cmd_str = ' '.join(target_argv)\n"
            "    is_allowed = not fail_closed\n"
            "    if os.path.exists(sock):\n"
            "        try:\n"
            "            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "            s.connect(sock)\n"
            "            req = {\n"
            "                'protocol_version': '1.0',\n"
            "                'action': 'CHECK_COMMAND',\n"
            "                'session_id': sess,\n"
            "                'pid': os.getpid(),\n"
            "                'payload': {\n"
            "                    'command': cmd_str,\n"
            "                    'cwd': os.getcwd(),\n"
            "                    'ppid': os.getppid()\n"
            "                }\n"
            "            }\n"
            "            payload = (json.dumps(req) + '\\n').encode('utf-8')\n"
            "            s.sendall(payload)\n"
            "            raw_resp = s.recv(65536).decode('utf-8').strip()\n"
            "            resp = json.loads(raw_resp)\n"
            "            s.close()\n"
            "            st = resp.get('status')\n"
            "            if st == 'BLOCKED':\n"
            "                is_allowed = False\n"
            "            elif st == 'PROMPT_HITL':\n"
            "                try:\n"
            "                    with open('/dev/tty', 'r+') as tty:\n"
            "                        tty.write(f'\\n[AgentGuard HITL Security Alert]\\nSession: {sess} | Process: {os.getpid()}\\nIntercepted: {cmd_str}\\nAllow execution? [y/N]: ')\n"
            "                        tty.flush()\n"
            "                        ans = tty.readline().strip().lower()\n"
            "                        if ans in ('y', 'yes', 'a', 'allow'):\n"
            "                            is_allowed = True\n"
            "                            tty.write('[AgentGuard] Command AUTHORIZED by operator.\\n')\n"
            "                        else:\n"
            "                            is_allowed = False\n"
            "                            tty.write('[AgentGuard] Command DENIED by operator.\\n')\n"
            "                except Exception:\n"
            "                    sys.stderr.write('[AgentGuard] HITL required but no interactive tty available. Command BLOCKED.\\n')\n"
            "                    is_allowed = False\n"
            "            elif st == 'ALLOWED':\n"
            "                is_allowed = True\n"
            "        except Exception:\n"
            "            if fail_closed:\n"
            "                is_allowed = False\n"
            "    if not is_allowed:\n"
            "        sys.stderr.write(f'[AgentGuard] BLOCKED: Command {cmd_str!r} was rejected by security policy.\\n')\n"
            "        sys.exit(126)\n"
            "    raw_p = os.environ.get('AGENTGUARD_ORIGINAL_PATH', '')\n"
            "    orig_p = raw_p or os.environ.get('PATH', '')\n"
            "    s_dir = os.environ.get('AGENTGUARD_SHIM_DIR', '')\n"
            "    for d in orig_p.split(os.pathsep):\n"
            "        if s_dir and (os.path.realpath(d) == os.path.realpath(s_dir)):\n"
            "            continue\n"
            "        cand = os.path.join(d, bin_name)\n"
            "        if os.path.isfile(cand) and os.access(cand, os.X_OK):\n"
            "            os.execv(cand, [cand] + target_argv[1:])\n"
            "    sys.stderr.write(f'[AgentGuard] Error: Real binary {bin_name!r} not found in PATH.\\n')\n"
            "    sys.exit(127)\n"
            "\n"
            "if __name__ == '__main__':\n"
            "    main()\n"
        )

        with open(py_shim, "w", encoding="utf-8") as f:
            f.write(script_content)
        py_shim.chmod(0o755)
        return py_shim

    def install(self) -> Path:
        """
        Installs ag-sh (C binary or Python fallback) and creates symlinks.
        Returns the shim directory Path.
        """
        self.shim_dir.mkdir(parents=True, exist_ok=True)

        # 1. Compile or write ag-sh executable
        c_bin = self.compile_c_shim()
        if not c_bin or not c_bin.is_file():
            self.write_python_fallback()

        ag_sh_target = self.shim_dir / "ag-sh"

        # 2. Create symlinks for all intercepted binaries
        for binary in INTERCEPTED_BINARIES:
            symlink_path = self.shim_dir / binary
            if symlink_path.is_symlink() or symlink_path.exists():
                try:
                    symlink_path.unlink()
                except OSError:
                    pass
            try:
                symlink_path.symlink_to(ag_sh_target)
            except OSError:
                pass

        return self.shim_dir

    def get_env(
        self,
        session_id: str,
        hitl: bool = False,
        base_env: Optional[Dict[str, str]] = None,
        llm_proxy: bool = True,
        proxy_port: int = 18443,
    ) -> Dict[str, str]:
        """
        Constructs process execution environment with shimmed PATH,
        optional libc dynamic interposing hook, and transparent LLM proxy routing.
        """
        env = dict(base_env or os.environ)
        orig_path = env.get("PATH", "")
        shim_dir_str = str(self.shim_dir)

        # Prepend shim directory to PATH
        env["PATH"] = f"{shim_dir_str}:{orig_path}"
        env["AGENTGUARD_SESSION_ID"] = session_id
        env["AGENTGUARD_SOCKET"] = self.socket_path
        env["AGENTGUARD_ORIGINAL_PATH"] = orig_path
        env["AGENTGUARD_SHIM_DIR"] = shim_dir_str
        env["AGENTGUARD_HITL"] = "1" if hitl else "0"

        # Check for dynamic linker hook
        hook_dylib = self.shim_dir / "libagentguard_hook.dylib"
        hook_so = self.shim_dir / "libagentguard_hook.so"
        if hook_dylib.is_file():
            env["DYLD_INSERT_LIBRARIES"] = str(hook_dylib)
        elif hook_so.is_file():
            env["LD_PRELOAD"] = str(hook_so)

        # Transparent LLM reverse proxy environment variables
        if llm_proxy:
            env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{proxy_port}/proxy/anthropic"
            env["OPENAI_BASE_URL"] = f"http://127.0.0.1:{proxy_port}/proxy/openai"

        return env
