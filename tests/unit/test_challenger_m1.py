"""
tests/unit/test_challenger_m1.py - Adversarial Challenge Suite.

Authored by challenger_m1_2.
Stress-tests:
1. Malformed YAML profiles, invalid fields, negative thresholds, missing files.
2. Packaging & entrypoint CLI invocation from clean subshells.
3. Environment variable injection & preservation in `ag wrap`.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

from agentguard.config import load_profile


class TestAdversarialConfigAndProfiles(unittest.TestCase):
    """Challenge profile loading, YAML parsing, and schema validation."""

    def test_missing_profile_raises_file_not_found(self):
        """Missing profile names or non-existent files raise exception."""
        with self.assertRaises(FileNotFoundError) as ctx:
            load_profile("definitely_nonexistent_profile_xyz_12345")
        self.assertIn("not found", str(ctx.exception))

        with self.assertRaises(FileNotFoundError):
            load_profile("/tmp/nonexistent_dir_9999/profile.yaml")

    def test_malformed_yaml_syntax_raises_value_error(self):
        """YAML with illegal syntax raises ValueError with parse details."""
        malformed_snippets = [
            "name: [broken yaml: {unclosed",
            "name: test\n  bad_indent: 1\n bad_indent_2: 2\n\t tab_err: true",
            "{: invalid json-yaml",
            'key: "unclosed string without end quote',
            "%TAG !yaml! tag:yaml.org,2002:\n!invalid tag",
        ]
        for snippet in malformed_snippets:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".yaml", delete=False
            ) as f:
                f.write(snippet)
                tmp_path = f.name
            try:
                with self.assertRaises(ValueError) as ctx:
                    load_profile(tmp_path)
                self.assertIn("Failed to parse YAML", str(ctx.exception))
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

    def test_non_dictionary_yaml_root_raises_value_error(self):
        """YAML documents whose root is not a mapping must raise ValueError."""
        non_dict_snippets = [
            "- item1\n- item2\n- item3",
            '"just a scalar string"',
            "12345",
            "true",
            "",
            "# only comments\n# nothing else\n",
        ]
        for snippet in non_dict_snippets:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".yaml", delete=False
            ) as f:
                f.write(snippet)
                tmp_path = f.name
            try:
                with self.assertRaises(ValueError) as ctx:
                    load_profile(tmp_path)
                self.assertIn(
                    "must contain a YAML dictionary", str(ctx.exception)
                )
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

    def test_invalid_field_data_types_raise_value_error(self):
        """Invalid types for fields must raise ValueError from Pydantic."""
        invalid_type_snippets = [
            "name: test\nvault:\n  entropy_threshold: ['not', 'float']",
            "name: test\nshell:\n  safe_commands: 'not_a_list'",
            "name: test\nshell:\n  block_tainted_only: ['bad_bool']",
            "name: test\nintent:\n  drift_threshold: {invalid: object}",
            "name: test\nfilesystem:\n  monitored_paths: 12345",
        ]
        for snippet in invalid_type_snippets:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".yaml", delete=False
            ) as f:
                f.write(snippet)
                tmp_path = f.name
            try:
                with self.assertRaises(ValueError) as ctx:
                    load_profile(tmp_path)
                self.assertIn("Invalid profile schema", str(ctx.exception))
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

    def test_extra_unknown_fields_are_tolerated(self):
        """Extra/unknown fields in profiles should be safely ignored."""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", delete=False
        ) as f:
            f.write(
                "name: test-extra-fields\n"
                "unknown_top_level_field: 42\n"
                "vault:\n"
                "  unknown_vault_flag: true\n"
            )
            tmp_path = f.name
        try:
            profile = load_profile(tmp_path)
            self.assertEqual(profile.name, "test-extra-fields")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_negative_thresholds_behavior(self):
        """
        Adversarial evaluation of negative and extreme thresholds.
        Documents current schema boundary behavior.
        """
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", delete=False
        ) as f:
            f.write(
                "name: negative-thresholds-test\n"
                "vault:\n"
                "  entropy_threshold: -5.0\n"
                "  min_token_length: -10\n"
                "intent:\n"
                "  drift_threshold: -0.5\n"
            )
            tmp_path = f.name
        try:
            profile = load_profile(tmp_path)
            self.assertEqual(profile.vault.entropy_threshold, -5.0)
            self.assertEqual(profile.vault.min_token_length, -10)
            self.assertEqual(profile.intent.drift_threshold, -0.5)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


class TestPackagingAndEntryPoints(unittest.TestCase):
    """Validates packaging and CLI execution in fresh subshell processes."""

    def test_entrypoint_ag_in_fresh_subshell(self):
        """ag binary is invokable from subshell and returns 0."""
        ag_bin = sys.prefix + "/bin/ag"
        if not os.path.exists(ag_bin):
            ag_bin = "ag"

        result = subprocess.run(
            [ag_bin, "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("AgentGuard", result.stdout)
        self.assertIn("daemon", result.stdout)
        self.assertIn("wrap", result.stdout)
        self.assertIn("status", result.stdout)
        self.assertIn("audit", result.stdout)

    def test_entrypoint_agentguard_alias_in_fresh_subshell(self):
        """agentguard alias is invokable from subshell and reports version."""
        agentguard_bin = sys.prefix + "/bin/agentguard"
        if not os.path.exists(agentguard_bin):
            agentguard_bin = "agentguard"

        result = subprocess.run(
            [agentguard_bin, "--version"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("0.1.0", result.stdout)

    def test_cli_execution_from_foreign_working_directory(self):
        """CLI functions when executed from a foreign directory (e.g. /tmp)."""
        ag_bin = sys.prefix + "/bin/ag"
        if not os.path.exists(ag_bin):
            ag_bin = "ag"

        result = subprocess.run(
            [ag_bin, "status", "--json"],
            cwd="/tmp",
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertIn("status", data)


class TestWrapEnvironmentInjection(unittest.TestCase):
    """Validates environment preservation and session ID injection."""

    def setUp(self):
        self.ag_bin = sys.prefix + "/bin/ag"
        if not os.path.exists(self.ag_bin):
            self.ag_bin = "ag"

    def test_custom_environment_variables_not_stripped(self):
        """Custom env vars pass through unstripped and unmodified."""
        custom_env = os.environ.copy()
        custom_env["TEST_CUSTOM_KEY_1"] = "alpha_numeric_value_123"
        custom_env["TEST_CUSTOM_KEY_SPACES"] = (
            "string with spaces and !@#$%^&*() symbols"
        )
        custom_env["TEST_CUSTOM_KEY_EMPTY"] = ""

        script = (
            "import os, json, sys\n"
            "output = {\n"
            "  'k1': os.environ.get('TEST_CUSTOM_KEY_1'),\n"
            "  'k2': os.environ.get('TEST_CUSTOM_KEY_SPACES'),\n"
            "  'k3': os.environ.get('TEST_CUSTOM_KEY_EMPTY'),\n"
            "  'session': os.environ.get('AGENTGUARD_SESSION_ID'),\n"
            "  'profile': os.environ.get('AGENTGUARD_PROFILE'),\n"
            "  'hitl': os.environ.get('AGENTGUARD_HITL'),\n"
            "  'orig_path': os.environ.get('AGENTGUARD_ORIGINAL_PATH'),\n"
            "}\n"
            "print('RESULT:' + json.dumps(output))\n"
        )

        proc = subprocess.run(
            [
                self.ag_bin,
                "wrap",
                "--profile",
                "generic",
                "--",
                sys.executable,
                "-c",
                script,
            ],
            env=custom_env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)

        match = re.search(r"RESULT:(\{.*\})", proc.stdout)
        self.assertIsNotNone(
            match, f"Could not find RESULT in output: {proc.stdout}"
        )
        data = json.loads(match.group(1))

        # Check preserved custom variables
        self.assertEqual(data["k1"], "alpha_numeric_value_123")
        self.assertEqual(
            data["k2"], "string with spaces and !@#$%^&*() symbols"
        )
        self.assertEqual(data["k3"], "")

        # Check injected AgentGuard variables
        self.assertIsNotNone(data["session"])
        self.assertTrue(re.match(r"^ag-sess-[a-f0-9]{12}$", data["session"]))
        self.assertEqual(data["profile"], "generic")
        self.assertEqual(data["hitl"], "0")
        self.assertIsNotNone(data["orig_path"])

    def test_session_id_uniqueness(self):
        """Every ag wrap execution produces a unique session ID."""
        session_ids = set()
        for _ in range(5):
            proc = subprocess.run(
                [
                    self.ag_bin,
                    "wrap",
                    "--profile",
                    "generic",
                    "--",
                    sys.executable,
                    "-c",
                    "import os; "
                    "print('SESSION:' + os.environ['AGENTGUARD_SESSION_ID'])",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0)
            match = re.search(r"SESSION:(ag-sess-[a-f0-9]{12})", proc.stdout)
            self.assertIsNotNone(match)
            session_ids.add(match.group(1))

        self.assertEqual(len(session_ids), 5, "Session ID collision detected!")

    def test_hitl_flag_environment_injection(self):
        """Passing --hitl sets AGENTGUARD_HITL=1 in child environment."""
        proc = subprocess.run(
            [
                self.ag_bin,
                "wrap",
                "--profile",
                "generic",
                "--hitl",
                "--",
                sys.executable,
                "-c",
                "import os; "
                "print('HITL:' + os.environ.get('AGENTGUARD_HITL', ''))",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("HITL:1", proc.stdout)

    def test_wrapped_exit_code_propagation(self):
        """ag wrap transparently propagates child process exit codes."""
        for expected_code in [0, 42, 7]:
            proc = subprocess.run(
                [
                    self.ag_bin,
                    "wrap",
                    "--profile",
                    "generic",
                    "--",
                    sys.executable,
                    "-c",
                    f"import sys; sys.exit({expected_code})",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, expected_code)

    def test_wrap_command_not_found_returns_127(self):
        """ag wrap wrapping a non-existent command returns exit code 127."""
        proc = subprocess.run(
            [
                self.ag_bin,
                "wrap",
                "--profile",
                "generic",
                "--",
                "nonexistent_executable_12345",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 127)
        self.assertIn(
            "Command 'nonexistent_executable_12345' not found", proc.stderr
        )


if __name__ == "__main__":
    unittest.main()
