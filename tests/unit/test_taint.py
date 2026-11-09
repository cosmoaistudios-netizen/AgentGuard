"""
Unit tests for AgentGuard Taint Provenance DAG Engine.
"""

import concurrent.futures
import os
import unittest

from agentguard.daemon.taint_engine import (
    EdgeType,
    NodeType,
    TaintEngine,
    TaintState,
)


class TestTaintBasics(unittest.TestCase):
    """Basic node creation, state defaults, and immutability invariants."""

    def setUp(self):
        self.engine = TaintEngine()

    def test_node_and_edge_creation(self):
        sess = self.engine.register_session(
            "sess_01", pid=1234, profile="generic"
        )
        self.assertEqual(sess.node_type, NodeType.SESSION)
        self.assertEqual(sess.state, TaintState.CLEAN)
        self.assertEqual(sess.session_id, "sess_01")
        self.assertEqual(sess.pid, 1234)

        proc = self.engine.register_process(5678, session_id="sess_01")
        self.assertEqual(proc.node_type, NodeType.PROCESS)
        self.assertEqual(proc.pid, 5678)

        file_node = self.engine.register_file("/tmp/shared.json")
        self.assertEqual(file_node.node_type, NodeType.FILE)
        self.assertTrue(file_node.id.startswith("file:/"))

    def test_initial_clean_state(self):
        sess = self.engine.register_session("sess_clean")
        self.assertFalse(self.engine.is_tainted("sess_clean"))
        self.assertEqual(sess.state, TaintState.CLEAN)
        self.assertIsNone(sess.tainted_at)

    def test_direct_node_tainting(self):
        self.engine.register_session("sess_direct")
        tainted = self.engine.mark_tainted(
            "sess_direct", reason="MaliciousInput"
        )
        self.assertIn("sess_direct", tainted)
        self.assertTrue(self.engine.is_tainted("sess_direct"))
        node = self.engine._sessions["sess_direct"]
        self.assertEqual(node.state, TaintState.TAINTED)
        self.assertIsNotNone(node.tainted_at)
        self.assertEqual(node.taint_reason, "MaliciousInput")

    def test_state_immutability_no_downgrade(self):
        self.engine.register_session("sess_t", taint="TAINTED")
        self.engine.register_session("sess_c", taint="CLEAN")

        # Reverse handoff from CLEAN to TAINTED must not clear taint
        self.engine.data_handoff("sess_c", "sess_t")
        self.assertTrue(self.engine.is_tainted("sess_t"))

        # Re-registering with CLEAN must not downgrade
        self.engine.register_session("sess_t", taint="CLEAN")
        self.assertTrue(self.engine.is_tainted("sess_t"))


class TestTaintPropagation(unittest.TestCase):
    """Single-hop, multi-hop, and pre-tainted edge propagation."""

    def setUp(self):
        self.engine = TaintEngine()

    def test_single_hop_data_handoff(self):
        self.engine.register_session("agent_a", taint="TAINTED")
        self.engine.register_session("agent_b", taint="CLEAN")

        self.assertFalse(self.engine.is_tainted("agent_b"))
        self.engine.data_handoff("agent_a", "agent_b")
        self.assertTrue(self.engine.is_tainted("agent_b"))

    def test_pre_tainted_edge_addition(self):
        self.engine.register_session("src", taint="TAINTED")
        self.engine.register_session("tgt", taint="CLEAN")

        # Edge addition automatically triggers propagation
        self.engine.add_edge("src", "tgt", EdgeType.DATA_HANDOFF)
        self.assertTrue(self.engine.is_tainted("tgt"))

    def test_transitive_multi_hop_chain(self):
        # Build DAG: A -> B -> C -> D
        self.engine.register_session("A", taint="CLEAN")
        self.engine.register_session("B", taint="CLEAN")
        self.engine.register_session("C", taint="CLEAN")
        self.engine.register_session("D", taint="CLEAN")

        self.engine.data_handoff("A", "B")
        self.engine.data_handoff("B", "C")
        self.engine.data_handoff("C", "D")

        self.assertFalse(self.engine.is_tainted("D"))

        # Taint A -> B, C, D must all become TAINTED
        self.engine.mark_tainted("A", reason="IngestedPR")
        self.assertTrue(self.engine.is_tainted("A"))
        self.assertTrue(self.engine.is_tainted("B"))
        self.assertTrue(self.engine.is_tainted("C"))
        self.assertTrue(self.engine.is_tainted("D"))

    def test_upstream_parent_isolation(self):
        # Orchestrator -> Specialist -> QA
        self.engine.register_session("orchestrator", taint="CLEAN")
        self.engine.register_session("specialist", taint="CLEAN")
        self.engine.register_session("qa", taint="CLEAN")

        self.engine.data_handoff("orchestrator", "specialist")
        self.engine.data_handoff("specialist", "qa")

        # Specialist becomes tainted
        self.engine.mark_tainted("specialist", reason="ExternalExploit")

        self.assertTrue(self.engine.is_tainted("specialist"))
        self.assertTrue(self.engine.is_tainted("qa"))
        # Upstream parent MUST remain clean
        self.assertFalse(self.engine.is_tainted("orchestrator"))


class TestCycleSafety(unittest.TestCase):
    """Cycle resilience and recursion overflow prevention."""

    def setUp(self):
        self.engine = TaintEngine()

    def test_two_node_cycle(self):
        # A -> B -> A
        self.engine.register_session("A", taint="CLEAN")
        self.engine.register_session("B", taint="CLEAN")

        self.engine.data_handoff("A", "B")
        self.engine.data_handoff("B", "A")

        # Must not raise RecursionError
        self.engine.mark_tainted("A")
        self.assertTrue(self.engine.is_tainted("A"))
        self.assertTrue(self.engine.is_tainted("B"))

    def test_subgraph_cycle(self):
        # A -> B -> C -> D -> B
        self.engine.register_session("A", taint="CLEAN")
        self.engine.register_session("B", taint="CLEAN")
        self.engine.register_session("C", taint="CLEAN")
        self.engine.register_session("D", taint="CLEAN")

        self.engine.data_handoff("A", "B")
        self.engine.data_handoff("B", "C")
        self.engine.data_handoff("C", "D")
        self.engine.data_handoff("D", "B")

        self.engine.mark_tainted("A")
        self.assertTrue(self.engine.is_tainted("D"))

    def test_deep_linear_chain_no_stack_overflow(self):
        # Chain of 2,000 nodes (exceeds default recursion limit of 1,000)
        n = 2000
        for i in range(n):
            self.engine.register_session(f"node_{i}", taint="CLEAN")
            if i > 0:
                self.engine.data_handoff(f"node_{i-1}", f"node_{i}")

        # Taint root node
        self.engine.mark_tainted("node_0")
        self.assertTrue(self.engine.is_tainted(f"node_{n-1}"))


class TestFileAndProcessTaint(unittest.TestCase):
    """File mediation and OS PID tracking."""

    def setUp(self):
        self.engine = TaintEngine()

    def test_file_write_and_read_propagation(self):
        agent_a = "producer_tainted"
        agent_b = "consumer_clean"
        self.engine.register_session(agent_a, taint="TAINTED")
        self.engine.register_session(agent_b, taint="CLEAN")

        shared_file = "/tmp/agentguard_test_shared.json"

        # Agent A writes file -> file becomes tainted
        self.engine.record_file_write(
            agent_a, shared_file, sha256="abc123hash"
        )
        self.assertTrue(self.engine.is_tainted(shared_file))

        # Agent B reads file -> Agent B becomes tainted
        self.engine.record_file_read(agent_b, shared_file)
        self.assertTrue(self.engine.is_tainted(agent_b))

    def test_pid_to_session_mapping(self):
        self.engine.register_session("agent_pid_test", pid=8899, taint="CLEAN")
        self.assertFalse(self.engine.is_tainted(8899))

        self.engine.mark_tainted("agent_pid_test")
        self.assertTrue(self.engine.is_tainted(8899))

    def test_file_taints_cache_compatibility(self):
        shared_file = "/tmp/cache_compat.json"
        self.engine.register_file(
            shared_file, sha256="hash1", tainted=True, source_agent="agent_x"
        )
        norm = os.path.abspath(shared_file)
        self.assertIn(norm, self.engine.file_taints)
        self.assertTrue(self.engine.file_taints[norm]["tainted"])
        self.assertEqual(
            self.engine.file_taints[norm]["source_agent"], "agent_x"
        )


class TestProvenanceAndConcurrency(unittest.TestCase):
    """Lineage reconstruction and multi-threaded stress."""

    def setUp(self):
        self.engine = TaintEngine()

    def test_provenance_chain_reconstruction(self):
        self.engine.register_session("root_untrusted", taint="CLEAN")
        self.engine.register_session("proxy_agent", taint="CLEAN")
        self.engine.register_session("target_agent", taint="CLEAN")

        self.engine.data_handoff("root_untrusted", "proxy_agent")
        self.engine.data_handoff("proxy_agent", "target_agent")

        self.engine.mark_tainted("root_untrusted", reason="PromptInjection")

        chain = self.engine.get_provenance_chain("target_agent")
        self.assertEqual(
            chain, ["root_untrusted", "proxy_agent", "target_agent"]
        )

    def test_concurrent_multi_threaded_burst(self):
        def task(idx: int):
            s_name = f"conc_{idx}"
            self.engine.register_session(s_name, pid=10000 + idx)
            if idx > 0:
                self.engine.data_handoff(f"conc_{idx-1}", s_name)
            if idx == 5:
                self.engine.mark_tainted(s_name)
            return self.engine.is_tainted(s_name)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(task, i) for i in range(20)]
            results = [
                f.result() for f in concurrent.futures.as_completed(futures)
            ]

        self.assertEqual(len(results), 20)
        st = self.engine.get_status_dict()
        self.assertGreater(st["tainted_sessions"], 0)

    def test_graph_snapshot(self):
        self.engine.register_session("snap_a", taint="CLEAN")
        self.engine.register_session("snap_b", taint="TAINTED")
        self.engine.data_handoff("snap_a", "snap_b")
        snap = self.engine.get_graph_snapshot()
        self.assertIn("nodes_count", snap)
        self.assertIn("edges_count", snap)
        self.assertGreaterEqual(snap["nodes_count"], 2)
        self.assertGreaterEqual(snap["edges_count"], 1)


if __name__ == "__main__":
    unittest.main()
