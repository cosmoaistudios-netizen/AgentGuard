"""Unit tests for AgentGuard Visual Branding & Logo Assets."""

from __future__ import annotations

import unittest
from rich.console import Console
from rich.panel import Panel

from agentguard.branding import (
    BRAND_CREDIT,
    BRAND_NAME,
    BRAND_SUBTITLE,
    LOGO_ASCII_SLANT,
    get_ascii_logo_text,
    get_branding_banner,
    get_compact_badge,
)
from agentguard.launcher import build_menu_panel
from agentguard.cockpit.app import CockpitApp


def render_to_text(renderable) -> str:
    console = Console(width=120, force_terminal=False, color_system=None)
    with console.capture() as capture:
        console.print(renderable)
    return capture.get()


class TestBrandingAssets(unittest.TestCase):
    """Test suite validating AgentGuard logo art, attribution, and banners."""

    def test_ascii_logo_contains_all_lines(self):
        self.assertEqual(len(LOGO_ASCII_SLANT), 6)
        text = get_ascii_logo_text()
        rendered = render_to_text(text)
        self.assertIn("____", rendered)
        self.assertIn("/____/", rendered)

    def test_branding_banner_contains_brand_and_credit(self):
        banner = get_branding_banner(include_subtitle=True, include_credit=True)
        rendered = render_to_text(banner)
        self.assertIn("Cosmo AI Studios", rendered)
        self.assertIn("Zero-Trust Security Kernel", rendered)

    def test_compact_badge(self):
        badge = get_compact_badge()
        rendered = render_to_text(badge)
        self.assertIn("AGENTGUARD", rendered)
        self.assertIn("Cosmo AI Studios", rendered)

    def test_launcher_menu_panel_renders_branding(self):
        panel = build_menu_panel(selected_idx=0, daemon_online=True, daemon_pid=9999)
        self.assertIsInstance(panel, Panel)
        rendered = render_to_text(panel)
        self.assertIn("Cosmo AI Studios", rendered)
        self.assertIn("Daemon Status", rendered)
        self.assertIn("Terminal Cockpit", rendered)

    def test_cockpit_header_large_terminal_renders_logo_and_credit(self):
        app = CockpitApp()
        panel = app.build_header(term_height=40)
        rendered = render_to_text(panel)
        self.assertIn("AGENTGUARD COCKPIT", rendered)
        self.assertIn("Cosmo AI Studios", rendered)
        self.assertIn("ONLINE", rendered)

    def test_cockpit_header_compact_terminal_renders_credit(self):
        app = CockpitApp()
        panel = app.build_header(term_height=24)
        rendered = render_to_text(panel)
        self.assertIn("AGENTGUARD COCKPIT", rendered)
        self.assertIn("Cosmo AI Studios", rendered)
        self.assertIn("ONLINE", rendered)


if __name__ == "__main__":
    unittest.main()
