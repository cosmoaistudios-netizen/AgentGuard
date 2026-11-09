"""AgentGuard Visual Branding & Logo Assets.

Provides ASCII logo art, stylized Rich banners, and attribution metadata
for CLI startup, interactive launcher, and Cockpit TUI.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from rich.text import Text

BRAND_NAME = "AgentGuard"
BRAND_SUBTITLE = "OS-Level Zero-Trust Security Kernel & Daemon for AI Agents"
BRAND_CREDIT = "made by Cosmo AI Studios"

# ASCII Slant Logo (60 columns wide)
LOGO_ASCII_SLANT: List[str] = [
    r"    ___                    __  ______                     __",
    r"   /   | ____ ____  ____  / /_/ ____/_  ______ __________/ /",
    r"  / /| |/ __ `/ _ \/ __ \/ __/ / __/ / / / __ `/ ___/ __  / ",
    r" / ___ / /_/ /  __/ / / / /_/ /_/ / /_/ / /_/ / /  / /_/ /  ",
    r"/_/  |_\__, /\___/_/ /_/\__/\____/\__,_/\__,_/_/   \__,_/   ",
    r"      /____/                                                ",
]

# Gradient colors across 6 lines
LOGO_COLORS: List[str] = [
    "bold bright_cyan",
    "bold cyan",
    "bold cyan",
    "bold bright_blue",
    "bold blue",
    "bold blue",
]


def get_ascii_logo_text(prefix_spaces: int = 0) -> Text:
    """Return stylized Rich Text of the AgentGuard ASCII logo."""
    text = Text()
    pad = " " * prefix_spaces
    for line, color in zip(LOGO_ASCII_SLANT, LOGO_COLORS):
        text.append(f"{pad}{line}\n", style=color)
    return text


def get_branding_banner(
    include_subtitle: bool = True,
    include_credit: bool = True,
    prefix_spaces: int = 0,
) -> Text:
    """Generate the full AgentGuard branding block with attribution."""
    banner = Text()
    pad = " " * prefix_spaces
    for line, color in zip(LOGO_ASCII_SLANT, LOGO_COLORS):
        banner.append(f"{pad}{line}\n", style=color)

    if include_subtitle:
        banner.append(f"{pad}         🛡️  {BRAND_SUBTITLE}\n", style="bold cyan")

    if include_credit:
        banner.append(f"{pad}                    {BRAND_CREDIT}\n\n", style="bold italic bright_magenta")

    return banner


def get_compact_badge() -> Text:
    """Return a single-line compact branding badge."""
    text = Text()
    text.append("🛡️ AGENTGUARD", style="bold cyan")
    text.append("  │  ", style="dim")
    text.append(BRAND_CREDIT, style="bold italic bright_magenta")
    return text
