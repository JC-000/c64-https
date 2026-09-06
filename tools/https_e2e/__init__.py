"""https_e2e -- End-to-end test helpers for the c64-https program.

Public API used by tests/rig_phase1_dhcp.py and (later) higher phases:

    from https_e2e import (
        BridgeEnv,
        launch_vice_on_bridge, shutdown_vice,
        press_key, wait_for_screen_text,
        check_prerequisites,
        platform_supported,
    )

Internals live in underscored helpers in each submodule.
"""

from .env import BridgeEnv, check_prerequisites, platform_supported
from .vice_on_bridge import launch_vice_on_bridge, shutdown_vice
from .c64_menu import press_key, wait_for_screen_text, get_screen_text
from .http_listener import start_http_listener, stop_http_listener
from .https_listener import start_https_listener, stop_https_listener

__all__ = [
    "BridgeEnv",
    "check_prerequisites",
    "platform_supported",
    "launch_vice_on_bridge",
    "shutdown_vice",
    "press_key",
    "wait_for_screen_text",
    "get_screen_text",
    "start_http_listener",
    "stop_http_listener",
    "start_https_listener",
    "stop_https_listener",
]
