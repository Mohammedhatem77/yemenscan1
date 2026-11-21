"""
WAF Evasion & Adaptive Request Throttling Engine for YemenScan.

Provides:
  1. Internal origin/proxy simulation headers (X-Forwarded-For, X-Real-IP, etc.)
  2. Realistic modern desktop User-Agent masking and rotation
  3. Adaptive rate throttling and jitter delay for stealthy benchmark scanning
  4. Non-destructive payload obfuscation helpers (double URL encoding, SQL comments)
"""

import os
import random
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Trusted Internal Headers (Bypass through Reverse Proxy Trust Simulation)
# ---------------------------------------------------------------------------
DEFAULT_SPOOFED_HEADERS: Dict[str, str] = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
    "Client-IP": "127.0.0.1",
    "X-Remote-IP": "127.0.0.1",
    "X-Client-IP": "127.0.0.1"
}

# ---------------------------------------------------------------------------
# Modern Desktop Browser User-Agents (Masking scanner signatures)
# ---------------------------------------------------------------------------
REALISTIC_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
]


@dataclass
class WAFEvasionConfig:
    """Holds calculated evasion configuration for a scan session."""
    is_behind_waf: bool = False
    waf_bypassed_via_origin: bool = False
    waf_provider: Optional[str] = None
    evasion_active: bool = False
    spoofed_headers: Dict[str, str] = field(default_factory=lambda: dict(DEFAULT_SPOOFED_HEADERS))
    user_agent: str = REALISTIC_USER_AGENTS[0]
    nuclei_delay: Optional[str] = None
    wapiti_tasks: Optional[int] = None


class WAFEvasionEngine:
    """
    Coordinates application-layer evasion, header simulation, and rate throttling
    for security tools (Nuclei, Wapiti, HTTPX).
    """

    @staticmethod
    def resolve_evasion_config(
        session_dir: str,
        scan_profile: str = "safe",
        force_evasion: bool = False
    ) -> WAFEvasionConfig:
        """
        Determines whether WAF evasion should be activated based on Stage 0 WAF detection
        and scan profile.
        
        Logic:
          - If origin IP is verified and bypassed at network layer (waf_bypassed==True):
            network routing handles it, evasion_active=False (unless deep profile or forced).
          - If target is behind WAF and origin IP was NOT found:
            evasion_active=True (applies header spoofing + User-Agent masking + throttling).
          - If scan_profile == 'deep':
            evasion_active=True (ensures stealth and header bypass on benchmark targets).
        """
        from core.origin_recon import load_waf_bypass_info
        waf_info = load_waf_bypass_info(session_dir)

        is_behind_waf = bool(waf_info.get("is_behind_waf"))
        waf_bypassed = bool(waf_info.get("waf_bypassed") and waf_info.get("verified_origins"))
        waf_provider = waf_info.get("waf_provider")

        evasion_active = False
        if force_evasion:
            evasion_active = True
        elif is_behind_waf and not waf_bypassed:
            evasion_active = True
        elif scan_profile == "deep":
            evasion_active = True

        cfg = WAFEvasionConfig(
            is_behind_waf=is_behind_waf,
            waf_bypassed_via_origin=waf_bypassed,
            waf_provider=waf_provider,
            evasion_active=evasion_active,
            user_agent=REALISTIC_USER_AGENTS[0]
        )

        if evasion_active:
            # Set throttling delay if behind WAF to prevent rate-limit IP block
            if is_behind_waf:
                cfg.nuclei_delay = "500ms"
                cfg.wapiti_tasks = 1  # single-thread stealth crawl

        return cfg

    @staticmethod
    def build_nuclei_args(config: WAFEvasionConfig) -> List[str]:
        """
        Builds extra Nuclei CLI flags for WAF evasion.
        Returns empty list if evasion_active is False to preserve standard baseline.
        """
        if not config.evasion_active:
            return []

        args: List[str] = []
        # Custom headers
        for h_name, h_val in config.spoofed_headers.items():
            args.extend(["-H", f"{h_name}: {h_val}"])
        # User-Agent header
        if config.user_agent:
            args.extend(["-H", f"User-Agent: {config.user_agent}"])
        # Delay throttling
        if config.nuclei_delay:
            args.extend(["-delay", config.nuclei_delay])

        return args

    @staticmethod
    def build_wapiti_args(config: WAFEvasionConfig) -> List[str]:
        """
        Builds extra Wapiti CLI flags for WAF evasion.
        Returns empty list if evasion_active is False.
        """
        if not config.evasion_active:
            return []

        args: List[str] = []
        # User-Agent
        if config.user_agent:
            args.extend(["--user-agent", config.user_agent])
        # Custom headers
        for h_name, h_val in config.spoofed_headers.items():
            args.extend(["--header", f"{h_name}: {h_val}"])

        return args

    @staticmethod
    def build_httpx_args(config: WAFEvasionConfig) -> List[str]:
        """
        Builds extra HTTPX CLI flags for WAF evasion.
        Returns empty list if evasion_active is False.
        """
        if not config.evasion_active:
            return []

        args: List[str] = []
        # Spoofed headers
        for h_name, h_val in config.spoofed_headers.items():
            args.extend(["-H", f"{h_name}: {h_val}"])
        # Realistic User-Agent
        if config.user_agent:
            args.extend(["-H", f"User-Agent: {config.user_agent}"])

        return args

    @staticmethod
    def build_kiterunner_args(config: WAFEvasionConfig) -> List[str]:
        """
        Builds extra Kiterunner CLI flags for WAF evasion.
        Returns empty list if evasion_active is False.
        """
        if not config.evasion_active:
            return []

        args: List[str] = []
        if config.user_agent:
            args.extend(["--user-agent", config.user_agent])
        for h_name, h_val in config.spoofed_headers.items():
            args.extend(["-H", f"{h_name}: {h_val}"])

        return args

    @staticmethod
    def obfuscate_sql_payload(payload: str) -> str:
        """
        Non-destructive SQL obfuscation using SQL comment inline substitution:
        e.g. 'UNION SELECT' -> 'UN/**/ION/**/SE/**/LECT'
        """
        substitutions = {
            "UNION": "UN/**/ION",
            "SELECT": "SE/**/LECT",
            "FROM": "FR/**/OM",
            "WHERE": "WH/**/ERE",
            "AND": "A/**/ND",
            "OR": "O/**/R",
            " ": "/**/"
        }
        obf = payload
        for k, v in substitutions.items():
            obf = obf.replace(k, v)
        return obf

    @staticmethod
    def double_url_encode(char_or_str: str) -> str:
        """
        Double URL encoding helper for non-destructive path / parameter validation:
        e.g. '/' -> '%252f', '\'' -> '%2527'
        """
        from urllib.parse import quote
        return quote(quote(char_or_str, safe=""), safe="")
