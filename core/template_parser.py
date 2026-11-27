"""
YemScan — Nuclei Template Parser (Phase 2).

Responsibility: Read a single YAML file exactly once, produce a TemplateParseResult
containing the raw data, detected protocols, structural flags, and content hash.

Design rules:
- Uses yaml.safe_load exclusively — never executes template code.
- Detects protocols from YAML keys, NOT from folder/path names.
- Never modifies snapshot files.
- Logs parse errors; never silently swallows them.
- Returns a TemplateParseResult even on failure (parse_errors will be non-empty).
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

import yaml

logger = logging.getLogger("yemenscan.template_parser")

# ---------------------------------------------------------------------------
# Protocol key taxonomy — exhaustive list of keys that indicate a protocol
# in a Nuclei template's top-level structure.
# ---------------------------------------------------------------------------
#
# "requests" is the legacy alias for "http" in older templates.
# "tcp" is the legacy alias for "network".
# Both must be detected.
#
PROTOCOL_KEYS: Dict[str, str] = {
    # Canonical → canonical name
    "http": "http",
    "requests": "http",       # legacy alias
    "dns": "dns",
    "ssl": "ssl",
    "headless": "headless",
    "network": "network",
    "tcp": "network",         # legacy alias
    "javascript": "javascript",
    "code": "code",
    "file": "file",
    "websocket": "websocket",
    "whois": "whois",
    "dast": "dast",
}

# Top-level keys that signal a workflow template (not an executable template)
WORKFLOW_KEYS: Set[str] = {"workflows"}

# Top-level keys that are purely metadata / informational
METADATA_KEYS: Set[str] = {
    "id", "info", "variables", "self-contained",
    "stop-at-first-match", "signature", "flow",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TemplateParseResult:
    """
    Immutable result of parsing one YAML template file.

    Fields:
        file_path:        Absolute filesystem path of the template file.
        relative_path:    Path relative to the snapshot root (POSIX separators).
        raw_data:         Parsed YAML as a Python dict (empty dict on failure).
        protocols:        Deduplicated list of canonical protocol names detected.
        is_executable:    True if the file contains at least one protocol section.
        is_workflow:      True if the file is a workflow definition (not an executable).
        is_self_contained:True if the template declares self-contained: true.
        has_flow:         True if a top-level "flow" key is present.
        content_hash:     SHA-256 hex digest of the raw file bytes.
        file_size_bytes:  Raw file size in bytes.
        parse_errors:     Non-empty list means parsing failed or was partial.
        raw_yaml_text:    Raw file text (decoded, stored for downstream use).
    """
    file_path: str
    relative_path: str
    raw_data: Dict[str, Any]
    protocols: List[str]
    is_executable: bool
    is_workflow: bool
    is_self_contained: bool
    has_flow: bool
    content_hash: str
    file_size_bytes: int
    parse_errors: List[str]
    raw_yaml_text: str

    @property
    def template_id(self) -> Optional[str]:
        """Convenience accessor for the top-level 'id' field."""
        v = self.raw_data.get("id")
        if isinstance(v, str) and v.strip():
            return v.strip()
        return None

    @property
    def is_valid(self) -> bool:
        """True when no parse errors occurred and a valid id is present."""
        return not self.parse_errors and self.template_id is not None

    def has_protocol(self, proto: str) -> bool:
        """Case-insensitive protocol membership test."""
        return proto.lower() in self.protocols


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class TemplateParser:
    """
    Reads a Nuclei YAML template file exactly once and returns a
    TemplateParseResult.  Thread-safe (stateless); create one instance and
    reuse across the entire snapshot.
    """

    def parse_file(self, file_path: str, snapshot_root: str) -> TemplateParseResult:
        """
        Parse a single Nuclei template YAML file.

        Args:
            file_path:      Absolute path to the .yaml file.
            snapshot_root:  Absolute path to the snapshot root directory.
                            Used to compute the relative path.

        Returns:
            TemplateParseResult — always returned, even on error.
        """
        relative_path = self._relative_posix(file_path, snapshot_root)
        content_hash = ""
        file_size_bytes = 0
        raw_yaml_text = ""
        raw_data: Dict[str, Any] = {}
        parse_errors: List[str] = []

        # 1. Read raw bytes — compute hash and decode text
        try:
            with open(file_path, "rb") as fh:
                raw_bytes = fh.read()
            file_size_bytes = len(raw_bytes)
            content_hash = hashlib.sha256(raw_bytes).hexdigest()
            raw_yaml_text = raw_bytes.decode("utf-8", errors="replace")
        except OSError as exc:
            msg = f"IO error reading '{relative_path}': {exc}"
            logger.warning(msg)
            parse_errors.append(msg)
            return TemplateParseResult(
                file_path=file_path,
                relative_path=relative_path,
                raw_data={},
                protocols=[],
                is_executable=False,
                is_workflow=False,
                is_self_contained=False,
                has_flow=False,
                content_hash=content_hash,
                file_size_bytes=file_size_bytes,
                parse_errors=parse_errors,
                raw_yaml_text="",
            )

        # 2. YAML parse — safe_load only
        try:
            parsed = yaml.safe_load(raw_yaml_text)
        except yaml.YAMLError as exc:
            msg = f"YAML parse error in '{relative_path}': {exc}"
            logger.warning(msg)
            parse_errors.append(msg)
            return TemplateParseResult(
                file_path=file_path,
                relative_path=relative_path,
                raw_data={},
                protocols=[],
                is_executable=False,
                is_workflow=False,
                is_self_contained=False,
                has_flow=False,
                content_hash=content_hash,
                file_size_bytes=file_size_bytes,
                parse_errors=parse_errors,
                raw_yaml_text=raw_yaml_text,
            )

        if not isinstance(parsed, dict):
            msg = f"Non-dict YAML root in '{relative_path}' (got {type(parsed).__name__})"
            logger.warning(msg)
            parse_errors.append(msg)
            return TemplateParseResult(
                file_path=file_path,
                relative_path=relative_path,
                raw_data={},
                protocols=[],
                is_executable=False,
                is_workflow=False,
                is_self_contained=False,
                has_flow=False,
                content_hash=content_hash,
                file_size_bytes=file_size_bytes,
                parse_errors=parse_errors,
                raw_yaml_text=raw_yaml_text,
            )

        raw_data = parsed

        # 3. Structural analysis
        top_keys: Set[str] = set(raw_data.keys())

        # Detect protocols
        seen_canonical: Set[str] = set()
        for key in top_keys:
            canonical = PROTOCOL_KEYS.get(key.lower())
            if canonical:
                seen_canonical.add(canonical)
        protocols = sorted(seen_canonical)

        # Workflow detection
        is_workflow = bool(top_keys & WORKFLOW_KEYS)

        # Executable: has at least one protocol section AND is not workflow-only
        is_executable = bool(protocols) and not is_workflow

        # Self-contained flag
        is_self_contained = bool(raw_data.get("self-contained", False))

        # Flow detection (multi-step conditional logic)
        has_flow = "flow" in top_keys

        # 4. Validate id field
        if not raw_data.get("id") or not isinstance(raw_data.get("id"), str):
            msg = f"Missing or non-string 'id' in '{relative_path}'"
            logger.warning(msg)
            parse_errors.append(msg)

        # 5. Validate info section
        info = raw_data.get("info")
        if not isinstance(info, dict):
            msg = f"Missing or invalid 'info' section in '{relative_path}'"
            logger.debug(msg)
            parse_errors.append(msg)

        return TemplateParseResult(
            file_path=file_path,
            relative_path=relative_path,
            raw_data=raw_data,
            protocols=protocols,
            is_executable=is_executable,
            is_workflow=is_workflow,
            is_self_contained=is_self_contained,
            has_flow=has_flow,
            content_hash=content_hash,
            file_size_bytes=file_size_bytes,
            parse_errors=parse_errors,
            raw_yaml_text=raw_yaml_text,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _relative_posix(file_path: str, snapshot_root: str) -> str:
        """Return POSIX-style relative path from snapshot_root to file_path."""
        try:
            rel = os.path.relpath(file_path, snapshot_root)
            return rel.replace("\\", "/")
        except ValueError:
            # On Windows, relpath can fail across drives
            return file_path.replace("\\", "/")

    @staticmethod
    def walk_snapshot(snapshot_root: str):
        """
        Generator: yields absolute file paths for all .yaml / .yml files
        inside snapshot_root, skipping hidden directories (starting with '.').
        Files are yielded in deterministic (sorted) order for reproducibility.
        """
        snapshot_root = os.path.abspath(snapshot_root)
        for dirpath, dirnames, filenames in os.walk(snapshot_root):
            # Skip hidden directories in-place (modifies dirnames to prune walk)
            dirnames[:] = sorted(
                d for d in dirnames if not d.startswith(".")
            )
            for fname in sorted(filenames):
                if fname.lower().endswith((".yaml", ".yml")) and not fname.startswith("."):
                    yield os.path.join(dirpath, fname)
