"""
YemScan — Phase 7.2.1: Shared Secure Headless Execution Readiness Service.

Provides:
  1. Hardened Docker + Chromium runtime builders shared across sequential and
     independent scanning layers without duplicating security controls.
  2. Strict browser sandbox preservation (NO `--no-sandbox`, NO `--privileged`,
     NO `seccomp=unconfined`, NO root container UID, NO Docker socket mounts).
  3. Server-verified `HeadlessReadinessService` verifying:
       - Chromium availability & version inside pinned Nuclei Docker image
       - Nuclei engine headless compatibility (`-lha` & `-headless -cdpe`)
       - Real isolated container execution with JavaScript DOM evaluation
       - Browser & container isolation invariants (`uid!=0`, `CapEff=0`,
         `NoNewPrivs=1`, `Seccomp=2`, `--read-only` `/`, nested PID/User NS,
         blocked unauthorized syscalls & external egress)
       - `/dev/shm` sizing, memory/PID limits, and clean process/temp teardown
  4. Never trusts user-supplied flags to assert headless availability.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple

from core.nuclei_shared import (
    NUCLEI_DOCKER_IMAGE,
    NUCLEI_ENGINE_DIGEST,
    NUCLEI_ENGINE_VERSION,
    NUCLEI_HEADLESS_BROWSER_PATH,
    NUCLEI_HEADLESS_CDP_HOST,
    NUCLEI_HEADLESS_CDP_PORT,
    NUCLEI_HEADLESS_MEMORY_LIMIT,
    NUCLEI_HEADLESS_MIN_SHM_BYTES,
    NUCLEI_HEADLESS_PIDS_LIMIT,
    NUCLEI_HEADLESS_SECCOMP_PROFILE,
    NUCLEI_HEADLESS_SHM_SIZE,
    NUCLEI_HEADLESS_TMPFS_SPEC,
    NUCLEI_HEADLESS_UID_GID,
)
from core.runner import get_docker_cmd, get_docker_volume_path

logger = logging.getLogger("yemenscan.headless_readiness")

_SIZE_RE = re.compile(r"^(\d+)([kmgKMG]?)$")
_SAFE_SCOPE_RE = re.compile(r"^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-.*]*[a-zA-Z0-9])?$")
_DANGEROUS_SECCOMP_SYSCALLS_FOR_ANYONE = frozenset({
    "mount",
    "umount",
    "umount2",
    "bpf",
    "ptrace",
    "kexec_load",
    "init_module",
    "finit_module",
    "perf_event_open",
    "reboot",
    "swapon",
    "swapoff",
    "open_by_handle_at",
})
_FORBIDDEN_MOUNT_SNIPPETS = (
    "docker.sock",
    "/etc/shadow",
    "/etc/passwd",
    ".env",
)


class HeadlessConfigurationError(ValueError):
    """Raised when Headless container or browser isolation configuration violates policy."""


def parse_size_bytes(size_spec: str) -> int:
    """Parse Docker size notation (`512m`, `1g`, `1073741824`) into bytes."""
    m = _SIZE_RE.match((size_spec or "").strip())
    if not m:
        raise HeadlessConfigurationError(f"Invalid size specification: {size_spec!r}")
    val = int(m.group(1))
    unit = m.group(2).lower()
    mult = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[unit]
    return val * mult


def validate_seccomp_profile(profile_path: str) -> Dict[str, Any]:
    """
    Validate that the scoped seccomp profile exists, defaults to SCMP_ACT_ERRNO,
    and does not allow dangerous container-escape syscalls unconditionally.
    """
    if not profile_path or not os.path.isfile(profile_path):
        raise HeadlessConfigurationError(f"Seccomp profile missing: {profile_path}")

    try:
        with open(profile_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        raise HeadlessConfigurationError(f"Invalid seccomp JSON ({profile_path}): {exc}") from exc

    if data.get("defaultAction") != "SCMP_ACT_ERRNO":
        raise HeadlessConfigurationError(
            f"Seccomp defaultAction must be SCMP_ACT_ERRNO (got {data.get('defaultAction')!r})"
        )

    for rule in data.get("syscalls", []):
        if rule.get("action") == "SCMP_ACT_ALLOW" and not rule.get("includes"):
            unconditional = set(rule.get("names") or []) & _DANGEROUS_SECCOMP_SYSCALLS_FOR_ANYONE
            if unconditional:
                raise HeadlessConfigurationError(
                    f"Seccomp profile unconditionally allows restricted syscalls: {sorted(unconditional)}"
                )

    return data


@dataclass
class HeadlessEnvironmentConfig:
    """Immutable hardened runtime configuration for isolated Headless Nuclei containers."""
    docker_image: str = NUCLEI_DOCKER_IMAGE
    engine_version: str = NUCLEI_ENGINE_VERSION
    engine_digest: str = NUCLEI_ENGINE_DIGEST
    browser_path: str = NUCLEI_HEADLESS_BROWSER_PATH
    seccomp_profile_path: str = NUCLEI_HEADLESS_SECCOMP_PROFILE
    container_user: str = NUCLEI_HEADLESS_UID_GID
    shm_size: str = NUCLEI_HEADLESS_SHM_SIZE
    tmpfs_spec: str = NUCLEI_HEADLESS_TMPFS_SPEC
    memory_limit: str = NUCLEI_HEADLESS_MEMORY_LIMIT
    pids_limit: int = NUCLEI_HEADLESS_PIDS_LIMIT
    cdp_host: str = NUCLEI_HEADLESS_CDP_HOST
    cdp_port: int = NUCLEI_HEADLESS_CDP_PORT
    startup_timeout_seconds: int = 20
    probe_timeout_seconds: int = 90

    def validate(self) -> None:
        """Fail closed if any container or sandbox security control is weakened."""
        if not self.docker_image or "@" not in self.docker_image:
            raise HeadlessConfigurationError("Docker image must be pinned with sha256 digest")

        parts = (self.container_user or "").strip().split(":")
        if len(parts) != 2 or not all(p.isdigit() for p in parts):
            raise HeadlessConfigurationError(
                f"container_user must be numeric uid:gid (got {self.container_user!r})"
            )
        uid, gid = int(parts[0]), int(parts[1])
        if uid <= 0 or gid <= 0:
            raise HeadlessConfigurationError(
                f"container_user must be non-root (got uid={uid}, gid={gid})"
            )

        if parse_size_bytes(self.shm_size) < NUCLEI_HEADLESS_MIN_SHM_BYTES:
            raise HeadlessConfigurationError(
                f"shm_size must be >= 512m for Chromium sandboxed stability (got {self.shm_size!r})"
            )

        if self.pids_limit <= 0 or self.pids_limit > 2048:
            raise HeadlessConfigurationError(f"pids_limit out of safe range: {self.pids_limit}")

        if self.cdp_host != "127.0.0.1":
            raise HeadlessConfigurationError(
                f"CDP debugging endpoint must bind loopback 127.0.0.1 only (got {self.cdp_host!r})"
            )

        if not (1024 <= self.cdp_port <= 65535):
            raise HeadlessConfigurationError(f"Invalid CDP port: {self.cdp_port}")

        validate_seccomp_profile(self.seccomp_profile_path)


def build_host_resolver_rules(authorized_scopes: Sequence[str] = ()) -> str:
    """
    Build Chromium `--host-resolver-rules` blocking all DNS resolution except
    loopback and explicitly authorized scan scope hosts.
    """
    excludes = ["localhost", "127.0.0.1"]
    seen = set(excludes)

    for raw in authorized_scopes:
        item = (raw or "").strip().lower().rstrip(".")
        if not item:
            continue
        # Strip scheme/port if caller passed URL or host:port
        if "://" in item:
            item = item.split("://", 1)[1].split("/", 1)[0]
        item = item.split(":", 1)[0]
        if not item or not _SAFE_SCOPE_RE.match(item):
            continue
        if item not in seen:
            seen.add(item)
            excludes.append(item)
        if item.startswith("*."):
            bare = item[2:]
            if bare and bare not in seen and _SAFE_SCOPE_RE.match(bare):
                seen.add(bare)
                excludes.append(bare)

    exclude_clauses = ", ".join(f"EXCLUDE {h}" for h in excludes)
    return f"MAP * ~NOTFOUND, {exclude_clauses}"


def build_chromium_launch_args(
    config: Optional[HeadlessEnvironmentConfig] = None,
    authorized_scopes: Sequence[str] = (),
    user_data_dir: str = "/tmp/chrome-profile",
) -> List[str]:
    """
    Construct hardened Chromium flags preserving the Renderer/Zygote/Utility
    User-Namespace + Chroot + Seccomp-BPF sandbox (`--no-sandbox` NEVER emitted).

    Note: `--disable-gpu-sandbox` applies solely to the disabled `--disable-gpu`
    helper subprocess because Alpine 3.24 Chromium 150's Vulkan/SwANGLE probe hits
    an internal GPU BPF trap (`nr=0x148`) before fallback; all untrusted web
    content renderers, zygotes, and utility services stay strictly sandboxed.
    """
    cfg = config or HeadlessEnvironmentConfig()
    cfg.validate()

    resolver_rules = build_host_resolver_rules(authorized_scopes)
    args = [
        cfg.browser_path,
        "--headless",
        "--disable-gpu",
        "--use-gl=disabled",
        "--disable-gpu-sandbox",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-domain-reliability",
        "--disable-sync",
        "--disable-default-apps",
        "--disable-client-side-phishing-detection",
        "--metrics-recording-only",
        "--mute-audio",
        f"--host-resolver-rules={resolver_rules}",
        f"--remote-debugging-address={cfg.cdp_host}",
        f"--remote-debugging-port={cfg.cdp_port}",
        f"--user-data-dir={user_data_dir}",
    ]
    if "--no-sandbox" in args:
        raise HeadlessConfigurationError("Refusing to emit --no-sandbox flag")
    return args


def build_hardened_docker_run_args(
    config: Optional[HeadlessEnvironmentConfig] = None,
    volume_mounts: Sequence[Tuple[str, str, str]] = (),
    network_mode: str = "none",
    container_name: Optional[str] = None,
) -> List[str]:
    """
    Construct `docker run` arguments enforcing least privilege, read-only rootfs,
    scoped Moby-derived seccomp, non-root user, `/dev/shm` sizing, and resource limits.
    """
    cfg = config or HeadlessEnvironmentConfig()
    cfg.validate()

    docker_cmd = get_docker_cmd()
    args: List[str] = [
        docker_cmd,
        "run",
        "--rm",
        "--init",
        "--network",
        network_mode,
    ]
    if container_name:
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", container_name)
        args.extend(["--name", safe_name])

    args.extend([
        "--user", cfg.container_user,
        "--cap-drop=ALL",
        "--security-opt", "no-new-privileges:true",
        "--security-opt", f"seccomp={os.path.abspath(cfg.seccomp_profile_path)}",
        "--read-only",
        "--tmpfs", cfg.tmpfs_spec,
        "--shm-size", cfg.shm_size,
        "--pids-limit", str(cfg.pids_limit),
        "--memory", cfg.memory_limit,
        "-e", "HOME=/tmp/h",
        "-e", "XDG_CONFIG_HOME=/tmp/cfg",
        "-e", "XDG_CACHE_HOME=/tmp/cache",
    ])

    for host_path, cont_path, mode in volume_mounts:
        norm_host = (host_path or "").replace("\\", "/").lower()
        norm_cont = (cont_path or "").replace("\\", "/").lower()
        for forbidden in _FORBIDDEN_MOUNT_SNIPPETS:
            if forbidden in norm_host or forbidden in norm_cont:
                raise HeadlessConfigurationError(
                    f"Forbidden mount path rejected ({host_path} -> {cont_path})"
                )
        if mode not in ("ro", "rw"):
            raise HeadlessConfigurationError(f"Invalid mount mode: {mode!r}")
        if norm_cont in ("/", "/etc", "/root", "/var", "/var/run"):
            raise HeadlessConfigurationError(f"Forbidden sensitive container mount target: {cont_path}")
        args.extend(["-v", f"{get_docker_volume_path(host_path)}:{cont_path}:{mode}"])

    return args


def build_cdp_container_entrypoint_script(
    nuclei_args: Sequence[str],
    config: Optional[HeadlessEnvironmentConfig] = None,
    authorized_scopes: Sequence[str] = (),
    user_data_dir: str = "/tmp/chrome-profile",
) -> str:
    """
    Build container shell script that:
      1. Launches pre-installed Chromium with sandbox preserved (`-cdpe` mode).
      2. Fails fast (`exit 70`) if CDP endpoint never becomes ready, preventing
         Nuclei from attempting to download an unpinned browser over the network.
      3. Runs `nuclei -no-stdin -duc -nc -headless -cdpe "$WS_URL" ...`.
      4. Cleans up Chromium processes and temporary user-data-dir on exit.
    """
    cfg = config or HeadlessEnvironmentConfig()
    cfg.validate()

    for arg in nuclei_args:
        if arg in ("-sc", "-system-chrome"):
            # We intentionally forbid auto-spawning via go-rod in container because
            # go-rod hardcodes --no-sandbox whenever /.dockerenv exists.
            raise HeadlessConfigurationError("Do not pass -sc/-system-chrome with -cdpe entrypoint")

    chr_args = build_chromium_launch_args(
        config=cfg,
        authorized_scopes=authorized_scopes,
        user_data_dir=user_data_dir,
    )
    quoted_chr = " ".join(shlex.quote(a) for a in chr_args)
    quoted_nuc = " ".join(shlex.quote(a) for a in nuclei_args)
    wait_iters = max(4, cfg.startup_timeout_seconds * 4)

    return "\n".join([
        "set -u",
        f"mkdir -p /tmp/h /tmp/cfg /tmp/cache {shlex.quote(user_data_dir)}",
        "cleanup() {",
        '  if [ -n "${CHR_PID:-}" ]; then',
        '    kill "$CHR_PID" 2>/dev/null || true',
        '    wait "$CHR_PID" 2>/dev/null || true',
        "  fi",
        "  killall -TERM chromium chrome chrome_crashpad_handler 2>/dev/null || true",
        "  sleep 0.3",
        "  killall -KILL chromium chrome chrome_crashpad_handler 2>/dev/null || true",
        f"  rm -rf {shlex.quote(user_data_dir)}",
        "}",
        "trap cleanup EXIT INT TERM",
        f"{quoted_chr} >/tmp/chrome.log 2>&1 &",
        "CHR_PID=$!",
        'WS_URL=""',
        f"for i in $(seq 1 {wait_iters}); do",
        f"  JSON=$(wget -qO- http://{cfg.cdp_host}:{cfg.cdp_port}/json/version 2>/dev/null || true)",
        '  if [ -n "$JSON" ]; then',
        '    WS_URL=$(printf \'%s\' "$JSON" | sed -n \'s/.*"webSocketDebuggerUrl"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p\')',
        '    if [ -n "$WS_URL" ]; then break; fi',
        "  fi",
        "  if ! kill -0 \"$CHR_PID\" 2>/dev/null; then break; fi",
        "  sleep 0.25",
        "done",
        'if [ -z "$WS_URL" ]; then',
        '  echo "HEADLESS_BROWSER_START_FAILED" >&2',
        "  cat /tmp/chrome.log >&2 2>/dev/null || true",
        "  exit 70",
        "fi",
        f'nuclei -no-stdin -duc -nc -headless -cdpe "$WS_URL" {quoted_nuc}',
    ])


# ---------------------------------------------------------------------------
# Readiness Probe Models & Executor
# ---------------------------------------------------------------------------

@dataclass
class HeadlessProbeOutcome:
    """Raw structured diagnostics from isolated Headless readiness probe."""
    docker_available: bool
    browser_available: bool
    browser_binary_path: Optional[str]
    browser_version: Optional[str]
    engine_compatible: bool
    nuclei_headless_actions_ok: bool
    browser_launch_ok: bool
    js_execution_ok: bool
    nuclei_cdpe_scan_ok: bool
    non_root_ok: bool
    capabilities_dropped_ok: bool
    no_new_privs_ok: bool
    seccomp_active_ok: bool
    readonly_rootfs_ok: bool
    no_docker_sock_ok: bool
    dangerous_syscalls_blocked_ok: bool
    egress_blocked_ok: bool
    browser_sandbox_active_ok: bool
    no_sandbox_flag_absent_ok: bool
    shm_size_bytes: int
    resources_ok: bool
    cleanup_ok: bool
    blocking_reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    raw_details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HeadlessReadinessReport:
    """Server-side verified Headless execution readiness verdict."""
    ready: bool
    checked_at: str
    elapsed_seconds: float
    engine_version: str
    engine_image: str
    engine_image_digest: str
    browser_available: bool
    browser_binary_path: Optional[str]
    browser_version: Optional[str]
    engine_compatible: bool
    browser_launch_ok: bool
    isolation_verified: bool
    resources_ok: bool
    blocking_reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    security_evidence: Dict[str, Any] = field(default_factory=dict)
    functional_evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ready": self.ready,
            "checked_at": self.checked_at,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "engine_version": self.engine_version,
            "engine_image": self.engine_image,
            "engine_image_digest": self.engine_image_digest,
            "browser_available": self.browser_available,
            "browser_binary_path": self.browser_binary_path,
            "browser_version": self.browser_version,
            "engine_compatible": self.engine_compatible,
            "browser_launch_ok": self.browser_launch_ok,
            "isolation_verified": self.isolation_verified,
            "resources_ok": self.resources_ok,
            "blocking_reasons": list(self.blocking_reasons),
            "warnings": list(self.warnings),
            "security_evidence": dict(self.security_evidence),
            "functional_evidence": dict(self.functional_evidence),
        }


class HeadlessProbeExecutor(Protocol):
    """Protocol for probing Headless readiness (enables deterministic unit testing)."""

    def run_probe(self, config: HeadlessEnvironmentConfig) -> HeadlessProbeOutcome:
        ...


class DockerHeadlessProbeExecutor:
    """
    Executes an isolated `--network none` Docker self-test against the pinned
    Nuclei image, proving browser availability, JS execution, Nuclei `-cdpe`
    compatibility, container/browser sandbox isolation, and resource cleanup.
    """

    def run_probe(self, config: HeadlessEnvironmentConfig) -> HeadlessProbeOutcome:
        config.validate()
        docker_cmd = get_docker_cmd()

        # Check pinned Docker image availability first (20s timeout handles slow Windows Docker Desktop)
        try:
            insp = subprocess.run(
                [docker_cmd, "image", "inspect", config.docker_image],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20.0,
            )
            if insp.returncode != 0:
                err = (insp.stderr or "").strip() or f"exit {insp.returncode}"
                return _failed_outcome(
                    docker_available=False,
                    reason=f"Pinned Docker image unavailable ({config.docker_image}): {err}",
                )
        except Exception as exc:
            return _failed_outcome(
                docker_available=False,
                reason=f"Docker daemon unreachable: {exc}",
            )

        probe_tmpl = """id: probe-headless-readiness
info:
  name: YemScan Headless Readiness Self-Test
  author: yemenscan
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}"
      - action: waitload
      - action: script
        name: jsval
        args:
          code: |
            () => document.getElementById('r') ? document.getElementById('r').textContent : ''
    matchers:
      - type: word
        words:
          - "YEMSCAN_HEADLESS_JS_6X7=42"
    extractors:
      - type: kval
        part: jsval
        kval:
          - jsval
"""

        with tempfile.TemporaryDirectory(prefix="yemenscan_headless_probe_") as tmp_dir:
            with open(os.path.join(tmp_dir, "probe.yaml"), "w", encoding="utf-8") as fh:
                fh.write(probe_tmpl)
            with open(os.path.join(tmp_dir, "targets.txt"), "w", encoding="utf-8") as fh:
                fh.write("http://127.0.0.1:18080/\n")

            docker_args = build_hardened_docker_run_args(
                config=config,
                volume_mounts=[(tmp_dir, "/in", "ro")],
                network_mode="none",
            )
            chr_args = build_chromium_launch_args(
                config=config,
                authorized_scopes=(),
                user_data_dir="/tmp/prof",
            )
            quoted_chr = " ".join(shlex.quote(a) for a in chr_args)

            container_sh = "\n".join([
                "set -u",
                "mkdir -p /tmp/h /tmp/cfg /tmp/cache /tmp/prof",
                f"if [ -x {shlex.quote(config.browser_path)} ]; then echo \"PROBE_BIN={config.browser_path}\"; else echo \"PROBE_BIN=\"; fi",
                f"VER_OUT=$({shlex.quote(config.browser_path)} --version 2>/dev/null || true)",
                "echo \"PROBE_CHR_VER=$VER_OUT\"",
                "LHA_OUT=$(nuclei -no-stdin -duc -nc -lha 2>&1 || true)",
                "if printf '%s' \"$LHA_OUT\" | grep -q 'navigate' && printf '%s' \"$LHA_OUT\" | grep -q 'script'; then echo 'PROBE_LHA=OK'; else echo 'PROBE_LHA=FAIL'; fi",
                # Static container security inspection
                "echo \"PROBE_UID=$(id -u):$(id -g)\"",
                "grep -E '^(CapEff|CapBnd|NoNewPrivs|Seccomp):' /proc/self/status | sed 's/^/PROBE_STATUS_/'",
                "mount | grep ' on / ' | head -n 1 | sed 's/^/PROBE_ROOTFS=/'",
                "if [ ! -e /var/run/docker.sock ]; then echo 'PROBE_NO_SOCK=OK'; else echo 'PROBE_NO_SOCK=FAIL'; fi",
                "SHM_KB=$(df -k /dev/shm | awk 'NR==2 {print $2}')",
                "echo \"PROBE_SHM_KB=${SHM_KB:-0}\"",
                "if unshare -m true 2>/dev/null; then echo 'PROBE_SYSCALL_BLOCK=FAIL'; else echo 'PROBE_SYSCALL_BLOCK=OK'; fi",
                "if wget -T 2 -qO- http://example.com >/dev/null 2>&1; then echo 'PROBE_EGRESS_BLOCK=FAIL'; else echo 'PROBE_EGRESS_BLOCK=OK'; fi",
                # Local loopback HTTP server inside isolated container
                "cat << 'EOF' > /tmp/handler.sh",
                "while IFS= read -r line; do",
                "  line=$(printf '%s' \"$line\" | tr -d '\\r')",
                "  [ -z \"$line\" ] && break",
                "done",
                "BODY=\"<html><body><div id='r'>loading</div><script>document.getElementById('r').textContent='YEMSCAN_HEADLESS_JS_6X7='+(6*7);</script></body></html>\"",
                "LEN=$(printf '%s' \"$BODY\" | wc -c)",
                "printf 'HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\nContent-Length: %s\\r\\nConnection: close\\r\\n\\r\\n%s' \"$LEN\" \"$BODY\"",
                "EOF",
                "nc -lk -p 18080 -e /bin/sh /tmp/handler.sh &",
                "SRV_PID=$!",
                "cleanup() {",
                "  if [ -n \"${CHR_PID:-}\" ]; then kill \"$CHR_PID\" 2>/dev/null || true; wait \"$CHR_PID\" 2>/dev/null || true; fi",
                "  if [ -n \"${SRV_PID:-}\" ]; then kill \"$SRV_PID\" 2>/dev/null || true; wait \"$SRV_PID\" 2>/dev/null || true; fi",
                "  rm -rf /tmp/prof",
                "}",
                "trap cleanup EXIT INT TERM",
                f"{quoted_chr} >/tmp/chrome.log 2>&1 &",
                "CHR_PID=$!",
                "WS_URL=\"\"",
                "for i in $(seq 1 40); do",
                f"  JSON=$(wget -qO- http://{config.cdp_host}:{config.cdp_port}/json/version 2>/dev/null || true)",
                "  if [ -n \"$JSON\" ]; then",
                "    WS_URL=$(printf '%s' \"$JSON\" | sed -n 's/.*\"webSocketDebuggerUrl\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p')",
                "    [ -n \"$WS_URL\" ] && break",
                "  fi",
                "  if ! kill -0 \"$CHR_PID\" 2>/dev/null; then break; fi",
                "  sleep 0.25",
                "done",
                "echo \"PROBE_WS_READY=$([ -n \"$WS_URL\" ] && echo OK || echo FAIL)\"",
                "echo \"PROBE_WS_URL=$WS_URL\"",
                # Inspect running Chromium children for active user/PID sandbox and absence of --no-sandbox
                "NESTED_NS=0",
                "NOSB_FOUND=0",
                "for p in /proc/[0-9]*; do",
                "  [ -r \"$p/status\" ] || continue",
                "  NSPID=$(grep '^NSpid:' \"$p/status\" 2>/dev/null || true)",
                "  CNT=$(printf '%s' \"$NSPID\" | wc -w)",
                "  SC=$(grep '^Seccomp:' \"$p/status\" 2>/dev/null | awk '{print $2}')",
                "  if [ \"$CNT\" -ge 3 ] && [ \"${SC:-0}\" = \"2\" ]; then NESTED_NS=$((NESTED_NS + 1)); fi",
                "  if [ -r \"$p/cmdline\" ]; then",
                "    CMDLINE=$(tr '\\0' ' ' < \"$p/cmdline\" 2>/dev/null || true)",
                "    case \"$CMDLINE\" in",
                "      /usr/lib/chromium/*)",
                "        case \"$CMDLINE\" in *--no-sandbox*) NOSB_FOUND=1 ;; esac",
                "        ;;",
                "    esac",
                "  fi",
                "done",
                "echo \"PROBE_SANDBOX_NS_PROCS=$NESTED_NS\"",
                "echo \"PROBE_NO_SANDBOX_ABSENT=$([ \"$NOSB_FOUND\" -eq 0 ] && echo OK || echo FAIL)\"",
                "if [ -n \"$WS_URL\" ]; then",
                "  NUC_OUT=$(nuclei -no-stdin -duc -nc -headless -cdpe \"$WS_URL\" -l /in/targets.txt -t /in/probe.yaml 2>&1)",
                "  NUC_RC=$?",
                "  echo \"PROBE_NUC_RC=$NUC_RC\"",
                "  if printf '%s' \"$NUC_OUT\" | grep -q 'probe-headless-readiness' && printf '%s' \"$NUC_OUT\" | grep -q 'YEMSCAN_HEADLESS_JS_6X7=42'; then",
                "    echo 'PROBE_JS_MATCH=OK'",
                "  else",
                "    echo 'PROBE_JS_MATCH=FAIL'",
                "  fi",
                "  printf '%s\\n' \"$NUC_OUT\" | sed 's/^/PROBE_NUC_LINE=/'",
                "else",
                "  echo 'PROBE_NUC_RC=70'",
                "  echo 'PROBE_JS_MATCH=FAIL'",
                "fi",
                # Explicit teardown verification
                "kill \"$CHR_PID\" 2>/dev/null || true",
                "wait \"$CHR_PID\" 2>/dev/null || true",
                "CHR_PID=\"\"",
                "killall -TERM chromium chrome chrome_crashpad_handler 2>/dev/null || true",
                "for _k in 1 2 3 4 5 6; do",
                "  REM=$(ps -o comm | grep -E '^(chromium|chrome)' || true)",
                "  [ -z \"$REM\" ] && break",
                "  sleep 0.25",
                "done",
                "if [ -n \"${REM:-}\" ]; then",
                "  killall -KILL chromium chrome chrome_crashpad_handler 2>/dev/null || true",
                "  sleep 0.25",
                "  REM=$(ps -o comm | grep -E '^(chromium|chrome)' || true)",
                "fi",
                "rm -rf /tmp/prof",
                "echo \"PROBE_CLEANUP=$([ -z \"${REM:-}\" ] && echo OK || echo FAIL)\"",
            ])

            cmd = docker_args + ["--entrypoint", "sh", config.docker_image, "-c", container_sh]
            try:
                proc = subprocess.run(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=config.probe_timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                return _failed_outcome(
                    docker_available=True,
                    reason=f"Headless readiness probe timed out after {config.probe_timeout_seconds}s: {exc}",
                )
            except Exception as exc:
                return _failed_outcome(
                    docker_available=True,
                    reason=f"Headless readiness probe execution failed: {exc}",
                )

        return _parse_probe_output(proc.returncode, proc.stdout or "", proc.stderr or "")


def _failed_outcome(docker_available: bool, reason: str) -> HeadlessProbeOutcome:
    return HeadlessProbeOutcome(
        docker_available=docker_available,
        browser_available=False,
        browser_binary_path=None,
        browser_version=None,
        engine_compatible=False,
        nuclei_headless_actions_ok=False,
        browser_launch_ok=False,
        js_execution_ok=False,
        nuclei_cdpe_scan_ok=False,
        non_root_ok=False,
        capabilities_dropped_ok=False,
        no_new_privs_ok=False,
        seccomp_active_ok=False,
        readonly_rootfs_ok=False,
        no_docker_sock_ok=False,
        dangerous_syscalls_blocked_ok=False,
        egress_blocked_ok=False,
        browser_sandbox_active_ok=False,
        no_sandbox_flag_absent_ok=False,
        shm_size_bytes=0,
        resources_ok=False,
        cleanup_ok=False,
        blocking_reasons=[reason],
    )


def _parse_probe_output(returncode: int, stdout: str, stderr: str) -> HeadlessProbeOutcome:
    kv: Dict[str, str] = {}
    nuc_lines: List[str] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if line.startswith("PROBE_NUC_LINE="):
            nuc_lines.append(line[len("PROBE_NUC_LINE="):])
        elif line.startswith("PROBE_STATUS_"):
            rest = line[len("PROBE_STATUS_"):]
            if ":" in rest:
                k, v = rest.split(":", 1)
                kv[f"STATUS_{k.strip()}"] = v.strip()
        elif line.startswith("PROBE_") and "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()

    browser_bin = kv.get("PROBE_BIN") or None
    browser_ver = kv.get("PROBE_CHR_VER") or None
    browser_available = bool(
        browser_bin
        and browser_ver
        and re.match(r"^(?:chromium|google chrome)\s+\d+\.", browser_ver.strip(), re.IGNORECASE)
    )

    lha_ok = kv.get("PROBE_LHA") == "OK"
    ws_ready = kv.get("PROBE_WS_READY") == "OK"
    js_match = kv.get("PROBE_JS_MATCH") == "OK"
    nuc_rc = kv.get("PROBE_NUC_RC")
    nuc_scan_ok = (nuc_rc == "0") and js_match

    non_root_ok = False
    uid_gid = kv.get("PROBE_UID", "")
    if ":" in uid_gid:
        u_s, g_s = uid_gid.split(":", 1)
        non_root_ok = u_s.isdigit() and g_s.isdigit() and int(u_s) > 0 and int(g_s) > 0

    cap_eff_ok = kv.get("STATUS_CapEff") == "0000000000000000"
    cap_bnd_ok = kv.get("STATUS_CapBnd") == "0000000000000000"
    caps_dropped_ok = cap_eff_ok and cap_bnd_ok
    no_new_privs_ok = kv.get("STATUS_NoNewPrivs") == "1"
    seccomp_active_ok = kv.get("STATUS_Seccomp") == "2"

    rootfs = kv.get("PROBE_ROOTFS", "")
    readonly_ok = "(ro," in rootfs or ",ro," in rootfs or ",ro)" in rootfs

    no_sock_ok = kv.get("PROBE_NO_SOCK") == "OK"
    syscalls_blocked_ok = kv.get("PROBE_SYSCALL_BLOCK") == "OK"
    egress_blocked_ok = kv.get("PROBE_EGRESS_BLOCK") == "OK"

    ns_procs = int(kv.get("PROBE_SANDBOX_NS_PROCS", "0") or "0")
    browser_sandbox_ok = ns_procs >= 1
    no_sandbox_absent_ok = kv.get("PROBE_NO_SANDBOX_ABSENT") == "OK"

    shm_kb = int(kv.get("PROBE_SHM_KB", "0") or "0")
    shm_bytes = shm_kb * 1024
    resources_ok = shm_bytes >= NUCLEI_HEADLESS_MIN_SHM_BYTES
    cleanup_ok = kv.get("PROBE_CLEANUP") == "OK"

    engine_compatible = browser_available and lha_ok and ws_ready
    browser_launch_ok = ws_ready and nuc_scan_ok and js_match

    reasons: List[str] = []
    if returncode != 0 and not kv:
        reasons.append(f"Container probe failed (exit {returncode}): {(stderr or '').strip()[:300]}")
    if not browser_available:
        reasons.append("Chromium binary missing or failed version check")
    if not lha_ok:
        reasons.append("Nuclei headless action support check (-lha) failed")
    if not ws_ready:
        reasons.append("Chromium CDP WebSocket endpoint failed to start cleanly")
    if not nuc_scan_ok:
        reasons.append(f"Nuclei -headless -cdpe JS execution probe failed (rc={nuc_rc})")
    if not non_root_ok:
        reasons.append(f"Container did not run as non-root user (uid:gid={uid_gid})")
    if not caps_dropped_ok:
        reasons.append("Linux capabilities not fully dropped inside container")
    if not no_new_privs_ok:
        reasons.append("no-new-privileges flag is inactive inside container")
    if not seccomp_active_ok:
        reasons.append("Docker seccomp filtering is not active (Seccomp != 2)")
    if not readonly_ok:
        reasons.append("Container root filesystem is not mounted read-only")
    if not no_sock_ok:
        reasons.append("Docker socket unexpectedly accessible inside Headless container")
    if not syscalls_blocked_ok:
        reasons.append("Restricted namespace/mount syscalls were not blocked by seccomp")
    if not egress_blocked_ok:
        reasons.append("Unauthorized outbound network egress was not blocked")
    if not browser_sandbox_ok:
        reasons.append("Chromium renderer/zygote user+PID namespace sandbox processes not detected")
    if not no_sandbox_absent_ok:
        reasons.append("Insecure --no-sandbox flag detected on Chromium command line")
    if not resources_ok:
        reasons.append(f"Insufficient /dev/shm size ({shm_bytes} bytes < {NUCLEI_HEADLESS_MIN_SHM_BYTES})")
    if not cleanup_ok:
        reasons.append("Leftover Chromium child processes remained after teardown")

    return HeadlessProbeOutcome(
        docker_available=True,
        browser_available=browser_available,
        browser_binary_path=browser_bin,
        browser_version=browser_ver,
        engine_compatible=engine_compatible,
        nuclei_headless_actions_ok=lha_ok,
        browser_launch_ok=browser_launch_ok,
        js_execution_ok=js_match,
        nuclei_cdpe_scan_ok=nuc_scan_ok,
        non_root_ok=non_root_ok,
        capabilities_dropped_ok=caps_dropped_ok,
        no_new_privs_ok=no_new_privs_ok,
        seccomp_active_ok=seccomp_active_ok,
        readonly_rootfs_ok=readonly_ok,
        no_docker_sock_ok=no_sock_ok,
        dangerous_syscalls_blocked_ok=syscalls_blocked_ok,
        egress_blocked_ok=egress_blocked_ok,
        browser_sandbox_active_ok=browser_sandbox_ok,
        no_sandbox_flag_absent_ok=no_sandbox_absent_ok,
        shm_size_bytes=shm_bytes,
        resources_ok=resources_ok,
        cleanup_ok=cleanup_ok,
        blocking_reasons=reasons,
        warnings=[
            "GPU subprocess uses --disable-gpu-sandbox alongside --disable-gpu --use-gl=disabled due to Alpine 3.24 Chromium 150 Vulkan/BPF trap (nr=0x148); all Renderer/Zygote/Utility sandboxes remain enforced."
        ],
        raw_details={
            "ws_url_present": bool(kv.get("PROBE_WS_URL")),
            "sandbox_nested_ns_procs": ns_procs,
            "nuclei_output": nuc_lines,
        },
    )


# ---------------------------------------------------------------------------
# Readiness Service
# ---------------------------------------------------------------------------

class HeadlessReadinessService:
    """
    Shared server-side verifier determining whether Headless Nuclei templates
    have a compatible, sandboxed, resource-backed execution environment.
    """

    def __init__(
        self,
        config: Optional[HeadlessEnvironmentConfig] = None,
        executor: Optional[HeadlessProbeExecutor] = None,
        cache_ttl_seconds: float = 120.0,
    ) -> None:
        self.config = config or HeadlessEnvironmentConfig()
        self.executor: HeadlessProbeExecutor = executor or DockerHeadlessProbeExecutor()
        self.cache_ttl_seconds = cache_ttl_seconds
        self._lock = threading.Lock()
        self._cached_report: Optional[HeadlessReadinessReport] = None
        self._cached_at_mono: float = 0.0

    def invalidate_cache(self) -> None:
        with self._lock:
            self._cached_report = None
            self._cached_at_mono = 0.0

    def check_readiness(self, force_refresh: bool = False) -> HeadlessReadinessReport:
        """
        Verify browser, compatibility, launch, isolation, and resources.
        Never trusts client-supplied readiness booleans.
        """
        with self._lock:
            now_m = time.monotonic()
            if (
                not force_refresh
                and self._cached_report is not None
                and (now_m - self._cached_at_mono) < self.cache_ttl_seconds
            ):
                return self._cached_report

        t0 = time.monotonic()
        try:
            self.config.validate()
        except HeadlessConfigurationError as exc:
            report = HeadlessReadinessReport(
                ready=False,
                checked_at=datetime.now(timezone.utc).isoformat(),
                elapsed_seconds=time.monotonic() - t0,
                engine_version=self.config.engine_version,
                engine_image=self.config.docker_image,
                engine_image_digest=self.config.engine_digest,
                browser_available=False,
                browser_binary_path=None,
                browser_version=None,
                engine_compatible=False,
                browser_launch_ok=False,
                isolation_verified=False,
                resources_ok=False,
                blocking_reasons=[f"Invalid Headless security configuration: {exc}"],
            )
            with self._lock:
                self._cached_report = report
                self._cached_at_mono = time.monotonic()
            return report

        outcome = self.executor.run_probe(self.config)
        elapsed = time.monotonic() - t0

        isolation_verified = (
            outcome.non_root_ok
            and outcome.capabilities_dropped_ok
            and outcome.no_new_privs_ok
            and outcome.seccomp_active_ok
            and outcome.readonly_rootfs_ok
            and outcome.no_docker_sock_ok
            and outcome.dangerous_syscalls_blocked_ok
            and outcome.egress_blocked_ok
            and outcome.browser_sandbox_active_ok
            and outcome.no_sandbox_flag_absent_ok
        )
        resources_ok = outcome.resources_ok and outcome.cleanup_ok

        ready = (
            outcome.docker_available
            and outcome.browser_available
            and outcome.engine_compatible
            and outcome.browser_launch_ok
            and isolation_verified
            and resources_ok
            and len(outcome.blocking_reasons) == 0
        )

        report = HeadlessReadinessReport(
            ready=ready,
            checked_at=datetime.now(timezone.utc).isoformat(),
            elapsed_seconds=elapsed,
            engine_version=self.config.engine_version,
            engine_image=self.config.docker_image,
            engine_image_digest=self.config.engine_digest,
            browser_available=outcome.browser_available,
            browser_binary_path=outcome.browser_binary_path,
            browser_version=outcome.browser_version,
            engine_compatible=outcome.engine_compatible,
            browser_launch_ok=outcome.browser_launch_ok,
            isolation_verified=isolation_verified,
            resources_ok=resources_ok,
            blocking_reasons=list(outcome.blocking_reasons),
            warnings=list(outcome.warnings),
            security_evidence={
                "non_root_ok": outcome.non_root_ok,
                "capabilities_dropped_ok": outcome.capabilities_dropped_ok,
                "no_new_privs_ok": outcome.no_new_privs_ok,
                "seccomp_active_ok": outcome.seccomp_active_ok,
                "readonly_rootfs_ok": outcome.readonly_rootfs_ok,
                "no_docker_sock_ok": outcome.no_docker_sock_ok,
                "dangerous_syscalls_blocked_ok": outcome.dangerous_syscalls_blocked_ok,
                "egress_blocked_ok": outcome.egress_blocked_ok,
                "browser_sandbox_active_ok": outcome.browser_sandbox_active_ok,
                "no_sandbox_flag_absent_ok": outcome.no_sandbox_flag_absent_ok,
                "sandbox_nested_ns_procs": outcome.raw_details.get("sandbox_nested_ns_procs", 0),
                "cleanup_ok": outcome.cleanup_ok,
            },
            functional_evidence={
                "docker_available": outcome.docker_available,
                "nuclei_headless_actions_ok": outcome.nuclei_headless_actions_ok,
                "js_execution_ok": outcome.js_execution_ok,
                "nuclei_cdpe_scan_ok": outcome.nuclei_cdpe_scan_ok,
                "shm_size_bytes": outcome.shm_size_bytes,
                "nuclei_output": outcome.raw_details.get("nuclei_output", []),
            },
        )

        with self._lock:
            self._cached_report = report
            self._cached_at_mono = time.monotonic()
        return report
