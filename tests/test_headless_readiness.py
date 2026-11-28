"""
YemScan — Phase 7.2.1 Tests: Secure Headless Execution Readiness.

Covers:
  - Hardened container + Chromium config validation & seccomp profile audit
  - Browser sandbox preservation (no --no-sandbox), non-root UID, read-only rootfs,
    /dev/shm >= 512MB, PID/memory caps, Docker socket exclusion, scope DNS rules
  - Fail-fast browser startup guard preventing auto-download over network
  - Failure isolation: functional pass WITHOUT isolation still yields ready=False
  - Anti-spoofing: untrusted caller capabilities cannot force headless_available=True
  - Preserves policy eligibility of all 222 Headless templates even when unavailable
  - Live isolated Docker probe against pinned projectdiscovery/nuclei:v3.11.1
  - Live official v10.5.1 signed headless template execution in hardened container
  - Real PostgreSQL evaluation across all 222 cataloged Headless templates
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

import pytest
from sqlalchemy import text

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal
from core.headless_readiness import (
    DockerHeadlessProbeExecutor,
    HeadlessConfigurationError,
    HeadlessEnvironmentConfig,
    HeadlessProbeOutcome,
    HeadlessReadinessService,
    build_cdp_container_entrypoint_script,
    build_chromium_launch_args,
    build_hardened_docker_run_args,
    build_host_resolver_rules,
    validate_seccomp_profile,
)
from core.nuclei_shared import (
    NUCLEI_DOCKER_IMAGE,
    NUCLEI_HEADLESS_SECCOMP_PROFILE,
)
from core.runner import get_docker_cmd, get_docker_volume_path
from core.template_selection_service import (
    EnvironmentCapabilities,
    ScanMode,
    TemplateSelectionService,
)

LIVE_VERSION_ID = "a1301c8a-e54e-4c6b-bd96-3b71d266d221"


def _pinned_image_present() -> bool:
    try:
        res = subprocess.run(
            [get_docker_cmd(), "image", "inspect", NUCLEI_DOCKER_IMAGE],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=20.0,
        )
        return res.returncode == 0
    except Exception:
        return False


class FakeProbeExecutor:
    def __init__(self, outcome: HeadlessProbeOutcome) -> None:
        self.outcome = outcome
        self.calls = 0

    def run_probe(self, config: HeadlessEnvironmentConfig) -> HeadlessProbeOutcome:
        self.calls += 1
        return self.outcome


def _healthy_outcome() -> HeadlessProbeOutcome:
    return HeadlessProbeOutcome(
        docker_available=True,
        browser_available=True,
        browser_binary_path="/usr/bin/chromium",
        browser_version="Chromium 150.0.7871.181 Alpine Linux",
        engine_compatible=True,
        nuclei_headless_actions_ok=True,
        browser_launch_ok=True,
        js_execution_ok=True,
        nuclei_cdpe_scan_ok=True,
        non_root_ok=True,
        capabilities_dropped_ok=True,
        no_new_privs_ok=True,
        seccomp_active_ok=True,
        readonly_rootfs_ok=True,
        no_docker_sock_ok=True,
        dangerous_syscalls_blocked_ok=True,
        egress_blocked_ok=True,
        browser_sandbox_active_ok=True,
        no_sandbox_flag_absent_ok=True,
        shm_size_bytes=1024 * 1024 * 1024,
        resources_ok=True,
        cleanup_ok=True,
        blocking_reasons=[],
        raw_details={"sandbox_nested_ns_procs": 6},
    )


# ---------------------------------------------------------------------------
# Unit & Security Policy Tests
# ---------------------------------------------------------------------------

def test_01_seccomp_profile_is_scoped_default_errno():
    data = validate_seccomp_profile(NUCLEI_HEADLESS_SECCOMP_PROFILE)
    assert data["defaultAction"] == "SCMP_ACT_ERRNO"

    # Dangerous syscalls remain gated/excluded from unconditional allow
    for rule in data["syscalls"]:
        if rule.get("action") == "SCMP_ACT_ALLOW" and not rule.get("includes"):
            names = set(rule.get("names") or [])
            assert not (names & {"mount", "bpf", "ptrace", "kexec_load", "init_module", "perf_event_open", "reboot"})


def test_02_config_rejects_weak_isolation_or_root_or_small_shm(tmp_path):
    with pytest.raises(HeadlessConfigurationError):
        HeadlessEnvironmentConfig(container_user="0:0").validate()

    with pytest.raises(HeadlessConfigurationError):
        HeadlessEnvironmentConfig(container_user="root:root").validate()

    with pytest.raises(HeadlessConfigurationError):
        HeadlessEnvironmentConfig(shm_size="64m").validate()

    with pytest.raises(HeadlessConfigurationError):
        HeadlessEnvironmentConfig(cdp_host="0.0.0.0").validate()

    with pytest.raises(HeadlessConfigurationError):
        HeadlessEnvironmentConfig(docker_image="projectdiscovery/nuclei:latest").validate()

    bad_seccomp = tmp_path / "bad_sec.json"
    bad_seccomp.write_text(json.dumps({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": []}))
    with pytest.raises(HeadlessConfigurationError):
        HeadlessEnvironmentConfig(seccomp_profile_path=str(bad_seccomp)).validate()


def test_03_builders_enforce_sandbox_no_socket_and_scope_dns():
    cfg = HeadlessEnvironmentConfig()
    chr_args = build_chromium_launch_args(cfg, authorized_scopes=["*.example.com", "https://api.test.local:8443"])
    assert "--no-sandbox" not in chr_args
    assert "--disable-dev-shm-usage" not in chr_args
    assert "--remote-debugging-address=127.0.0.1" in chr_args
    rules_arg = [a for a in chr_args if a.startswith("--host-resolver-rules=")][0]
    assert "MAP * ~NOTFOUND" in rules_arg
    assert "EXCLUDE *.example.com" in rules_arg
    assert "EXCLUDE example.com" in rules_arg
    assert "EXCLUDE api.test.local" in rules_arg

    # Unsafe scope tokens ignored
    rules_sanitized = build_host_resolver_rules(["bad;rm -rf /", "ok.example.org"])
    assert "rm -rf" not in rules_sanitized
    assert "EXCLUDE ok.example.org" in rules_sanitized

    docker_args = build_hardened_docker_run_args(cfg, network_mode="none")
    joined = " ".join(docker_args)
    assert "--user 65534:65534" in joined
    assert "--cap-drop=ALL" in joined
    assert "no-new-privileges:true" in joined
    assert "--read-only" in joined
    assert "--shm-size 1g" in joined
    assert "--privileged" not in joined
    assert "seccomp=unconfined" not in joined

    with pytest.raises(HeadlessConfigurationError):
        build_hardened_docker_run_args(cfg, volume_mounts=[("/var/run/docker.sock", "/var/run/docker.sock", "ro")])

    with pytest.raises(HeadlessConfigurationError):
        build_hardened_docker_run_args(cfg, volume_mounts=[(os.getcwd(), "/app/.env", "ro")])

    script = build_cdp_container_entrypoint_script(["-l", "/in/targets.txt"], cfg)
    assert "exit 70" in script
    assert "trap cleanup EXIT INT TERM" in script
    assert "-headless -cdpe" in script
    assert "--no-sandbox" not in script

    with pytest.raises(HeadlessConfigurationError):
        build_cdp_container_entrypoint_script(["-sc", "-l", "/in/targets.txt"], cfg)


def test_04_functional_pass_without_isolation_never_reports_ready():
    # Even when js_execution_ok and nuclei_cdpe_scan_ok are True,
    # failing isolation MUST mark ready=False!
    out = _healthy_outcome()
    out.no_sandbox_flag_absent_ok = False
    out.blocking_reasons = ["Insecure --no-sandbox flag detected"]

    svc = HeadlessReadinessService(executor=FakeProbeExecutor(out))
    report = svc.check_readiness(force_refresh=True)
    assert report.browser_launch_ok is True
    assert report.isolation_verified is False
    assert report.ready is False

    # Missing browser sandbox also blocks readiness
    out2 = _healthy_outcome()
    out2.browser_sandbox_active_ok = False
    out2.blocking_reasons = ["Chromium sandbox processes missing"]
    svc2 = HeadlessReadinessService(executor=FakeProbeExecutor(out2))
    r2 = svc2.check_readiness(force_refresh=True)
    assert r2.isolation_verified is False
    assert r2.ready is False

    # Browser launch crash failure -> ready=False
    out3 = _healthy_outcome()
    out3.browser_launch_ok = False
    out3.js_execution_ok = False
    out3.nuclei_cdpe_scan_ok = False
    out3.blocking_reasons = ["Chromium CDP WebSocket endpoint failed"]
    svc3 = HeadlessReadinessService(executor=FakeProbeExecutor(out3))
    r3 = svc3.check_readiness(force_refresh=True)
    assert r3.ready is False


def test_05_anti_spoofing_and_policy_eligibility_preserved_when_headless_down():
    down_out = _healthy_outcome()
    down_out.browser_launch_ok = False
    down_out.blocking_reasons = ["Simulated browser failure"]
    down_svc = HeadlessReadinessService(executor=FakeProbeExecutor(down_out))
    down_report = down_svc.check_readiness(force_refresh=True)
    assert down_report.ready is False

    # Caller tries to spoof headless_available=True in payload -> MUST be ignored
    spoof_caps = EnvironmentCapabilities.from_server_and_user_input(
        headless_report=down_report,
        user_payload={"headless_available": True},
        authorized_scopes=["*.example.com"],
    )
    assert spoof_caps.headless_available is False
    assert spoof_caps.headless_server_verified is True

    # Bound TemplateSelectionService also overrides untrusted caller caps
    db = SessionLocal()
    try:
        # Pick real headless-only template from v10.5.1 catalog if present
        row = db.execute(
            text(
                "SELECT template_id FROM nuclei_templates "
                "WHERE repository_version_id = :vid "
                "  AND (sequential_eligible OR independent_eligible) "
                "  AND 'headless' = ANY(protocols) "
                "  AND NOT (relative_path LIKE 'dast/%%') "
                "LIMIT 1"
            ),
            {"vid": LIVE_VERSION_ID},
        ).first()
        if row is None:
            pytest.skip("Live catalog version not present in PostgreSQL")
        tid = row[0]

        sel = TemplateSelectionService(session=db, headless_readiness_service=down_svc)
        res = sel.evaluate_target_and_readiness(
            repository_version_id=LIVE_VERSION_ID,
            template_ids=[tid],
            target="https://app.example.com",
            environment_caps=EnvironmentCapabilities(
                headless_available=True,  # Attempted client override!
                authorized_scopes=["*.example.com"],
            ),
        )
        assert res.server_headless_verified is True
        assert res.headless_blocking_reasons == ["Simulated browser failure"]
        assert res.templates[0].eligible is True  # Policy eligibility untouched!
        assert res.templates[0].execution_ready is False
        assert res.templates[0].overall_ready is False
        assert "headless_browser_unavailable" in res.templates[0].blocking_reasons
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Live Isolated Docker Functional & Security Tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _pinned_image_present(), reason="Pinned Nuclei Docker image unavailable")
def test_06_live_isolated_docker_readiness_functional_and_security():
    service = HeadlessReadinessService(
        config=HeadlessEnvironmentConfig(),
        executor=DockerHeadlessProbeExecutor(),
    )
    report = service.check_readiness(force_refresh=True)

    assert report.ready is True, f"Headless readiness failed: {report.blocking_reasons}"
    assert report.browser_available is True
    assert report.browser_binary_path == "/usr/bin/chromium"
    assert "chromium" in (report.browser_version or "").lower()
    assert report.engine_compatible is True
    assert report.browser_launch_ok is True
    assert report.isolation_verified is True
    assert report.resources_ok is True

    sec = report.security_evidence
    assert sec["non_root_ok"] is True
    assert sec["capabilities_dropped_ok"] is True
    assert sec["no_new_privs_ok"] is True
    assert sec["seccomp_active_ok"] is True
    assert sec["readonly_rootfs_ok"] is True
    assert sec["no_docker_sock_ok"] is True
    assert sec["dangerous_syscalls_blocked_ok"] is True
    assert sec["egress_blocked_ok"] is True
    assert sec["browser_sandbox_active_ok"] is True
    assert sec["no_sandbox_flag_absent_ok"] is True
    assert sec["sandbox_nested_ns_procs"] >= 1
    assert sec["cleanup_ok"] is True

    func = report.functional_evidence
    assert func["js_execution_ok"] is True
    assert func["nuclei_cdpe_scan_ok"] is True
    assert func["shm_size_bytes"] >= 512 * 1024 * 1024


@pytest.mark.skipif(not _pinned_image_present(), reason="Pinned Nuclei Docker image unavailable")
def test_07_live_official_v1051_headless_templates_and_browser_failure_handling():
    snap_extract = r"d:\yemenscan1\storage\nuclei\versions\a1301c8a-e54e-4c6b-bd96-3b71d266d221\headless\extract-urls.yaml"
    snap_cookie = r"d:\yemenscan1\storage\nuclei\versions\a1301c8a-e54e-4c6b-bd96-3b71d266d221\headless\cookie-consent-detection.yaml"
    if not (os.path.isfile(snap_extract) and os.path.isfile(snap_cookie)):
        pytest.skip("Official v10.5.1 headless templates snapshot missing")

    cfg = HeadlessEnvironmentConfig()
    with tempfile.TemporaryDirectory() as tmp:
        for src in (snap_extract, snap_cookie):
            with open(src, "r", encoding="utf-8") as rf:
                with open(os.path.join(tmp, os.path.basename(src)), "w", encoding="utf-8") as wf:
                    wf.write(rf.read())
        with open(os.path.join(tmp, "targets.txt"), "w", encoding="utf-8") as tf:
            tf.write("http://127.0.0.1:18081/\n")

        docker_args = build_hardened_docker_run_args(
            config=cfg,
            volume_mounts=[(tmp, "/in", "ro")],
            network_mode="none",
        )
        run_script = build_cdp_container_entrypoint_script(
            nuclei_args=[
                "-l", "/in/targets.txt",
                "-t", "/in/extract-urls.yaml",
                "-t", "/in/cookie-consent-detection.yaml",
                "-headc", "1",
            ],
            config=cfg,
            authorized_scopes=["127.0.0.1"],
        )
        full_sh = "\n".join([
            "cat << 'EOF' > /tmp/srv.sh",
            "while IFS= read -r l; do l=$(printf '%s' \"$l\" | tr -d '\\r'); [ -z \"$l\" ] && break; done",
            "B='<html><body><p>We use cookies</p><a href=\"http://127.0.0.1:18081/app.js\">js</a></body></html>'",
            "L=$(printf '%s' \"$B\" | wc -c)",
            "printf 'HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\nContent-Length: %s\\r\\nConnection: close\\r\\n\\r\\n%s' \"$L\" \"$B\"",
            "EOF",
            "nc -lk -p 18081 -e /bin/sh /tmp/srv.sh &",
            "SRV_PID=$!",
            run_script,
            "RC=$?",
            "kill $SRV_PID 2>/dev/null || true",
            "exit $RC",
        ])

        res = subprocess.run(
            docker_args + ["--entrypoint", "sh", cfg.docker_image, "-c", full_sh],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        assert res.returncode == 0
        assert "extract-urls" in res.stdout
        assert "http://127.0.0.1:18081/app.js" in res.stdout
        assert "cookie-consent-detection" in res.stdout

        # Also prove fail-fast handling when browser fails to start (e.g. non-existent browser_path):
        broken_cfg = HeadlessEnvironmentConfig(browser_path="/nonexistent/chromium-missing")
        fail_outcome = DockerHeadlessProbeExecutor().run_probe(broken_cfg)
        assert fail_outcome.browser_available is False
        assert fail_outcome.browser_launch_ok is False
        assert any("Chromium" in r for r in fail_outcome.blocking_reasons)


@pytest.mark.skipif(not _pinned_image_present(), reason="Pinned Nuclei Docker image unavailable")
def test_08_real_catalog_222_headless_templates_readiness_with_live_service():
    db = SessionLocal()
    try:
        rows = db.execute(
            text(
                "SELECT template_id, relative_path "
                "FROM nuclei_templates "
                "WHERE repository_version_id = :vid "
                "  AND (sequential_eligible OR independent_eligible) "
                "  AND 'headless' = ANY(protocols)"
            ),
            {"vid": LIVE_VERSION_ID},
        ).all()
        if not rows:
            pytest.skip("Live catalog version not present in PostgreSQL")
        assert len(rows) == 222

        readiness_svc = HeadlessReadinessService(
            config=HeadlessEnvironmentConfig(),
            executor=DockerHeadlessProbeExecutor(),
        )
        sel = TemplateSelectionService(session=db, headless_readiness_service=readiness_svc)
        eval_res = sel.evaluate_target_and_readiness(
            repository_version_id=LIVE_VERSION_ID,
            template_ids=[r[0] for r in rows],
            target="https://example.com",
            scan_mode=ScanMode.INDEPENDENT,
            environment_caps=EnvironmentCapabilities(
                headless_available=True,
                authorized_scopes=["example.com", "*.example.com"],
            ),
        )
        assert eval_res.server_headless_verified is True
        assert eval_res.total_evaluated == 222
        assert eval_res.ineligible_count == 0
        assert eval_res.readiness_breakdown["missing_headless"] == 0
        # 194 of the 222 are in dast/ and still require Phase 7.2.3 DAST crawl inputs
        assert eval_res.readiness_breakdown["missing_dast_inputs"] == 194
        # Non-DAST Headless templates without missing OAST/auth/vars are fully ready now
        assert eval_res.ready_count >= 1
    finally:
        db.close()
