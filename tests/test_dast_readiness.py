"""
YemScan — Phase 7.2.3 Tests: Shared DAST Input Normalization & Execution Readiness.

Verifies:
  - Accurate separation of fuzzing parts (query/path/body/request), HTTP methods,
    and self-generated template variables vs external variables
  - Bare URLs never falsely unlock query/body/path/request DAST templates and produce
    exact canonical missing-requirement reasons
  - OR alternatives across Query, Body, Path, and Request satisfy templates without
    requiring Query when another supported vector is present
  - Parameterized URLs, JSONL object requests, and Base64 Burp XML normalization
  - Scope & SSRF protections (rejects out-of-scope domains, internal/private IPs)
  - Sequential (HTTPX + Kiterunner inputs only; Wapiti independent/complementary, never
    claimed to cover unexecuted Nuclei DAST scenarios) vs Independent (no discovery prerequisite)
  - Integration with TemplateSelectionService + Phase 7.2.1 Headless + OAST deferred (-ni)
  - Live isolated Docker (--network none) Nuclei v3.11.1 DAST execution for GET query,
    POST JSONL body, Headless+DAST (-dast -cdpe), and OAST disabled (-ni)
  - Full 244-DAST PostgreSQL catalog evaluation across sequential & independent scenarios
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile

import pytest
from sqlalchemy import text

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal
from core.dast_readiness import (
    DastInputCollector,
    DastInputContext,
    DastReadinessService,
    analyze_dast_template_doc,
    build_nuclei_dast_args,
    evaluate_dast_template_inputs,
)
from core.headless_readiness import (
    HeadlessEnvironmentConfig,
    HeadlessProbeExecutor,
    HeadlessProbeOutcome,
    HeadlessReadinessService,
    build_cdp_container_entrypoint_script,
    build_hardened_docker_run_args,
)
from core.nuclei_shared import NUCLEI_DOCKER_IMAGE
from core.runner import get_docker_cmd, get_docker_volume_path
from core.template_selection_service import (
    EnvironmentCapabilities,
    ScanMode,
    TemplateSelectionService,
)

LIVE_VERSION_ID = "a1301c8a-e54e-4c6b-bd96-3b71d266d221"
SNAP_DIR = rf"d:\yemenscan1\storage\nuclei\versions\{LIVE_VERSION_ID}"


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


class _StubHeadlessExecutor:
    def __init__(self, ready: bool) -> None:
        self._ready = ready

    def run_probe(self, config: HeadlessEnvironmentConfig) -> HeadlessProbeOutcome:
        return HeadlessProbeOutcome(
            docker_available=True,
            browser_available=self._ready,
            browser_binary_path="/usr/bin/chromium" if self._ready else None,
            browser_version="Chromium 150.0.7871.181 Alpine Linux" if self._ready else None,
            engine_compatible=self._ready,
            nuclei_headless_actions_ok=self._ready,
            browser_launch_ok=self._ready,
            js_execution_ok=self._ready,
            nuclei_cdpe_scan_ok=self._ready,
            non_root_ok=True,
            capabilities_dropped_ok=True,
            no_new_privs_ok=True,
            seccomp_active_ok=True,
            readonly_rootfs_ok=True,
            no_docker_sock_ok=True,
            dangerous_syscalls_blocked_ok=True,
            egress_blocked_ok=True,
            browser_sandbox_active_ok=self._ready,
            no_sandbox_flag_absent_ok=True,
            shm_size_bytes=1024 * 1024 * 1024,
            resources_ok=True,
            cleanup_ok=True,
            blocking_reasons=[] if self._ready else ["Simulated headless unavailable"],
        )


# ---------------------------------------------------------------------------
# Unit & Requirement Analysis Tests
# ---------------------------------------------------------------------------

def test_01_template_analyzer_distinguishes_self_generated_vs_external_vars():
    doc = {
        "id": "test-csp-dast",
        "variables": {"nonce_val": "{{rand_int(1,9)}}"},
        "headless": [
            {
                "steps": [{"action": "navigate", "args": {"url": "{{BaseURL}}"}}],
                "payloads": {"injection": ["<script>alert(1)</script>"]},
                "fuzzing": [{"part": "query", "type": "replace", "mode": "single", "fuzz": ["{{injection}}"]}],
            }
        ],
    }
    req = analyze_dast_template_doc(
        doc=doc,
        template_id="test-csp-dast",
        relative_path="dast/vulnerabilities/xss/csp-bypass/test.yaml",
        protocols=["headless", "http"],
        policy_details={
            "headless_requirement": True,
            "oast_requirement": False,
            "required_variables": ["injection", "nonce_val", "BaseURL", "api_token"],
        },
    )
    assert req.is_dast is True
    assert req.required_fuzz_parts == {"query"}
    assert req.requires_headless is True
    assert req.requires_oast is False
    assert set(req.self_generated_variables) == {"injection", "nonce_val", "BaseURL"}
    assert req.external_required_variables == ["api_token"]

    # Also verify real v10.5.1 templates if snapshot exists on disk
    if os.path.isdir(SNAP_DIR):
        svc = DastReadinessService(snapshot_dir=SNAP_DIR)
        r_csp = svc.inspect_template(
            "duckduckgo-api-csp-bypass",
            "dast/vulnerabilities/xss/csp-bypass/duckduckgo-api-csp-bypass.yaml",
            protocols=["headless", "http"],
            policy_details={"headless_requirement": True, "required_variables": ["injection"]},
        )
        assert r_csp.required_fuzz_parts == {"query"}
        assert r_csp.external_required_variables == []
        assert r_csp.self_generated_variables == ["injection"]

        r_py = svc.inspect_template(
            "python-code-injection",
            "dast/vulnerabilities/cmdi/python-code-injection.yaml",
            protocols=["http"],
            policy_details={"required_variables": ["Command", "injection"]},
        )
        assert r_py.required_fuzz_parts == {"query", "body"}
        assert r_py.accepted_methods == {"GET", "POST", "PUT"}
        assert r_py.external_required_variables == []


def test_02_bare_url_never_unlocks_and_alternatives_satisfy_without_query():
    ctx_bare = DastInputCollector.from_user_inputs(
        urls=["https://app.example.com/"],
        authorized_scopes=["example.com", "*.example.com"],
    )
    assert ctx_bare.has_any_inputs is True
    assert ctx_bare.has_bare_url_only is True
    assert ctx_bare.has_query_params is False

    # 1. Exact canonical missing reasons on bare URL
    q_req = analyze_dast_template_doc(
        {"id": "q-only", "http": [{"fuzzing": [{"part": "query"}]}]},
        "q-only",
        "dast/vulnerabilities/ssti/q-only.yaml",
    )
    ok_q, reasons_q = evaluate_dast_template_inputs(q_req, ctx_bare)
    assert ok_q is False
    assert reasons_q == ["dast_missing_query_parameters"]

    b_req = analyze_dast_template_doc(
        {"id": "b-only", "http": [{"fuzzing": [{"part": "body"}]}]},
        "b-only",
        "dast/vulnerabilities/cmdi/b-only.yaml",
    )
    ok_b, reasons_b = evaluate_dast_template_inputs(b_req, ctx_bare)
    assert ok_b is False
    assert reasons_b == ["dast_missing_request_body"]

    p_req = analyze_dast_template_doc(
        {"id": "p-only", "http": [{"fuzzing": [{"part": "path"}]}]},
        "p-only",
        "dast/vulnerabilities/xss/p-only.yaml",
    )
    ok_p, reasons_p = evaluate_dast_template_inputs(p_req, ctx_bare)
    assert ok_p is False
    assert reasons_p == ["dast_missing_path_inputs"]

    req_req = analyze_dast_template_doc(
        {"id": "req-fuzz", "http": [{"fuzzing": [{"part": "request"}]}]},
        "req-fuzz",
        "dast/vulnerabilities/sqli/req-fuzz.yaml",
    )
    ok_r, reasons_r = evaluate_dast_template_inputs(req_req, ctx_bare)
    assert ok_r is False
    assert reasons_r == ["dast_missing_request_inputs"]

    qb_req = analyze_dast_template_doc(
        {"id": "qb-alt", "http": [{"fuzzing": [{"parts": ["query", "body"]}]}]},
        "qb-alt",
        "dast/vulnerabilities/cmdi/qb-alt.yaml",
    )
    ok_qb, reasons_qb = evaluate_dast_template_inputs(qb_req, ctx_bare)
    assert ok_qb is False
    assert reasons_qb == ["dast_missing_query_or_body_inputs"]

    qp_req = analyze_dast_template_doc(
        {"id": "qp-alt", "http": [{"fuzzing": [{"part": "query"}, {"part": "path"}]}]},
        "qp-alt",
        "dast/vulnerabilities/xss/qp-alt.yaml",
    )
    ok_qp, reasons_qp = evaluate_dast_template_inputs(qp_req, ctx_bare)
    assert ok_qp is False
    assert reasons_qp == ["dast_missing_query_or_path_inputs"]

    qbp_req = analyze_dast_template_doc(
        {"id": "qbp-alt", "http": [{"fuzzing": [{"part": "body"}, {"part": "query"}, {"part": "path"}]}]},
        "qbp-alt",
        "dast/vulnerabilities/xss/qbp-alt.yaml",
    )
    ok_qbp, reasons_qbp = evaluate_dast_template_inputs(qbp_req, ctx_bare)
    assert ok_qbp is False
    assert reasons_qbp == ["dast_missing_query_body_or_path_inputs"]

    # 2. Supported OR alternatives satisfy template WITHOUT Query parameters
    ctx_post_body = DastInputCollector.from_user_inputs(
        http_requests=[{"url": "https://app.example.com/", "method": "POST", "body": "name=alice"}],
        authorized_scopes=["example.com", "*.example.com"],
    )
    assert evaluate_dast_template_inputs(qb_req, ctx_post_body) == (True, [])
    assert evaluate_dast_template_inputs(qbp_req, ctx_post_body) == (True, [])
    assert evaluate_dast_template_inputs(req_req, ctx_post_body) == (True, [])
    # Strictly query-only still accurately fails with dast_missing_query_parameters
    assert evaluate_dast_template_inputs(q_req, ctx_post_body) == (False, ["dast_missing_query_parameters"])

    ctx_path_only = DastInputCollector.from_user_inputs(
        urls=["https://app.example.com/api/items"],
        authorized_scopes=["example.com", "*.example.com"],
    )
    assert evaluate_dast_template_inputs(qp_req, ctx_path_only) == (True, [])
    assert evaluate_dast_template_inputs(qbp_req, ctx_path_only) == (True, [])
    assert evaluate_dast_template_inputs(qb_req, ctx_path_only) == (False, ["dast_missing_query_or_body_inputs"])

    # 3. Multi-method context must evaluate only compatible-method records
    ctx_mixed = DastInputCollector.from_user_inputs(
        urls=["https://app.example.com/search?q=1"],
        http_requests=[{"url": "https://app.example.com/", "method": "POST", "body": ""}],
        authorized_scopes=["example.com", "*.example.com"],
    )
    post_qb_req = analyze_dast_template_doc(
        {
            "id": "post-qb",
            "http": [{
                "pre-condition": [{"type": "dsl", "dsl": ['method == "POST"']}],
                "fuzzing": [{"parts": ["query", "body"]}],
            }],
        },
        "post-qb",
        "dast/vulnerabilities/cmdi/post-qb.yaml",
    )
    assert evaluate_dast_template_inputs(post_qb_req, ctx_mixed) == (False, ["dast_missing_query_or_body_inputs"])


def test_03_input_formats_jsonl_burp_and_method_matching(tmp_path):
    # 1. Valid JSONL object schema & rejection of plain string request
    valid_jsonl = json.dumps({
        "request": {
            "raw": "POST /api/login HTTP/1.1\r\nHost: app.example.com\r\nContent-Type: application/json\r\nContent-Length: 14\r\n\r\n{\"user\":\"bob\"}",
            "endpoint": "https://app.example.com/api/login",
            "body": "{\"user\":\"bob\"}",
            "header": {"Content-Type": "application/json"},
        },
        "url": "https://app.example.com/api/login",
    })
    bad_jsonl = json.dumps({"request": "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n"})

    ctx = DastInputCollector.from_user_inputs(
        jsonl_lines=[valid_jsonl, bad_jsonl],
        authorized_scopes=["example.com", "*.example.com"],
    )
    assert len(ctx.records) == 1
    assert len(ctx.rejected_invalid) == 1
    assert ctx.records[0].method == "POST"
    assert ctx.records[0].has_body is True
    assert ctx.recommended_input_mode == "jsonl"

    out_jsonl = str(tmp_path / "dast_in.jsonl")
    mode_written = ctx.write_nuclei_input_file(out_jsonl)
    assert mode_written == "jsonl"
    parsed_back = json.loads(open(out_jsonl, "r", encoding="utf-8").read().strip())
    assert isinstance(parsed_back["request"], dict)
    assert parsed_back["request"]["body"] == "{\"user\":\"bob\"}"

    # 2. Burp base64 XML
    raw_http = "POST /comment HTTP/1.1\r\nHost: app.example.com\r\nContent-Length: 7\r\n\r\nmsg=hey"
    b64 = base64.b64encode(raw_http.encode("utf-8")).decode("ascii")
    burp_xml = f"<items><item><url>https://app.example.com/comment</url><request base64=\"true\">{b64}</request></item></items>"
    ctx_burp = DastInputCollector.from_user_inputs(burp_xml=burp_xml, authorized_scopes=["example.com", "*.example.com"])
    assert len(ctx_burp.records) == 1
    assert ctx_burp.records[0].body == "msg=hey"
    assert ctx_burp.records[0].method == "POST"

    # 3. Body-only / POST-body template passes with POST body, blocked for GET-only
    body_tpl = analyze_dast_template_doc(
        {"id": "post-body", "http": [{"pre-condition": [{"type": "dsl", "dsl": ['method == "POST"']}], "fuzzing": [{"part": "body"}]}]},
        "post-body",
        "dast/vulnerabilities/cmdi/post-body.yaml",
    )
    ok_post, _ = evaluate_dast_template_inputs(body_tpl, ctx)
    assert ok_post is True

    get_only_tpl = analyze_dast_template_doc(
        {"id": "get-query", "http": [{"pre-condition": [{"type": "dsl", "dsl": ['method == "GET"']}], "fuzzing": [{"part": "query"}]}]},
        "get-query",
        "dast/vulnerabilities/ssti/get-query.yaml",
    )
    ok_get, reasons_get = evaluate_dast_template_inputs(get_only_tpl, ctx)
    assert ok_get is False
    assert "dast_incompatible_http_method" in reasons_get


def test_04_scope_and_ssrf_blocks_out_of_scope_and_private_ips(tmp_path):
    ctx = DastInputCollector.from_user_inputs(
        urls=[
            "https://app.example.com/search?q=1",
            "https://evil-thirdparty.org/search?q=1",
            "http://169.254.169.254/latest/meta-data/?x=1",
            "http://10.1.2.3/admin?id=5",
            "file:///etc/passwd",
        ],
        authorized_scopes=["example.com", "*.example.com"],
    )
    assert len(ctx.records) == 1
    assert ctx.records[0].url == "https://app.example.com/search?q=1"
    assert len(ctx.rejected_out_of_scope) >= 1
    assert len(ctx.rejected_invalid) >= 1

    out_list = str(tmp_path / "targets.txt")
    ctx.write_nuclei_input_file(out_list, input_mode="list")
    lines = [l.strip() for l in open(out_list, encoding="utf-8") if l.strip()]
    assert lines == ["https://app.example.com/search?q=1"]

    # CLI builder enforces -dast, -ni (OAST deferred), and sandboxed -cdpe (no -sc)
    args = build_nuclei_dast_args(
        input_file_path="/in/targets.txt",
        template_paths=["dast/"],
        input_mode="list",
        enable_headless=True,
        cdp_ws_url="ws://127.0.0.1:9222/devtools/browser/abc",
        disable_oast=True,
    )
    assert "-dast" in args
    assert "-ni" in args
    assert "-headless" in args and "-cdpe" in args
    assert "-sc" not in args and "-system-chrome" not in args


def test_05_sequential_httpx_kiterunner_vs_independent_session(tmp_path):
    # Create mock Stage 2 sequential session directory (no new crawler!)
    sess_dir = tmp_path / "sess_seq"
    sess_dir.mkdir()
    with open(sess_dir / "active_urls.json", "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"url": "https://app.example.com", "scope_tag": "in_scope_full", "method": "GET"}) + "\n")
        fh.write(json.dumps({"url": "https://help.example.com", "scope_tag": "third_party_passive", "method": "GET"}) + "\n")
    with open(sess_dir / "api_endpoints.json", "w", encoding="utf-8") as fh:
        json.dump([{"url": "https://app.example.com/api/v1/users", "method": "GET"}], fh)

    seq_ctx = DastInputCollector.from_sequential_session(
        str(sess_dir),
        authorized_scopes=["example.com", "*.example.com"],
    )
    assert seq_ctx.input_source_mode == "sequential_discovery"
    summary_seq = seq_ctx.to_summary_dict()
    assert "covered_by_wapiti_in_sequential" not in summary_seq
    assert summary_seq["input_source_mode"] == "sequential_discovery"
    assert len(seq_ctx.records) == 2
    assert seq_ctx.has_query_params is False
    assert seq_ctx.has_non_root_path is True
    # Third-party SaaS asset from HTTPX was properly excluded
    assert len(seq_ctx.rejected_out_of_scope) == 1

    # Also verify api_endpoints.txt fallback when api_endpoints.json is absent
    sess_txt = tmp_path / "sess_txt"
    sess_txt.mkdir()
    (sess_txt / "api_endpoints.txt").write_text("https://app.example.com/v2/health\n", encoding="utf-8")
    seq_txt_ctx = DastInputCollector.from_sequential_session(
        str(sess_txt),
        authorized_scopes=["example.com", "*.example.com"],
    )
    assert len(seq_txt_ctx.records) == 1
    assert seq_txt_ctx.records[0].source == "kiterunner"
    assert seq_txt_ctx.has_non_root_path is True

    # Independent mode requires NO session_dir or discovery tool output
    ind_ctx = DastInputCollector.from_user_inputs(
        urls=["https://app.example.com/item?id=42"],
        authorized_scopes=["example.com", "*.example.com"],
    )
    assert ind_ctx.input_source_mode == "independent_user_supplied"
    summary_ind = ind_ctx.to_summary_dict()
    assert "covered_by_wapiti_in_sequential" not in summary_ind
    assert summary_ind["input_source_mode"] == "independent_user_supplied"
    assert ind_ctx.has_query_params is True


# ---------------------------------------------------------------------------
# Live Isolated Docker & PostgreSQL 244-DAST Catalog Integration Tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _pinned_image_present(), reason="Pinned Nuclei Docker image unavailable")
def test_06_live_docker_dast_get_post_jsonl_headless_and_oast_disabled():
    if not os.path.isdir(SNAP_DIR):
        pytest.skip("Official v10.5.1 snapshot directory unavailable")

    with tempfile.TemporaryDirectory() as tmp:
        for name, rel in [
            ("sqli.yaml", r"dast\vulnerabilities\sqli\sqli-error-based.yaml"),
            ("domxss.yaml", r"dast\vulnerabilities\xss\dom-xss.yaml"),
            ("ssrf.yaml", r"dast\vulnerabilities\ssrf\blind-ssrf.yaml"),
        ]:
            with open(os.path.join(SNAP_DIR, rel), "r", encoding="utf-8") as rf:
                with open(os.path.join(tmp, name), "w", encoding="utf-8") as wf:
                    wf.write(rf.read())

        # Build POST JSONL input via shared DastInputCollector
        ctx_post = DastInputCollector.from_user_inputs(
            http_requests=[{
                "url": "http://127.0.0.1:18090/submit",
                "method": "POST",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "username=alice",
            }],
            authorized_scopes=["127.0.0.1"],
            allow_loopback_for_tests=True,
        )
        assert ctx_post.recommended_input_mode == "jsonl"
        ctx_post.write_nuclei_input_file(os.path.join(tmp, "post.jsonl"), input_mode="jsonl")

        # Build GET query URL list for Headless + DAST test
        ctx_get = DastInputCollector.from_user_inputs(
            urls=["http://127.0.0.1:18090/page?q=hello"],
            authorized_scopes=["127.0.0.1"],
            allow_loopback_for_tests=True,
        )
        ctx_get.write_nuclei_input_file(os.path.join(tmp, "get_q.txt"), input_mode="list")

        vol = get_docker_volume_path(tmp)

        # 1. HTTP POST JSONL SQLi + -ni OAST disabled inside --network none container
        dast_post_args = build_nuclei_dast_args(
            input_file_path="/in/post.jsonl",
            template_paths=["/in/sqli.yaml", "/in/ssrf.yaml"],
            input_mode="jsonl",
            disable_oast=True,
        )
        sh_http = "\n".join([
            "mkdir -p /tmp/h /tmp/cfg /tmp/cache",
            "cat << 'EOF' > /tmp/srv.sh",
            "REQ_LINE=''; CL=0",
            "while IFS= read -r l; do",
            "  l=$(printf '%s' \"$l\" | tr -d '\\r')",
            "  [ -z \"$REQ_LINE\" ] && REQ_LINE=\"$l\"",
            "  case \"$l\" in Content-Length:*|content-length:*) CL=$(printf '%s' \"$l\" | awk '{print $2}') ;; esac",
            "  [ -z \"$l\" ] && break",
            "done",
            "BODY_IN=''; if [ \"${CL:-0}\" -gt 0 ] 2>/dev/null; then BODY_IN=$(dd bs=1 count=\"$CL\" 2>/dev/null || true); fi",
            "case \"$REQ_LINE$BODY_IN\" in",
            "  *\\'*|*\\\"*) B=\"<html>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</html>\" ;;",
            "  *) B=\"<html>OK</html>\" ;;",
            "esac",
            "L=$(printf '%s' \"$B\" | wc -c)",
            "printf 'HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\nContent-Length: %s\\r\\nConnection: close\\r\\n\\r\\n%s' \"$L\" \"$B\"",
            "EOF",
            "nc -lk -p 18090 -e /bin/sh /tmp/srv.sh &",
            "SRV_PID=$!",
            f"nuclei {' '.join(dast_post_args)}",
            "RC=$?",
            "kill $SRV_PID 2>/dev/null || true",
            "exit $RC",
        ])
        res_post = subprocess.run(
            [
                get_docker_cmd(), "run", "--rm", "--init", "--network", "none",
                "--user", "65534:65534", "--cap-drop=ALL",
                "-e", "HOME=/tmp/h", "-e", "XDG_CONFIG_HOME=/tmp/cfg", "-e", "XDG_CACHE_HOME=/tmp/cache",
                "-v", f"{vol}:/in:ro", "--entrypoint", "sh", NUCLEI_DOCKER_IMAGE, "-c", sh_http,
            ],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
        )
        assert res_post.returncode == 0
        assert "sqli-error-based" in res_post.stdout
        assert "[body:username]" in res_post.stdout
        assert "blind-ssrf" not in res_post.stdout

        # 2. Hardened Phase 7.2.1 Headless + DAST (-dast -cdpe -ni)
        cfg = HeadlessEnvironmentConfig()
        dargs = build_hardened_docker_run_args(config=cfg, volume_mounts=[(tmp, "/in", "ro")], network_mode="none")
        cdpe_sh = build_cdp_container_entrypoint_script(
            nuclei_args=["-ni", "-dast", "-l", "/in/get_q.txt", "-t", "/in/domxss.yaml"],
            config=cfg,
            authorized_scopes=["127.0.0.1"],
        )
        sh_hl = "\n".join([
            "cat << 'EOF' > /tmp/hl.sh",
            "while IFS= read -r l; do l=$(printf '%s' \"$l\" | tr -d '\\r'); [ -z \"$l\" ] && break; done",
            "B='<html><body><script>const p=new URLSearchParams(location.search).get(\"q\")||\"\"; if(p){document.write(p);}</script></body></html>'",
            "L=$(printf '%s' \"$B\" | wc -c)",
            "printf 'HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\nContent-Length: %s\\r\\nConnection: close\\r\\n\\r\\n%s' \"$L\" \"$B\"",
            "EOF",
            "nc -lk -p 18090 -e /bin/sh /tmp/hl.sh &",
            "SRV_PID=$!",
            cdpe_sh,
            "RC=$?",
            "kill $SRV_PID 2>/dev/null || true",
            "exit $RC",
        ])
        res_hl = subprocess.run(
            dargs + ["--entrypoint", "sh", cfg.docker_image, "-c", sh_hl],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
        )
        assert res_hl.returncode == 0
        assert "dom-xss" in res_hl.stdout


def test_07_real_catalog_244_dast_readiness_sequential_and_independent(tmp_path):
    db = SessionLocal()
    try:
        cnt = db.execute(
            text(
                "SELECT COUNT(*) FROM nuclei_templates "
                "WHERE repository_version_id = :vid "
                "  AND (sequential_eligible OR independent_eligible) "
                "  AND relative_path LIKE 'dast/%%'"
            ),
            {"vid": LIVE_VERSION_ID},
        ).scalar_one()
        if cnt == 0:
            pytest.skip("Live catalog version not present in PostgreSQL")
        assert cnt == 244

        hl_ready_svc = HeadlessReadinessService(executor=_StubHeadlessExecutor(ready=True))
        hl_down_svc = HeadlessReadinessService(executor=_StubHeadlessExecutor(ready=False))

        sel_ready = TemplateSelectionService(session=db, headless_readiness_service=hl_ready_svc)
        sel_down = TemplateSelectionService(session=db, headless_readiness_service=hl_down_svc)

        # Scenario A: Sequential mode with only HTTPX bare origin (honest missing-input reasons, no fake Wapiti excuse)
        sess_bare = tmp_path / "seq_bare"
        sess_bare.mkdir()
        (sess_bare / "active_urls.json").write_text(
            json.dumps({"url": "https://example.com", "scope_tag": "in_scope_full", "method": "GET"}) + "\n",
            encoding="utf-8",
        )
        ctx_seq_bare = DastInputCollector.from_sequential_session(
            str(sess_bare),
            authorized_scopes=["example.com", "*.example.com"],
        )
        eval_seq_bare = sel_ready.evaluate_dast_suite_readiness(
            repository_version_id=LIVE_VERSION_ID,
            target="https://example.com",
            dast_input_context=ctx_seq_bare,
            scan_mode=ScanMode.SEQUENTIAL,
            interactsh_available=False,
            authorized_scopes=["example.com", "*.example.com"],
        )
        assert eval_seq_bare.total_evaluated == 244
        assert eval_seq_bare.ineligible_count == 0
        assert eval_seq_bare.ready_count == 0
        assert eval_seq_bare.readiness_breakdown["missing_dast_inputs"] == 244
        assert eval_seq_bare.readiness_breakdown["missing_variables"] == 0
        assert not any("sequential_dast_handled_by_wapiti" in t.blocking_reasons for t in eval_seq_bare.templates)
        assert eval_seq_bare.dast_input_summary is not None
        assert "covered_by_wapiti_in_sequential" not in eval_seq_bare.dast_input_summary
        assert eval_seq_bare.dast_detailed_breakdown == {
            "dast_missing_query_parameters": 200,
            "dast_missing_query_or_body_inputs": 40,
            "dast_missing_query_or_path_inputs": 2,
            "dast_missing_query_body_or_path_inputs": 1,
            "dast_missing_request_inputs": 1,
        }

        # Scenario B: Sequential mode with HTTPX + Kiterunner API path (no query params)
        sess_kr = tmp_path / "seq_kr"
        sess_kr.mkdir()
        (sess_kr / "active_urls.json").write_text(
            json.dumps({"url": "https://example.com", "scope_tag": "in_scope_full", "method": "GET"}) + "\n",
            encoding="utf-8",
        )
        (sess_kr / "api_endpoints.json").write_text(
            json.dumps([{"url": "https://example.com/api/items", "method": "GET"}]),
            encoding="utf-8",
        )
        ctx_seq_kr = DastInputCollector.from_sequential_session(
            str(sess_kr),
            authorized_scopes=["example.com", "*.example.com"],
        )
        eval_seq_kr = sel_ready.evaluate_dast_suite_readiness(
            repository_version_id=LIVE_VERSION_ID,
            target="https://example.com",
            dast_input_context=ctx_seq_kr,
            scan_mode=ScanMode.SEQUENTIAL,
            interactsh_available=False,
            authorized_scopes=["example.com", "*.example.com"],
        )
        assert eval_seq_kr.total_evaluated == 244
        assert eval_seq_kr.ineligible_count == 0
        # 4 non-OAST path/request templates unlock (google-storage-csp-bypass, dom-xss, reflected-xss, sqli-error-based)
        assert eval_seq_kr.ready_count == 4
        assert eval_seq_kr.readiness_breakdown["missing_dast_inputs"] == 240
        assert eval_seq_kr.dast_detailed_breakdown == {
            "dast_missing_query_parameters": 200,
            "dast_missing_query_or_body_inputs": 40,
        }

        # Scenario C: Independent POST + body (NO Query params!) unlocks body/path/request alternatives
        ctx_post_body = DastInputCollector.from_user_inputs(
            http_requests=[{
                "url": "https://example.com/submit",
                "method": "POST",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "name=alice",
            }],
            authorized_scopes=["example.com", "*.example.com"],
        )
        eval_post_body = sel_ready.evaluate_dast_suite_readiness(
            repository_version_id=LIVE_VERSION_ID,
            target="https://example.com",
            dast_input_context=ctx_post_body,
            scan_mode=ScanMode.INDEPENDENT,
            interactsh_available=False,
            authorized_scopes=["example.com", "*.example.com"],
        )
        assert eval_post_body.total_evaluated == 244
        assert eval_post_body.ineligible_count == 0
        # None of the 44 templates supporting body/path/request fail due to missing query!
        by_id = {t.template_id: t for t in eval_post_body.templates}
        assert by_id["python-code-injection"].overall_ready is True
        assert by_id["reflected-xss"].overall_ready is True
        assert by_id["dom-xss"].overall_ready is True
        assert by_id["sqli-error-based"].overall_ready is True
        assert "dast_incompatible_http_method" in by_id["CVE-2020-9402"].blocking_reasons

        # Scenario D: Independent mode with parameterized GET URL + verified Headless + OAST deferred
        ctx_ind_q = DastInputCollector.from_user_inputs(
            urls=["https://example.com/search?q=test"],
            authorized_scopes=["example.com", "*.example.com"],
        )
        eval_ind_q = sel_ready.evaluate_dast_suite_readiness(
            repository_version_id=LIVE_VERSION_ID,
            target="https://example.com",
            dast_input_context=ctx_ind_q,
            scan_mode=ScanMode.INDEPENDENT,
            interactsh_available=False,
            authorized_scopes=["example.com", "*.example.com"],
        )
        assert eval_ind_q.total_evaluated == 244
        assert eval_ind_q.ineligible_count == 0
        assert eval_ind_q.readiness_breakdown["missing_dast_inputs"] == 0
        assert eval_ind_q.readiness_breakdown["missing_variables"] == 0
        assert eval_ind_q.readiness_breakdown["missing_headless"] == 0
        assert eval_ind_q.readiness_breakdown["missing_oast"] == 32
        assert eval_ind_q.ready_count == 212  # 194 Headless+DAST + 18 Plain HTTP DAST!

        # Scenario E: Independent parameterized URL when Headless is unavailable
        eval_ind_no_hl = sel_down.evaluate_dast_suite_readiness(
            repository_version_id=LIVE_VERSION_ID,
            target="https://example.com",
            dast_input_context=ctx_ind_q,
            scan_mode=ScanMode.INDEPENDENT,
            interactsh_available=False,
            authorized_scopes=["example.com", "*.example.com"],
        )
        assert eval_ind_no_hl.total_evaluated == 244
        assert eval_ind_no_hl.ready_count == 18
        assert eval_ind_no_hl.readiness_breakdown["missing_headless"] == 194
        assert eval_ind_no_hl.readiness_breakdown["missing_oast"] == 32
    finally:
        db.close()
