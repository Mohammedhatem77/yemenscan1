import os
import time
from typing import Dict, Any, List
from core.session import get_session_dir, update_status
from core.runner import is_scan_cancelled, ScanCancelledException
from core.stage1_discovery import run_subfinder, run_naabu
from core.stage2_web_probing import run_httpx, run_kiterunner_or_api_probing
from core.stage3_vulnerabilities import (
    prepare_nuclei_targets,
    run_nuclei,
    run_optimized_nuclei,
    run_wapiti_dast,
    unify_and_save_vulnerabilities
)
from core.scope_classifier import load_scoped_urls
from core.execution_engine import _run_nuclei_takeover_check

def run_full_pipeline(domain: str, scan_id: str) -> None:
    """
    Executes the end-to-end 3-phase Black-box attack surface management pipeline:
    1. Phase 1: Subfinder (Subdomains) -> Naabu (Ports)
    2. Phase 2: HTTPX (Live Web Servers) -> Kiterunner (API & Route Discovery)
    3. Phase 3: Nuclei (CVEs & OWASP API Top 10) + Wapiti (DAST Web Top 10) -> Unified Report
    Supports real-time cancellation, preserves stage assets, and honors tool outcomes.
    """
    session_dir = get_session_dir(scan_id)
    tool_statuses: Dict[str, str] = {}
    phase_completed = {"phase1": False, "phase2": False, "phase3": False}
    
    try:
        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled before starting.")

        print(f"[*] بدء عملية الاستطلاع والفحص الأمني الشامل للنطاق: {domain}\n", flush=True)
        update_status(
            scan_id,
            status="running",
            stage="phase1_discovery",
            progress=5,
            log_message=f"بدء تنفيذ خط الفحص الشامل للنطاق المستهدف: {domain}"
        )
        
        # -------------------------------------------------------------
        # Phase 1: Discovery & Port Scanning
        # -------------------------------------------------------------
        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled.")
        ok_sub, subdomains = run_subfinder(domain, session_dir, scan_id)
        if ok_sub:
            tool_statuses["subfinder"] = "success" if subdomains else "empty"
        else:
            tool_statuses["subfinder"] = "failed"
            
        clean_domain = domain.strip().lower()
        if "://" in clean_domain:
            clean_domain = clean_domain.split("://", 1)[1]
        clean_domain = clean_domain.split("/", 1)[0].split(":", 1)[0].rstrip(".")

        # Prepare Naabu targets: Root Domain + valid discovered subdomains (subdomains.txt is untouched)
        naabu_targets = [clean_domain] + [s for s in subdomains if s.lower() != clean_domain]
        naabu_targets_file = os.path.join(session_dir, "naabu_targets.txt")
        try:
            with open(naabu_targets_file, "w", encoding="utf-8", newline="\n") as f:
                for t in naabu_targets:
                    f.write(f"{t}\n")
        except Exception:
            pass
            
        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled.")
        ok_ports, open_ports = run_naabu(naabu_targets, session_dir, scan_id)
        if ok_ports:
            tool_statuses["naabu"] = "success" if open_ports else "empty"
        else:
            tool_statuses["naabu"] = "failed"
            
        if ok_sub or ok_ports:
            phase_completed["phase1"] = True
        
        # -------------------------------------------------------------
        # Phase 2: Web & API Probing
        # -------------------------------------------------------------
        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled.")
        update_status(
            scan_id,
            stage="phase2_web_probing",
            progress=40,
            tool_status=tool_statuses
        )
        ok_http, web_targets, active_urls = run_httpx(session_dir, scan_id)
        if ok_http:
            tool_statuses["httpx"] = "success" if active_urls else "empty"
        else:
            tool_statuses["httpx"] = "failed"
            
        if active_urls:
            if is_scan_cancelled(scan_id):
                raise ScanCancelledException(f"Scan {scan_id} was cancelled.")
            ok_api, api_endpoints = run_kiterunner_or_api_probing(active_urls, session_dir, scan_id)
            if ok_api:
                tool_statuses["kiterunner"] = "success" if api_endpoints else "empty"
            else:
                tool_statuses["kiterunner"] = "failed"
        else:
            tool_statuses["kiterunner"] = "skipped"
            api_endpoints = []
            
        if ok_http:
            phase_completed["phase2"] = True
        
        # -------------------------------------------------------------
        # Phase 3: Vulnerability Scanning
        # -------------------------------------------------------------
        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled.")
        update_status(
            scan_id,
            stage="phase3_vulnerabilities",
            progress=70,
            tool_status=tool_statuses
        )

        # ── Scope Guard: عزل أصول الطرف الثالث وتطبيق نطاق الفحص الصارم ──
        scoped = load_scoped_urls(session_dir)
        in_scope_urls    = scoped["in_scope_urls"]
        third_party_urls = scoped["third_party_urls"]
        excluded_count   = scoped["excluded_count"]

        if excluded_count > 0:
            print(
                f"[Scope Guard] ✅ خط الفحص الكامل: استبعاد {excluded_count} أصل تابع لطرف ثالث من DAST و CVEs.",
                flush=True
            )

        # 1. Nuclei — فحص CVEs على الأصول الداخلية فقط
        all_targets = prepare_nuclei_targets(session_dir)
        if in_scope_urls and all_targets:
            from urllib.parse import urlparse
            in_scope_origins = {f"{urlparse(u).scheme}://{urlparse(u).netloc}".rstrip("/") for u in in_scope_urls if u}
            filtered_targets = [t for t in all_targets if any(t.startswith(o) or o.startswith(t) for o in in_scope_origins)]
            if filtered_targets:
                all_targets = filtered_targets
                nuclei_txt = os.path.join(session_dir, "nuclei_targets.txt")
                with open(nuclei_txt, "w", encoding="utf-8") as fh:
                    for t in all_targets:
                        fh.write(f"{t}\n")

        nuclei_findings: List[Dict[str, Any]] = []
        if in_scope_urls and all_targets:
            if is_scan_cancelled(scan_id):
                raise ScanCancelledException(f"Scan {scan_id} was cancelled.")
            ok_nuc, nuclei_findings = run_nuclei(session_dir, scan_id)
            if ok_nuc:
                tool_statuses["nuclei"] = "success" if nuclei_findings else "empty"
            else:
                tool_statuses["nuclei"] = "failed"
        else:
            tool_statuses["nuclei"] = "skipped"
            ok_nuc = True

        # 2. Nuclei Takeover — فحص سلبي أحادي فقط على أصول الطرف الثالث
        if third_party_urls:
            print(
                f"[Scope Guard] 🎯 تشغيل Nuclei Takeover على {len(third_party_urls)} أصل خارجي...",
                flush=True
            )
            ok_tak, tak_findings = _run_nuclei_takeover_check(session_dir, scan_id, third_party_urls)
            if tak_findings:
                nuclei_findings = nuclei_findings + tak_findings

        # 3. Wapiti DAST — على الأصول الداخلية فقط (استبعاد 100% للطرف الثالث)
        wapiti_findings: List[Dict[str, Any]] = []
        dast_targets = in_scope_urls if in_scope_urls else []
        if dast_targets:
            if is_scan_cancelled(scan_id):
                raise ScanCancelledException(f"Scan {scan_id} was cancelled.")
            ok_wap, wapiti_findings = run_wapiti_dast(session_dir, scan_id, dast_targets)
            if ok_wap:
                tool_statuses["wapiti"] = "success" if wapiti_findings else "empty"
            else:
                tool_statuses["wapiti"] = "failed"
        else:
            tool_statuses["wapiti"] = "skipped"
            ok_wap = True

        if (all_targets and ok_nuc) or (active_urls and ok_wap) or (not all_targets and not active_urls):
            phase_completed["phase3"] = True
        
        # Unify and generate executive findings (completely isolated inside session_dir)
        unify_and_save_vulnerabilities(session_dir, scan_id, nuclei_findings, wapiti_findings)

        # Accurately compute final status based on tool outcomes
        failed_tools = [t for t, s in tool_statuses.items() if s == "failed"]
        success_tools = [t for t, s in tool_statuses.items() if s in ("success", "empty")]
        
        if failed_tools and not success_tools:
            final_status = "failed"
            has_error = True
            msg = "فشلت جميع أدوات الفحص أثناء التنفيذ."
        elif failed_tools and success_tools:
            final_status = "partial"
            has_error = True
            msg = f"اكتمل الفحص جزئياً: نجحت {len(success_tools)} أدوات وفشلت {len(failed_tools)} أدوات."
        else:
            final_status = "completed"
            has_error = False
            msg = "اكتمل الفحص الأمني الشامل بنجاح."

        update_status(
            scan_id,
            status=final_status,
            stage=final_status,
            progress=100,
            is_completed=True,
            has_error=has_error,
            tool_status=tool_statuses,
            log_message=msg
        )

    except ScanCancelledException:
        print(f"[*] [STOPPED] تم إيقاف عملية الفحص للنطاق: {domain} بناءً على طلب المستخدم.\n", flush=True)
        tool_statuses["cancellation"] = "cancelled"
        update_status(
            scan_id,
            status="stopped",
            stage="stopped",
            tool="none",
            progress=100,
            is_completed=True,
            tool_status=tool_statuses,
            log_message="🛑 تم إيقاف عملية الفحص بنجاح بناءً على طلب المستخدم."
        )
    except Exception as e:
        tool_statuses["pipeline_error"] = "failed"
        has_prior = any(phase_completed.values())
        terminal_status = "partial" if has_prior else "failed"
        update_status(
            scan_id,
            status=terminal_status,
            stage=terminal_status,
            progress=100,
            is_completed=True,
            has_error=True,
            error=f"حدث استثناء غير متوقع أثناء تشغيل خط الفحص: {str(e)}",
            tool_status=tool_statuses
        )
