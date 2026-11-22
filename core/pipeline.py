import os
import time
import json
import shutil
import inspect
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

def package_session_evidence_and_metadata(
    session_dir: str,
    scan_id: str,
    domain: str,
    final_status: str,
    tool_statuses: Dict[str, str]
) -> None:
    """
    Consolidates individual tool metadata into a unified scan_metadata.json
    and packages forensic raw outputs into a raw_evidence/ subfolder.
    Preserves existing files for backward-compatibility while organizing evidence.
    """
    try:
        # 1. Consolidate metadata from all 6 tools
        tool_metas: Dict[str, Any] = {}
        meta_map = {
            "subfinder": "subfinder_metadata.json",
            "naabu": "naabu_metadata.json",
            "httpx": "httpx_metadata.json",
            "kiterunner": "kiterunner_metadata.json",
            "nuclei": "nuclei_metadata.json",
            "wapiti": "wapiti_metadata.json"
        }
        for tool, fname in meta_map.items():
            fpath = os.path.join(session_dir, fname)
            if os.path.exists(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8") as mf:
                        tool_metas[tool] = json.load(mf)
                except Exception:
                    tool_metas[tool] = {"status": tool_statuses.get(tool, "unknown")}
            elif tool in tool_statuses:
                tool_metas[tool] = {"status": tool_statuses[tool]}

        unified_meta = {
            "scan_id": scan_id,
            "target_domain": domain,
            "final_status": final_status,
            "tool_statuses": tool_statuses,
            "tools": tool_metas
        }
        waf_file = os.path.join(session_dir, "waf_bypass.json")
        if os.path.exists(waf_file):
            try:
                with open(waf_file, "r", encoding="utf-8") as wf:
                    unified_meta["waf_bypass"] = json.load(wf)
            except Exception:
                pass

        try:
            from core.waf_evasion import WAFEvasionEngine
            ev_cfg = WAFEvasionEngine.resolve_evasion_config(session_dir)
            unified_meta["waf_evasion"] = {
                "evasion_active": ev_cfg.evasion_active,
                "is_behind_waf": ev_cfg.is_behind_waf,
                "spoofed_headers_count": len(ev_cfg.spoofed_headers) if ev_cfg.evasion_active else 0,
                "user_agent_masked": ev_cfg.evasion_active,
                "nuclei_delay": ev_cfg.nuclei_delay if ev_cfg.evasion_active else None
            }
        except Exception:
            pass
        meta_path = os.path.join(session_dir, "scan_metadata.json")
        with open(meta_path, "w", encoding="utf-8") as out_m:
            json.dump(unified_meta, out_m, ensure_ascii=False, indent=2)

        # 2. Package raw evidence logs into raw_evidence/
        evidence_dir = os.path.join(session_dir, "raw_evidence")
        raw_evidence_files = [
            "subfinder_raw.jsonl",
            "naabu_raw.jsonl",
            "httpx_raw.jsonl",
            "kiterunner_raw.jsonl",
            "nuclei_raw.jsonl",
            "wapiti_raw.json",
            "nuclei_stderr.log",
            "kiterunner_stderr.log"
        ]
        has_evidence = any(os.path.exists(os.path.join(session_dir, f)) for f in raw_evidence_files)
        if has_evidence:
            os.makedirs(evidence_dir, exist_ok=True)
            for rf in raw_evidence_files:
                src = os.path.join(session_dir, rf)
                if os.path.exists(src):
                    try:
                        shutil.move(src, os.path.join(evidence_dir, rf))
                    except Exception:
                        pass

        # 3. Clean any residual intermediate files (e.g. wapiti_raw_*.json)
        try:
            for fname in os.listdir(session_dir):
                if fname.startswith("wapiti_raw_") and fname.endswith(".json"):
                    try:
                        os.remove(os.path.join(session_dir, fname))
                    except Exception:
                        pass
        except Exception:
            pass
    except Exception as e:
        print(f"[-] ملاحظة: تعذر أرشفة الأدلة الخام والميتاداتا: {e}", flush=True)

def _invoke_tool_with_profile(tool_func, *args, **kwargs):
    """
    Invokes tool_func passing profile kwargs only if the target callable supports them.
    Protects against legacy test mocks or teammate signatures without swallowing internal TypeErrors.
    """
    target = getattr(tool_func, "side_effect", None)
    if not callable(target):
        target = tool_func
    try:
        sig = inspect.signature(target)
        params = sig.parameters
        has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
        if has_var_kw:
            return tool_func(*args, **kwargs)
        filtered = {k: v for k, v in kwargs.items() if k in params}
        return tool_func(*args, **filtered)
    except (ValueError, TypeError):
        return tool_func(*args, **kwargs)

def run_full_pipeline(domain: str, scan_id: str, scan_profile: str = "safe") -> None:
    """
    Executes the end-to-end 3-phase Black-box attack surface management pipeline:
    1. Phase 1: Subfinder (Subdomains) -> Naabu (Ports)
    2. Phase 2: HTTPX (Live Web Servers) -> Kiterunner (API & Route Discovery)
    3. Phase 3: Nuclei (CVEs & OWASP API Top 10) + Wapiti (DAST Web Top 10) -> Unified Report
    Supports real-time cancellation, preserves stage assets, and honors tool outcomes.

    Args:
        domain: Target domain to scan.
        scan_id: Session ID.
        scan_profile: One of 'safe', 'dast_light', 'deep'. Controls tool timeouts,
                      rate limits, concurrency, and DAST module injection depth.
    """
    _VALID_PROFILES = {"safe", "dast_light", "deep"}
    if scan_profile not in _VALID_PROFILES:
        scan_profile = "safe"
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
        
        clean_domain = domain.strip().lower()
        if "://" in clean_domain:
            clean_domain = clean_domain.split("://", 1)[1]
        clean_domain = clean_domain.split("/", 1)[0].split(":", 1)[0].rstrip(".")

        # -------------------------------------------------------------
        # Phase 0: WAF Detection & Scope-Guarded Origin IP Discovery Gateway
        # -------------------------------------------------------------
        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled.")

        update_status(
            scan_id,
            status="running",
            stage="stage0_origin_gateway",
            progress=6,
            log_message=f"المرحلة 0: فحص جدار الحماية (WAF) وكشف السيرفر الحقيقي للنطاق: {clean_domain}"
        )

        try:
            from core.origin_recon import run_origin_recon
            waf_result = run_origin_recon(clean_domain)
            waf_file = os.path.join(session_dir, "waf_bypass.json")
            with open(waf_file, "w", encoding="utf-8") as wf:
                json.dump(waf_result, wf, ensure_ascii=False, indent=2)

            if waf_result.get("waf_bypassed"):
                orig_ip = waf_result["verified_origins"][0]["origin_ip"]
                prov = waf_result.get("waf_provider", "WAF")
                print(f"[+] [WAF Bypass] ✅ تم كشف السيرفر الحقيقي بنجاح: {orig_ip} خلف جدار {prov}", flush=True)
            elif waf_result.get("is_behind_waf"):
                print(f"[*] [WAF Detected] النطاق محمي بجدار حماية ({waf_result.get('waf_provider')})، جاري استكمال الفحص الشامل.", flush=True)
            else:
                print(f"[*] [WAF Check] النطاق مباشر ولا يظهر جدار حماية سحابي وسيط.", flush=True)
        except Exception as ex:
            print(f"[!] Warning: Origin recon error in Stage 0: {ex}", flush=True)

        # -------------------------------------------------------------
        # Phase 1: Discovery & Port Scanning
        # -------------------------------------------------------------
        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled.")

        update_status(
            scan_id,
            status="running",
            stage="phase1_discovery",
            progress=10,
            log_message=f"المرحلة الأولى: تشغيل Subfinder و Naabu للنطاق: {clean_domain}"
        )
        ok_sub, subdomains = run_subfinder(clean_domain, session_dir, scan_id)
        if ok_sub:
            tool_statuses["subfinder"] = "success" if subdomains else "empty"
        else:
            tool_statuses["subfinder"] = "failed"

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
        ok_ports, open_ports = _invoke_tool_with_profile(run_naabu, naabu_targets, session_dir, scan_id, scan_profile=scan_profile)
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
            
        if ok_http:
            phase_completed["phase2"] = True

        # ── Pipeline Zero-Target Guard ────────────────────────────────
        # If no open ports and no live web services were discovered on the target
        if not open_ports and not active_urls:
            print(f"[!] [Zero-Target Guard] لم يتم العثور على أي منافذ مفتوحة أو خدمات ويب نشطة للنطاق {domain}. إيقاف الفحص بأمان لمنع إعلان إكمال وهمي.", flush=True)
            tool_statuses["kiterunner"] = "skipped"
            tool_statuses["nuclei"] = "skipped"
            tool_statuses["wapiti"] = "skipped"

            unify_and_save_vulnerabilities(session_dir, scan_id, [], [])

            final_status = "blocked_no_targets"
            has_error = True
            msg = "تنبيه: لم يتم اكتشاف أي منافذ مفتوحة أو خدمات ويب نشطة على الهدف (قد يكون الهدف محجوباً بواسطة جدار حماية أو غير متصل بالشبكة). تم إنهاء الفحص بأمان دون فحص ثغرات."

            package_session_evidence_and_metadata(
                session_dir=session_dir,
                scan_id=scan_id,
                domain=domain,
                final_status=final_status,
                tool_statuses=tool_statuses
            )

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
            return

        # If non-web open ports exist, but zero live web services (HTTP/HTTPS) were discovered
        if open_ports and not active_urls:
            print(f"[*] [Zero-Target Guard] تم اكتشاف {len(open_ports)} منفذ نشط ولكن لا توجد خدمات ويب. تخطي أدوات فحص الويب.", flush=True)
            tool_statuses["kiterunner"] = "skipped"
            tool_statuses["nuclei"] = "skipped"
            tool_statuses["wapiti"] = "skipped"

            unify_and_save_vulnerabilities(session_dir, scan_id, [], [])

            final_status = "partial"
            has_error = False
            msg = f"اكتمل الفحص جزئياً: تم اكتشاف {len(open_ports)} منفذ نشط، ولكن لا توجد خدمات ويب (HTTP/HTTPS) لفحص ثغرات التطبيقات."

            package_session_evidence_and_metadata(
                session_dir=session_dir,
                scan_id=scan_id,
                domain=domain,
                final_status=final_status,
                tool_statuses=tool_statuses
            )

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
            return

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
        in_scope_urls    = scoped.get("in_scope_urls") or []
        third_party_urls = scoped.get("third_party_urls") or []
        excluded_count   = scoped.get("excluded_count") or 0

        # Fallback to active_urls if scoped list is empty
        if not in_scope_urls and active_urls:
            in_scope_urls = [u for u in active_urls if u]

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
            ok_nuc, nuclei_findings = _invoke_tool_with_profile(run_nuclei, session_dir, scan_id, scan_profile=scan_profile)
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
            ok_wap, wapiti_findings = _invoke_tool_with_profile(run_wapiti_dast, session_dir, scan_id, dast_targets, profile=scan_profile)
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
        elif not open_ports and not active_urls:
            final_status = "blocked_no_targets"
            has_error = True
            msg = "تنبيه: لم يتم اكتشاف أي منافذ مفتوحة أو خدمات ويب نشطة على الهدف (قد يكون الهدف محجوباً بواسطة جدار حماية أو غير متصل بالشبكة)."
        else:
            final_status = "completed"
            has_error = False
            msg = "اكتمل الفحص الأمني الشامل بنجاح."

        # Consolidate metadata and package raw evidence
        package_session_evidence_and_metadata(
            session_dir=session_dir,
            scan_id=scan_id,
            domain=domain,
            final_status=final_status,
            tool_statuses=tool_statuses
        )

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
