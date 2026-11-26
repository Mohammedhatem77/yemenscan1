"""
Celery Distributed Tasks Definition & Dispatcher for YemenScan.

Defines asynchronous tasks for the full scanning pipeline, individual stages,
and tools, with a seamless fallback to in-process execution when Redis/Celery
is unavailable (e.g. during local tests).
"""

import os
import sys
import json
import logging
from typing import Optional, Dict, Any

from core.celery_app import celery_app, is_celery_broker_reachable
from core.pipeline import run_full_pipeline
from core.execution_engine import (
    run_stage1_pipeline,
    run_stage2_pipeline,
    run_stage3_pipeline,
    run_tool_in_session,
    run_standalone_subfinder,
    run_standalone_naabu,
    run_standalone_httpx,
    run_standalone_kiterunner,
    run_standalone_nuclei,
    run_standalone_wapiti,
)
from core.session import (
    create_standalone_session,
    get_session_dir,
    get_status,
    update_status,
)
from core.db_service import ingest_scan_from_directory, complete_scan_session
from database import SessionLocal

logger = logging.getLogger("yemenscan.tasks")


class BrokerConnectionError(Exception):
    """Raised when task scheduling fails due to broker unreachability or Celery errors."""
    pass


ALLOWED_STANDALONE_TOOLS = {"subfinder", "naabu", "httpx", "kiterunner", "nuclei", "wapiti"}
ALLOWED_STANDALONE_OPTIONS = {"ports", "severity", "category", "tags", "modules", "profile", "targets"}



# ---------------------------------------------------------------------------
# Celery Asynchronous Tasks
# ---------------------------------------------------------------------------

@celery_app.task(bind=True, name="yemenscan.tasks.full_scan_pipeline",
                 soft_time_limit=1800, time_limit=2400)
def celery_run_full_pipeline(self, domain: str, scan_id: str, scan_profile: str = "safe", resume: bool = False):
    """Executes the full pipeline via Celery worker and ingests into DB."""
    logger.info("[Celery Worker] Starting full scan (resume=%s) for %s (Scan ID: %s, Profile: %s)", resume, domain, scan_id, scan_profile)
    try:
        run_full_pipeline(domain, scan_id, scan_profile=scan_profile, resume=resume)
        try:
            with SessionLocal() as db:
                ingest_scan_from_directory(db, scan_id, domain=domain)
        except Exception as db_err:
            logger.error("[Celery Worker] DB ingestion error for %s: %s", scan_id, db_err)
        return {"status": "success", "scan_id": scan_id, "domain": domain, "scan_profile": scan_profile, "resume": resume}
    except Exception as e:
        logger.error("[Celery Worker] Error in full scan %s: %s", scan_id, e)
        try:
            with SessionLocal() as db:
                complete_scan_session(db, scan_id, status="failed")
        except Exception:
            pass
        raise e


@celery_app.task(bind=True, name="yemenscan.tasks.stage1_discovery")
def celery_run_stage1(self, scan_id: str, domain: str):
    """Executes stage 1 (Discovery) via Celery worker."""
    return run_stage1_pipeline(scan_id, domain)


@celery_app.task(bind=True, name="yemenscan.tasks.stage2_web_probing")
def celery_run_stage2(self, scan_id: str):
    """Executes stage 2 (Web Probing) via Celery worker."""
    return run_stage2_pipeline(scan_id)


@celery_app.task(bind=True, name="yemenscan.tasks.stage3_vulnerabilities",
                 soft_time_limit=1800, time_limit=2400)
def celery_run_stage3(self, scan_id: str, scan_profile: str = "safe"):
    """Executes stage 3 (Vulnerabilities) via Celery worker.
    
    Args:
        scan_profile: One of 'safe', 'dast_light', 'deep'. Drives timeouts,
                      rate-limits, concurrency and DAST module selection.
                      Note: deep profile overrides soft_time_limit/time_limit
                      at dispatch time via apply_async(kwargs).
    """
    return run_stage3_pipeline(scan_id, scan_profile=scan_profile)


@celery_app.task(bind=True, name="yemenscan.tasks.tool_in_session")
def celery_run_tool(self, scan_id: str, tool_name: str, options: Dict[str, Any]):
    """Executes an individual tool in a session via Celery worker."""
    return run_tool_in_session(scan_id, tool_name, options)


@celery_app.task(bind=True, name="yemenscan.tasks.update_nuclei_templates")
def celery_update_nuclei_templates(self):
    """Executes asynchronous background template update & validation."""
    from core.template_updater import run_template_update_job
    return run_template_update_job()


@celery_app.task(
    bind=True,
    name="yemenscan.tasks.standalone_tool",
    soft_time_limit=1800,
    time_limit=2400
)
def celery_run_standalone_tool(
    self,
    scan_id: str,
    tool_name: str,
    target: Any,
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Executes an independent security tool (Subfinder, Naabu, HTTPX, Kiterunner, Nuclei, Wapiti)
    asynchronously inside a Celery worker, updating status and persisting results.
    """
    tool_clean = str(tool_name or "").strip().lower()
    if tool_clean not in ALLOWED_STANDALONE_TOOLS:
        err = f"Tool '{tool_clean}' is not in allowed standalone tools list."
        logger.error("[Celery Worker] %s", err)
        update_status(scan_id, status="failed", stage="failed", is_completed=True, has_error=True, error=err)
        raise ValueError(err)

    # Defense-in-depth: re-verify target safety inside Celery Worker before Docker execution
    from core.target_validator import validate_standalone_target, TargetValidationError
    try:
        clean_target = validate_standalone_target(tool_clean, target)
    except TargetValidationError as ve:
        err = f"فشل التحقق الأمني داخل عامل Celery للهدف: {str(ve)}"
        logger.error("[Celery Worker] %s", err)
        update_status(scan_id, status="failed", stage="failed", is_completed=True, has_error=True, error=err, log_message=err)
        raise ValueError(err)

    session_dir = get_session_dir(scan_id)
    opts = options or {}
    logger.info("[Celery Worker] Starting standalone tool %s for scan %s (target=%s)", tool_clean, scan_id, clean_target)

    update_status(
        scan_id,
        status="running",
        stage=f"running_{tool_clean}",
        tool=tool_clean,
        progress=20,
        log_message=f"بدء تشغيل أداة {tool_clean} المستقلة في عامل Celery..."
    )

    try:
        if tool_clean == "subfinder":
            res = run_standalone_subfinder(domain=str(clean_target), session_dir=session_dir, scan_id=scan_id)
        elif tool_clean == "naabu":
            ports = opts.get("ports")
            res = run_standalone_naabu(target=str(clean_target), ports=ports, session_dir=session_dir, scan_id=scan_id)
        elif tool_clean == "httpx":
            targets = clean_target if isinstance(clean_target, list) else [str(clean_target)]
            res = run_standalone_httpx(targets=targets, session_dir=session_dir, scan_id=scan_id)
        elif tool_clean == "kiterunner":
            res = run_standalone_kiterunner(target_url=str(clean_target), session_dir=session_dir, scan_id=scan_id)
        elif tool_clean == "nuclei":
            res = run_standalone_nuclei(
                target_url=str(clean_target),
                severity=opts.get("severity"),
                category=opts.get("category"),
                tags=opts.get("tags"),
                session_dir=session_dir,
                scan_id=scan_id
            )
        elif tool_clean == "wapiti":
            res = run_standalone_wapiti(
                target_url=str(clean_target),
                modules=opts.get("modules"),
                profile=opts.get("profile", "safe"),
                session_dir=session_dir,
                scan_id=scan_id
            )
        else:
            raise ValueError(f"Unhandled tool: {tool_clean}")

        # Persist results in session directory
        results_file = os.path.join(session_dir, "results.json")
        try:
            with open(results_file, "w", encoding="utf-8") as rf:
                json.dump(res, rf, ensure_ascii=False, indent=2)
        except Exception as fe:
            logger.warning("[Celery Worker] Could not write results.json for %s: %s", scan_id, fe)

        # Update status
        is_success = res.get("status") == "success"
        final_status = "completed" if is_success else "failed"

        # Save results directly in status.json
        status_file = os.path.join(session_dir, "status.json")
        try:
            if os.path.exists(status_file):
                with open(status_file, "r", encoding="utf-8") as sf:
                    s_dict = json.load(sf)
                s_dict["results"] = res
                with open(status_file, "w", encoding="utf-8") as sf:
                    json.dump(s_dict, sf, ensure_ascii=False, indent=2)
        except Exception:
            pass

        update_status(
            scan_id,
            status=final_status,
            stage="completed" if is_success else "failed",
            tool=tool_clean,
            progress=100,
            is_completed=True,
            has_error=not is_success,
            tool_status={tool_clean: "success" if is_success else "failed"},
            log_message=f"اكتمل تنفيذ أداة {tool_clean} بنجاح." if is_success else f"انتهى تنفيذ أداة {tool_clean} بحالة فشل."
        )
        return res
    except Exception as e:
        logger.error("[Celery Worker] Error executing standalone tool %s for %s: %s", tool_clean, scan_id, e)
        update_status(
            scan_id,
            status="failed",
            stage="failed",
            tool=tool_clean,
            progress=100,
            is_completed=True,
            has_error=True,
            error=str(e),
            log_message=f"حدث استثناء أثناء تشغيل أداة {tool_clean}: {str(e)}"
        )
        raise e


# ---------------------------------------------------------------------------
# Smart Dispatcher (Celery with graceful BackgroundTasks fallback)
# ---------------------------------------------------------------------------

def _compute_dynamic_celery_limits(
    profile_cfg: Dict[str, Any],
    session_dir: Optional[str] = None,
) -> tuple[int, int]:
    """
    Computes adaptive Celery (soft_time_limit, time_limit) scaled proportionally
    to discovered or allowed origin counts while preserving matrix minimums.
    """
    base_soft = int(profile_cfg.get("celery_soft_time_limit", 2400))
    base_hard = int(profile_cfg.get("celery_time_limit", 3000))
    max_origins = int(profile_cfg.get("wapiti_max_origins", 10))
    per_origin_scan = int(profile_cfg.get("wapiti_max_scan_time", 240))

    origin_count = max_origins
    if session_dir:
        active_txt = os.path.join(session_dir, "active_urls.txt")
        if os.path.exists(active_txt):
            try:
                with open(active_txt, "r", encoding="utf-8", errors="replace") as af:
                    lines = [l.strip() for l in af if l.strip()]
                if lines:
                    from urllib.parse import urlparse
                    uniq = {f"{urlparse(u).scheme}://{urlparse(u).netloc}" for u in lines if "://" in u}
                    origin_count = min(max_origins, max(1, len(uniq)))
            except Exception:
                pass

    # Allocate headroom for Stage 1/2 + Nuclei + Wapiti per-origin budget (capped at 6 hours)
    scaled_soft = min(21600, max(base_soft, origin_count * per_origin_scan + 1800))
    scaled_hard = min(23400, max(base_hard, scaled_soft + 900))
    return scaled_soft, scaled_hard


def dispatch_scan_pipeline(domain: str, scan_id: str, scan_profile: str = "safe", background_tasks=None, resume: bool = False) -> str:
    """
    Dispatches full scan to Celery worker if Redis is reachable;
    otherwise gracefully falls back to FastAPI BackgroundTasks or in-process.
    Dynamically loads profile config to set Celery soft/hard time limits.
    Supports atomic resumption (resume=True).
    Returns: 'celery' or 'background_tasks'
    """
    _VALID_PROFILES = {"safe", "dast_light", "deep"}
    if scan_profile not in _VALID_PROFILES:
        scan_profile = "safe"

    from core.security_scan_planner import SecurityScanPlanner
    planner = SecurityScanPlanner()
    profile_cfg = planner.get_profile_config(scan_profile)
    sess_dir = None
    try:
        sess_dir = get_session_dir(scan_id)
    except Exception:
        sess_dir = None
    soft_tl, hard_tl = _compute_dynamic_celery_limits(profile_cfg, session_dir=sess_dir)

    if is_celery_broker_reachable():
        try:
            celery_run_full_pipeline.apply_async(
                args=[domain, scan_id, scan_profile, resume],
                soft_time_limit=soft_tl,
                time_limit=hard_tl,
                ignore_result=True
            )
            print(f"[+] Scan {scan_id} (resume={resume}) dispatched to Celery worker (profile={scan_profile}, soft_limit={soft_tl}s, hard_limit={hard_tl}s).", flush=True)
            return "celery"
        except Exception as ex:
            print(f"[!] Warning: Celery dispatch failed ({ex}), falling back to background tasks.", flush=True)

    # Fallback to local background tasks
    if background_tasks:
        background_tasks.add_task(_execute_full_scan_fallback, domain, scan_id, scan_profile, resume)
    else:
        _execute_full_scan_fallback(domain, scan_id, scan_profile, resume)
    return "background_tasks"


def dispatch_stage1(scan_id: str, domain: str, background_tasks=None) -> str:
    if is_celery_broker_reachable():
        try:
            celery_run_stage1.apply_async(args=[scan_id, domain], ignore_result=True)
            print(f"[+] Stage 1 for {scan_id} dispatched to Celery worker.", flush=True)
            return "celery"
        except Exception:
            pass
    if background_tasks:
        background_tasks.add_task(run_stage1_pipeline, scan_id, domain)
    else:
        run_stage1_pipeline(scan_id, domain)
    return "background_tasks"


def dispatch_stage2(scan_id: str, background_tasks=None) -> str:
    if is_celery_broker_reachable():
        try:
            celery_run_stage2.apply_async(args=[scan_id], ignore_result=True)
            print(f"[+] Stage 2 for {scan_id} dispatched to Celery worker.", flush=True)
            return "celery"
        except Exception:
            pass
    if background_tasks:
        background_tasks.add_task(run_stage2_pipeline, scan_id)
    else:
        run_stage2_pipeline(scan_id)
    return "background_tasks"


def dispatch_stage3(scan_id: str, scan_profile: str = "safe", background_tasks=None) -> str:
    """Dispatches Stage 3 to Celery worker or BackgroundTasks fallback.
    
    Args:
        scan_profile: One of 'safe', 'dast_light', 'deep'. Passed to the
                      pipeline and all tool calls. Deep profile extends
                      Celery time limits automatically.
    """
    # Validate profile
    _VALID_PROFILES = {"safe", "dast_light", "deep"}
    if scan_profile not in _VALID_PROFILES:
        scan_profile = "safe"

    from core.security_scan_planner import SecurityScanPlanner
    planner = SecurityScanPlanner()
    profile_cfg = planner.get_profile_config(scan_profile)
    sess_dir = None
    try:
        sess_dir = get_session_dir(scan_id)
    except Exception:
        sess_dir = None
    soft_tl, hard_tl = _compute_dynamic_celery_limits(profile_cfg, session_dir=sess_dir)

    if is_celery_broker_reachable():
        try:
            celery_run_stage3.apply_async(
                args=[scan_id, scan_profile],
                soft_time_limit=soft_tl,
                time_limit=hard_tl,
                ignore_result=True
            )
            print(f"[+] Stage 3 for {scan_id} dispatched to Celery worker (profile={scan_profile}, soft_limit={soft_tl}s, hard_limit={hard_tl}s).", flush=True)
            return "celery"
        except Exception:
            pass
    if background_tasks:
        background_tasks.add_task(run_stage3_pipeline, scan_id, scan_profile)
    else:
        run_stage3_pipeline(scan_id, scan_profile)
    return "background_tasks"


def dispatch_tool(scan_id: str, tool_name: str, options: Dict[str, Any], background_tasks=None) -> str:
    if is_celery_broker_reachable():
        try:
            celery_run_tool.apply_async(args=[scan_id, tool_name, options], ignore_result=True)
            print(f"[+] Tool {tool_name} for {scan_id} dispatched to Celery worker.", flush=True)
            return "celery"
        except Exception:
            pass
    if background_tasks:
        background_tasks.add_task(run_tool_in_session, scan_id, tool_name, options)
    else:
        run_tool_in_session(scan_id, tool_name, options)
    return "background_tasks"


def _execute_full_scan_fallback(domain: str, scan_id: str, scan_profile: str = "safe", resume: bool = False):
    """In-process execution of full scan with DB ingestion."""
    try:
        run_full_pipeline(domain, scan_id, scan_profile=scan_profile, resume=resume)
        try:
            with SessionLocal() as db:
                ingest_scan_from_directory(db, scan_id, domain=domain)
        except Exception as db_err:
            print(f"[!] Database ingestion error for {scan_id}: {db_err}", flush=True)
    except Exception as e:
        print(f"[!] Error in scan background task for {scan_id}: {e}", flush=True)
        try:
            with SessionLocal() as db:
                complete_scan_session(db, scan_id, status="failed")
        except Exception:
            pass


def dispatch_template_update(background_tasks=None) -> Dict[str, str]:
    """Dispatches template update to Celery or FastAPI BackgroundTasks."""
    from core.template_updater import run_template_update_job
    if is_celery_broker_reachable():
        try:
            celery_update_nuclei_templates.apply_async(ignore_result=True)
            logger.info("[Celery Dispatcher] Template update dispatched to Celery worker.")
            return {"mode": "celery", "status": "started", "message": "تم إرسال مهمة تحديث القوالب إلى عامل سيليري في الخلفية."}
        except Exception as ex:
            logger.warning("[Celery Dispatcher] Failed to dispatch to Celery (%s), falling back.", ex)
    if background_tasks:
        background_tasks.add_task(run_template_update_job)
    else:
        import threading
        threading.Thread(target=run_template_update_job, daemon=True).start()
    return {"mode": "background_tasks", "status": "started", "message": "تم بدء تحديث القوالب في الخلفية."}


def dispatch_standalone_tool(
    tool_name: str,
    target: Any,
    options: Optional[Dict[str, Any]] = None,
    scan_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Validates tool and inputs, registers a standalone scan session, and dispatches
    the task strictly to Celery. If Redis broker is unreachable, records failure and
    raises BrokerConnectionError. Strictly prohibits direct in-process tool execution.
    """
    tool_clean = str(tool_name or "").strip().lower()
    if tool_clean not in ALLOWED_STANDALONE_TOOLS:
        raise ValueError(
            f"الأداة غير معروفة: '{tool_name}'. الأدوات المسموحة هي: {', '.join(sorted(ALLOWED_STANDALONE_TOOLS))}"
        )

    # Validate target presence and security boundaries
    if not target or (isinstance(target, str) and not target.strip()) or (isinstance(target, list) and not target):
        raise ValueError("الهدف المطلوب فحصه غير صالح أو فارغ.")

    from core.target_validator import validate_standalone_target, TargetValidationError
    try:
        clean_target = validate_standalone_target(tool_clean, target)
    except TargetValidationError as ve:
        raise ValueError(str(ve))

    # Validate options whitelist: prevent arbitrary CLI/Docker injection
    opts = options or {}
    disallowed_keys = set(opts.keys()) - ALLOWED_STANDALONE_OPTIONS
    if disallowed_keys:
        raise ValueError(f"خيارات تشغيل غير مصرح بها: {', '.join(sorted(disallowed_keys))}")

    # Create tracked session
    if not scan_id:
        scan_id = create_standalone_session(tool_clean, clean_target, opts)

    # Check broker reachability
    if not is_celery_broker_reachable():
        err_msg = "تعذر الاتصال بخادم الرسائل (Redis). لا يمكن جدولة الفحص المستقل حالياً."
        logger.error("[Celery Dispatcher] Broker unreachable for standalone %s (scan_id=%s)", tool_clean, scan_id)
        update_status(
            scan_id,
            status="scheduling_failed",
            stage="scheduling_failed",
            is_completed=True,
            has_error=True,
            error=err_msg,
            log_message="تعذر إرسال المهمة إلى وسيط الرسائل (Redis). تم إيقاف الفحص بأمان دون تشغيل محلي."
        )
        raise BrokerConnectionError(err_msg)

    # Dispatch to Celery with deterministic task ID to avoid duplicate submission
    try:
        task = celery_run_standalone_tool.apply_async(
            args=[scan_id, tool_clean, clean_target, opts],
            task_id=f"standalone_{scan_id}"
        )
        print(f"[+] Standalone tool {tool_clean} for {scan_id} dispatched to Celery worker (task_id={task.id}).", flush=True)
        return {
            "status": "scheduled",
            "scan_id": scan_id,
            "tool": tool_clean,
            "task_id": task.id,
            "target": target,
            "message": f"تمت جدولة فحص أداة {tool_clean} بنجاح عبر عامل Celery في الخلفية.",
            "status_endpoint": f"/api/tools/{scan_id}/status",
            "results_endpoint": f"/api/tools/{scan_id}/results"
        }
    except Exception as ex:
        err_msg = f"فشل إرسال المهمة إلى Celery: {str(ex)}"
        logger.error("[Celery Dispatcher] Failed to enqueue task %s: %s", scan_id, ex)
        update_status(
            scan_id,
            status="scheduling_failed",
            stage="scheduling_failed",
            is_completed=True,
            has_error=True,
            error=err_msg,
            log_message=f"فشل إرسال المهمة إلى Celery: {str(ex)}"
        )
        raise BrokerConnectionError(err_msg)


