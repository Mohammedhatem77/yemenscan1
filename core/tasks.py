"""
Celery Distributed Tasks Definition & Dispatcher for YemenScan.

Defines asynchronous tasks for the full scanning pipeline, individual stages,
and tools, with a seamless fallback to in-process execution when Redis/Celery
is unavailable (e.g. during local tests).
"""

import os
import sys
import logging
from typing import Optional, Dict, Any

from core.celery_app import celery_app, is_celery_broker_reachable
from core.pipeline import run_full_pipeline
from core.execution_engine import (
    run_stage1_pipeline,
    run_stage2_pipeline,
    run_stage3_pipeline,
    run_tool_in_session,
)
from core.db_service import ingest_scan_from_directory, complete_scan_session
from database import SessionLocal

logger = logging.getLogger("yemenscan.tasks")


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


# ---------------------------------------------------------------------------
# Smart Dispatcher (Celery with graceful BackgroundTasks fallback)
# ---------------------------------------------------------------------------

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
    soft_tl = profile_cfg.get("celery_soft_time_limit", 1800)
    hard_tl = profile_cfg.get("celery_time_limit", 2400)

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
    soft_tl = profile_cfg.get("celery_soft_time_limit", 1800)
    hard_tl = profile_cfg.get("celery_time_limit", 2400)

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

