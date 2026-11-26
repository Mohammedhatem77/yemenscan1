"""
Standalone Independent Security Tools API Router for YemenScan.

This module houses all HTTP endpoints, Pydantic schemas, and dispatch handlers
for on-demand independent tool executions:
- Subfinder (subdomain discovery)
- Naabu (port scanning)
- HTTPX (service probing & tech detection)
- Kiterunner (API endpoint discovery)
- Nuclei (standalone vulnerability scanning)
- Wapiti (standalone dynamic web vulnerability scanning)
- Status and results polling endpoints
- Origin IP / WAF bypass discovery
- Standalone scan results persistence to database

Maintains strict backwards compatibility with existing API contracts.
"""

import os
import json
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from core.target_validator import validate_standalone_target, TargetValidationError
from core.tasks import dispatch_standalone_tool, BrokerConnectionError
from core.session import get_status, get_session_dir
from core.execution_engine import get_tools_readiness_status
from core.db_service import (
    create_target_and_session,
    save_discovered_assets,
    ingest_vulnerabilities,
    complete_scan_session
)
from core.origin_recon import run_origin_recon

router = APIRouter()

TAG_STANDALONE = "3. فحص الأدوات المستقلة (Independent Security Tools)"


# ---------------------------------------------------------------------------
# Pydantic Request Models
# ---------------------------------------------------------------------------

class StandaloneSubfinderReq(BaseModel):
    domain: str


class StandaloneNaabuReq(BaseModel):
    target: str
    ports: Optional[str] = None


class StandaloneHttpxReq(BaseModel):
    targets: List[str]


class StandaloneKiterunnerReq(BaseModel):
    target_url: str


class StandaloneNucleiReq(BaseModel):
    target_url: str
    severity: Optional[str] = "medium,high,critical"
    category: Optional[str] = None
    tags: Optional[str] = None


class StandaloneWapitiReq(BaseModel):
    target_url: str
    modules: Optional[str] = None
    profile: Optional[str] = "safe"  # 'safe' | 'dast_light' | 'deep'


class OriginReconReq(BaseModel):
    domain: str


class SaveStandaloneReq(BaseModel):
    tool: str
    target: str
    results: Dict[str, Any]


# ---------------------------------------------------------------------------
# Standalone Tool Endpoints
# ---------------------------------------------------------------------------

@router.post("/api/tools/subfinder", tags=[TAG_STANDALONE])
def run_standalone_subfinder_endpoint(req: StandaloneSubfinderReq):
    """تشغيل Subfinder المستقل لاكتشاف النطاقات الفرعية لنطاق محدد عبر Celery."""
    if not req.domain or len(req.domain.strip()) < 3:
        raise HTTPException(status_code=400, detail="يرجى إدخال نطاق صالح للبحث عن نطاقاته الفرعية.")
    try:
        clean_domain = validate_standalone_target("subfinder", req.domain)
    except TargetValidationError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    try:
        return dispatch_standalone_tool("subfinder", clean_domain)
    except BrokerConnectionError as bce:
        raise HTTPException(status_code=503, detail=str(bce))
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@router.post("/api/tools/naabu", tags=[TAG_STANDALONE])
def run_standalone_naabu_endpoint(req: StandaloneNaabuReq):
    """تشغيل Naabu المستقل لفحص المنافذ المفتوحة لنطاق أو عنوان IP محدد عبر Celery."""
    if not req.target or len(req.target.strip()) < 3:
        raise HTTPException(status_code=400, detail="يرجى إدخال هدف صالح لفحص المنافذ.")
    try:
        clean_target = validate_standalone_target("naabu", req.target)
    except TargetValidationError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    try:
        opts = {"ports": req.ports} if req.ports else {}
        return dispatch_standalone_tool("naabu", clean_target, options=opts)
    except BrokerConnectionError as bce:
        raise HTTPException(status_code=503, detail=str(bce))
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@router.post("/api/tools/httpx", tags=[TAG_STANDALONE])
def run_standalone_httpx_endpoint(req: StandaloneHttpxReq):
    """تشغيل HTTPX المستقل للتحقق من خدمات الويب النشطة وبصمات التقنيات عبر Celery."""
    if not req.targets:
        raise HTTPException(status_code=400, detail="يرجى إرسال قائمة بالأهداف (نطاقات أو عناوين IP أو روابط).")
    try:
        clean_targets = validate_standalone_target("httpx", req.targets)
    except TargetValidationError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    try:
        return dispatch_standalone_tool("httpx", clean_targets)
    except BrokerConnectionError as bce:
        raise HTTPException(status_code=503, detail=str(bce))
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@router.post("/api/tools/kiterunner", tags=[TAG_STANDALONE])
def run_standalone_kiterunner_endpoint(req: StandaloneKiterunnerReq):
    """تشغيل Kiterunner المستقل لاكتشاف مسارات APIs و Endpoints الحساسة عبر Celery."""
    if not req.target_url:
        raise HTTPException(status_code=400, detail="يرجى إدخال رابط ويب يبدأ بـ http:// أو https://")
    try:
        clean_target = validate_standalone_target("kiterunner", req.target_url)
    except TargetValidationError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    try:
        return dispatch_standalone_tool("kiterunner", clean_target)
    except BrokerConnectionError as bce:
        raise HTTPException(status_code=503, detail=str(bce))
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@router.post("/api/tools/nuclei", tags=[TAG_STANDALONE])
def run_standalone_nuclei_endpoint(req: StandaloneNucleiReq):
    """تشغيل Nuclei المستقل لفحص الثغرات وفق قوالب محددة ودرجات الخطورة عبر Celery."""
    if not req.target_url:
        raise HTTPException(status_code=400, detail="يرجى إدخال رابط ويب أو نطاق صالح للفحص.")
    try:
        clean_target = validate_standalone_target("nuclei", req.target_url)
    except TargetValidationError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    opts = {}
    if req.severity:
        opts["severity"] = req.severity
    if req.category:
        opts["category"] = req.category
    if req.tags:
        opts["tags"] = req.tags
    try:
        return dispatch_standalone_tool("nuclei", clean_target, options=opts)
    except BrokerConnectionError as bce:
        raise HTTPException(status_code=503, detail=str(bce))
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@router.post("/api/tools/wapiti", tags=[TAG_STANDALONE])
def run_standalone_wapiti_endpoint(req: StandaloneWapitiReq):
    """تشغيل Wapiti المستقل للفحص الديناميكي للثغرات الحركية (DAST) عبر Celery."""
    if not req.target_url:
        raise HTTPException(status_code=400, detail="يرجى إدخال رابط ويب يبدأ بـ http:// أو https://")
    try:
        clean_target = validate_standalone_target("wapiti", req.target_url)
    except TargetValidationError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    _VALID_PROFILES = {"safe", "dast_light", "deep"}
    prof = req.profile if req.profile in _VALID_PROFILES else "safe"
    opts = {"profile": prof}
    if req.modules:
        opts["modules"] = req.modules
    try:
        return dispatch_standalone_tool("wapiti", clean_target, options=opts)
    except BrokerConnectionError as bce:
        raise HTTPException(status_code=503, detail=str(bce))
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@router.get("/api/tools/status", tags=[TAG_STANDALONE])
def get_tools_status_endpoint():
    """التحقق من جاهزية وحالة الحاويات الست والأدوات في النظام."""
    return get_tools_readiness_status()


@router.get("/api/tools/{scan_id}/status", tags=[TAG_STANDALONE])
def get_standalone_tool_status_endpoint(scan_id: str):
    """الاستعلام عن حالة تقدم وتنفيذ فحص الأداة المستقلة في الخلفية."""
    status = get_status(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"جلسة الفحص المستقل '{scan_id}' غير موجودة.")
    return {
        "status": status.get("status"),
        "scan_id": scan_id,
        "tool": status.get("tool"),
        "target": status.get("target"),
        "current_stage": status.get("current_stage"),
        "progress_percentage": status.get("progress_percentage", 0),
        "is_completed": status.get("is_completed", False),
        "has_error": status.get("has_error", False),
        "error_message": status.get("error_message"),
        "logs": status.get("logs", [])
    }


@router.get("/api/tools/{scan_id}/results", tags=[TAG_STANDALONE])
def get_standalone_tool_results_endpoint(scan_id: str):
    """استرجاع نتائج فحص الأداة المستقلة بعد اكتمال تنفيذها عبر Celery."""
    status = get_status(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"جلسة الفحص المستقل '{scan_id}' غير موجودة.")

    if not status.get("is_completed"):
        return {
            "status": status.get("status", "running"),
            "scan_id": scan_id,
            "tool": status.get("tool"),
            "is_completed": False,
            "message": "عملية الفحص ما زالت قيد التنفيذ في الخلفية."
        }

    results = status.get("results")
    if not results:
        session_dir = get_session_dir(scan_id)
        results_file = os.path.join(session_dir, "results.json")
        if os.path.exists(results_file):
            try:
                with open(results_file, "r", encoding="utf-8") as rf:
                    results = json.load(rf)
            except Exception:
                pass

    if not results:
        if status.get("has_error"):
            raise HTTPException(status_code=500, detail=status.get("error_message") or "فشل تشغيل الأداة في الخلفية.")
        results = {"tool": status.get("tool"), "status": "completed", "findings": []}

    return results


@router.post("/api/tools/origin-ip", tags=[TAG_STANDALONE])
def run_origin_recon_endpoint(req: OriginReconReq):
    """كشف السيرفر الحقيقي (Origin IP) وتجاوز جدران الحماية (WAF Bypass)."""
    if not req.domain or len(req.domain.strip()) < 3:
        raise HTTPException(status_code=400, detail="يرجى إدخال نطاق صالح لاستكشاف الأصل.")
    return run_origin_recon(req.domain.strip())


@router.post("/api/tools/save-to-db", tags=[TAG_STANDALONE])
def save_standalone_to_db_endpoint(req: SaveStandaloneReq, db: Session = Depends(get_db)):
    """حفظ نتائج الفحص المستقل كجلسة موثقة في قاعدة البيانات."""
    try:
        clean_target = req.target.strip()
        if "://" in clean_target:
            domain_part = urlparse(clean_target).netloc or clean_target
        else:
            domain_part = clean_target.split("/")[0]
        domain_part = domain_part.split(":")[0].rstrip(".")
        if not domain_part:
            domain_part = "standalone-target"

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rand_id = uuid.uuid4().hex[:6]
        scan_id = f"standalone_{req.tool}_{timestamp}_{rand_id}"

        target, session = create_target_and_session(db, domain_part, scan_id)
        
        tool_lower = req.tool.lower().strip()
        if tool_lower == "subfinder":
            subdomains = req.results.get("subdomains", [])
            save_discovered_assets(db, scan_id, subdomains, [])
        elif tool_lower == "naabu":
            open_ports = req.results.get("open_ports", [])
            save_discovered_assets(db, scan_id, open_ports, [])
        elif tool_lower == "httpx":
            web_targets = req.results.get("web_targets", [])
            active_urls = req.results.get("active_urls", [])
            save_discovered_assets(db, scan_id, web_targets or active_urls, [])
        elif tool_lower == "kiterunner":
            api_endpoints = req.results.get("api_endpoints", [])
            save_discovered_assets(db, scan_id, [], api_endpoints)
        elif tool_lower in ("nuclei", "wapiti"):
            findings = req.results.get("findings", [])
            ingest_vulnerabilities(db, scan_id, findings)
            
        complete_scan_session(db, scan_id, status="completed")
        return {
            "status": "success",
            "scan_id": scan_id,
            "message": f"تم حفظ نتائج أداة {req.tool} بنجاح في قاعدة البيانات!"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"فشل حفظ النتائج في قاعدة البيانات: {str(e)}")
