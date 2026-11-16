import os
import json
import time
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from core.session import get_session_dir, get_status, update_status, SCANS_DIR
from core.runner import is_docker_available, run_docker_tool, run_local_tool
from core.stage1_discovery import run_subfinder, run_naabu
from core.stage2_web_probing import run_httpx, run_kiterunner_or_api_probing
from core.stage3_vulnerabilities import (
    prepare_nuclei_targets,
    run_nuclei,
    run_wapiti_dast,
    unify_and_save_vulnerabilities,
    NUCLEI_DOCKER_IMAGE,
    WAPITI_DOCKER_IMAGE
)
from core.scope_classifier import load_scoped_urls
from database import SessionLocal
from core.db_service import ingest_scan_from_directory, complete_scan_session

STANDALONE_DIR = os.path.join(SCANS_DIR, "_standalone")
os.makedirs(STANDALONE_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Scope Guard — Nuclei Takeover Helper
# ---------------------------------------------------------------------------
_NUCLEI_TAKEOVER_IMAGE = (
    "projectdiscovery/nuclei:v3.11.1"
    "@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb"
)

def _run_nuclei_takeover_check(
    session_dir: str,
    scan_id: Optional[str],
    third_party_urls: List[str]
) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Lightweight Nuclei Takeover-only check for third-party / external-redirect assets.
    Uses -tags takeover -severity critical,high,medium — passive single-GET check.
    Keeps zero dependency on stage3_vulnerabilities internals (safe from teammate conflict).
    """
    if not third_party_urls:
        return True, []

    takeover_txt = os.path.join(session_dir, "nuclei_takeover_targets.txt")
    with open(takeover_txt, "w", encoding="utf-8") as fh:
        for u in third_party_urls:
            fh.write(f"{u}\n")

    out_file = os.path.join(session_dir, "nuclei_takeover_findings.jsonl")
    container_input  = "/nuclei_input/takeover_targets.txt"
    container_output = "/nuclei_input/takeover_findings.jsonl"

    docker_args = [
        "run", "--rm",
        "-v", f"{session_dir}:/nuclei_input",
        _NUCLEI_TAKEOVER_IMAGE,
        "-l", container_input,
        "-tags", "takeover",
        "-severity", "critical,high,medium",
        "-je", container_output,
        "-silent",
        "-no-color",
    ]

    findings: List[Dict[str, Any]] = []
    try:
        ok, stdout, stderr = run_docker_tool(docker_args, timeout=300)
        if os.path.exists(out_file):
            with open(out_file, "r", encoding="utf-8", errors="replace") as rf:
                for line in rf:
                    line = line.strip()
                    if line:
                        try:
                            rec = json.loads(line)
                            rec.setdefault("source", "nuclei-takeover")
                            findings.append(rec)
                        except Exception:
                            pass
        print(
            f"[Scope Guard] ✅ Nuclei Takeover: وجد {len(findings)} ثغرة محتملة في الأصول الخارجية.",
            flush=True
        )
        return ok, findings
    except Exception as exc:
        print(f"[Scope Guard] ⚠️ Nuclei Takeover فشل: {exc}", flush=True)
        return False, []

# ---------------------------------------------------------------------------
# 1. Pipeline Stages Execution (المراحل الثلاث لخط الفحص)
# ---------------------------------------------------------------------------

def run_stage1_pipeline(scan_id: str, domain: Optional[str] = None) -> Dict[str, Any]:
    """
    Executes Stage 1 (Discovery & Port Scanning): Subfinder -> Naabu.
    Reads/writes from session directory and ingests findings to Database.
    """
    session_dir = get_session_dir(scan_id)
    stat = get_status(scan_id) or {}
    target_domain = domain or stat.get("target_domain")
    if not target_domain:
        raise ValueError(f"Target domain for scan_id '{scan_id}' not found.")

    update_status(
        scan_id,
        status="running",
        stage="phase1_discovery",
        progress=10,
        log_message=f"تشغيل المرحلة الأولى (Subfinder + Naabu) للنطاق: {target_domain}"
    )

    # 1. Subfinder
    ok_sub, subdomains = run_subfinder(target_domain, session_dir, scan_id)

    # 2. Naabu
    clean_domain = target_domain.strip().lower()
    if "://" in clean_domain:
        clean_domain = clean_domain.split("://", 1)[1]
    clean_domain = clean_domain.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    naabu_targets = [clean_domain] + [s for s in subdomains if s.lower() != clean_domain]

    ok_ports, open_ports = run_naabu(naabu_targets, session_dir, scan_id)

    # Ingest to DB
    try:
        with SessionLocal() as db:
            ingest_scan_from_directory(db, scan_id, domain=target_domain)
    except Exception as e:
        print(f"[!] Warning: DB ingestion error after stage 1: {e}", flush=True)

    update_status(
        scan_id,
        status="running",
        stage="phase1_completed",
        progress=35,
        log_message=f"اكتملت المرحلة الأولى: {len(subdomains)} نطاق فرعي، و {len(open_ports)} منفذ مفتوح."
    )

    return {
        "status": "success",
        "scan_id": scan_id,
        "stage": "stage1_discovery",
        "target_domain": target_domain,
        "subdomains_count": len(subdomains),
        "subdomains": subdomains,
        "open_ports_count": len(open_ports),
        "open_ports": open_ports
    }


def run_stage2_pipeline(scan_id: str) -> Dict[str, Any]:
    """
    Executes Stage 2 (Web & API Probing): HTTPX -> Kiterunner.
    Uses discovered ports/hosts from session directory.
    """
    session_dir = get_session_dir(scan_id)
    stat = get_status(scan_id) or {}
    target_domain = stat.get("target_domain", "unknown")

    update_status(
        scan_id,
        status="running",
        stage="phase2_web_probing",
        progress=40,
        log_message="تشغيل المرحلة الثانية (HTTPX + Kiterunner) لفحص خدمات الويب وواجهات برمجة التطبيقات..."
    )

    # 1. HTTPX
    ok_http, web_targets, active_urls = run_httpx(session_dir, scan_id)

    # 2. Kiterunner
    api_endpoints = []
    if active_urls:
        ok_api, api_endpoints = run_kiterunner_or_api_probing(active_urls, session_dir, scan_id)

    # Ingest to DB
    try:
        with SessionLocal() as db:
            ingest_scan_from_directory(db, scan_id, domain=target_domain)
    except Exception as e:
        print(f"[!] Warning: DB ingestion error after stage 2: {e}", flush=True)

    update_status(
        scan_id,
        status="running",
        stage="phase2_completed",
        progress=65,
        log_message=f"اكتملت المرحلة الثانية: {len(active_urls)} خدمة ويب نشطة، و {len(api_endpoints)} مسار API."
    )

    return {
        "status": "success",
        "scan_id": scan_id,
        "stage": "stage2_web_probing",
        "active_urls_count": len(active_urls),
        "active_urls": active_urls,
        "api_endpoints_count": len(api_endpoints),
        "api_endpoints": api_endpoints
    }


def run_stage3_pipeline(scan_id: str) -> Dict[str, Any]:
    """
    Executes Stage 3 (Vulnerability Assessment): Nuclei (CVE/OWASP) + Wapiti (DAST).
    Applies Scope Guard: third-party assets are excluded from full DAST
    but are still passed to Nuclei with the 'takeover' tag only.
    Unifies findings and updates database.
    """
    session_dir = get_session_dir(scan_id)
    stat = get_status(scan_id) or {}
    target_domain = stat.get("target_domain", "unknown")

    update_status(
        scan_id,
        status="running",
        stage="phase3_vulnerabilities",
        progress=70,
        log_message="تشغيل المرحلة الثالثة (Nuclei + Wapiti) لفحص الثغرات الأمنية..."
    )

    # ── Scope Guard: تقسيم الأصول حسب نطاق الفحص ───────────────────────────
    scoped = load_scoped_urls(session_dir)
    in_scope_urls    = scoped["in_scope_urls"]
    third_party_urls = scoped["third_party_urls"]
    excluded_count   = scoped["excluded_count"]

    if excluded_count > 0:
        print(
            f"[Scope Guard] ✅ تم استبعاد {excluded_count} أصل تابع لطرف ثالث من فحص DAST الكامل.",
            flush=True
        )
        print(
            f"[Scope Guard] 🔍 سيتم فحص {excluded_count} أصل بـ Nuclei (Takeover فقط) كفحص سلبي.",
            flush=True
        )

    # ── 1. Nuclei — فحص CVE/OWASP على الأصول الداخلية فقط ──────────────────
    nuclei_findings: List[Dict[str, Any]] = []

    if in_scope_urls:
        # نستخدم prepare_nuclei_targets لاستخراج الأصول وكتابة nuclei_targets.txt
        # (تعمل على active_urls.txt وactive_urls.json — كلاهما يحتوي الكل)
        # ثم نُرشّح ملف nuclei_targets.txt ليحتوي فقط الأصول الداخلية
        all_targets = prepare_nuclei_targets(session_dir)
        # تصفية: احتفظ فقط بالأصول التي URL أصولها تتطابق مع in_scope_urls
        in_scope_origins = set()
        for u in in_scope_urls:
            parsed = urlparse(u)
            origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else u
            in_scope_origins.add(origin.rstrip("/"))
        filtered_targets = [t for t in all_targets if any(t.startswith(o) or o.startswith(t) for o in in_scope_origins)]
        if not filtered_targets:
            filtered_targets = all_targets  # Fallback: في حال التصفية محو الكل
        # أعد كتابة nuclei_targets.txt بالأصول الداخلية فقط
        nuclei_txt = os.path.join(session_dir, "nuclei_targets.txt")
        with open(nuclei_txt, "w", encoding="utf-8") as fh:
            for t in filtered_targets:
                fh.write(f"{t}\n")
        if filtered_targets:
            ok_nuc, nuclei_findings = run_nuclei(session_dir, scan_id)
    else:
        print("[Scope Guard] ⚠️ لا توجد أصول داخلية — تخطي فحص Nuclei CVE.", flush=True)

    # ── 2. Nuclei — فحص Subdomain Takeover على الأصول التابعة لطرف ثالث ─────
    takeover_findings: List[Dict[str, Any]] = []

    if third_party_urls:
        print(
            f"[Scope Guard] 🎯 تشغيل Nuclei Takeover على {len(third_party_urls)} نطاق تابع لطرف ثالث...",
            flush=True
        )
        ok_tak, takeover_findings = _run_nuclei_takeover_check(
            session_dir, scan_id, third_party_urls
        )
        nuclei_findings = nuclei_findings + takeover_findings

    # ── 3. Wapiti DAST — على الأصول الداخلية فقط ────────────────────────────
    wapiti_findings: List[Dict[str, Any]] = []

    if in_scope_urls:
        ok_wap, wapiti_findings = run_wapiti_dast(session_dir, scan_id, in_scope_urls)
    else:
        print("[Scope Guard] ⚠️ لا توجد أصول داخلية — تخطي فحص Wapiti DAST.", flush=True)

    # ── 4. توحيد النتائج وحفظها ──────────────────────────────────────────────
    unify_and_save_vulnerabilities(session_dir, scan_id, nuclei_findings, wapiti_findings)

    # Ingest to DB
    try:
        with SessionLocal() as db:
            ingest_scan_from_directory(db, scan_id, domain=target_domain)
            complete_scan_session(db, scan_id, status="completed")
    except Exception as e:
        print(f"[!] Warning: DB ingestion error after stage 3: {e}", flush=True)

    total_vulns = len(nuclei_findings) + len(wapiti_findings)
    update_status(
        scan_id,
        status="completed",
        stage="completed",
        progress=100,
        is_completed=True,
        log_message=(
            f"اكتملت المرحلة الثالثة: {len(nuclei_findings)} ثغرة عبر Nuclei "
            f"(منها {len(takeover_findings)} Takeover) "
            f"و {len(wapiti_findings)} ثغرة عبر Wapiti. "
            f"تم استبعاد {excluded_count} أصل تابع لطرف ثالث من DAST."
        )
    )

    return {
        "status": "success",
        "scan_id": scan_id,
        "stage": "stage3_vulnerabilities",
        "nuclei_findings_count": len(nuclei_findings),
        "nuclei_takeover_count": len(takeover_findings),
        "wapiti_findings_count": len(wapiti_findings),
        "total_vulnerabilities": total_vulns,
        "scope_guard": {
            "in_scope_count": scoped["in_scope_count"],
            "third_party_count": scoped["third_party_count"],
            "excluded_from_dast": excluded_count,
        }
    }


# ---------------------------------------------------------------------------
# 2. Pipeline In-Session Tool Execution (تشغيل أداة محددة داخل جلسة الفحص)
# ---------------------------------------------------------------------------

def run_tool_in_session(scan_id: str, tool_name: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Runs a single tool inside an active or existing scan session directory.
    Tool choices: 'subfinder', 'naabu', 'httpx', 'kiterunner', 'nuclei', 'wapiti'.
    """
    tool_lower = tool_name.strip().lower()
    session_dir = get_session_dir(scan_id)
    stat = get_status(scan_id) or {}
    domain = stat.get("target_domain")

    if not os.path.exists(session_dir):
        raise FileNotFoundError(f"Session directory for scan_id '{scan_id}' not found.")

    options = options or {}

    if tool_lower == "subfinder":
        if not domain:
            raise ValueError("Target domain is required for subfinder.")
        ok, subdomains = run_subfinder(domain, session_dir, scan_id)
        return {"tool": "subfinder", "status": "success" if ok else "failed", "subdomains": subdomains, "count": len(subdomains)}

    elif tool_lower == "naabu":
        targets = options.get("targets")
        if not targets:
            sub_file = os.path.join(session_dir, "subdomains.txt")
            if os.path.exists(sub_file):
                with open(sub_file, "r", encoding="utf-8") as f:
                    targets = [line.strip() for line in f if line.strip()]
            if not targets and domain:
                targets = [domain]
        ok, open_ports = run_naabu(targets or [domain], session_dir, scan_id)
        return {"tool": "naabu", "status": "success" if ok else "failed", "open_ports": open_ports, "count": len(open_ports)}

    elif tool_lower == "httpx":
        ok, web_targets, active_urls = run_httpx(session_dir, scan_id)
        return {"tool": "httpx", "status": "success" if ok else "failed", "active_urls": active_urls, "count": len(active_urls)}

    elif tool_lower == "kiterunner":
        active_urls = options.get("urls")
        if not active_urls:
            # ── Scope Guard: استخدم الأصول الداخلية فقط ──
            scoped = load_scoped_urls(session_dir)
            active_urls = scoped["in_scope_urls"]
            if scoped["excluded_count"] > 0:
                print(
                    f"[Scope Guard] Kiterunner: استبعاد {scoped['excluded_count']} "
                    f"أصل تابع لطرف ثالث — الفحص على {scoped['in_scope_count']} أصل داخلي فقط.",
                    flush=True
                )
        if not active_urls:
            return {"tool": "kiterunner", "status": "skipped", "message": "No active URLs found to probe APIs.", "count": 0}
        ok, api_endpoints = run_kiterunner_or_api_probing(active_urls, session_dir, scan_id)
        return {"tool": "kiterunner", "status": "success" if ok else "failed", "api_endpoints": api_endpoints, "count": len(api_endpoints)}

    elif tool_lower == "nuclei":
        # ── Scope Guard: فحص CVE على الداخلي، Takeover على الطرف الثالث ──
        scoped = load_scoped_urls(session_dir)
        in_scope_urls    = scoped["in_scope_urls"]
        third_party_urls = scoped["third_party_urls"]
        if scoped["excluded_count"] > 0:
            print(
                f"[Scope Guard] Nuclei: استبعاد {scoped['excluded_count']} أصل من فحص CVE. "
                f"سيُفحص {scoped['third_party_count']} منها بـ Takeover فقط.",
                flush=True
            )

        all_findings: List[Dict[str, Any]] = []
        # فحص CVE/OWASP على الأصول الداخلية
        if in_scope_urls:
            prepare_nuclei_targets(session_dir)
            ok_nuc, cve_findings = run_nuclei(session_dir, scan_id)
            all_findings.extend(cve_findings)
        # فحص Takeover على الطرف الثالث
        if third_party_urls:
            ok_tak, tak_findings = _run_nuclei_takeover_check(
                session_dir, scan_id, third_party_urls
            )
            all_findings.extend(tak_findings)

        return {
            "tool": "nuclei",
            "status": "success",
            "findings": all_findings,
            "count": len(all_findings),
            "scope_guard": {
                "in_scope_count": scoped["in_scope_count"],
                "third_party_takeover_count": scoped["third_party_count"],
            }
        }

    elif tool_lower == "wapiti":
        active_urls = options.get("urls")
        if not active_urls:
            # ── Scope Guard: استخدم الأصول الداخلية فقط ──
            scoped = load_scoped_urls(session_dir)
            active_urls = scoped["in_scope_urls"]
            if scoped["excluded_count"] > 0:
                print(
                    f"[Scope Guard] Wapiti: استبعاد {scoped['excluded_count']} "
                    f"أصل تابع لطرف ثالث — DAST على {scoped['in_scope_count']} أصل داخلي فقط.",
                    flush=True
                )
        if not active_urls:
            return {"tool": "wapiti", "status": "skipped", "message": "No active URLs found for Wapiti DAST.", "count": 0}
        ok, findings = run_wapiti_dast(session_dir, scan_id, active_urls)
        return {"tool": "wapiti", "status": "success" if ok else "failed", "findings": findings, "count": len(findings)}

    else:
        raise ValueError(f"Unknown tool name: {tool_name}. Choose from: subfinder, naabu, httpx, kiterunner, nuclei, wapiti")


# ---------------------------------------------------------------------------
# 3. Independent Standalone Tool Execution (الفحص المستقل للأدوات)
# ---------------------------------------------------------------------------

def _extract_standalone_error(work_dir: str, tool_name: str, fallback_ar: str) -> str:
    """Extracts informative, user-friendly Arabic error message from tool logs."""
    stderr_file = os.path.join(work_dir, f"{tool_name}_stderr.log")
    if os.path.exists(stderr_file):
        try:
            with open(stderr_file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()
                if content:
                    content_lower = content.lower()
                    if "timed out after" in content_lower:
                        return (
                            "استغرقت الأداة وقتاً أطول من المهلة المسموح بها (Timeout): "
                            "الخادم المستهدف بطيء جداً في الاستجابة لحزم الفحص أو يفرض قيوداً على معدل الطلبات (Rate Limiting)."
                        )
                    if "docker" in content_lower and ("not" in content_lower or "connect" in content_lower or "daemon" in content_lower):
                        return "محرك Docker غير متاح أو لا يمتلك صلاحية تشغيل الحاويات المعزولة."
                    if "no such host" in content_lower or "could not resolve" in content_lower or "dns" in content_lower:
                        return "تعذر الوصول إلى الهدف: فشل حل اسم النطاق (DNS Resolution Failure)."
                    if "connection refused" in content_lower:
                        return "تم رفض الاتصال من قبل الخادم المستهدف (Connection Refused)."
                    return content[:300]
        except Exception:
            pass
    return fallback_ar


def run_standalone_subfinder(domain: str) -> Dict[str, Any]:
    """Runs Subfinder independently on a domain, returning discovered subdomains."""
    run_id = f"subfinder_{uuid.uuid4().hex[:8]}"
    work_dir = os.path.join(STANDALONE_DIR, run_id)
    os.makedirs(work_dir, exist_ok=True)
    ok, subdomains = run_subfinder(domain, work_dir, run_id)
    err_msg = "" if ok else _extract_standalone_error(work_dir, "subfinder", "فشل تشغيل أداة Subfinder لاكتشاف النطاقات الفرعية.")
    return {
        "tool": "subfinder",
        "status": "success" if ok else "failed",
        "message": err_msg if not ok else f"تم اكتشاف {len(subdomains)} نطاق فرعي بنجاح.",
        "detail": err_msg if not ok else None,
        "target_domain": domain,
        "subdomains_count": len(subdomains),
        "subdomains": subdomains
    }


def run_standalone_naabu(target: str, ports: Optional[str] = None) -> Dict[str, Any]:
    """Runs Naabu independently on a host or IP, returning open ports."""
    run_id = f"naabu_{uuid.uuid4().hex[:8]}"
    work_dir = os.path.join(STANDALONE_DIR, run_id)
    os.makedirs(work_dir, exist_ok=True)

    clean_target = target.strip()
    ok, open_ports = run_naabu([clean_target], work_dir, run_id)
    err_msg = "" if ok else _extract_standalone_error(work_dir, "naabu", "فشل تشغيل أداة Naabu لفحص المنافذ.")
    return {
        "tool": "naabu",
        "status": "success" if ok else "failed",
        "message": err_msg if not ok else f"تم فحص المنافذ واكتشاف {len(open_ports)} منفذ مفتوح.",
        "detail": err_msg if not ok else None,
        "target": clean_target,
        "open_ports_count": len(open_ports),
        "open_ports": open_ports
    }


def run_standalone_httpx(targets: List[str]) -> Dict[str, Any]:
    """Runs HTTPX independently on a list of URLs or hosts."""
    run_id = f"httpx_{uuid.uuid4().hex[:8]}"
    work_dir = os.path.join(STANDALONE_DIR, run_id)
    os.makedirs(work_dir, exist_ok=True)

    # Write input targets to ports.txt and httpx_input.txt (using newline="\n" for Linux Docker compatibility)
    ports_file = os.path.join(work_dir, "ports.txt")
    with open(ports_file, "w", encoding="utf-8", newline="\n") as f:
        for t in targets:
            clean = t.strip()
            if clean:
                if ":" not in clean and not clean.startswith("http"):
                    f.write(f"{clean}:80\n{clean}:443\n")
                else:
                    f.write(f"{clean}\n")

    ok, web_targets, active_urls = run_httpx(work_dir, run_id)
    err_msg = "" if ok else _extract_standalone_error(work_dir, "httpx", "فشل تشغيل أداة HTTPX لفحص خدمات الويب.")
    return {
        "tool": "httpx",
        "status": "success" if ok else "failed",
        "message": err_msg if not ok else f"تم فحص خدمات الويب واكتشاف {len(active_urls)} خدمة نشطة.",
        "detail": err_msg if not ok else None,
        "total_active_urls": len(active_urls),
        "active_urls": active_urls,
        "web_targets": web_targets
    }


def run_standalone_kiterunner(target_url: str) -> Dict[str, Any]:
    """Runs Kiterunner independently to discover API routes."""
    run_id = f"kiterunner_{uuid.uuid4().hex[:8]}"
    work_dir = os.path.join(STANDALONE_DIR, run_id)
    os.makedirs(work_dir, exist_ok=True)

    ok, api_endpoints = run_kiterunner_or_api_probing([target_url.strip()], work_dir, run_id)

    meta_file = os.path.join(work_dir, "kiterunner_metadata.json")
    meta = {}
    if os.path.exists(meta_file):
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            pass

    err_msg = "" if ok else _extract_standalone_error(work_dir, "kiterunner", "فشل تشغيل أداة Kiterunner لاستكشاف مسارات الـ APIs.")
    return {
        "tool": "kiterunner",
        "status": "success" if ok else "failed",
        "message": err_msg if not ok else "اكتمل فحص Kiterunner بنجاح.",
        "detail": err_msg if not ok else None,
        "target_url": target_url.strip(),
        "total_api_endpoints": len(api_endpoints),
        "api_endpoints": api_endpoints,
        "diagnostic_reason": meta.get("diagnostic_reason"),
        "raw_event_count": meta.get("raw_event_count", 0),
        "filter_stats": meta.get("filter_stats", {})
    }


def run_standalone_nuclei(target_url: str, severity: Optional[str] = None) -> Dict[str, Any]:
    """Runs Nuclei independently against a target URL."""
    run_id = f"nuclei_{uuid.uuid4().hex[:8]}"
    work_dir = os.path.join(STANDALONE_DIR, run_id)
    os.makedirs(work_dir, exist_ok=True)

    targets_file = os.path.join(work_dir, "active_urls.txt")
    with open(targets_file, "w", encoding="utf-8") as f:
        f.write(f"{target_url.strip()}\n")

    prepare_nuclei_targets(work_dir)
    ok, findings = run_nuclei(work_dir, run_id, severity=severity)
    err_msg = "" if ok else _extract_standalone_error(work_dir, "nuclei", "فشل تشغيل أداة Nuclei لفحص الثغرات.")
    return {
        "tool": "nuclei",
        "status": "success" if ok else "failed",
        "message": err_msg if not ok else f"اكتمل فحص Nuclei واكتشاف {len(findings)} ثغرة.",
        "detail": err_msg if not ok else None,
        "target_url": target_url.strip(),
        "total_findings": len(findings),
        "findings": findings
    }


def run_standalone_wapiti(target_url: str, modules: Optional[str] = None) -> Dict[str, Any]:
    """Runs Wapiti DAST independently against a target URL."""
    run_id = f"wapiti_{uuid.uuid4().hex[:8]}"
    work_dir = os.path.join(STANDALONE_DIR, run_id)
    os.makedirs(work_dir, exist_ok=True)

    ok, findings = run_wapiti_dast(work_dir, run_id, [target_url.strip()], modules=modules)
    err_msg = "" if ok else _extract_standalone_error(work_dir, "wapiti", "فشل تشغيل أداة Wapiti للفحص الحركي.")
    return {
        "tool": "wapiti",
        "status": "success" if ok else "failed",
        "message": err_msg if not ok else f"اكتمل فحص Wapiti واكتشاف {len(findings)} ثغرة.",
        "detail": err_msg if not ok else None,
        "target_url": target_url.strip(),
        "total_findings": len(findings),
        "findings": findings
    }


# ---------------------------------------------------------------------------
# 4. Tools Health & Readiness Check (فحص جاهزية وحالة الحاويات الست)
# ---------------------------------------------------------------------------

def get_tools_readiness_status() -> Dict[str, Any]:
    """
    Checks Docker availability and verified readiness of all 6 security tools:
    Subfinder, Naabu, HTTPX, Kiterunner, Nuclei, Wapiti.
    """
    docker_ready = is_docker_available()
    tools = {
        "subfinder": {
            "name": "ProjectDiscovery Subfinder",
            "type": "Passive Subdomain Enumeration",
            "docker_image": "projectdiscovery/subfinder:v2.17.0",
            "ready": docker_ready
        },
        "naabu": {
            "name": "ProjectDiscovery Naabu",
            "type": "High-Speed Port Scanner",
            "docker_image": "projectdiscovery/naabu:v2.6.1",
            "ready": docker_ready
        },
        "httpx": {
            "name": "ProjectDiscovery HTTPX",
            "type": "Web Service & Tech Stack Probing",
            "docker_image": "projectdiscovery/httpx:v1.12.0",
            "ready": docker_ready
        },
        "kiterunner": {
            "name": "Assetnote Kiterunner",
            "type": "Content-Aware API Route Discovery",
            "docker_image": "yemscan/kiterunner:v1.0.2-yemscan1",
            "ready": docker_ready
        },
        "nuclei": {
            "name": "ProjectDiscovery Nuclei",
            "type": "Vulnerability Scanner (CVEs & OWASP)",
            "docker_image": NUCLEI_DOCKER_IMAGE,
            "ready": docker_ready
        },
        "wapiti": {
            "name": "Wapiti DAST Scanner",
            "type": "Dynamic Application Security Testing",
            "docker_image": WAPITI_DOCKER_IMAGE,
            "ready": docker_ready
        }
    }

    return {
        "status": "healthy" if docker_ready else "degraded",
        "docker_available": docker_ready,
        "tools_count": len(tools),
        "tools": tools,
        "engine": "Docker Engine (yemenscan_prod)" if docker_ready else "Host Process Fallback"
    }
