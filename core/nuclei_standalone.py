"""
Standalone Independent Nuclei Execution Engine for YemenScan.

This module provides dedicated execution logic for independent on-demand Nuclei scanning.
Separated from the sequential scanning pipeline (core/stage3_vulnerabilities.py) to enable
Team 2 to evolve catalog-based selection, indexing, and preview without coupling to sequential stages.

Strictly preserves:
- Official Docker container execution (fail-closed, no fallback)
- Target normalization and scope validation
- Exact CLI argument generation and flags
- Output parsing via shared nuclei parser (core/nuclei_shared.py)
"""

import os
import shutil
import tempfile
from typing import List, Dict, Any, Optional, Set

from core.runner import run_docker_tool
from core.nuclei_shared import (
    NUCLEI_DOCKER_IMAGE,
    NUCLEI_RUNTIME_TEMPLATES_DIR,
    NUCLEI_TEMPLATES_OFFICIAL_DIR,
    normalize_target_origin,
    parse_nuclei_json_output
)


def build_standalone_nuclei_args(
    targets_path: str,
    selected_template_arg: str,
    output_path: str,
    severity: Optional[str] = None,
    tags: Optional[str] = None,
    rate_limit: int = 150,
    concurrency: int = 25,
    additional_tags: Optional[List[str]] = None
) -> List[str]:
    """
    Constructs the CLI argument vector for standalone Nuclei Docker container execution.
    """
    effective_severity = (severity or "medium,high,critical").strip()
    if effective_severity.lower() in ("all", "*"):
        effective_severity = "info,low,medium,high,critical"

    args = [
        "-l", targets_path,
        "-t", selected_template_arg,
        "-jsonl",
        "-o", output_path,
        "-severity", effective_severity,
        "-pt", "http",
        "-etags", "dos,fuzz,bruteforce,intrusive,local",
        "-dut",
        "-ni",
        "-lna",
        "-iv", "4",
        "-irr",
        "-rl", str(rate_limit),
        "-c", str(concurrency),
        "-bs", str(concurrency),
        "-timeout", "6",
        "-retries", "1",
        "-duc",
        "-nc",
        "-silent"
    ]

    all_tags = list(additional_tags or [])
    if tags and tags.strip():
        all_tags.append(tags.strip())

    if all_tags:
        combined_tags = ",".join(t for t in all_tags if t)
        args.extend(["-tags", combined_tags])

    return args


def run_standalone_nuclei(
    target_url: str,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    tags: Optional[str] = None,
    rate_limit: int = 150,
    concurrency: int = 25,
    run_docker_tool_fn: Optional[Any] = None
) -> List[Dict[str, Any]]:
    """
    Runs a targeted safe Nuclei scan on a specific URL or domain using the official Docker container.
    Supports official template libraries, direct category/tag filtering, configurable severities,
    and adaptive rate limiting.
    """
    if not target_url or not target_url.strip():
        return []

    runner_fn = run_docker_tool_fn or run_docker_tool
    clean_target = target_url.strip()
    targets: List[str] = []
    valid_origins: Set[str] = set()

    if clean_target.startswith("http://") or clean_target.startswith("https://"):
        norm = normalize_target_origin(clean_target)
        if norm:
            targets.append(norm)
            valid_origins.add(norm)
    else:
        # Target provided without scheme (e.g. toom.de): test both HTTPS and HTTP
        dom = clean_target.split("/")[0].split(":")[0].strip()
        https_origin = f"https://{dom}"
        http_origin = f"http://{dom}"
        targets = [https_origin, http_origin]
        valid_origins = {https_origin, http_origin}

    if not targets:
        return []

    tmp_base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scans", ".tmp"))
    os.makedirs(tmp_base, exist_ok=True)
    temp_dir = tempfile.mkdtemp(prefix="nuclei_single_", dir=tmp_base)
    try:
        tf = os.path.join(temp_dir, "nuclei_targets.txt")
        with open(tf, "w", encoding="utf-8") as f:
            for t in targets:
                f.write(f"{t}\n")

        target_templates_dir = NUCLEI_RUNTIME_TEMPLATES_DIR if os.path.exists(NUCLEI_RUNTIME_TEMPLATES_DIR) else NUCLEI_TEMPLATES_OFFICIAL_DIR
        extra_vols = [(target_templates_dir, "/opt/nuclei-templates")]

        # Determine template directory or path
        selected_t_arg = "/opt/nuclei-templates"
        additional_tags = []
        if tags and tags.strip():
            additional_tags.append(tags.strip())

        if category and category.lower() not in ("all", "", "*", "none"):
            clean_cat = category.strip().lower()
            # 1. Check if category matches a subfolder under http/ or root
            cat_http_path = os.path.join(target_templates_dir, "http", clean_cat)
            cat_direct_path = os.path.join(target_templates_dir, clean_cat)
            if os.path.exists(cat_http_path):
                selected_t_arg = f"/opt/nuclei-templates/http/{clean_cat}"
            elif os.path.exists(cat_direct_path):
                selected_t_arg = f"/opt/nuclei-templates/{clean_cat}"
            else:
                # 2. Category is a technology or tag (e.g. wordpress, php, apache, nginx, iis, api)
                http_sub = os.path.join(target_templates_dir, "http")
                selected_t_arg = "/opt/nuclei-templates/http" if os.path.exists(http_sub) else "/opt/nuclei-templates"
                additional_tags.append(clean_cat)
        else:
            http_sub = os.path.join(target_templates_dir, "http")
            if os.path.exists(http_sub):
                selected_t_arg = "/opt/nuclei-templates/http"

        args = build_standalone_nuclei_args(
            targets_path="/data/nuclei_targets.txt",
            selected_template_arg=selected_t_arg,
            output_path="/data/nuclei_raw.jsonl",
            severity=severity,
            tags=tags,
            rate_limit=rate_limit,
            concurrency=concurrency,
            additional_tags=additional_tags
        )

        success, _ = runner_fn(
            image=NUCLEI_DOCKER_IMAGE,
            args=args,
            volume_dir=temp_dir,
            timeout=300,
            extra_volumes=extra_vols
        )
        if not success:
            return []
        raw_file = os.path.join(temp_dir, "nuclei_raw.jsonl")
        findings, _ = parse_nuclei_json_output(raw_file, valid_target_origins=valid_origins)
        return findings
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
