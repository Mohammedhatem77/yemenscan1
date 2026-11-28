"""
YemScan — Phase 7.2.3: Shared DAST Input Normalization & Execution Readiness Service.

Designed for shared reuse across both Sequential and Independent scanning without
adding external crawler tools or modifying Wapiti:
  - Sequential Scan: Users provide only a target/domain; Nuclei relies on actual inputs
    discovered by HTTPX and Kiterunner, executes all eligible, compatible DAST templates
    whose input requirements are met, and keeps unready templates eligible in catalog
    with exact missing-requirement reasons. Wapiti independently handles crawling, form
    discovery, and dynamic input testing in Stage 3 as a complementary scanner.
  - Independent Scan: Users may explicitly supply parameterized URLs, API paths,
    or structured/raw HTTP requests (JSONL/Burp) without requiring discovery tools
    or Wapiti beforehand, enabling granular matching against all 244 DAST templates.

Empirical Guarantees Verified Against Nuclei v3.11.1 (`projectdiscovery/nuclei:v3.11.1`):
  1. DAST templates require `-dast`; without it, Nuclei excludes them (`[WRN] Excluded ...`).
  2. Bare URLs (`https://example.com/`) do NOT trigger `part: query` or non-root `part: path`
     fuzzing payloads.
  3. `-im jsonl` strictly requires `request` to be a JSON object
     `{"raw": ..., "endpoint": ..., "body": ..., "header": {...}}`, NOT a plain string.
  4. `-im burp` expects Base64-encoded `<request>` payloads.
  5. `-ni` (`-no-interactsh`) keeps OAST disabled while allowing non-OAST DAST execution.
  6. Headless DAST (`194 / 244` templates) runs cleanly alongside `-cdpe "$WS_URL"` under
     Phase 7.2.1's sandboxed Chromium runtime.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qs, urlsplit, urlunsplit

import yaml

from core.nuclei_shared import NUCLEI_VERSIONS_DIR
from core.target_validator import is_safe_host_or_ip

logger = logging.getLogger("yemenscan.dast_readiness")

# Nuclei v3.11.1 runtime built-ins & helper expressions (never supplied by user `-var`)
NUCLEI_BUILTIN_PLACEHOLDERS: frozenset[str] = frozenset({
    "BaseURL",
    "RootURL",
    "Hostname",
    "Host",
    "Port",
    "Path",
    "File",
    "Scheme",
    "DN",
    "SD",
    "RDN",
    "FQDN",
    "IP",
    "interactsh-url",
})

SUPPORTED_DAST_INPUT_MODES: frozenset[str] = frozenset({"list", "jsonl", "burp"})
VALID_HTTP_METHODS: frozenset[str] = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})


# ---------------------------------------------------------------------------
# Template Requirement Analysis
# ---------------------------------------------------------------------------

@dataclass
class DastTemplateRequirements:
    """Exact execution requirements extracted from a DAST template YAML."""
    template_id: str
    relative_path: str
    is_dast: bool
    protocols: List[str]
    required_fuzz_parts: Set[str]
    accepted_methods: Set[str]
    requires_headless: bool
    requires_oast: bool
    requires_auth: bool
    checks_non_empty_query: bool
    self_generated_variables: List[str] = field(default_factory=list)
    external_required_variables: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template_id": self.template_id,
            "relative_path": self.relative_path,
            "is_dast": self.is_dast,
            "protocols": list(self.protocols),
            "required_fuzz_parts": sorted(self.required_fuzz_parts),
            "accepted_methods": sorted(self.accepted_methods) if self.accepted_methods else ["ANY"],
            "requires_headless": self.requires_headless,
            "requires_oast": self.requires_oast,
            "requires_auth": self.requires_auth,
            "checks_non_empty_query": self.checks_non_empty_query,
            "self_generated_variables": list(self.self_generated_variables),
            "external_required_variables": list(self.external_required_variables),
        }


def analyze_dast_template_doc(
    doc: Dict[str, Any],
    template_id: str,
    relative_path: str,
    protocols: Optional[Sequence[str]] = None,
    tags: Optional[Sequence[str]] = None,
    policy_details: Optional[Dict[str, Any]] = None,
) -> DastTemplateRequirements:
    """
    Analyze parsed YAML structure + policy metadata of a Nuclei template to
    accurately separate:
      - external request/input parts (`query`, `path`, `body`, `header`, `cookie`, `request`)
      - HTTP method pre-conditions (`GET`, `POST`, `PUT`, ...)
      - self-generated template variables (`payloads`, `variables`, `constants`, extractors)
        vs genuine external variables.
    """
    pd = policy_details if isinstance(policy_details, dict) else {}
    proto_list = [str(p).lower() for p in (protocols or [])]
    tag_list = [str(t).lower() for t in (tags or [])]
    rel_norm = (relative_path or "").replace("\\", "/")
    is_dast = rel_norm.startswith("dast/") or ("dast" in tag_list)

    # Collect locally generated identifiers inside template YAML
    local_defs: Set[str] = set()
    for top_key in ("variables", "constants"):
        block = doc.get(top_key)
        if isinstance(block, dict):
            local_defs.update(str(k) for k in block.keys())

    fuzz_parts: Set[str] = set()
    accepted_methods: Set[str] = set()
    checks_non_empty_query = False
    has_headless_block = bool(doc.get("headless"))

    for section_key in ("http", "requests", "headless"):
        entries = doc.get(section_key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue

            if isinstance(entry.get("payloads"), dict):
                local_defs.update(str(k) for k in entry["payloads"].keys())

            for ext in (entry.get("extractors") or []):
                if isinstance(ext, dict) and ext.get("name"):
                    local_defs.add(str(ext["name"]))

            for st in (entry.get("steps") or []):
                if isinstance(st, dict) and st.get("name"):
                    local_defs.add(str(st["name"]))

            for pc in (entry.get("pre-condition") or entry.get("pre_condition") or []):
                if not isinstance(pc, dict):
                    continue
                for dsl_expr in (pc.get("dsl") or []):
                    s_dsl = str(dsl_expr)
                    if "query_params" in s_dsl:
                        checks_non_empty_query = True
                    for m in re.findall(r'method\s*==\s*["\']([A-Z]+)["\']', s_dsl):
                        accepted_methods.add(m.upper())

            for fz in (entry.get("fuzzing") or []):
                if not isinstance(fz, dict):
                    continue
                p_single = fz.get("part")
                p_multi = fz.get("parts")
                extracted: List[str] = []
                if p_single:
                    extracted.append(str(p_single).strip().lower())
                if isinstance(p_multi, list):
                    extracted.extend(str(p).strip().lower() for p in p_multi if p)
                elif p_multi:
                    extracted.append(str(p_multi).strip().lower())
                if not extracted:
                    # Nuclei defaults fuzzing without explicit `part`/`parts` to query/request parts
                    fuzz_parts.add("query")
                else:
                    fuzz_parts.update(extracted)

    # Fallback if a DAST-tagged template lacked an explicit YAML fuzzing section
    if is_dast and not fuzz_parts:
        fuzz_parts.add("query")

    raw_policy_vars = [str(v) for v in (pd.get("required_variables") or []) if v]
    self_gen_vars: List[str] = []
    ext_vars: List[str] = []
    for v in raw_policy_vars:
        if v in local_defs or v in NUCLEI_BUILTIN_PLACEHOLDERS:
            self_gen_vars.append(v)
        else:
            ext_vars.append(v)

    requires_headless = bool(pd.get("headless_requirement") or ("headless" in proto_list) or has_headless_block)
    requires_oast = bool(pd.get("oast_requirement"))
    requires_auth = bool(pd.get("authentication_requirements"))

    return DastTemplateRequirements(
        template_id=template_id,
        relative_path=rel_norm,
        is_dast=is_dast,
        protocols=proto_list,
        required_fuzz_parts=fuzz_parts,
        accepted_methods=accepted_methods,
        requires_headless=requires_headless,
        requires_oast=requires_oast,
        requires_auth=requires_auth,
        checks_non_empty_query=checks_non_empty_query,
        self_generated_variables=self_gen_vars,
        external_required_variables=ext_vars,
    )


def load_dast_template_requirements(
    template_id: str,
    relative_path: str,
    snapshot_dir: Optional[str] = None,
    protocols: Optional[Sequence[str]] = None,
    tags: Optional[Sequence[str]] = None,
    policy_details: Optional[Dict[str, Any]] = None,
) -> DastTemplateRequirements:
    """
    Load YAML from immutable snapshot directory when available, otherwise infer
    conservatively from catalog metadata (`policy_details` + protocols + tags).
    """
    if snapshot_dir:
        full_path = os.path.normpath(os.path.join(snapshot_dir, relative_path))
        snap_norm = os.path.normpath(snapshot_dir)
        # Ensure traversal safety within snapshot boundary
        if full_path.startswith(snap_norm + os.sep) and os.path.isfile(full_path):
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                    doc = yaml.safe_load(fh)
                if isinstance(doc, dict):
                    return analyze_dast_template_doc(
                        doc=doc,
                        template_id=template_id,
                        relative_path=relative_path,
                        protocols=protocols,
                        tags=tags,
                        policy_details=policy_details,
                    )
            except Exception as exc:
                logger.warning("Failed parsing DAST template %s for requirements: %s", relative_path, exc)

    # Conservative metadata-only fallback (when snapshot path is absent, e.g. unit test fixtures)
    pd = policy_details if isinstance(policy_details, dict) else {}
    rel_norm = (relative_path or "").replace("\\", "/")
    is_dast = rel_norm.startswith("dast/") or ("dast" in [str(t).lower() for t in (tags or [])])
    proto_list = [str(p).lower() for p in (protocols or [])]
    return DastTemplateRequirements(
        template_id=template_id,
        relative_path=rel_norm,
        is_dast=is_dast,
        protocols=proto_list,
        required_fuzz_parts={"query"},
        accepted_methods=set(),
        requires_headless=bool(pd.get("headless_requirement") or ("headless" in proto_list)),
        requires_oast=bool(pd.get("oast_requirement")),
        requires_auth=bool(pd.get("authentication_requirements")),
        checks_non_empty_query=False,
        self_generated_variables=[],
        external_required_variables=[str(v) for v in (pd.get("required_variables") or []) if v],
    )


# ---------------------------------------------------------------------------
# Normalized DAST Inputs & Scope Enforcement
# ---------------------------------------------------------------------------

def _host_matches_scope(host: str, authorized_scopes: Sequence[str]) -> bool:
    clean_host = (host or "").strip().lower().rstrip(".")
    if not clean_host:
        return False
    for raw_pat in authorized_scopes:
        pat = (raw_pat or "").strip().lower().rstrip(".")
        if not pat:
            continue
        if "://" in pat:
            pat = pat.split("://", 1)[1].split("/", 1)[0]
        pat = pat.split(":", 1)[0]
        if pat.startswith("*."):
            base = pat[2:]
            if clean_host == base or clean_host.endswith("." + base):
                return True
        elif clean_host == pat:
            return True
    return False


@dataclass
class DastInputRecord:
    """Single normalized, scope-verified HTTP target/request suitable for DAST."""
    url: str
    method: str
    scheme: str
    host: str
    port: int
    path: str
    has_non_root_path: bool
    query_params: Dict[str, List[str]]
    has_query_params: bool
    headers: Dict[str, str]
    has_custom_headers: bool
    body: str
    has_body: bool
    cookies: Dict[str, str]
    has_cookies: bool
    source: str
    in_scope: bool = True
    scope_reason: Optional[str] = None

    def to_raw_http_request(self) -> str:
        """Render canonical HTTP/1.1 raw request string compatible with Nuclei JSONL."""
        parsed = urlsplit(self.url)
        req_target = parsed.path or "/"
        if parsed.query:
            req_target = f"{req_target}?{parsed.query}"

        hdrs = dict(self.headers)
        if not any(k.lower() == "host" for k in hdrs):
            default_port = 443 if self.scheme == "https" else 80
            host_hdr = self.host if self.port == default_port else f"{self.host}:{self.port}"
            hdrs["Host"] = host_hdr

        body_bytes = self.body.encode("utf-8")
        if self.body and not any(k.lower() == "content-length" for k in hdrs):
            hdrs["Content-Length"] = str(len(body_bytes))

        if self.cookies and not any(k.lower() == "cookie" for k in hdrs):
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())

        lines = [f"{self.method} {req_target} HTTP/1.1"]
        for k, v in hdrs.items():
            clean_k = str(k).replace("\r", "").replace("\n", "").strip()
            clean_v = str(v).replace("\r", "").replace("\n", "").strip()
            if clean_k:
                lines.append(f"{clean_k}: {clean_v}")
        lines.append("")
        lines.append(self.body or "")
        return "\r\n".join(lines)

    def to_nuclei_jsonl_obj(self) -> Dict[str, Any]:
        """
        Return the exact `HttpRequestResponse` JSONL object structure verified on
        `Nuclei v3.11.1 -im jsonl`.
        """
        return {
            "request": {
                "raw": self.to_raw_http_request(),
                "endpoint": self.url,
                "body": self.body or "",
                "header": dict(self.headers),
            },
            "url": self.url,
        }


@dataclass
class DastInputContext:
    """Shared normalized DAST input bundle used by readiness & execution layers."""
    records: List[DastInputRecord] = field(default_factory=list)
    rejected_out_of_scope: List[Dict[str, str]] = field(default_factory=list)
    rejected_invalid: List[Dict[str, str]] = field(default_factory=list)
    input_source_mode: str = "independent_user_supplied"

    @property
    def has_any_inputs(self) -> bool:
        return len(self.records) > 0

    @property
    def available_methods(self) -> Set[str]:
        return {r.method for r in self.records}

    @property
    def has_query_params(self) -> bool:
        return any(r.has_query_params for r in self.records)

    @property
    def has_non_root_path(self) -> bool:
        return any(r.has_non_root_path for r in self.records)

    @property
    def has_body(self) -> bool:
        return any(r.has_body for r in self.records)

    @property
    def has_custom_headers(self) -> bool:
        return any(r.has_custom_headers for r in self.records)

    @property
    def has_cookies(self) -> bool:
        return any(r.has_cookies for r in self.records)

    @property
    def has_bare_url_only(self) -> bool:
        return self.has_any_inputs and not (
            self.has_query_params
            or self.has_non_root_path
            or self.has_body
            or self.has_custom_headers
            or self.has_cookies
        )

    @property
    def sources_summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for r in self.records:
            counts[r.source] = counts.get(r.source, 0) + 1
        return counts

    @property
    def recommended_input_mode(self) -> str:
        """Select `jsonl` whenever non-GET methods, bodies, or custom headers exist."""
        if any(r.method != "GET" or r.has_body or r.has_custom_headers or r.has_cookies for r in self.records):
            return "jsonl"
        return "list"

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "total_valid_in_scope": len(self.records),
            "rejected_out_of_scope_count": len(self.rejected_out_of_scope),
            "rejected_invalid_count": len(self.rejected_invalid),
            "available_methods": sorted(self.available_methods),
            "has_query_params": self.has_query_params,
            "has_non_root_path": self.has_non_root_path,
            "has_body": self.has_body,
            "has_custom_headers": self.has_custom_headers,
            "has_cookies": self.has_cookies,
            "has_bare_url_only": self.has_bare_url_only,
            "recommended_input_mode": self.recommended_input_mode,
            "sources_summary": self.sources_summary,
            "input_source_mode": self.input_source_mode,
        }

    def write_nuclei_input_file(
        self,
        output_path: str,
        input_mode: Optional[str] = None,
    ) -> str:
        """
        Serialize strictly in-scope DAST inputs into `-im list` or `-im jsonl`.
        Raises ValueError if no valid in-scope inputs exist.
        """
        in_scope = [r for r in self.records if r.in_scope]
        if not in_scope:
            raise ValueError("Cannot generate Nuclei DAST input file without in-scope records")

        mode = input_mode or self.recommended_input_mode
        if mode not in ("list", "jsonl"):
            raise ValueError(f"Unsupported generated DAST input mode: {mode!r}")

        with open(output_path, "w", encoding="utf-8", newline="\n") as fh:
            if mode == "list":
                seen: Set[str] = set()
                for rec in in_scope:
                    if rec.url not in seen:
                        seen.add(rec.url)
                        fh.write(rec.url + "\n")
            else:
                for rec in in_scope:
                    fh.write(json.dumps(rec.to_nuclei_jsonl_obj(), ensure_ascii=False) + "\n")

        return mode


class DastInputCollector:
    """
    Normalizes, validates SSRF/scope safety, and constructs `DastInputContext` from:
      - Independent user inputs (URLs with params, HTTP request dicts, JSONL, Burp XML)
      - Existing Sequential session artifacts (HTTPX `active_urls.json` & Kiterunner `api_endpoints.json`)
    """

    @staticmethod
    def _parse_cookies(headers: Dict[str, str], explicit_cookies: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        out: Dict[str, str] = {}
        if isinstance(explicit_cookies, dict):
            for k, v in explicit_cookies.items():
                if str(k).strip():
                    out[str(k).strip()] = str(v)
        for hk, hv in headers.items():
            if hk.lower() == "cookie" and hv:
                for part in str(hv).split(";"):
                    if "=" in part:
                        ck, cv = part.split("=", 1)
                        if ck.strip():
                            out[ck.strip()] = cv.strip()
        return out

    @classmethod
    def _normalize_record(
        cls,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, Any]] = None,
        body: str = "",
        cookies: Optional[Dict[str, str]] = None,
        source: str = "user_url",
        authorized_scopes: Sequence[str] = (),
        allow_loopback_for_tests: bool = False,
    ) -> Tuple[Optional[DastInputRecord], Optional[str], Optional[str]]:
        """Returns `(record, rejection_type, rejection_reason)`."""
        raw_u = (url or "").strip()
        if not raw_u or any(ch.isspace() for ch in raw_u):
            return None, "invalid", f"Invalid or whitespace-containing URL: {url!r}"

        if "://" not in raw_u:
            raw_u = f"http://{raw_u}"

        try:
            parsed = urlsplit(raw_u)
        except Exception as exc:
            return None, "invalid", f"Unparseable URL {url!r}: {exc}"

        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return None, "invalid", f"Unsupported URL scheme {scheme!r}"

        host = (parsed.hostname or "").strip().lower().rstrip(".")
        if not host:
            return None, "invalid", f"Missing hostname in URL {url!r}"

        if authorized_scopes and not _host_matches_scope(host, authorized_scopes):
            return None, "out_of_scope", f"Host '{host}' is outside authorized_scopes"

        is_loopback = host in ("127.0.0.1", "localhost", "::1")
        if not (allow_loopback_for_tests and is_loopback):
            safe, ssrf_reason = is_safe_host_or_ip(host)
            if not safe:
                return None, "out_of_scope", f"Blocked unsafe/internal host '{host}': {ssrf_reason}"

        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        norm_url = urlunsplit((scheme, parsed.netloc.lower(), path, parsed.query, ""))

        clean_method = (method or "GET").strip().upper()
        if clean_method not in VALID_HTTP_METHODS:
            return None, "invalid", f"Unsupported HTTP method: {clean_method!r}"

        clean_headers: Dict[str, str] = {}
        if isinstance(headers, dict):
            for k, v in headers.items():
                sk = str(k).strip()
                if sk:
                    clean_headers[sk] = str(v)

        cookie_map = cls._parse_cookies(clean_headers, cookies)
        non_trivial_hdrs = {
            k: v for k, v in clean_headers.items()
            if k.lower() not in ("host", "content-length", "connection", "accept", "user-agent", "cookie")
        }
        q_params = parse_qs(parsed.query, keep_blank_values=True)
        body_str = body if isinstance(body, str) else (json.dumps(body) if body is not None else "")

        rec = DastInputRecord(
            url=norm_url,
            method=clean_method,
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            has_non_root_path=bool(path and path != "/"),
            query_params=q_params,
            has_query_params=len(q_params) > 0,
            headers=clean_headers,
            has_custom_headers=len(non_trivial_hdrs) > 0,
            body=body_str,
            has_body=bool(body_str.strip()),
            cookies=cookie_map,
            has_cookies=len(cookie_map) > 0,
            source=source,
            in_scope=True,
        )
        return rec, None, None

    @classmethod
    def _ingest_item(
        cls,
        ctx: DastInputContext,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, Any]] = None,
        body: str = "",
        cookies: Optional[Dict[str, str]] = None,
        source: str = "user_url",
        authorized_scopes: Sequence[str] = (),
        allow_loopback_for_tests: bool = False,
    ) -> None:
        rec, rej_type, rej_reason = cls._normalize_record(
            url=url,
            method=method,
            headers=headers,
            body=body,
            cookies=cookies,
            source=source,
            authorized_scopes=authorized_scopes,
            allow_loopback_for_tests=allow_loopback_for_tests,
        )
        if rec is not None:
            ctx.records.append(rec)
        elif rej_type == "out_of_scope":
            ctx.rejected_out_of_scope.append({"url": str(url), "reason": rej_reason or "out_of_scope"})
        else:
            ctx.rejected_invalid.append({"url": str(url), "reason": rej_reason or "invalid"})

    @classmethod
    def from_user_inputs(
        cls,
        urls: Sequence[str] = (),
        http_requests: Sequence[Dict[str, Any]] = (),
        jsonl_lines: Sequence[str] = (),
        burp_xml: Optional[str] = None,
        authorized_scopes: Sequence[str] = (),
        allow_loopback_for_tests: bool = False,
    ) -> DastInputContext:
        """Normalize explicit independent-scan DAST inputs supplied by caller/UI."""
        ctx = DastInputContext(input_source_mode="independent_user_supplied")

        for u in urls:
            cls._ingest_item(
                ctx,
                url=u,
                method="GET",
                source="user_url",
                authorized_scopes=authorized_scopes,
                allow_loopback_for_tests=allow_loopback_for_tests,
            )

        for req in http_requests:
            if not isinstance(req, dict):
                ctx.rejected_invalid.append({"url": str(req), "reason": "Request entry must be an object"})
                continue
            cls._ingest_item(
                ctx,
                url=str(req.get("url") or req.get("endpoint") or ""),
                method=str(req.get("method") or "GET"),
                headers=req.get("headers") or req.get("header"),
                body=req.get("body") or "",
                cookies=req.get("cookies"),
                source="user_request",
                authorized_scopes=authorized_scopes,
                allow_loopback_for_tests=allow_loopback_for_tests,
            )

        for raw_line in jsonl_lines:
            line = (raw_line or "").strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as exc:
                ctx.rejected_invalid.append({"url": line[:120], "reason": f"Invalid JSONL line: {exc}"})
                continue
            if not isinstance(obj, dict) or not isinstance(obj.get("request"), dict):
                ctx.rejected_invalid.append({
                    "url": line[:120],
                    "reason": "Nuclei JSONL requires object field 'request' (HttpRequestResponse schema)",
                })
                continue
            req_obj = obj["request"]
            endpoint = str(req_obj.get("endpoint") or obj.get("url") or "")
            raw_http = str(req_obj.get("raw") or "")
            first_line = raw_http.splitlines()[0] if raw_http else ""
            method = first_line.split(" ", 1)[0] if " " in first_line else "GET"
            cls._ingest_item(
                ctx,
                url=endpoint,
                method=method,
                headers=req_obj.get("header") if isinstance(req_obj.get("header"), dict) else None,
                body=str(req_obj.get("body") or ""),
                source="jsonl",
                authorized_scopes=authorized_scopes,
                allow_loopback_for_tests=allow_loopback_for_tests,
            )

        if burp_xml:
            cls._ingest_burp_xml(
                ctx,
                burp_xml=burp_xml,
                authorized_scopes=authorized_scopes,
                allow_loopback_for_tests=allow_loopback_for_tests,
            )

        return ctx

    @classmethod
    def _ingest_burp_xml(
        cls,
        ctx: DastInputContext,
        burp_xml: str,
        authorized_scopes: Sequence[str],
        allow_loopback_for_tests: bool,
    ) -> None:
        try:
            root = ET.fromstring(burp_xml)
        except Exception as exc:
            ctx.rejected_invalid.append({"url": "<burp_xml>", "reason": f"Malformed Burp XML: {exc}"})
            return

        for item in root.findall(".//item"):
            url = (item.findtext("url") or "").strip()
            method = (item.findtext("method") or "GET").strip().upper()
            req_el = item.find("request")
            hdrs: Dict[str, str] = {}
            body = ""
            if req_el is not None and req_el.text:
                raw_txt = req_el.text.strip()
                if req_el.attrib.get("base64", "true").lower() == "true":
                    try:
                        raw_txt = base64.b64decode(raw_txt, validate=True).decode("utf-8", errors="replace")
                    except Exception as exc:
                        ctx.rejected_invalid.append({"url": url, "reason": f"Invalid base64 Burp request: {exc}"})
                        continue
                if "\r\n\r\n" in raw_txt:
                    head_part, body = raw_txt.split("\r\n\r\n", 1)
                elif "\n\n" in raw_txt:
                    head_part, body = raw_txt.split("\n\n", 1)
                else:
                    head_part, body = raw_txt, ""
                head_lines = head_part.splitlines()
                if head_lines and " " in head_lines[0]:
                    method = head_lines[0].split(" ", 1)[0].strip().upper()
                for hl in head_lines[1:]:
                    if ":" in hl:
                        hk, hv = hl.split(":", 1)
                        hdrs[hk.strip()] = hv.strip()

            cls._ingest_item(
                ctx,
                url=url,
                method=method,
                headers=hdrs,
                body=body,
                source="burp",
                authorized_scopes=authorized_scopes,
                allow_loopback_for_tests=allow_loopback_for_tests,
            )

    @classmethod
    def from_sequential_session(
        cls,
        session_dir: str,
        authorized_scopes: Sequence[str] = (),
        allow_loopback_for_tests: bool = False,
    ) -> DastInputContext:
        """
        Inspect existing HTTPX (`active_urls.json` / `.txt`) and Kiterunner
        (`api_endpoints.json` / `.txt`) session outputs read-only without invoking
        any new crawler or extracting Wapiti outputs.
        """
        ctx = DastInputContext(input_source_mode="sequential_discovery")
        seen_keys: Set[Tuple[str, str]] = set()

        # 1. HTTPX active_urls.json (respect scope_tag from Phase/PR #17 hardening)
        active_json = os.path.join(session_dir, "active_urls.json")
        if os.path.isfile(active_json):
            try:
                with open(active_json, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        s = line.strip()
                        if not s:
                            continue
                        try:
                            rec = json.loads(s)
                        except Exception:
                            continue
                        url = str(rec.get("url") or "").strip()
                        scope_tag = str(rec.get("scope_tag") or "").strip().lower()
                        if scope_tag in ("third_party_passive", "external_redirect"):
                            ctx.rejected_out_of_scope.append({
                                "url": url,
                                "reason": f"Excluded by Stage 2 scope_tag={scope_tag}",
                            })
                            continue
                        method = str(rec.get("method") or "GET").upper()
                        key = (method, url)
                        if url and key not in seen_keys:
                            seen_keys.add(key)
                            cls._ingest_item(
                                ctx,
                                url=url,
                                method=method,
                                source="httpx",
                                authorized_scopes=authorized_scopes,
                                allow_loopback_for_tests=allow_loopback_for_tests,
                            )
            except Exception as exc:
                logger.warning("Failed reading active_urls.json in %s: %s", session_dir, exc)

        # Fallback: active_urls.txt if active_urls.json wasn't present
        active_txt = os.path.join(session_dir, "active_urls.txt")
        if not os.path.isfile(active_json) and os.path.isfile(active_txt):
            with open(active_txt, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    url = line.strip()
                    key = ("GET", url)
                    if url and key not in seen_keys:
                        seen_keys.add(key)
                        cls._ingest_item(
                            ctx,
                            url=url,
                            method="GET",
                            source="httpx",
                            authorized_scopes=authorized_scopes,
                            allow_loopback_for_tests=allow_loopback_for_tests,
                        )

        # 2. Kiterunner api_endpoints.json
        api_json = os.path.join(session_dir, "api_endpoints.json")
        if os.path.isfile(api_json):
            try:
                with open(api_json, "r", encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                if isinstance(data, list):
                    for ep in data:
                        if not isinstance(ep, dict):
                            continue
                        url = str(ep.get("url") or "").strip()
                        method = str(ep.get("method") or "GET").upper()
                        key = (method, url)
                        if url and key not in seen_keys:
                            seen_keys.add(key)
                            cls._ingest_item(
                                ctx,
                                url=url,
                                method=method,
                                source="kiterunner",
                                authorized_scopes=authorized_scopes,
                                allow_loopback_for_tests=allow_loopback_for_tests,
                            )
            except Exception as exc:
                logger.warning("Failed reading api_endpoints.json in %s: %s", session_dir, exc)

        # Fallback: api_endpoints.txt if api_endpoints.json wasn't present
        api_txt = os.path.join(session_dir, "api_endpoints.txt")
        if not os.path.isfile(api_json) and os.path.isfile(api_txt):
            with open(api_txt, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    url = line.strip()
                    key = ("GET", url)
                    if url and key not in seen_keys:
                        seen_keys.add(key)
                        cls._ingest_item(
                            ctx,
                            url=url,
                            method="GET",
                            source="kiterunner",
                            authorized_scopes=authorized_scopes,
                            allow_loopback_for_tests=allow_loopback_for_tests,
                        )

        return ctx


# ---------------------------------------------------------------------------
# DAST Readiness Matching Engine & Nuclei CLI Builder
# ---------------------------------------------------------------------------

_ALTERNATIVE_MISSING_REASON_MAP: Dict[frozenset[str], str] = {
    frozenset({"query"}): "dast_missing_query_parameters",
    frozenset({"body"}): "dast_missing_request_body",
    frozenset({"path"}): "dast_missing_path_inputs",
    frozenset({"request"}): "dast_missing_request_inputs",
    frozenset({"header"}): "dast_missing_request_headers",
    frozenset({"cookie"}): "dast_missing_cookies",
    frozenset({"body", "query"}): "dast_missing_query_or_body_inputs",
    frozenset({"path", "query"}): "dast_missing_query_or_path_inputs",
    frozenset({"body", "path"}): "dast_missing_body_or_path_inputs",
    frozenset({"body", "path", "query"}): "dast_missing_query_body_or_path_inputs",
}


def resolve_missing_dast_input_reason(req: DastTemplateRequirements) -> str:
    """
    Map a template's supported fuzzing parts (including OR alternatives across
    query/body/path/request) to one accurate canonical missing-input reason code.
    """
    parts = frozenset(p.strip().lower() for p in req.required_fuzz_parts if p)
    if not parts or "request" in parts:
        return "dast_missing_request_inputs"
    mapped = _ALTERNATIVE_MISSING_REASON_MAP.get(parts)
    if mapped:
        return mapped
    canonical_order = ("query", "body", "path", "header", "cookie")
    ordered = [p for p in canonical_order if p in parts] + sorted(parts - set(canonical_order))
    return f"dast_missing_{'_or_'.join(ordered)}_inputs"


def _record_matches_template_part(rec: DastInputRecord, part: str) -> bool:
    if part == "query":
        return rec.has_query_params
    if part == "path":
        return rec.has_non_root_path
    if part == "body":
        return rec.has_body
    if part == "header":
        return rec.has_custom_headers
    if part == "cookie":
        return rec.has_cookies
    if part == "request":
        return (
            rec.has_query_params
            or rec.has_body
            or rec.has_non_root_path
            or rec.has_custom_headers
            or rec.has_cookies
        )
    return False


def evaluate_dast_template_inputs(
    req: DastTemplateRequirements,
    dast_context: DastInputContext,
) -> Tuple[bool, List[str]]:
    """
    Determine whether `dast_context` provides at least one in-scope input record
    satisfying `req`'s fuzzing parts (supporting OR alternatives across Query, Body,
    and Path), HTTP method pre-conditions, and explicit query_params rules.

    Returns `(inputs_ready, blocking_reasons)`.
    """
    if not dast_context.has_any_inputs:
        return False, ["dast_no_in_scope_inputs"]

    # 1. Check method compatibility across available records
    method_candidates = [
        r for r in dast_context.records
        if not req.accepted_methods or (r.method in req.accepted_methods)
    ]
    if not method_candidates:
        return False, ["dast_incompatible_http_method"]

    # 2. Check explicit `query_params` pre-condition if present on compatible methods
    if req.checks_non_empty_query:
        query_candidates = [r for r in method_candidates if r.has_query_params]
        if not query_candidates:
            return False, ["dast_missing_query_parameters"]
        method_candidates = query_candidates

    # 3. Check fuzzing parts (OR alternatives across query / body / path / header / cookie / request)
    for rec in method_candidates:
        if any(_record_matches_template_part(rec, part) for part in req.required_fuzz_parts):
            return True, []

    # 4. Report the exact missing requirement reason based on candidate-method deficits
    return False, [resolve_missing_dast_input_reason(req)]


def build_nuclei_dast_args(
    input_file_path: str,
    template_paths: Sequence[str],
    output_path: Optional[str] = None,
    input_mode: str = "list",
    enable_headless: bool = False,
    cdp_ws_url: Optional[str] = None,
    disable_oast: bool = True,
    rate_limit: int = 50,
    concurrency: int = 10,
    timeout_seconds: int = 10,
) -> List[str]:
    """
    Construct validated Nuclei v3.11.1 DAST CLI flags for future Phase 7.2.5/7.2.6
    integration:
      - Always enables `-dast`.
      - Enforces `-im list|jsonl|burp`.
      - Disables public Interactsh calls with `-ni` when OAST is deferred.
      - Uses sandboxed `-cdpe` (never `-sc` / `--no-sandbox`) when Headless is active.
    """
    if input_mode not in SUPPORTED_DAST_INPUT_MODES:
        raise ValueError(f"Unsupported DAST input mode for Nuclei v3.11.1: {input_mode!r}")

    args: List[str] = [
        "-no-stdin",
        "-duc",
        "-nc",
        "-dast",
        "-l",
        input_file_path,
    ]
    if input_mode != "list":
        args.extend(["-im", input_mode])

    for tp in template_paths:
        args.extend(["-t", tp])

    if output_path:
        args.extend(["-jsonl", "-o", output_path])

    if disable_oast:
        args.append("-ni")

    if enable_headless:
        if not cdp_ws_url:
            raise ValueError("cdp_ws_url is required when enable_headless=True (never use -sc in Docker)")
        args.extend(["-headless", "-cdpe", cdp_ws_url])

    args.extend([
        "-rl", str(rate_limit),
        "-c", str(concurrency),
        "-timeout", str(timeout_seconds),
    ])
    return args


class DastReadinessService:
    """
    Shared service evaluating all DAST templates against normalized DAST inputs,
    Headless readiness, OAST availability, and target scope.
    """

    def __init__(self, snapshot_dir: Optional[str] = None) -> None:
        self.snapshot_dir = snapshot_dir

    def inspect_template(
        self,
        template_id: str,
        relative_path: str,
        protocols: Optional[Sequence[str]] = None,
        tags: Optional[Sequence[str]] = None,
        policy_details: Optional[Dict[str, Any]] = None,
    ) -> DastTemplateRequirements:
        return load_dast_template_requirements(
            template_id=template_id,
            relative_path=relative_path,
            snapshot_dir=self.snapshot_dir,
            protocols=protocols,
            tags=tags,
            policy_details=policy_details,
        )

    def evaluate_template_readiness(
        self,
        req: DastTemplateRequirements,
        dast_context: Optional[DastInputContext],
        legacy_dast_inputs_available: bool = False,
        headless_available: bool = False,
        interactsh_available: bool = False,
        auth_credentials_provided: bool = False,
        variables_provided: Optional[Dict[str, str]] = None,
        scan_mode: str = "independent",
    ) -> Tuple[bool, List[str]]:
        """
        Evaluate a single DAST template against runtime capabilities + DAST inputs.
        Never drops ineligible/unready templates from catalog; returns exact missing causes.
        """
        blocking: List[str] = []
        provided_vars = variables_provided or {}

        if dast_context is None:
            if not legacy_dast_inputs_available:
                blocking.append(resolve_missing_dast_input_reason(req))
        else:
            ok_inputs, input_reasons = evaluate_dast_template_inputs(req, dast_context)
            if not ok_inputs:
                blocking.extend(input_reasons)

        if req.requires_headless and not headless_available:
            blocking.append("headless_browser_unavailable")

        if req.requires_oast and not interactsh_available:
            blocking.append("interactsh_oast_unavailable")

        if req.requires_auth and not auth_credentials_provided:
            blocking.append("auth_credentials_missing")

        missing_ext_vars = [v for v in req.external_required_variables if v not in provided_vars]
        if missing_ext_vars:
            blocking.append(f"required_variables_missing:{missing_ext_vars}")

        return (len(blocking) == 0), blocking
