"""
YemScan — Phase 2 & 3 Classification Test Suite.

Tests cover:
  TC-01  Valid YAML template parsing
  TC-02  Invalid YAML parse error handling
  TC-03  Missing 'id' field
  TC-04  Missing 'info' section
  TC-05  Protocol detection from YAML keys (not path)
  TC-06  Legacy protocol aliases (requests→http, tcp→network)
  TC-07  Workflow template detection
  TC-08  Multi-protocol template detection
  TC-09  Metadata extraction — CVE/CWE/CVSS normalisation
  TC-10  Metadata extraction — no fabrication on missing fields
  TC-11  Tags normalisation
  TC-12  Author normalisation (list / string / comma-separated)
  TC-13  Severity normalisation
  TC-14  IgnoreRuleSet tag exclusion
  TC-15  IgnoreRuleSet file exclusion
  TC-16  IgnoreRuleSet missing file → empty ruleset (no crash)
  TC-17  HTTP template → eligible
  TC-18  SSL template → eligible
  TC-19  DNS template → eligible
  TC-20  Headless template → eligible
  TC-21  Code template → ineligible (unsupported_protocol)
  TC-22  File template → ineligible (unsupported_protocol)
  TC-23  DAST path template → ineligible (unsafe_behavior)
  TC-24  Workflow template → ineligible (workflow_deferred)
  TC-25  Network/TCP with web port → eligible
  TC-26  Network with non-web service tags → ineligible (outside_web_scope)
  TC-27  Network/JS with no signals → ineligible (unresolved_classification)
  TC-28  Official ignore tag exclusion → ineligible
  TC-29  Official ignore file exclusion → ineligible
  TC-30  Invalid template (parse errors) → ineligible (invalid_template)
  TC-31  Interactsh/OAST detection
  TC-32  Authentication requirement detection
  TC-33  Determinism: same input → same classification
  TC-34  Snapshot immutability: classification does not modify any file
  TC-35  ClassificationService.process_snapshot on a mini snapshot dir
  TC-36  Invariant check: total == eligible + ineligible + parse_errors
  TC-37  Zero impact: existing tests still importable (non-regression guard)
"""

from __future__ import annotations

import os
import tempfile
import textwrap
from pathlib import Path
from typing import List

import pytest

from core.template_parser import TemplateParser, TemplateParseResult
from core.template_metadata import MetadataExtractor
from core.template_eligibility import (
    ClassificationPolicy,
    EligibilityClassifier,
    IgnoreRuleSet,
    RC_ELIGIBLE,
    RC_INVALID_TEMPLATE,
    RC_OFFICIAL_IGNORE,
    RC_OUTSIDE_WEB_SCOPE,
    RC_UNRESOLVED,
    RC_UNSUPPORTED_PROTOCOL,
    RC_UNSAFE_BEHAVIOR,
    RC_DAST_REVIEW,
    RC_WORKFLOW_DEFERRED,
    STATUS_ELIGIBLE,
    STATUS_INELIGIBLE,
)
from core.template_classification_service import (
    TemplateClassificationService,
    ClassificationSummary,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def parser() -> TemplateParser:
    return TemplateParser()


@pytest.fixture(scope="module")
def extractor() -> MetadataExtractor:
    return MetadataExtractor()


@pytest.fixture(scope="module")
def policy() -> ClassificationPolicy:
    return ClassificationPolicy.v1()


@pytest.fixture(scope="module")
def classifier(policy) -> EligibilityClassifier:
    return EligibilityClassifier(policy)


@pytest.fixture(scope="module")
def empty_ignore() -> IgnoreRuleSet:
    return IgnoreRuleSet.empty()


REPO_VERSION_ID = "test-00000000-0000-0000-0000-000000000001"


def _make_yaml_file(content: str, tmpdir: str, filename: str = "test.yaml") -> str:
    """Write YAML content to a temp file; return absolute path."""
    path = os.path.join(tmpdir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(textwrap.dedent(content))
    return path


def _parse(parser, tmpdir, content, filename="test.yaml"):
    path = _make_yaml_file(content, tmpdir, filename)
    return parser.parse_file(path, tmpdir)


# ---------------------------------------------------------------------------
# TC-01  Valid YAML template parsing
# ---------------------------------------------------------------------------

def test_tc01_valid_yaml_parsing(parser, tmp_path):
    content = """
    id: test-valid-01
    info:
      name: Valid Test Template
      author: tester
      severity: medium
      tags: test,http
    http:
      - method: GET
        path:
          - "{{BaseURL}}/test"
        matchers:
          - type: status
            status: [200]
    """
    result = _parse(parser, str(tmp_path), content)
    assert result.is_valid, f"Expected valid, got errors: {result.parse_errors}"
    assert result.template_id == "test-valid-01"
    assert "http" in result.protocols
    assert result.is_executable
    assert not result.is_workflow
    assert len(result.content_hash) == 64  # SHA-256 hex
    assert result.file_size_bytes > 0


# ---------------------------------------------------------------------------
# TC-02  Invalid YAML parse error handling
# ---------------------------------------------------------------------------

def test_tc02_invalid_yaml(parser, tmp_path):
    content = "id: broken\ninfo:\n  name: broken\n  bad: [unclosed bracket\n"
    result = _parse(parser, str(tmp_path), content)
    assert not result.is_valid
    assert result.parse_errors
    assert result.protocols == []


# ---------------------------------------------------------------------------
# TC-03  Missing 'id' field
# ---------------------------------------------------------------------------

def test_tc03_missing_id(parser, tmp_path):
    content = """
    info:
      name: No ID Template
      severity: info
    http:
      - method: GET
        path:
          - "{{BaseURL}}/"
    """
    result = _parse(parser, str(tmp_path), content)
    assert not result.is_valid
    assert result.template_id is None
    assert result.parse_errors


# ---------------------------------------------------------------------------
# TC-04  Missing 'info' section
# ---------------------------------------------------------------------------

def test_tc04_missing_info(parser, tmp_path):
    content = "id: no-info-template\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n"
    result = _parse(parser, str(tmp_path), content)
    # id is present so parse_errors will note missing info, but template_id exists
    assert result.template_id == "no-info-template"
    assert "http" in result.protocols
    assert result.parse_errors  # missing info flagged


# ---------------------------------------------------------------------------
# TC-05  Protocol detection from YAML keys (not path)
# ---------------------------------------------------------------------------

def test_tc05_protocol_from_yaml_keys_not_path(parser, tmp_path):
    # File is in a "code/" style folder but declares http: in YAML
    content = """
    id: http-in-code-folder
    info:
      name: HTTP in code folder
      severity: info
    http:
      - method: GET
        path: ["{{BaseURL}}/"]
    """
    # Put file in a "code" subdirectory
    code_dir = tmp_path / "code"
    code_dir.mkdir()
    path = str(code_dir / "test.yaml")
    with open(path, "w") as fh:
        fh.write(textwrap.dedent(content))
    result = parser.parse_file(path, str(tmp_path))
    assert "http" in result.protocols
    assert "code" not in result.protocols


# ---------------------------------------------------------------------------
# TC-06  Legacy protocol aliases
# ---------------------------------------------------------------------------

def test_tc06_legacy_aliases(parser, tmp_path):
    # 'requests' is alias for 'http', 'tcp' is alias for 'network'
    content_requests = """
    id: legacy-requests
    info:
      name: Legacy Requests
      severity: info
    requests:
      - method: GET
        path: ["{{BaseURL}}/"]
    """
    r1 = _parse(parser, str(tmp_path), content_requests, "requests.yaml")
    assert "http" in r1.protocols

    content_tcp = """
    id: legacy-tcp
    info:
      name: Legacy TCP
      severity: info
    tcp:
      - host: ["{{Hostname}}"]
        port: 23
    """
    r2 = _parse(parser, str(tmp_path), content_tcp, "tcp.yaml")
    assert "network" in r2.protocols


# ---------------------------------------------------------------------------
# TC-07  Workflow template detection
# ---------------------------------------------------------------------------

def test_tc07_workflow_detection(parser, tmp_path):
    content = """
    id: test-workflow
    info:
      name: Test Workflow
      severity: info
    workflows:
      - template: http/some-template.yaml
    """
    result = _parse(parser, str(tmp_path), content)
    assert result.is_workflow
    assert not result.is_executable


# ---------------------------------------------------------------------------
# TC-08  Multi-protocol template detection
# ---------------------------------------------------------------------------

def test_tc08_multi_protocol(parser, tmp_path):
    content = """
    id: multi-proto
    info:
      name: Multi Protocol
      severity: info
    http:
      - method: GET
        path: ["{{BaseURL}}/"]
    ssl:
      - address: "{{Host}}:{{Port}}"
    """
    result = _parse(parser, str(tmp_path), content)
    assert "http" in result.protocols
    assert "ssl" in result.protocols
    assert len(result.protocols) == 2


# ---------------------------------------------------------------------------
# TC-09  Metadata extraction — CVE/CWE/CVSS
# ---------------------------------------------------------------------------

def test_tc09_cve_cwe_cvss_extraction(parser, extractor, tmp_path):
    content = """
    id: cve-test-template
    info:
      name: CVE Test
      severity: critical
      classification:
        cve-id: CVE-2021-44228
        cwe-id:
          - CWE-502
          - CWE-78
        cvss-score: 10.0
        cvss-metrics: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    http:
      - method: GET
        path: ["{{BaseURL}}/"]
    """
    parse = _parse(parser, str(tmp_path), content)
    meta = extractor.extract(parse)
    assert meta.cve_id == "CVE-2021-44228"
    assert "CWE-502" in meta.cwe_ids
    assert "CWE-78" in meta.cwe_ids
    assert meta.cvss_score == 10.0
    assert meta.cvss_vector is not None
    assert "CVSS:3.1" in meta.cvss_vector


# ---------------------------------------------------------------------------
# TC-10  No fabrication on missing fields
# ---------------------------------------------------------------------------

def test_tc10_no_fabrication(parser, extractor, tmp_path):
    content = """
    id: minimal-template
    info:
      name: Minimal
      severity: info
    http:
      - method: GET
        path: ["{{BaseURL}}/"]
    """
    parse = _parse(parser, str(tmp_path), content)
    meta = extractor.extract(parse)
    assert meta.cve_id is None
    assert meta.cwe_ids == []
    assert meta.cvss_score is None
    assert meta.cvss_vector is None
    assert meta.description is None
    assert meta.remediation is None
    assert meta.shodan_query is None
    assert meta.verified is None
    assert meta.max_request is None


# ---------------------------------------------------------------------------
# TC-11  Tags normalisation
# ---------------------------------------------------------------------------

def test_tc11_tags_normalisation(parser, extractor, tmp_path):
    content = """
    id: tag-test
    info:
      name: Tag Test
      severity: info
      tags: "HTTP, SSL, Dos, CVE"
    http:
      - method: GET
        path: ["{{BaseURL}}/"]
    """
    parse = _parse(parser, str(tmp_path), content)
    meta = extractor.extract(parse)
    # All lowercase, sorted, deduplicated
    assert all(t == t.lower() for t in meta.tags)
    assert meta.tags == sorted(meta.tags)
    assert len(meta.tags) == len(set(meta.tags))


# ---------------------------------------------------------------------------
# TC-12  Author normalisation
# ---------------------------------------------------------------------------

def test_tc12_author_normalisation(parser, extractor, tmp_path):
    # Comma-separated string
    content = """
    id: author-test
    info:
      name: Author Test
      severity: info
      author: "alice, bob, charlie"
    http:
      - method: GET
        path: ["{{BaseURL}}/"]
    """
    parse = _parse(parser, str(tmp_path), content)
    meta = extractor.extract(parse)
    assert isinstance(meta.author, list)
    assert "alice" in meta.author
    assert "bob" in meta.author

    # List form
    content2 = """
    id: author-list-test
    info:
      name: Author List Test
      severity: info
      author:
        - dave
        - eve
    http:
      - method: GET
        path: ["{{BaseURL}}/"]
    """
    parse2 = _parse(parser, str(tmp_path), content2, "author2.yaml")
    meta2 = extractor.extract(parse2)
    assert "dave" in meta2.author
    assert "eve" in meta2.author


# ---------------------------------------------------------------------------
# TC-13  Severity normalisation
# ---------------------------------------------------------------------------

def test_tc13_severity_normalisation(parser, extractor, tmp_path):
    for sev_in, expected in [("CRITICAL", "critical"), ("High", "high"),
                              ("medium", "medium"), ("LOW", "low"),
                              ("INFO", "info"), ("garbage", "unknown"), ("", "unknown")]:
        content = f"""
        id: sev-{sev_in.lower() or 'empty'}
        info:
          name: Sev Test
          severity: "{sev_in}"
        http:
          - method: GET
            path: ["{{{{BaseURL}}}}/"]
        """
        parse = _parse(parser, str(tmp_path), content, f"sev_{sev_in or 'empty'}.yaml")
        meta = extractor.extract(parse)
        assert meta.severity == expected, f"Input: {sev_in!r}, expected {expected!r}, got {meta.severity!r}"


# ---------------------------------------------------------------------------
# TC-14  IgnoreRuleSet tag exclusion
# ---------------------------------------------------------------------------

def test_tc14_ignore_tag_exclusion(tmp_path):
    ignore_content = "tags:\n  - dos\n  - fuzz\nfiles: []\n"
    ignore_path = str(tmp_path / ".nuclei-ignore")
    with open(ignore_path, "w") as f:
        f.write(ignore_content)
    ruleset = IgnoreRuleSet.from_file(ignore_path)

    excluded, rc, rule = ruleset.is_excluded("any-id", ["dos", "http"], "http/x.yaml")
    assert excluded
    assert rc == RC_OFFICIAL_IGNORE
    assert "dos" in rule

    excluded2, _, _ = ruleset.is_excluded("any-id", ["http"], "http/x.yaml")
    assert not excluded2


# ---------------------------------------------------------------------------
# TC-15  IgnoreRuleSet file exclusion
# ---------------------------------------------------------------------------

def test_tc15_ignore_file_exclusion(tmp_path):
    ignore_content = "tags: []\nfiles:\n  - http/cves/2019/CVE-2019-14696.yaml\n"
    ignore_path = str(tmp_path / ".nuclei-ignore")
    with open(ignore_path, "w") as f:
        f.write(ignore_content)
    ruleset = IgnoreRuleSet.from_file(ignore_path)

    excluded, rc, rule = ruleset.is_excluded(
        "CVE-2019-14696", [], "http/cves/2019/CVE-2019-14696.yaml"
    )
    assert excluded
    assert rc == RC_OFFICIAL_IGNORE

    excluded2, _, _ = ruleset.is_excluded(
        "other-id", [], "http/cves/2019/OTHER.yaml"
    )
    assert not excluded2


# ---------------------------------------------------------------------------
# TC-16  IgnoreRuleSet missing file → empty ruleset (no crash)
# ---------------------------------------------------------------------------

def test_tc16_ignore_missing_file():
    ruleset = IgnoreRuleSet.from_file("/nonexistent/path/.nuclei-ignore")
    excluded, _, _ = ruleset.is_excluded("any-id", ["dos"], "http/x.yaml")
    # No exclusions since file is missing
    assert not excluded


# ---------------------------------------------------------------------------
# Helper: build a parse+metadata pipeline and classify
# ---------------------------------------------------------------------------

def _classify_yaml(yaml_content, tmpdir, classifier, ignore, filename="tpl.yaml"):
    parser = TemplateParser()
    extractor = MetadataExtractor()
    path = _make_yaml_file(yaml_content, tmpdir, filename)
    parse_result = parser.parse_file(path, tmpdir)
    metadata = extractor.extract(parse_result)
    return classifier.classify(
        metadata=metadata,
        ignore_ruleset=ignore,
        repository_version_id=REPO_VERSION_ID,
        raw_yaml_text=parse_result.raw_yaml_text,
        parse_errors=parse_result.parse_errors if parse_result.parse_errors else None,
    )


# ---------------------------------------------------------------------------
# TC-17  HTTP → eligible
# ---------------------------------------------------------------------------

def test_tc17_http_eligible(classifier, empty_ignore, tmp_path):
    content = """
    id: http-eligible
    info:
      name: HTTP Eligible
      severity: medium
    http:
      - method: GET
        path: ["{{BaseURL}}/"]
        matchers:
          - type: status
            status: [200]
    """
    result = _classify_yaml(content, str(tmp_path), classifier, empty_ignore)
    assert result.security_status == STATUS_ELIGIBLE
    assert result.sequential_eligible
    assert result.independent_eligible
    assert RC_ELIGIBLE in result.eligibility_reasons


# ---------------------------------------------------------------------------
# TC-18  SSL → eligible
# ---------------------------------------------------------------------------

def test_tc18_ssl_eligible(classifier, empty_ignore, tmp_path):
    content = """
    id: ssl-eligible
    info:
      name: SSL Check
      severity: info
      tags: ssl
    ssl:
      - address: "{{Host}}:{{Port}}"
    """
    result = _classify_yaml(content, str(tmp_path), classifier, empty_ignore, "ssl.yaml")
    assert result.security_status == STATUS_ELIGIBLE
    assert RC_ELIGIBLE in result.eligibility_reasons


# ---------------------------------------------------------------------------
# TC-19  DNS → eligible
# ---------------------------------------------------------------------------

def test_tc19_dns_eligible(classifier, empty_ignore, tmp_path):
    content = """
    id: dns-eligible
    info:
      name: DNS Check
      severity: info
      tags: dns
    dns:
      - name: "{{FQDN}}"
        type: A
        matchers:
          - type: word
            words: ["127.0.0.1"]
    """
    result = _classify_yaml(content, str(tmp_path), classifier, empty_ignore, "dns.yaml")
    assert result.security_status == STATUS_ELIGIBLE


# ---------------------------------------------------------------------------
# TC-20  Headless → eligible
# ---------------------------------------------------------------------------

def test_tc20_headless_eligible(classifier, empty_ignore, tmp_path):
    content = """
    id: headless-eligible
    info:
      name: Headless Check
      severity: info
      tags: headless
    headless:
      - steps:
          - action: navigate
            args:
              url: "{{BaseURL}}"
    """
    result = _classify_yaml(content, str(tmp_path), classifier, empty_ignore, "headless.yaml")
    assert result.security_status == STATUS_ELIGIBLE
    assert result.execution_requirements["headless"] is True


# ---------------------------------------------------------------------------
# TC-21  Code → ineligible
# ---------------------------------------------------------------------------

def test_tc21_code_ineligible(classifier, empty_ignore, tmp_path):
    content = """
    id: code-ineligible
    info:
      name: Code Template
      severity: info
    code:
      - engine: [python3]
        source: |
          print("hello")
    """
    result = _classify_yaml(content, str(tmp_path), classifier, empty_ignore, "code.yaml")
    assert result.security_status == STATUS_INELIGIBLE
    assert RC_UNSUPPORTED_PROTOCOL in result.eligibility_reasons


# ---------------------------------------------------------------------------
# TC-22  File → ineligible
# ---------------------------------------------------------------------------

def test_tc22_file_ineligible(classifier, empty_ignore, tmp_path):
    content = """
    id: file-ineligible
    info:
      name: File Template
      severity: info
    file:
      - extensions:
          - all
    """
    result = _classify_yaml(content, str(tmp_path), classifier, empty_ignore, "file.yaml")
    assert result.security_status == STATUS_INELIGIBLE
    assert RC_UNSUPPORTED_PROTOCOL in result.eligibility_reasons


# ---------------------------------------------------------------------------
# TC-23  DAST path → ineligible (unsafe_behavior)
# ---------------------------------------------------------------------------

def test_tc23_dast_path_ineligible(classifier, empty_ignore, tmp_path):
    # Put template under dast/ subdirectory
    dast_dir = tmp_path / "dast"
    dast_dir.mkdir()
    content = """
    id: dast-sqli
    info:
      name: DAST SQLi
      severity: high
    http:
      - method: GET
        path: ["{{BaseURL}}/"]
    """
    path = str(dast_dir / "sqli.yaml")
    with open(path, "w") as f:
        f.write(textwrap.dedent(content))
    parse_result = TemplateParser().parse_file(path, str(tmp_path))
    metadata = MetadataExtractor().extract(parse_result)
    result = classifier.classify(
        metadata=metadata,
        ignore_ruleset=empty_ignore,
        repository_version_id=REPO_VERSION_ID,
        raw_yaml_text=parse_result.raw_yaml_text,
    )
    assert result.security_status == STATUS_INELIGIBLE
    assert (
        RC_DAST_REVIEW in result.eligibility_reasons
        or RC_UNSAFE_BEHAVIOR in result.eligibility_reasons
    )


# ---------------------------------------------------------------------------
# TC-24  Workflow → ineligible (workflow_deferred)
# ---------------------------------------------------------------------------

def test_tc24_workflow_ineligible(classifier, empty_ignore, tmp_path):
    content = """
    id: test-workflow
    info:
      name: Test Workflow
      severity: info
    workflows:
      - template: http/some-template.yaml
    """
    result = _classify_yaml(content, str(tmp_path), classifier, empty_ignore, "wf.yaml")
    assert result.security_status == STATUS_INELIGIBLE
    assert RC_WORKFLOW_DEFERRED in result.eligibility_reasons


# ---------------------------------------------------------------------------
# TC-25  Network/TCP with web port → eligible
# ---------------------------------------------------------------------------

def test_tc25_network_web_port_eligible(classifier, empty_ignore, tmp_path):
    content = """
    id: network-web-port
    info:
      name: Network Web Port
      severity: info
      tags: network,tcp
    tcp:
      - host: ["{{Hostname}}"]
        port: 8080
    """
    result = _classify_yaml(content, str(tmp_path), classifier, empty_ignore, "net_web.yaml")
    assert result.security_status == STATUS_ELIGIBLE
    assert result.web_relevant is True


# ---------------------------------------------------------------------------
# TC-26  Network with non-web service tags → ineligible (outside_web_scope)
# ---------------------------------------------------------------------------

def test_tc26_network_non_web_ineligible(classifier, empty_ignore, tmp_path):
    content = """
    id: network-ssh
    info:
      name: SSH Banner Grab
      severity: info
      tags: network,ssh,telnet
    tcp:
      - host: ["{{Hostname}}"]
        port: 22
    """
    result = _classify_yaml(content, str(tmp_path), classifier, empty_ignore, "net_ssh.yaml")
    assert result.security_status == STATUS_INELIGIBLE
    assert RC_OUTSIDE_WEB_SCOPE in result.eligibility_reasons
    assert result.web_relevant is False


# ---------------------------------------------------------------------------
# TC-27  Network/JS with no signals → ineligible (unresolved)
# ---------------------------------------------------------------------------

def test_tc27_network_unresolved(classifier, empty_ignore, tmp_path):
    content = """
    id: network-generic
    info:
      name: Generic Network Probe
      severity: info
      tags: network,tcp
    tcp:
      - host: ["{{Hostname}}"]
        port: 12345
    """
    result = _classify_yaml(content, str(tmp_path), classifier, empty_ignore, "net_generic.yaml")
    assert result.security_status == STATUS_INELIGIBLE
    assert RC_UNRESOLVED in result.eligibility_reasons
    assert result.web_relevant is None


# ---------------------------------------------------------------------------
# TC-28  Official ignore tag exclusion → ineligible
# ---------------------------------------------------------------------------

def test_tc28_official_ignore_tag(tmp_path):
    ignore_path = str(tmp_path / ".nuclei-ignore")
    with open(ignore_path, "w") as f:
        f.write("tags:\n  - dos\n  - bruteforce\nfiles: []\n")
    ruleset = IgnoreRuleSet.from_file(ignore_path)
    policy = ClassificationPolicy.v1()
    classifier_local = EligibilityClassifier(policy)

    content = """
    id: dos-template
    info:
      name: DoS Test
      severity: high
      tags: dos,http
    http:
      - method: GET
        path: ["{{BaseURL}}/"]
    """
    parse = TemplateParser().parse_file(
        _make_yaml_file(content, str(tmp_path), "dos.yaml"), str(tmp_path)
    )
    meta = MetadataExtractor().extract(parse)
    result = classifier_local.classify(
        metadata=meta,
        ignore_ruleset=ruleset,
        repository_version_id=REPO_VERSION_ID,
        raw_yaml_text=parse.raw_yaml_text,
    )
    assert result.security_status == STATUS_INELIGIBLE
    assert RC_OFFICIAL_IGNORE in result.eligibility_reasons
    assert result.exclusion_rule is not None
    assert "dos" in result.exclusion_rule


# ---------------------------------------------------------------------------
# TC-29  Official ignore file exclusion → ineligible
# ---------------------------------------------------------------------------

def test_tc29_official_ignore_file(tmp_path):
    ignore_path = str(tmp_path / ".nuclei-ignore")
    with open(ignore_path, "w") as f:
        f.write("tags: []\nfiles:\n  - http/cves/2019/CVE-2019-14696.yaml\n")
    ruleset = IgnoreRuleSet.from_file(ignore_path)
    policy = ClassificationPolicy.v1()
    classifier_local = EligibilityClassifier(policy)

    # Create the template at the matching relative path
    cve_dir = tmp_path / "http" / "cves" / "2019"
    cve_dir.mkdir(parents=True)
    cve_path = str(cve_dir / "CVE-2019-14696.yaml")
    with open(cve_path, "w") as f:
        f.write(textwrap.dedent("""
        id: CVE-2019-14696
        info:
          name: CVE 2019 14696
          severity: high
        http:
          - method: GET
            path: ["{{BaseURL}}/"]
        """))
    parse = TemplateParser().parse_file(cve_path, str(tmp_path))
    meta = MetadataExtractor().extract(parse)
    result = classifier_local.classify(
        metadata=meta,
        ignore_ruleset=ruleset,
        repository_version_id=REPO_VERSION_ID,
        raw_yaml_text=parse.raw_yaml_text,
    )
    assert result.security_status == STATUS_INELIGIBLE
    assert RC_OFFICIAL_IGNORE in result.eligibility_reasons


# ---------------------------------------------------------------------------
# TC-30  Invalid template (parse errors) → ineligible (invalid_template)
# ---------------------------------------------------------------------------

def test_tc30_invalid_template(classifier, empty_ignore, tmp_path):
    content = "id: broken\ninfo:\n  name: broken\n  bad: [unclosed"
    result = _classify_yaml(content, str(tmp_path), classifier, empty_ignore, "broken.yaml")
    assert result.security_status == STATUS_INELIGIBLE
    assert RC_INVALID_TEMPLATE in result.eligibility_reasons


# ---------------------------------------------------------------------------
# TC-31  Interactsh/OAST detection
# ---------------------------------------------------------------------------

def test_tc31_interactsh_detection(classifier, empty_ignore, tmp_path):
    content = """
    id: oast-template
    info:
      name: OAST Template
      severity: high
      tags: oast,ssrf
    http:
      - method: GET
        path: ["{{BaseURL}}/?url={{interactsh-url}}"]
        matchers:
          - type: word
            words: ["Interactsh Server"]
    """
    result = _classify_yaml(content, str(tmp_path), classifier, empty_ignore, "oast.yaml")
    assert result.execution_requirements["interactsh"] is True


# ---------------------------------------------------------------------------
# TC-32  Authentication requirement detection
# ---------------------------------------------------------------------------

def test_tc32_auth_detection(classifier, empty_ignore, tmp_path):
    content = """
    id: auth-template
    info:
      name: Default Login
      severity: medium
      tags: default-login,http
    http:
      - method: POST
        path: ["{{BaseURL}}/login"]
        body: "username=admin&password=admin"
        matchers:
          - type: word
            words: ["Login successful"]
    """
    result = _classify_yaml(content, str(tmp_path), classifier, empty_ignore, "auth.yaml")
    assert result.execution_requirements["authentication"] is True


# ---------------------------------------------------------------------------
# TC-33  Determinism
# ---------------------------------------------------------------------------

def test_tc33_determinism(classifier, empty_ignore, tmp_path):
    content = """
    id: determinism-test
    info:
      name: Determinism
      severity: medium
    http:
      - method: GET
        path: ["{{BaseURL}}/"]
    """
    r1 = _classify_yaml(content, str(tmp_path), classifier, empty_ignore, "det1.yaml")
    r2 = _classify_yaml(content, str(tmp_path), classifier, empty_ignore, "det2.yaml")
    assert r1.security_status == r2.security_status
    assert r1.eligibility_reasons == r2.eligibility_reasons
    assert r1.sequential_eligible == r2.sequential_eligible
    assert r1.policy_version == r2.policy_version


# ---------------------------------------------------------------------------
# TC-34  Snapshot immutability
# ---------------------------------------------------------------------------

def test_tc34_snapshot_immutability(tmp_path):
    """Classification must not modify any file in the snapshot directory."""
    content = """
    id: immutable-test
    info:
      name: Immutable
      severity: info
    http:
      - method: GET
        path: ["{{BaseURL}}/"]
    """
    yaml_path = _make_yaml_file(content, str(tmp_path))
    before_mtime = os.path.getmtime(yaml_path)
    before_size = os.path.getsize(yaml_path)

    parser = TemplateParser()
    extractor = MetadataExtractor()
    policy = ClassificationPolicy.v1()
    classifier_local = EligibilityClassifier(policy)

    parse = parser.parse_file(yaml_path, str(tmp_path))
    meta = extractor.extract(parse)
    classifier_local.classify(
        metadata=meta,
        ignore_ruleset=IgnoreRuleSet.empty(),
        repository_version_id=REPO_VERSION_ID,
        raw_yaml_text=parse.raw_yaml_text,
    )

    assert os.path.getmtime(yaml_path) == before_mtime
    assert os.path.getsize(yaml_path) == before_size


# ---------------------------------------------------------------------------
# TC-35  ClassificationService on a mini snapshot
# ---------------------------------------------------------------------------

def test_tc35_classification_service_mini_snapshot(tmp_path):
    """Full pipeline on a minimal snapshot directory."""
    # Create .nuclei-ignore
    with open(str(tmp_path / ".nuclei-ignore"), "w") as f:
        f.write("tags:\n  - dos\nfiles: []\n")

    # Create some templates
    templates = {
        "http/eligible.yaml": """
            id: http-eligible
            info:
              name: Eligible
              severity: medium
            http:
              - method: GET
                path: ["{{BaseURL}}/"]
        """,
        "code/ineligible.yaml": """
            id: code-ineligible
            info:
              name: Ineligible Code
              severity: info
            code:
              - engine: [python3]
                source: |
                  print("x")
        """,
        "dast/unsafe.yaml": """
            id: dast-unsafe
            info:
              name: DAST unsafe
              severity: high
            http:
              - unsafe: true
                method: GET
                path: ["{{BaseURL}}/"]
        """,
        "workflows/my-workflow.yaml": """
            id: my-workflow
            info:
              name: Workflow
              severity: info
            workflows:
              - template: http/eligible.yaml
        """,
        "http/dos-excluded.yaml": """
            id: dos-excluded
            info:
              name: DOS
              severity: high
              tags: dos,http
            http:
              - method: GET
                path: ["{{BaseURL}}/"]
        """,
    }

    for rel_path, content in templates.items():
        full_path = tmp_path / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        with open(str(full_path), "w") as f:
            f.write(textwrap.dedent(content))

    service = TemplateClassificationService()
    summary = service.process_snapshot(
        repository_version_id=REPO_VERSION_ID,
        snapshot_path=str(tmp_path),
    )

    assert summary.total_yaml_files == 5
    assert summary.total_eligible >= 1       # http/eligible.yaml
    assert summary.total_ineligible >= 4     # code, dast, workflow, dos-excluded
    assert summary.invariant_holds, (
        f"Invariant failed: files={summary.total_yaml_files} "
        f"processed={summary.total_processed} "
        f"eligible={summary.total_eligible} ineligible={summary.total_ineligible}"
    )


# ---------------------------------------------------------------------------
# TC-36  Invariant check
# ---------------------------------------------------------------------------

def test_tc36_invariant(tmp_path):
    """total_yaml_files == eligible + ineligible + parse_errors"""
    with open(str(tmp_path / ".nuclei-ignore"), "w") as f:
        f.write("tags: []\nfiles: []\n")
    # 3 valid templates + 1 broken
    for i in range(3):
        with open(str(tmp_path / f"t{i}.yaml"), "w") as f:
            f.write(textwrap.dedent(f"""
            id: template-{i}
            info:
              name: Template {i}
              severity: info
            http:
              - method: GET
                path: ["{{{{BaseURL}}}}/"]
            """))
    with open(str(tmp_path / "broken.yaml"), "w") as f:
        f.write("id: broken\nbad: [unclosed")

    service = TemplateClassificationService()
    summary = service.process_snapshot(
        repository_version_id=REPO_VERSION_ID,
        snapshot_path=str(tmp_path),
    )
    assert summary.total_yaml_files == 4
    assert summary.total_processed == 4            # all 4 files were processed
    assert summary.total_eligible == 3             # 3 valid HTTP templates
    assert summary.total_ineligible == 1           # broken.yaml → invalid_template
    assert summary.total_parse_errors == 1         # broken.yaml had parse error
    assert summary.invariant_holds, (
        f"Invariant broken: files={summary.total_yaml_files} "
        f"processed={summary.total_processed} "
        f"eligible={summary.total_eligible} ineligible={summary.total_ineligible}"
    )


# ---------------------------------------------------------------------------
# TC-37  Zero impact on existing scan modules (non-regression import guard)
# ---------------------------------------------------------------------------

def test_tc37_zero_impact_non_regression():
    """Importing new modules must not break existing scan module imports."""
    import core.nuclei_shared  # noqa: F401
    import core.template_parser  # noqa: F401
    import core.template_metadata  # noqa: F401
    import core.template_eligibility  # noqa: F401
    import core.template_classification_service  # noqa: F401
    # Existing modules must still be importable
    import core.nuclei_repository_service  # noqa: F401
    # stage3 uses docker; just check it imports
    try:
        import core.stage3_vulnerabilities  # noqa: F401
    except Exception:
        pass  # docker/env deps are optional in test env
