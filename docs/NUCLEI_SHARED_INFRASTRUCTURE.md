# Nuclei Shared Template Infrastructure (Phases 1–6) — Developer Setup & Handoff Guide

## 1. Overview & Approved Baseline

This package delivers the shared Nuclei template repository, eligibility classification (`v1.2.0`), metadata extraction, PostgreSQL 17-column catalog, and `TemplateSelectionService` for YemScan:

- **Nuclei Templates Upstream Version:** `v10.5.1`
- **Approved Upstream Commit:** `79fb682760ab3d5b0e22afbb44709353cbebf023`
- **Classification Policy:** `v1.2.0` (Controlled Comprehensive DAST Integration)
- **Expected Catalog Totals (`v10.5.1` / `v1.2.0`):**
  - Indexed Executable Templates (`nuclei_templates`): `13,897` (of `14,126` walked YAMLs; `207` workflows and `22` helpers/profiles omitted; `22` hidden `.github`/CI YAMLs skipped; `14,148` raw YAMLs on disk)
  - Eligible Templates (`sequential_eligible = true` & `independent_eligible = true`): `12,113` (includes `244` eligible DAST templates)
  - Ineligible Templates: `1,784` (includes `4` AI DAST templates `dast_ai_unresolved` and `213` official `.nuclei-ignore` matches)
- **Catalog Schema:** Strictly **17 columns** on `nuclei_templates` (`created_at` replaced by `policy_details.indexed_at` JSONB)
- **Version Status:** Remains `staging` until Phase 7 activation approval

> **Note on Repository UUIDs:** `initialize_repository()` generates a new UUID (`TemplateRepositoryVersion.id`) per environment. Never hardcode another developer's UUID—always obtain `version.id` dynamically from `initialize_repository()` or `template_repository_versions`.

---

## 2. Prerequisites & Dependencies

1. **PostgreSQL 15+** running and reachable via `DATABASE_URL` (silent fallback to SQLite for `postgresql://` URLs is prohibited in `database.py`).
2. **Python environment & dependencies:**

```bash
pip install -r requirements.txt
# Test runner (and optional Python 3.14 PostgreSQL driver if psycopg2 wheel is unavailable):
pip install pytest psycopg[binary]
```

3. **Configure `.env` (never commit `.env`):**

```env
DATABASE_URL=postgresql://<USER>:<PASSWORD>@localhost:5432/<DB_NAME>
```

---

## 3. Database Schema Migration (17-Column Catalog)

Initialize all tables, indexes (including GIN indexes on `tags`, `protocols`, `cve_ids`, and `name` FTS), and run non-destructive migrations:

```bash
python init_db.py
```

If upgrading an existing database that previously had an 18th `created_at` column on `nuclei_templates`, `init_db.py` automatically preserves existing timestamps into `policy_details->'indexed_at'`, verifies zero unpreserved rows, and drops `created_at` atomically (reversible via `rollback_nuclei_templates_created_at_pg`).

---

## 4. Official Nuclei Templates Setup & Snapshot Creation

Clone the official `nuclei-templates` repository locally into `nuclei_templates_official/` (gitignored) and pin it strictly to the approved release commit:

```bash
git clone https://github.com/projectdiscovery/nuclei-templates.git nuclei_templates_official
git -C nuclei_templates_official checkout 79fb682760ab3d5b0e22afbb44709353cbebf023
```

---

## 5. Snapshot Staging, Classification (`v1.2.0`), and PostgreSQL Indexing

Run the pipeline using the shared Python APIs (snapshot remains in `staging`):

```python
from core.nuclei_repository_service import initialize_repository
from core.template_classification_service import TemplateClassificationService
from core.template_eligibility import ClassificationPolicy
from core.template_catalog_indexer import TemplateCatalogIndexer

# 1. Create immutable read-only snapshot under storage/nuclei/versions/<uuid>
version = initialize_repository()
print("Registered:", version.id, version.upstream_version, version.status)

# 2. Classify templates once under Policy v1.2.0
classifier_svc = TemplateClassificationService(ClassificationPolicy.v1_2())
summary = classifier_svc.process_snapshot(version.id)

# 3. Index executable templates into PostgreSQL nuclei_templates
indexer = TemplateCatalogIndexer()
indexing = indexer.index_classification_results(summary)
print(
    f"indexed={indexing.total_indexed}, "
    f"eligible={indexing.sequential_eligible_count}, "
    f"ineligible={indexing.ineligible_count}"
)
```

Expected counts for `v10.5.1` + `v1.2.0`: `indexed=13897, eligible=12113, ineligible=1784`.

---

## 6. Verification & Shared Component Tests

Ensure `DATABASE_URL` points to your PostgreSQL instance and run the shared component test suites:

```bash
python -m pytest \
  tests/test_nuclei_repository_service.py \
  tests/test_template_classification.py \
  tests/test_template_catalog.py \
  tests/test_template_selection_service.py -v
```

Expected baseline: **129 passed, 0 failed, 0 skipped**.

> **Known Pending Non-Nuclei Issue:** In `tests/test_nuclei_wapiti_integration.py`, `test_27_max_scan_time_documentation` currently fails (`240 != 120` in Wapiti's `core/security_scan_planner.py`), unrelated to the shared Nuclei template infrastructure and intentionally left untouched in Phases 1–6.

---

## 7. Shared Service & Integration Contract Location

All shared query/selection interfaces, Python dataclasses, and TypeScript/JSON API contracts live in:

- **[`core/template_selection_service.py`](../core/template_selection_service.py)**
  - **Python Data Contracts:** `TemplateFilter`, `PaginationParams`, `TemplateRecord`, `TemplateQueryResult`, `SelectionStats`, `ValidationResult`, `SelectionPreview`, `VersionInfo`, `PaginatedTagsResult`, `AvailableFilters`, `SelectionState`, `EnvironmentCapabilities`, `TemplateReadinessStatus`, `TargetReadinessEvaluation`
  - **Service Entry Points (`TemplateSelectionService`):** `get_version_info`, `get_template`, `query_templates`, `get_sequential_set`, `get_selection_stats`, `validate_selection`, `preview_selection`, `get_available_filters`, `get_all_tags`, `select_all_matching_ids`, `manage_selection`, `evaluate_target_and_readiness`
  - **TypeScript & JSON Contracts:** `Shared Data Contract — Independent Scan API` section at the bottom of `core/template_selection_service.py`
  - **Approved 6 Independent Filter Dimensions:** `template_ids`, `name_search`, `cve_ids`, `tags` (**OR** within list), `severities`, `protocols` (**OR** within criterion, **AND** across criteria)
