"""Tests de la generación de informes (HTML/JSON)."""

from __future__ import annotations

import json

from tenant_auditor.models import AuditReport, CheckResult, Finding, Severity
from tenant_auditor.report import ReportGenerator


def _finding(sev: Severity, check_name: str, count: int = 1) -> Finding:
    return Finding(
        check_id="x",
        check_name=check_name,
        severity=sev,
        description="Descripción del hallazgo de prueba",
        recommendation="Aplicar la recomendación de prueba",
        reference="Referencia de prueba",
        affected_count=count,
    )


def _sample_report() -> AuditReport:
    return AuditReport(
        domain="ejemplo.com",
        tool_version="1.0.0",
        mode="dry-run",
        results=[
            CheckResult(
                check_id="2sv",
                check_name="Usuarios sin 2SV",
                findings=[_finding(Severity.CRITICAL, "Usuarios sin 2SV", count=3)],
            ),
            CheckResult(
                check_id="drive",
                check_name="Compartición Drive",
                findings=[_finding(Severity.MEDIUM, "Compartición Drive")],
            ),
        ],
    )


def test_render_html_incluye_dominio_y_severidad() -> None:
    html = ReportGenerator().render_html(_sample_report())
    assert "ejemplo.com" in html
    assert "critica" in html or "crítica" in html.lower()
    assert "<html" in html.lower()


def test_render_html_incluye_hallazgos() -> None:
    html = ReportGenerator().render_html(_sample_report())
    assert "Usuarios sin 2SV" in html
    assert "Recomendación" in html
    assert "Aplicar la recomendación de prueba" in html


def test_render_json_es_valido() -> None:
    payload = ReportGenerator().render_json(_sample_report())
    data = json.loads(payload)
    assert data["domain"] == "ejemplo.com"
    assert data["mode"] == "dry-run"


def test_write_all_escribe_html_y_json(tmp_path) -> None:
    written = ReportGenerator().write_all(_sample_report(), str(tmp_path), ["html", "json"])
    assert "html" in written
    assert "json" in written
    assert list(tmp_path.glob("audit_ejemplo.com_*.html"))


def test_write_all_sin_pdf_no_falla(tmp_path) -> None:
    """Pedir solo HTML/JSON no requiere WeasyPrint."""
    written = ReportGenerator().write_all(_sample_report(), str(tmp_path), ["html"])
    assert "pdf" not in written


def test_informe_sin_hallazgos_muestra_mensaje() -> None:
    report = AuditReport(domain="ejemplo.com", tool_version="1.0.0", results=[])
    html = ReportGenerator().render_html(report)
    assert "Sin hallazgos" in html or "cumple" in html
