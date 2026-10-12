"""Tests de los modelos de dominio."""

from __future__ import annotations

from tenant_auditor.models import (
    AuditReport,
    CheckResult,
    Finding,
    Severity,
    TenantData,
)


def _finding(sev: Severity, count: int = 1) -> Finding:
    return Finding(
        check_id="x",
        check_name="X",
        severity=sev,
        description="d",
        recommendation="r",
        reference="ref",
        affected_count=count,
    )


def test_severity_weight_ordenado() -> None:
    assert Severity.CRITICAL.weight > Severity.HIGH.weight > Severity.MEDIUM.weight
    assert Severity.MEDIUM.weight > Severity.LOW.weight > Severity.INFO.weight


def test_severity_color_distintos() -> None:
    colors = {s.color for s in Severity}
    assert len(colors) == len(list(Severity))


def test_report_no_cuenta_hallazgos_compliant() -> None:
    ok = Finding(
        check_id="x",
        check_name="X",
        severity=Severity.INFO,
        description="",
        recommendation="",
        reference="",
        compliant=True,
    )
    report = AuditReport(
        domain="ejemplo.com",
        tool_version="1.0.0",
        results=[CheckResult(check_id="x", check_name="X", findings=[ok])],
    )
    assert report.total_findings == 0


def test_report_score_baja_con_hallazgos() -> None:
    report = AuditReport(
        domain="ejemplo.com",
        tool_version="1.0.0",
        results=[CheckResult(check_id="x", check_name="X", findings=[_finding(Severity.CRITICAL)])],
    )
    assert report.overall_score() == 85  # 100 - 15


def test_report_score_nunca_negativo() -> None:
    many = [_finding(Severity.CRITICAL) for _ in range(20)]
    report = AuditReport(
        domain="ejemplo.com",
        tool_version="1.0.0",
        results=[CheckResult(check_id="x", check_name="X", findings=many)],
    )
    assert report.overall_score() == 0


def test_counts_by_severity() -> None:
    report = AuditReport(
        domain="ejemplo.com",
        tool_version="1.0.0",
        results=[
            CheckResult(
                check_id="x",
                check_name="X",
                findings=[_finding(Severity.CRITICAL), _finding(Severity.HIGH)],
            )
        ],
    )
    counts = report.counts_by_severity()
    assert counts["critica"] == 1
    assert counts["alta"] == 1
    assert counts["media"] == 0


def test_tenant_data_por_defecto_vacio() -> None:
    data = TenantData(domain="ejemplo.com")
    assert data.users == []
    assert data.errors == []
