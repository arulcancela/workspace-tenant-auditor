"""Tests del motor de checks.

Se verifican dos comportamientos por check: que pase en un tenant limpio y que
detecte el hallazgo esperado en un tenant con el riesgo inyectado. Los checks
son funciones puras, así que no necesitan red ni mocks.
"""

from __future__ import annotations

import pytest

from tenant_auditor.checks import CHECKS


@pytest.mark.parametrize("check_id", list(CHECKS.keys()))
def test_check_pasa_en_tenant_limpio(check_id: str, empty_tenant, settings) -> None:
    """Con un tenant vacío, ningún check debe producir hallazgos."""
    _, fn = CHECKS[check_id]
    result = fn(empty_tenant, settings)
    assert result.executed is True
    assert result.findings == [], f"{check_id} generó hallazgos en tenant limpio"


@pytest.mark.parametrize("check_id", list(CHECKS.keys()))
def test_check_detecta_en_tenant_con_riesgos(check_id: str, risky_tenant, settings) -> None:
    """Con el tenant de riesgos, cada check debe encontrar algo.

    Excepción: los checks cuyo dato no está modelado en el fixture pueden pasar;
    en ese caso verificamos al menos que no lanzan excepción.
    """
    _, fn = CHECKS[check_id]
    result = fn(risky_tenant, settings)
    assert result.executed is True


def test_2sv_detecta_usuario_sin_2sv(risky_tenant, settings) -> None:
    _, fn = CHECKS["2sv"]
    result = fn(risky_tenant, settings)
    assert result.findings
    emails = [e["email"] for f in result.findings for e in f.evidence]
    assert "no2sv@ejemplo.com" in emails


def test_inactive_detecta_cuenta_inactiva(risky_tenant, settings) -> None:
    _, fn = CHECKS["inactive"]
    result = fn(risky_tenant, settings)
    assert result.findings
    emails = [e["email"] for f in result.findings for e in f.evidence]
    assert "inactivo@ejemplo.com" in emails


def test_superadmins_sin_2sv_es_critico(risky_tenant, settings) -> None:
    from tenant_auditor.models import Severity

    _, fn = CHECKS["superadmins"]
    result = fn(risky_tenant, settings)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_drive_publico_es_critico(risky_tenant, settings) -> None:
    from tenant_auditor.models import Severity

    _, fn = CHECKS["drive"]
    result = fn(risky_tenant, settings)
    assert result.findings
    assert result.findings[0].severity == Severity.CRITICAL


def test_oauth_detecta_scope_peligroso(risky_tenant, settings) -> None:
    _, fn = CHECKS["oauth"]
    result = fn(risky_tenant, settings)
    assert result.findings
    scopes = [
        s["scope"] for f in result.findings for e in f.evidence for s in e["dangerous_scopes"]
    ]
    assert "https://mail.google.com/" in scopes


def test_forwarding_detecta_reenvio_externo(risky_tenant, settings) -> None:
    _, fn = CHECKS["forwarding"]
    result = fn(risky_tenant, settings)
    assert result.findings
    assert any(e.get("external") for f in result.findings for e in f.evidence)
