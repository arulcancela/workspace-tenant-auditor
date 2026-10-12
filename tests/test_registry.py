"""Tests del registro y ejecutor de checks."""

from __future__ import annotations

import pytest

from tenant_auditor.checks.registry import (
    CHECKS,
    available_check_ids,
    resolve_check_ids,
    run_checks,
)


def test_hay_al_menos_10_checks() -> None:
    assert len(CHECKS) >= 10


def test_ids_en_minusculas_sin_espacios() -> None:
    for check_id in CHECKS:
        assert check_id == check_id.lower()
        assert " " not in check_id


def test_resolve_all_devuelve_todos() -> None:
    assert resolve_check_ids("all") == available_check_ids()
    assert resolve_check_ids(None) == available_check_ids()


def test_resolve_seleccion_parcial() -> None:
    assert resolve_check_ids("2sv,oauth") == ["2sv", "oauth"]


def test_resolve_id_invalido_lanza() -> None:
    with pytest.raises(ValueError, match="desconocidos"):
        resolve_check_ids("2sv,inexistente")


def test_run_checks_cronometra_y_ejecuta(risky_tenant, settings) -> None:
    results = run_checks(risky_tenant, ["2sv", "drive"], settings)
    assert len(results) == 2
    assert all(r.executed for r in results)
    assert all(r.duration_ms >= 0 for r in results)


def test_run_checks_aisla_excepciones(risky_tenant, settings, monkeypatch) -> None:
    """Si un check lanza excepción, se captura y no afecta a los demás."""
    from tenant_auditor.checks import registry

    def boom(_data, _settings):  # noqa: ANN001
        raise RuntimeError("fallo simulado")

    monkeypatch.setitem(registry.CHECKS, "2sv", ("Roto", boom))
    results = registry.run_checks(risky_tenant, ["2sv", "drive"], settings)
    assert len(results) == 2
    broken = next(r for r in results if r.check_id == "2sv")
    assert broken.executed is False
    assert "fallo simulado" in (broken.error or "")
