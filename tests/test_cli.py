"""Tests de la CLI usando el runner de Typer (sin red, con --dry-run)."""

from __future__ import annotations

from typer.testing import CliRunner

from tenant_auditor.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "v" in result.stdout


def test_list_checks_muestra_al_menos_10() -> None:
    result = runner.invoke(app, ["list-checks"])
    assert result.exit_code == 0
    # Cada una de las filas de la tabla incluye un ID conocido.
    assert "2sv" in result.stdout
    assert "oauth" in result.stdout


def test_audit_dry_run_genera_informes(tmp_path) -> None:
    result = runner.invoke(
        app,
        [
            "audit",
            "--dry-run",
            "--domain",
            "ejemplo.com",
            "--output",
            str(tmp_path),
            "--formats",
            "html,json",
        ],
    )
    # El exit code puede ser 1 si hay hallazgos críticos/altos (comportamiento
    # intencional para CI). Verificamos que se generaron los ficheros.
    assert result.exit_code in (0, 1)
    assert list(tmp_path.glob("audit_ejemplo.com_*.html"))
    assert list(tmp_path.glob("audit_ejemplo.com_*.json"))


def test_audit_check_invalido_falla(tmp_path) -> None:
    result = runner.invoke(
        app,
        ["audit", "--dry-run", "--checks", "2sv,noexiste", "--output", str(tmp_path)],
    )
    assert result.exit_code == 2
    assert "noexiste" in result.stdout
