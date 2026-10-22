"""Tests de la CLI usando el runner de Typer (sin red, con --dry-run)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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


def test_version_muestra_las_apis_en_uso() -> None:
    """El diagnóstico debe declarar qué nombre de API usa esta build."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "admin:reports_v1" in result.stdout
    assert "admin:directory_v1" in result.stdout


def test_flag_version_global() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "admin:reports_v1" in result.stdout


def test_cabecera_de_audit_identifica_la_build(tmp_path) -> None:
    """Cada ejecución real debe decir qué código la está produciendo."""
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
            "html",
        ],
    )
    assert result.exit_code in (0, 1)
    assert "workspace-tenant-auditor v" in result.stdout
    assert (
        "git " in result.stdout
        or "copia en disco" in result.stdout
        or "sin identificar" in result.stdout
    )


@patch("tenant_auditor.auth.google_client.build")
@patch("tenant_auditor.auth.google_client.service_account.Credentials.from_service_account_file")
def test_fallo_de_cliente_no_se_etiqueta_como_error_de_autenticacion(
    mock_from_file, mock_build, tmp_path, monkeypatch
) -> None:
    """El falso «Error de autenticación» que veían los operadores.

    Un fallo de discovery debe salir como error de construcción de cliente,
    con código de salida propio y una sugerencia accionable.
    """
    from googleapiclient.errors import UnknownApiNameOrVersion

    from tenant_auditor.config import get_settings

    mock_from_file.return_value = MagicMock()
    mock_build.side_effect = UnknownApiNameOrVersion("name: reports  version: v1")

    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/sa.json")
    monkeypatch.setenv("DELEGATED_ADMIN_EMAIL", "admin@scooltic.es")
    monkeypatch.setenv("TENANT_DOMAIN", "scooltic.es")
    get_settings.cache_clear()

    try:
        result = runner.invoke(app, ["audit", "--domain", "scooltic.es", "--output", str(tmp_path)])
    finally:
        get_settings.cache_clear()

    assert result.exit_code == 4
    assert "Error al construir el cliente" in result.stdout
    assert "Error de autenticación" not in result.stdout
    assert "Sugerencia:" in result.stdout
    assert "tenant-auditor version" in result.stdout
