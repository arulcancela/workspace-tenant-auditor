"""Tests de la capa de autenticación con mocks de la API de Google.

Estos tests NO acceden a Google: se mockean service_account y build para
verificar la lógica de construcción de credenciales, la inyección del subject
de Domain-Wide Delegation y el manejo de errores.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tenant_auditor.auth.google_client import (
    AuthError,
    ClientBuildError,
    ServiceAccountConfig,
    build_service_account_config,
    clear_client_cache,
    get_directory_service,
    get_reports_service,
    get_service,
)
from tenant_auditor.config import Settings


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    clear_client_cache()
    yield
    clear_client_cache()


def test_config_falla_sin_credenciales() -> None:
    settings = Settings(tenant_domain="ejemplo.com", google_application_credentials="")
    with pytest.raises(AuthError, match="GOOGLE_APPLICATION_CREDENTIALS"):
        build_service_account_config(settings)


def test_config_falla_sin_admin_delegado() -> None:
    settings = Settings(
        tenant_domain="ejemplo.com",
        google_application_credentials="/tmp/sa.json",
        delegated_admin_email="",
    )
    with pytest.raises(AuthError, match="DELEGATED_ADMIN_EMAIL"):
        build_service_account_config(settings)


def test_config_valida_correctamente() -> None:
    settings = Settings(
        tenant_domain="ejemplo.com",
        google_application_credentials="/tmp/sa.json",
        delegated_admin_email="admin@ejemplo.com",
    )
    config = build_service_account_config(settings)
    assert config.domain == "ejemplo.com"
    assert config.delegated_admin_email == "admin@ejemplo.com"
    assert config.scopes  # al menos un scope por defecto


@patch("tenant_auditor.auth.google_client.build")
@patch("tenant_auditor.auth.google_client.service_account.Credentials.from_service_account_file")
def test_dwd_inyecta_subject(mock_from_file, mock_build) -> None:
    """Verifica que se llama a with_subject con el admin delegado (DWD)."""
    creds = MagicMock()
    delegated = MagicMock()
    creds.with_subject.return_value = delegated
    mock_from_file.return_value = creds
    mock_build.return_value = MagicMock()

    settings = Settings(
        tenant_domain="ejemplo.com",
        google_application_credentials="/tmp/sa.json",
        delegated_admin_email="admin@ejemplo.com",
    )
    config = build_service_account_config(settings)
    get_directory_service(config)

    creds.with_subject.assert_called_once_with("admin@ejemplo.com")
    mock_build.assert_called_once()
    # El cliente se construye con las credenciales delegadas.
    _, kwargs = mock_build.call_args
    assert kwargs["credentials"] is delegated


@patch("tenant_auditor.auth.google_client.build")
@patch("tenant_auditor.auth.google_client.service_account.Credentials.from_service_account_file")
def test_cliente_se_cachea(mock_from_file, mock_build) -> None:
    """El cliente debe construirse una sola vez y reutilizarse."""
    creds = MagicMock()
    creds.with_subject.return_value = MagicMock()
    mock_from_file.return_value = creds
    mock_build.return_value = MagicMock()

    settings = Settings(
        tenant_domain="ejemplo.com",
        google_application_credentials="/tmp/sa.json",
        delegated_admin_email="admin@ejemplo.com",
    )
    config = build_service_account_config(settings)
    get_directory_service(config)
    get_directory_service(config)

    assert mock_build.call_count == 1


@patch("tenant_auditor.auth.google_client.service_account.Credentials.from_service_account_file")
def test_fichero_inexistente_lanza_autherror(mock_from_file) -> None:
    mock_from_file.side_effect = FileNotFoundError()
    settings = Settings(
        tenant_domain="ejemplo.com",
        google_application_credentials="/no/existe.json",
        delegated_admin_email="admin@ejemplo.com",
    )
    config = build_service_account_config(settings)
    with pytest.raises(AuthError, match="No se encontró"):
        get_directory_service(config)


def _config_de_prueba() -> ServiceAccountConfig:
    settings = Settings(
        tenant_domain="ejemplo.com",
        google_application_credentials="/tmp/sa.json",
        delegated_admin_email="admin@ejemplo.com",
    )
    return build_service_account_config(settings)


@patch("tenant_auditor.auth.google_client.build")
@patch("tenant_auditor.auth.google_client.service_account.Credentials.from_service_account_file")
def test_reports_service_usa_admin_reports_v1(mock_from_file, mock_build) -> None:
    """Regresión: la Reports API debe construirse como ``admin:reports_v1``.

    Antes se usaba ``build("reports", "v1")``, que devuelve
    ``UnknownApiNameOrVersion`` (HTTP 404 en el discovery) y abortaba la
    auditoría real con un falso "error de autenticación" (código de salida 3).
    La Reports API de Google Workspace se consume a través del cliente del
    Admin SDK: ``build("admin", "reports_v1")``.
    """
    creds = MagicMock()
    creds.with_subject.return_value = MagicMock()
    mock_from_file.return_value = creds
    mock_build.return_value = MagicMock()

    get_reports_service(_config_de_prueba())

    mock_build.assert_called_once()
    api, version = mock_build.call_args.args[:2]
    assert (api, version) == ("admin", "reports_v1"), (
        "La Reports API debe construirse como ('admin', 'reports_v1'); "
        f"se usó ('{api}', '{version}')."
    )


@patch("tenant_auditor.auth.google_client.build")
@patch("tenant_auditor.auth.google_client.service_account.Credentials.from_service_account_file")
def test_directory_service_usa_admin_directory_v1(mock_from_file, mock_build) -> None:
    """Regresión: la Directory API debe construirse como ``admin:directory_v1``."""
    creds = MagicMock()
    creds.with_subject.return_value = MagicMock()
    mock_from_file.return_value = creds
    mock_build.return_value = MagicMock()

    get_directory_service(_config_de_prueba())

    mock_build.assert_called_once()
    api, version = mock_build.call_args.args[:2]
    assert (api, version) == ("admin", "directory_v1")


@patch("tenant_auditor.auth.collector._collect_delegated")
@patch("tenant_auditor.auth.collector._collect_login_activities")
@patch("tenant_auditor.auth.collector._collect_oauth_tokens")
@patch("tenant_auditor.auth.collector._collect_super_admins")
@patch("tenant_auditor.auth.collector._collect_aliases")
@patch("tenant_auditor.auth.collector._collect_domains")
@patch("tenant_auditor.auth.collector._collect_groups")
@patch("tenant_auditor.auth.collector._collect_users")
@patch("tenant_auditor.auth.collector.get_reports_service")
@patch("tenant_auditor.auth.collector.get_directory_service")
def test_fallo_de_reports_no_aborta_la_recopilacion(
    mock_dir,
    mock_reports,
    mock_users,
    mock_groups,
    mock_domains,
    mock_aliases,
    mock_admins,
    mock_oauth,
    mock_login,
    mock_delegated,
) -> None:
    """Regresión de robustez: un fallo al construir el cliente de Reports NO
    debe abortar la auditoría.

    Antes, `get_reports_service()` se llamaba fuera del bloque `_safe`, de modo
    que cualquier error al construir el cliente (p.ej. el bug de `reports:v1`)
    propagaba `AuthError` y tumbaba toda la auditoría. Ahora es opcional: si
    falla, se registra como aviso no fatal en `TenantData.errors` y la
    recopilación continúa.
    """
    from tenant_auditor.auth.collector import collect_tenant_data

    mock_directory = MagicMock()
    mock_directory.users.return_value.list.return_value.execute.return_value = {"users": []}
    mock_directory.groups.return_value.list.return_value.execute.return_value = {"groups": []}
    mock_directory.domains.return_value.list.return_value.execute.return_value = {"domains": []}
    mock_directory.members.return_value.list.return_value.execute.return_value = {"members": []}
    mock_directory.tokens.return_value.list.return_value.execute.return_value = {"items": []}
    mock_dir.return_value = mock_directory

    mock_reports.side_effect = AuthError("No se pudo construir el cliente admin:reports_v1")
    # El resto de la recopilación devuelve vacío (evitamos red y paginación).
    for m in (
        mock_users,
        mock_groups,
        mock_domains,
        mock_aliases,
        mock_admins,
        mock_delegated,
        mock_oauth,
    ):
        m.return_value = []

    config = _config_de_prueba()
    data = collect_tenant_data(config, settings=None)

    assert any("reports_client" in e for e in data.errors), data.errors
    assert data.login_activities == {}
    # La auditoría sigue teniendo datos (estructura válida) pese al fallo.
    assert data.domain == "ejemplo.com"


@patch("tenant_auditor.auth.collector.get_reports_service")
@patch("tenant_auditor.auth.collector.get_directory_service")
def test_fallo_de_directory_si_propaga_error(mock_dir, mock_reports) -> None:
    """El cliente de Directory es imprescindible: si falla, debe propagarse."""
    from tenant_auditor.auth.collector import collect_tenant_data

    mock_dir.side_effect = AuthError("No se pudo construir el cliente admin:directory_v1")

    config = _config_de_prueba()
    with pytest.raises(AuthError, match="directory_v1"):
        collect_tenant_data(config, settings=None)


@patch("tenant_auditor.auth.google_client.build")
@patch("tenant_auditor.auth.google_client.service_account.Credentials.from_service_account_file")
def test_nombre_de_api_invalido_no_se_reporta_como_error_de_autenticacion(
    mock_from_file, mock_build
) -> None:
    """Regresión del bug que veían los operadores: ``UnknownApiNameOrVersion``.

    El fallo real es de discovery (nombre de API inexistente), no de
    credenciales. Antes se lanzaba ``AuthError`` y la CLI lo presentaba como
    «Error de autenticación», lo que mandaba a revisar el sitio equivocado.
    """
    from googleapiclient.errors import UnknownApiNameOrVersion

    creds = MagicMock()
    creds.with_subject.return_value = MagicMock()
    mock_from_file.return_value = creds
    mock_build.side_effect = UnknownApiNameOrVersion("name: reports  version: v1")

    with pytest.raises(ClientBuildError) as excinfo:
        get_service("reports", "v1", _config_de_prueba())

    error = excinfo.value
    assert not isinstance(error, AuthError)
    assert "reports:v1" in str(error)
    assert "discovery" in str(error)
    assert "antigua" in error.hint
    assert "tenant-auditor version" in error.hint


@patch("tenant_auditor.auth.google_client.build")
@patch("tenant_auditor.auth.google_client.service_account.Credentials.from_service_account_file")
def test_api_deshabilitada_sugiere_habilitarla(mock_from_file, mock_build) -> None:
    """Un 403 de servicio deshabilitado debe apuntar a la consola de APIs."""
    creds = MagicMock()
    creds.with_subject.return_value = MagicMock()
    mock_from_file.return_value = creds
    mock_build.side_effect = RuntimeError(
        "HttpError 403: accessNotConfigured. Admin SDK API has not been used in project"
    )

    with pytest.raises(ClientBuildError) as excinfo:
        get_directory_service(_config_de_prueba())

    assert "no está habilitada" in str(excinfo.value)
    assert "Admin SDK API" in excinfo.value.hint
