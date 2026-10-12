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
    build_service_account_config,
    clear_client_cache,
    get_directory_service,
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
