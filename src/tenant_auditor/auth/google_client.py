"""Construcción de clientes autenticados para las APIs de Google Workspace.

Estrategia de autenticación
===========================
Se usa una **Service Account** con **Domain-Wide Delegation (DWD)**. Este
patrón es el estándar enterprise para automatización sin interacción humana:

1. Una Service Account de Google Cloud actúa como identidad de máquina.
2. El superadmin del tenant autoriza los *scopes* de esa Service Account en
   la Consola de Admin (Seguridad > Controles de la API > Delegación de todo
   el dominio).
3. El código *suplanta* (impersona) a un usuario del tenant (idealmente un
   superadmin de solo lectura o una cuenta dedicada de auditoría) mediante
   `with_subject()`. Así las llamadas quedan registradas como hechas por ese
   usuario y respetan los permisos del tenant.

No se guardan secretos en el código: solo se lee la ruta al JSON desde
configuración. Ver SECURITY.md para el detalle operativo y de mínimo privilegio.
"""

from __future__ import annotations

import logging

from google.oauth2 import service_account
from googleapiclient.discovery import build

from tenant_auditor.config import Settings
from tenant_auditor.models import ServiceAccountConfig

logger = logging.getLogger(__name__)

# Cache de clientes por scope+subject para no reconstruir en cada llamada.
_CLIENT_CACHE: dict[tuple[str, str], object] = {}


class AuthError(RuntimeError):
    """Error controlado durante la construcción de credenciales."""


def build_service_account_config(settings: Settings) -> ServiceAccountConfig:
    """Construye y valida la configuración de la Service Account.

    Falla pronto (fail-fast) si faltan datos imprescindibles, con mensajes
    accionables para el operador.
    """
    if not settings.google_application_credentials:
        raise AuthError(
            "Falta GOOGLE_APPLICATION_CREDENTIALS. Copia .env.example a .env "
            "y apunta a la ruta del JSON de la Service Account."
        )
    if not settings.delegated_admin_email:
        raise AuthError(
            "Falta DELEGATED_ADMIN_EMAIL. Debe ser un superadmin del tenant "
            "que la Service Account suplantará."
        )
    if not settings.scopes_list:
        raise AuthError("No hay scopes configurados en GOOGLE_SCOPES.")

    return ServiceAccountConfig(
        credentials_path=settings.google_application_credentials,
        delegated_admin_email=settings.delegated_admin_email,
        scopes=settings.scopes_list,
        domain=settings.tenant_domain,
    )


def _get_credentials(config: ServiceAccountConfig):
    """Crea credenciales con DWD (impersonación del usuario delegado)."""
    try:
        creds = service_account.Credentials.from_service_account_file(
            config.credentials_path, scopes=config.scopes
        )
    except FileNotFoundError as exc:
        raise AuthError(
            f"No se encontró el fichero de credenciales: {config.credentials_path}"
        ) from exc
    except Exception as exc:  # noqa: BLE001 - se reempaqueta como AuthError
        raise AuthError(f"Credenciales de Service Account inválidas: {exc}") from exc

    # Domain-Wide Delegation: suplantamos al usuario delegado del tenant.
    delegated = creds.with_subject(config.delegated_admin_email)
    return delegated


def get_service(api: str, version: str, config: ServiceAccountConfig):
    """Devuelve un cliente autenticado y cacheado para la API solicitada.

    Args:
        api: Nombre de la API, p.ej. "admin" o "reports".
        version: Versión de la API, p.ej. "directory_v1" o "v1".
        config: Configuración de la Service Account.
    """
    cache_key = (f"{api}:{version}", config.delegated_admin_email)
    if cache_key in _CLIENT_CACHE:
        return _CLIENT_CACHE[cache_key]

    credentials = _get_credentials(config)
    try:
        service = build(api, version, credentials=credentials, cache_discovery=False)
    except Exception as exc:  # noqa: BLE001
        raise AuthError(f"No se pudo construir el cliente {api}:{version}: {exc}") from exc

    _CLIENT_CACHE[cache_key] = service
    logger.debug("Cliente %s:%s construido y cacheado", api, version)
    return service


def get_directory_service(config: ServiceAccountConfig):
    """Cliente de la Directory API (Admin SDK)."""
    return get_service("admin", "directory_v1", config)


def get_reports_service(config: ServiceAccountConfig):
    """Cliente de la Reports API (actividades de login, tokens OAuth)."""
    return get_service("reports", "v1", config)


def clear_client_cache() -> None:
    """Limpia la caché de clientes. Útil en tests."""
    _CLIENT_CACHE.clear()
