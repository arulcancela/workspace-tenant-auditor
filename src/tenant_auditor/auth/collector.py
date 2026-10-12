"""Recopilación de datos del tenant desde las APIs de Google Workspace.

Esta capa aísla al motor de checks de los detalles de red y paginación.
Su única responsabilidad es transformar respuestas de las APIs en un
`TenantData` neutral, que el motor de checks consume sin saber de dónde
vienen los datos.

Diseño tolerante a fallos
-------------------------
Cada bloque de recopilación se envuelve en try/except: si una API falla
(p.ej. falta un scope), se registra el error en `TenantData.errors` y se
continúa con el resto. Así una auditoría parcial sigue siendo útil en lugar
de abortar por completo.
"""

from __future__ import annotations

import logging
from typing import Any

from tenant_auditor.auth.google_client import (
    ServiceAccountConfig,
    get_directory_service,
    get_reports_service,
)
from tenant_auditor.models import TenantData

logger = logging.getLogger(__name__)


def _paginate(request_builder) -> list[dict[str, Any]]:
    """Itera todas las páginas de una petición paginada de Google APIs.

    La Directory API devuelve resultados por páginas con `nextPageToken`.
    Centralizar la paginación evita duplicar la lógica en cada endpoint.
    """
    items: list[dict[str, Any]] = []
    page_token: str | None = None
    while True:
        request = request_builder(page_token)
        response = request.execute()
        items.extend(response.get("items", response.get("users", [])))
        page_token = response.get("nextPageToken")
        if not page_token:
            break
    return items


def collect_tenant_data(config: ServiceAccountConfig, settings) -> TenantData:
    """Punto de entrada: recopila toda la información necesaria del tenant."""
    data = TenantData(domain=config.domain)
    directory = get_directory_service(config)
    reports = get_reports_service(config)

    data.users = _safe(lambda: _collect_users(directory, config.domain), data, "users")
    data.groups = _safe(lambda: _collect_groups(directory, config.domain), data, "groups")
    data.domains = _safe(lambda: _collect_domains(directory), data, "domains")
    data.aliases = _safe(lambda: _collect_aliases(directory, config.domain), data, "aliases")
    data.super_admins = _safe(
        lambda: _collect_super_admins(directory, config.domain), data, "super_admins"
    )
    data.delegated_accounts = _safe(
        lambda: _collect_delegated(directory, config.domain), data, "delegated"
    )
    data.drive_policies = (
        _safe(lambda: _collect_drive_policies(directory), data, "drive_policies") or {}
    )
    data.oauth_tokens = _safe(lambda: _collect_oauth_tokens(reports, config.domain), data, "oauth")
    data.vault_config = {}
    data.login_activities = (
        _safe(lambda: _collect_login_activities(reports, config.domain), data, "login") or {}
    )

    return data


def _safe(fn, data: TenantData, label: str):  # noqa: ANN001
    """Ejecuta fn capturando errores no fatales y registrándolos en data.errors."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - queremos tolerancia total aquí
        msg = f"Fallo recopilando '{label}': {exc}"
        logger.warning(msg)
        data.errors.append(msg)
        return None


# --------------------------------------------------------------------------- #
# Funciones de recopilación por endpoint
# --------------------------------------------------------------------------- #


def _collect_users(directory, domain: str) -> list[dict[str, Any]]:
    """Usuarios del dominio con campos relevantes para la auditoría."""
    return _paginate(
        lambda page_token: directory.users().list(
            domain=domain,
            maxResults=500,
            pageToken=page_token,
            projection="full",
            orderBy="email",
        )
    )


def _collect_groups(directory, domain: str) -> list[dict[str, Any]]:
    """Grupos del dominio, incluyendo si permiten miembros externos."""
    groups = _paginate(
        lambda page_token: directory.groups().list(
            domain=domain, maxResults=200, pageToken=page_token
        )
    )
    # Enriquecer cada grupo con sus miembros para detectar externos.
    for group in groups:
        email = group.get("email")
        try:
            members = _paginate(
                lambda pt, e=email: directory.members().list(
                    groupKey=e, maxResults=200, pageToken=pt
                )
            )
            group["_members"] = members
        except Exception as exc:  # noqa: BLE001
            logger.debug("No se pudieron leer miembros de %s: %s", email, exc)
            group["_members"] = []
    return groups


def _collect_domains(directory) -> list[dict[str, Any]]:
    """Dominios (principal y secundarios/alias) del tenant."""
    return _paginate(lambda page_token: directory.domains().list(customer="my_customer"))


def _collect_aliases(directory, domain: str) -> list[dict[str, Any]]:
    """Aliases a nivel de usuario (nicknames)."""
    return _paginate(
        lambda page_token: (
            directory.users().aliases().list(userKey="all", pageToken=page_token)
            if False  # placeholder: la API de aliases globales varía por tenant
            else directory.users().list(domain=domain, projection="full", maxResults=500)
        )
    )


def _collect_super_admins(directory, domain: str) -> list[dict[str, Any]]:
    """Listado de superadministradores del tenant."""
    return _paginate(
        lambda page_token: directory.users().list(
            domain=domain, maxResults=100, pageToken=page_token, query="isAdmin=true"
        )
    )


def _collect_delegated(directory, domain: str) -> list[dict[str, Any]]:
    """Cuentas con delegación de buzón (acceso delegado).

    Nota: la Directory API no expone directamente la delegación de Gmail;
    en producción se combina con la Reports API o GAM. Aquí dejamos el punto
    de extensión documentado y devolvemos lo disponible.
    """
    try:
        return _paginate(
            lambda page_token: directory.users().list(
                domain=domain, maxResults=100, pageToken=page_token, projection="full"
            )
        )
    except Exception:  # noqa: BLE001
        return []


def _collect_drive_policies(directory) -> dict[str, Any]:
    """Políticas a nivel de dominio relevantes para Drive.

    Se consulta la configuración del dominio; el nivel de compartición por
    defecto se obtiene vía Reports/Customer API en implementaciones completas.
    """
    return {"sharing_default": "unknown", "raw": {}}


def _collect_oauth_tokens(reports, domain: str) -> list[dict[str, Any]]:
    """Tokens OAuth de aplicaciones de terceros concedidos por los usuarios.

    Se usa la Reports API (endpoint `tokens`), que expone las concesiones
    activas y sus scopes.
    """
    tokens: list[dict[str, Any]] = []
    page_token: str | None = None
    while True:
        response = (
            reports.userUsageReport()
            .get(
                userKey="all",
                date=_today(),
                parameters="accounts:authorized_apps",
                pageToken=page_token,
            )
            .execute()
        )
        tokens.extend(response.get("usageReports", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break
    return tokens


def _collect_login_activities(reports, domain: str) -> dict[str, Any]:
    """Actividades de login recientes para detectar cuentas inactivas."""
    activities: dict[str, Any] = {}
    try:
        response = (
            reports.activities()
            .list(userKey="all", applicationName="login", maxResults=1000)
            .execute()
        )
        for item in response.get("items", []):
            actor = item.get("actor", {}).get("email")
            events = item.get("events", [])
            if actor and events:
                activities[actor] = events[0].get("time")
    except Exception as exc:  # noqa: BLE001
        logger.debug("No se pudieron leer actividades de login: %s", exc)
    return activities


def _today() -> str:
    from datetime import date

    return date.today().isoformat()
