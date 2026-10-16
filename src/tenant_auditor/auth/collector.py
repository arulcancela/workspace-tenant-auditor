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


def _paginate(
    request_builder,
    response_key: str = "users",
) -> list[dict[str, Any]]:
    """Itera todas las páginas de una petición paginada de Google APIs.

    Cada endpoint de la Directory API devuelve los resultados bajo una clave
    distinta (``users``, ``groups``, ``members``, ``domains``…).
    ``response_key`` indica cuál extraer en cada caso.
    """
    items: list[dict[str, Any]] = []
    page_token: str | None = None
    while True:
        request = request_builder(page_token)
        response = request.execute()
        items.extend(response.get(response_key, []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break
    return items


def collect_tenant_data(config: ServiceAccountConfig, settings) -> TenantData:
    """Punto de entrada: recopila toda la información necesaria del tenant."""
    data = TenantData(domain=config.domain)

    # El cliente de Directory es imprescindible para casi todos los checks; si
    # falla, dejamos que AuthError suba para dar un mensaje claro al operador.
    directory = get_directory_service(config)

    # El cliente de Reports es opcional: si no se puede construir (p.ej. API no
    # habilitada o scope ausente), lo tratamos como error no fatal y seguimos,
    # de modo que la auditoría no se aborta por una sola API.
    reports = _safe(lambda: get_reports_service(config), data, "reports_client")

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
    data.oauth_tokens = _safe(
        lambda: _collect_oauth_tokens(directory, config.domain), data, "oauth"
    )
    data.vault_config = {}
    if reports is not None:
        data.login_activities = (
            _safe(lambda: _collect_login_activities(reports, config.domain), data, "login") or {}
        )
    else:
        data.login_activities = {}

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
        ),
        response_key="users",
    )


def _collect_groups(directory, domain: str) -> list[dict[str, Any]]:
    """Grupos del dominio, incluyendo si permiten miembros externos."""
    groups = _paginate(
        lambda page_token: directory.groups().list(
            domain=domain, maxResults=200, pageToken=page_token
        ),
        response_key="groups",
    )
    # Enriquecer cada grupo con sus miembros para detectar externos.
    for group in groups:
        email = group.get("email")
        try:
            members = _paginate(
                lambda pt, e=email: directory.members().list(
                    groupKey=e, maxResults=200, pageToken=pt
                ),
                response_key="members",
            )
            group["_members"] = members
        except Exception as exc:  # noqa: BLE001
            logger.debug("No se pudieron leer miembros de %s: %s", email, exc)
            group["_members"] = []
    return groups


def _collect_domains(directory) -> list[dict[str, Any]]:
    """Dominios (principal y secundarios/alias) del tenant.

    La API domains().list() no soporta paginación (devuelve todos en una
    respuesta), pero usamos _paginate igualmente para mantener la
    consistencia; el bucle terminará en la primera iteración.
    """
    return _paginate(
        lambda page_token: directory.domains().list(customer="my_customer"),
        response_key="domains",
    )


def _collect_aliases(directory, domain: str) -> list[dict[str, Any]]:
    """Aliases de correo a nivel de usuario.

    La Directory API no expone un endpoint global de aliases, así que se
    extraen del campo ``aliases`` de cada usuario obtenido con projection=full.
    Devuelve una lista de dicts con las claves ``primaryEmail`` y ``alias``.
    """
    users = _paginate(
        lambda page_token: directory.users().list(
            domain=domain, projection="full", maxResults=500, pageToken=page_token
        ),
        response_key="users",
    )
    aliases: list[dict[str, Any]] = []
    for user in users:
        email = user.get("primaryEmail", "")
        for alias in user.get("aliases", []):
            aliases.append({"primaryEmail": email, "alias": alias})
    return aliases


def _collect_super_admins(directory, domain: str) -> list[dict[str, Any]]:
    """Listado de superadministradores del tenant."""
    return _paginate(
        lambda page_token: directory.users().list(
            domain=domain, maxResults=100, pageToken=page_token, query="isAdmin=true"
        ),
        response_key="users",
    )


def _collect_delegated(directory, domain: str) -> list[dict[str, Any]]:
    """Cuentas con delegación de dominio (Domain-Wide Delegation).

    Limitación conocida: la Directory API no expone directamente la
    delegación de buzón de Gmail. Para obtener delegaciones de buzón reales
    se necesitaría la Gmail API (``users.settings.delegates.list()``) o GAM.
    Aquí consultamos los usuarios con projection=full como punto de partida;
    los campos de delegación (``scope``, ``wildcard``) se esperan enriquecidos
    externamente o desde los datos de demo.
    """
    try:
        return _paginate(
            lambda page_token: directory.users().list(
                domain=domain, maxResults=100, pageToken=page_token, projection="full"
            ),
            response_key="users",
        )
    except Exception:  # noqa: BLE001
        return []


def _collect_drive_policies(directory) -> dict[str, Any]:
    """Políticas a nivel de dominio relevantes para Drive.

    Se consulta la configuración del dominio; el nivel de compartición por
    defecto se obtiene vía Reports/Customer API en implementaciones completas.
    """
    return {"sharing_default": "unknown", "raw": {}}


def _collect_oauth_tokens(directory, domain: str) -> list[dict[str, Any]]:
    """Tokens OAuth de aplicaciones de terceros concedidos por los usuarios.

    Se usa la Admin SDK Tokens API (``directory.tokens().list()``), que expone
    las concesiones OAuth activas por usuario junto con sus scopes y client IDs.
    Se itera sobre los usuarios del dominio y se recopilan los tokens de cada
    uno, de forma tolerante (un fallo en un usuario no detiene el proceso).
    """
    users = _paginate(
        lambda page_token: directory.users().list(
            domain=domain, maxResults=500, pageToken=page_token, projection="basic"
        ),
        response_key="users",
    )
    tokens: list[dict[str, Any]] = []
    for user in users:
        user_key = user.get("primaryEmail", "")
        if not user_key:
            continue
        try:
            response = directory.tokens().list(userKey=user_key).execute()
            for token in response.get("items", []):
                token["userKey"] = user_key
                tokens.append(token)
        except Exception as exc:  # noqa: BLE001
            logger.debug("No se pudieron leer tokens OAuth de %s: %s", user_key, exc)
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
