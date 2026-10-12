"""Registro central de checks y ejecutor.

El motor es deliberadamente simple: un diccionario `CHECKS` mapea un
identificador corto (el que el usuario pasa en `--checks`) a su función de
implementación. `run_checks()` ejecuta los checks seleccionados, cronometra
cada uno y captura errores individuales para no tumbar la auditoría entera.

Añadir un check nuevo = implementar la función + registrarla aquí. Nada más.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from tenant_auditor.checks import (
    delegations,
    drive_sharing,
    external_groups,
    inactive_users,
    oauth_apps,
    retention_vault,
    secondary_domains,
    superadmins,
    two_step_verification,
    unassigned_ou,
    weak_passwords,
)
from tenant_auditor.models import CheckResult, TenantData

logger = logging.getLogger(__name__)

# Mapa id-lógico -> (nombre legible, función de check)
CHECKS: dict[str, tuple[str, Callable[[TenantData, object], CheckResult]]] = {
    "2sv": ("Usuarios sin verificación en dos pasos (2SV)", two_step_verification.run),
    "passwords": ("Contraseñas sin cambiar en 180+ días", weak_passwords.run),
    "superadmins": ("Superadministradores del tenant", superadmins.run),
    "delegations": ("Delegación de dominio y acceso delegado", delegations.run),
    "drive": ("Compartición externa en Drive", drive_sharing.run),
    "external_groups": ("Grupos con miembros externos", external_groups.run),
    "oauth": ("Aplicaciones OAuth de terceros y scopes", oauth_apps.run),
    "forwarding": ("Reenvío automático de correo", weak_passwords.run_forwarding),
    "aliases": ("Aliases y dominios secundarios", secondary_domains.run),
    "vault": ("Política de retención y Vault", retention_vault.run),
    "inactive": ("Cuentas inactivas (90+ días sin login)", inactive_users.run),
    "ou": ("Usuarios sin OU asignada o mal clasificados", unassigned_ou.run),
}


def available_check_ids() -> list[str]:
    """Lista de identificadores de checks disponibles."""
    return sorted(CHECKS.keys())


def resolve_check_ids(raw: str | None) -> list[str]:
    """Resuelve la selección de checks a partir del argumento `--checks`.

    Acepta una lista separada por comas. Si es None o 'all', devuelve todos.
    Valida los identificadores desconocidos con un error claro.
    """
    if not raw or raw.strip().lower() == "all":
        return available_check_ids()

    requested = [c.strip().lower() for c in raw.split(",") if c.strip()]
    unknown = [c for c in requested if c not in CHECKS]
    if unknown:
        raise ValueError(
            f"Checks desconocidos: {', '.join(unknown)}. "
            f"Disponibles: {', '.join(available_check_ids())}"
        )
    return requested


def run_checks(data: TenantData, check_ids: list[str], settings) -> list[CheckResult]:  # noqa: ANN001
    """Ejecuta los checks indicados y devuelve sus resultados.

    Cada check se cronometra y sus excepciones se aíslan en su propio
    CheckResult, de modo que un check roto no impide ver los demás.
    """
    results: list[CheckResult] = []
    for check_id in check_ids:
        name, fn = CHECKS[check_id]
        start = time.perf_counter()
        try:
            result = fn(data, settings)
            result.check_id = check_id
            result.check_name = name
            logger.info("Check '%s' completado: %d hallazgos", check_id, len(result.findings))
        except Exception as exc:  # noqa: BLE001
            logger.error("Check '%s' falló: %s", check_id, exc)
            result = CheckResult(check_id=check_id, check_name=name, executed=False, error=str(exc))
        result.duration_ms = round((time.perf_counter() - start) * 1000, 2)
        results.append(result)
    return results
