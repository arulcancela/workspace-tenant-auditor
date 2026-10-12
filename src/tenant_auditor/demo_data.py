"""Carga de datos de demostración para el modo `--dry-run`.

Permite que cualquiera pruebe la herramienta sin credenciales reales ni acceso
a un tenant. Los datos se cargan desde `examples/demo_data/tenant_sample.json`
si existe; en su caso, se usa un generador programático equivalente como
respaldo para que el modo demo nunca falle.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tenant_auditor.models import TenantData

logger = logging.getLogger(__name__)

# Buscamos el fixture relativo al repo (no al paquete instalado).
_DEMO_PATHS = [
    Path(__file__).resolve().parents[2] / "examples" / "demo_data" / "tenant_sample.json",
    Path.cwd() / "examples" / "demo_data" / "tenant_sample.json",
]


def load_demo_data(domain: str = "ejemplo.com") -> TenantData:
    """Devuelve un TenantData de ejemplo, listo para ejecutar todos los checks."""
    for path in _DEMO_PATHS:
        if path.exists():
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                raw["domain"] = domain
                logger.debug("Datos demo cargados desde %s", path)
                return TenantData(**raw)
            except Exception as exc:  # noqa: BLE001
                logger.warning("No se pudo cargar %s (%s); usando generador interno.", path, exc)

    return _generate_demo_data(domain)


def _generate_demo_data(domain: str) -> TenantData:
    """Genera un conjunto de datos demo realista de forma programática."""
    now = datetime.now(UTC)

    def iso(days_ago: int) -> str:
        return (now - timedelta(days=days_ago)).isoformat()

    users = [
        # Sin 2SV, activo -> hallazgo crítico
        {
            "primaryEmail": f"becario@{domain}",
            "isEnrolledIn2Sv": False,
            "isEnforcedIn2Sv": False,
            "suspended": False,
            "lastLoginTime": iso(2),
            "orgUnitPath": "/Becarios",
            "passwordLastChanged": iso(200),
        },
        # Inactivo 150 días -> hallazgo
        {
            "primaryEmail": f"antiguo.empleado@{domain}",
            "isEnrolledIn2Sv": False,
            "suspended": False,
            "lastLoginTime": iso(150),
            "orgUnitPath": "/",
        },
        # Contraseña obsoleta
        {
            "primaryEmail": f"contabilidad@{domain}",
            "isEnrolledIn2Sv": True,
            "suspended": False,
            "lastLoginTime": iso(1),
            "orgUnitPath": "/Finanzas",
            "passwordLastChanged": iso(400),
        },
        # Con reenvío externo -> hallazgo
        {
            "primaryEmail": f"ventas@{domain}",
            "isEnrolledIn2Sv": True,
            "suspended": False,
            "lastLoginTime": iso(3),
            "orgUnitPath": "/Ventas",
            "forwardingAddress": "externo@competidor.com",
        },
        # Usuario sano
        {
            "primaryEmail": f"cto@{domain}",
            "isEnrolledIn2Sv": True,
            "isEnforcedIn2Sv": True,
            "suspended": False,
            "lastLoginTime": iso(0),
            "orgUnitPath": "/Direccion",
            "passwordLastChanged": iso(30),
        },
        # Superadmin sin 2SV -> crítico
        {
            "primaryEmail": f"superadmin1@{domain}",
            "isEnrolledIn2Sv": False,
            "isEnforcedIn2Sv": False,
            "suspended": False,
            "lastLoginTime": iso(1),
            "orgUnitPath": "/Direccion",
        },
    ]

    groups = [
        {
            "email": f"todos@{domain}",
            "name": "Todos",
            "_members": [
                {"email": f"cto@{domain}"},
                {"email": f"ventas@{domain}"},
                {"email": "contacto@proveedor-externo.com"},  # externo
            ],
        },
        {
            "email": f"finanzas@{domain}",
            "name": "Finanzas",
            "_members": [
                {"email": f"contabilidad@{domain}"},
                {"email": "auditor@consultora-externa.com"},  # externo en grupo sensible
            ],
        },
    ]

    domains = [
        {"domainName": domain, "isPrimary": True, "verified": True},
        {"domainName": "marca-alternativa.com", "isPrimary": False, "verified": False},
    ]

    super_admins = [
        {
            "primaryEmail": f"superadmin1@{domain}",
            "isEnrolledIn2Sv": False,
            "lastLoginTime": iso(1),
        },
        {"primaryEmail": f"cto@{domain}", "isEnrolledIn2Sv": True, "lastLoginTime": iso(0)},
    ]

    delegated_accounts = [
        {"primaryEmail": f"helpdesk@{domain}", "scope": "gmail.readonly", "scope_count": 2},
        {
            "primaryEmail": f"integracion@{domain}",
            "scope": "*",
            "scope_count": 12,
            "wildcard": True,
        },
    ]

    drive_policies = {"sharing_default": "public", "raw": {"allowExternalSharing": True}}

    oauth_tokens = [
        {
            "client_id": "1234567890.apps.googleusercontent.com",
            "userKey": f"ventas@{domain}",
            "scopes": ["https://mail.google.com/", "https://www.googleapis.com/auth/drive"],
        },
        {
            "client_id": "99887766.apps.googleusercontent.com",
            "userKey": f"contabilidad@{domain}",
            "scopes": ["https://www.googleapis.com/auth/drive.readonly"],
        },
    ]

    aliases = [
        {"primaryEmail": f"info@{domain}", "alias": f"ventas@{domain}"},
    ]

    vault_config = {"enabled": True, "retention_policies": [], "retention_days": None}

    login_activities = {f"ventas@{domain}": iso(3)}

    return TenantData(
        domain=domain,
        users=users,
        groups=groups,
        domains=domains,
        super_admins=super_admins,
        delegated_accounts=delegated_accounts,
        drive_policies=drive_policies,
        oauth_tokens=oauth_tokens,
        aliases=aliases,
        vault_config=vault_config,
        login_activities=login_activities,
    )
