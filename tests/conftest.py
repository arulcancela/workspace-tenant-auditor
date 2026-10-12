"""Fixtures compartidos de pytest.

Centraliza la construcción de `TenantData` de ejemplo y de un `Settings` de
pruebas, para que los tests de checks sean concisos y deterministas.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tenant_auditor.config import Settings
from tenant_auditor.models import TenantData


def _iso(days_ago: int) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).isoformat()


@pytest.fixture
def settings() -> Settings:
    """Settings de pruebas con umbrales conocidos."""
    return Settings(
        tenant_domain="ejemplo.com",
        inactive_days_threshold=90,
        password_max_age_days=180,
        dry_run=True,
    )


@pytest.fixture
def empty_tenant() -> TenantData:
    """Tenant sin datos: todos los checks deben pasar."""
    return TenantData(domain="ejemplo.com")


@pytest.fixture
def risky_tenant() -> TenantData:
    """Tenant con problemas a propósito, para disparar los checks."""
    return TenantData(
        domain="ejemplo.com",
        users=[
            {
                "primaryEmail": "no2sv@ejemplo.com",
                "isEnrolledIn2Sv": False,
                "suspended": False,
                "lastLoginTime": _iso(2),
                "orgUnitPath": "/",
            },
            {
                "primaryEmail": "inactivo@ejemplo.com",
                "isEnrolledIn2Sv": True,
                "suspended": False,
                "lastLoginTime": _iso(200),
                "orgUnitPath": "/Ventas",
            },
            {
                "primaryEmail": "conreenvio@ejemplo.com",
                "isEnrolledIn2Sv": True,
                "suspended": False,
                "lastLoginTime": _iso(1),
                "orgUnitPath": "/Ventas",
                "forwardingAddress": "ext@otro.com",
            },
        ],
        groups=[
            {
                "email": "equipo@ejemplo.com",
                "name": "Equipo",
                "_members": [{"email": "x@externo.com"}],
            }
        ],
        domains=[
            {"domainName": "ejemplo.com", "isPrimary": True, "verified": True},
            {"domainName": "secundario.com", "isPrimary": False, "verified": False},
        ],
        super_admins=[
            {"primaryEmail": "root@ejemplo.com", "isEnrolledIn2Sv": False, "lastLoginTime": _iso(1)}
        ],
        delegated_accounts=[
            {"primaryEmail": "app@ejemplo.com", "scope_count": 10, "wildcard": True}
        ],
        drive_policies={"sharing_default": "public"},
        oauth_tokens=[
            {
                "client_id": "abc.apps.googleusercontent.com",
                "userKey": "x@ejemplo.com",
                "scopes": ["https://mail.google.com/"],
            }
        ],
        vault_config={"enabled": False},
    )
