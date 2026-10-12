"""Checks: contraseñas obsoletas y reenvío automático de correo.

Dos riesgos relacionados con la gestión de credenciales y la fuga de correo:

1. **Contraseña sin cambiar en más de N días**: indicador indirecto de
   credenciales antiguas/posiblemente compartidas. Referencia: buenas prácticas
   de rotación y CIS §1.
2. **Reenvío automático activo**: un atacante (o un usuario que se va) puede
   configurar un reenvío para exfiltrar correo de forma persistente.

Referencia: Google Workspace Security Best Practices; MITRE ATT&CK T1114.003
(Email Forwarding Rule).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tenant_auditor.models import CheckResult, Finding, Severity, TenantData

CHECK_ID = "passwords"
CHECK_NAME = "Contraseñas sin cambiar en 180+ días"
CHECK_ID_FWD = "forwarding"
CHECK_NAME_FWD = "Reenvío automático de correo activado"


def _parse_dt(value: str | None) -> datetime | None:
    """Parsea fechas de Google (ISO 8601 con 'Z') a datetime UTC-aware."""
    if not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except (ValueError, TypeError):
        return None


def run(data: TenantData, settings) -> CheckResult:  # noqa: ANN001
    """Detecta contraseñas cuyo último cambio supera el umbral configurado."""
    max_age = getattr(settings, "password_max_age_days", 180)
    now = datetime.now(UTC)
    threshold = now - timedelta(days=max_age)

    affected: list[dict] = []
    for user in data.users:
        if user.get("suspended"):
            continue
        # Campo real de cambio de contraseña proviene de la Reports API / GAM;
        # usamos lastLoginTime como aproximación documentada si no está disponible.
        pwd_changed = _parse_dt(user.get("passwordLastChanged") or user.get("lastLoginTime"))
        if pwd_changed is None:
            continue
        if pwd_changed < threshold:
            affected.append(
                {
                    "email": user.get("primaryEmail"),
                    "passwordLastChanged": pwd_changed.isoformat(),
                    "days_since_change": (now - pwd_changed).days,
                }
            )

    if not affected:
        return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME)

    finding = Finding(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        severity=Severity.MEDIUM,
        description=(
            f"{len(affected)} usuario(s) no han cambiado su contraseña en más de "
            f"{max_age} días. Contraseñas longevas amplían la ventana de exposición "
            "si se filtran."
        ),
        evidence=sorted(affected, key=lambda x: x["days_since_change"], reverse=True)[:50],
        recommendation=(
            "Forzar cambio de contraseña para los afectados y, a largo plazo, "
            "priorizar 2SV/FIDO2 sobre rotaciones periódicas. Revisar la política "
            "de caducidad de contraseñas del tenant."
        ),
        reference="NIST SP 800-63B; CIS Google Workspace Benchmark",
        affected_count=len(affected),
    )
    return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME, findings=[finding])


def run_forwarding(data: TenantData, settings) -> CheckResult:  # noqa: ANN001, ARG001
    """Detecta usuarios con reenvío automático de correo configurado."""
    affected: list[dict] = []
    for user in data.users:
        forwarding = user.get("forwardingAddress") or user.get("autoForwarding")
        if not forwarding:
            continue
        # autoForwarding puede ser un dict (Gmail API) o string (campo simple)
        if isinstance(forwarding, dict):
            enabled = forwarding.get("enabled")
            address = forwarding.get("emailAddress")
        else:
            enabled = True
            address = str(forwarding)
        if enabled and address:
            affected.append(
                {
                    "email": user.get("primaryEmail"),
                    "forwarding_to": address,
                    "external": not address.endswith(f"@{data.domain}") if data.domain else True,
                }
            )

    if not affected:
        return CheckResult(check_id=CHECK_ID_FWD, check_name=CHECK_NAME_FWD)

    external = [a for a in affected if a["external"]]
    severity = Severity.HIGH if external else Severity.MEDIUM
    finding = Finding(
        check_id=CHECK_ID_FWD,
        check_name=CHECK_NAME_FWD,
        severity=severity,
        description=(
            f"{len(affected)} usuario(s) con reenvío automático activo"
            + (f", de los cuales {len(external)} reenvían fuera del dominio." if external else ".")
            + " Un reenvío externo puede exfiltrar correo de forma persistente."
        ),
        evidence=affected[:50],
        recommendation=(
            "Revisar cada reenvío y desactivar los que no sean de negocio. "
            "Bloquear reenvío automático a dominios externos salvo excepción "
            "aprobada (Consola Admin > Gmail > Reenvío)."
        ),
        reference="MITRE ATT&CK T1114.003; CIS Google Workspace Benchmark §5",
        affected_count=len(affected),
    )
    return CheckResult(check_id=CHECK_ID_FWD, check_name=CHECK_NAME_FWD, findings=[finding])
