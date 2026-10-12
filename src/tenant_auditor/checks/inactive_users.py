"""Check: cuentas inactivas (sin login en más de 90 días).

Riesgo: las cuentas inactivas son deuda de seguridad. A menudo pertenecen a
ex-empleados, becarios o cuentas de servicio olvidadas, siguen licenciadas
(coste) y mantienen acceso a recursos. Son un objetivo fácil porque nadie vigila
su actividad.

Referencia: CIS Google Workspace Benchmark v1.3 §1.4 (inactive accounts);
Google — "Offboard users and remove dormant accounts".
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tenant_auditor.models import CheckResult, Finding, Severity, TenantData

CHECK_ID = "inactive"
CHECK_NAME = "Cuentas inactivas (90+ días sin login)"


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except (ValueError, TypeError):
        return None


def run(data: TenantData, settings) -> CheckResult:  # noqa: ANN001
    """Detecta usuarios que no han iniciado sesión en el periodo umbral."""
    threshold_days = getattr(settings, "inactive_days_threshold", 90)
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=threshold_days)

    affected: list[dict] = []
    for user in data.users:
        if user.get("suspended"):
            continue
        last = _parse_dt(
            user.get("lastLoginTime") or data.login_activities.get(user.get("primaryEmail", ""))
        )
        if last is None:
            # Sin datos de login: tratar como candidato a revisar.
            affected.append(
                {
                    "email": user.get("primaryEmail"),
                    "lastLoginTime": None,
                    "days_inactive": None,
                    "note": "sin datos de login",
                }
            )
            continue
        if last < cutoff:
            affected.append(
                {
                    "email": user.get("primaryEmail"),
                    "lastLoginTime": last.isoformat(),
                    "days_inactive": (now - last).days,
                }
            )

    if not affected:
        return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME)

    severity = Severity.HIGH if len(affected) > 10 else Severity.MEDIUM
    finding = Finding(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        severity=severity,
        description=(
            f"{len(affected)} cuenta(s) sin login en más de {threshold_days} días "
            "(o sin datos de actividad). Representan deuda de seguridad y coste "
            "de licencias."
        ),
        evidence=sorted(
            affected,
            key=lambda x: x["days_inactive"] if x["days_inactive"] is not None else 10**6,
            reverse=True,
        )[:50],
        recommendation=(
            "Revisar cada cuenta: si el empleado ya no está, suspenderla y luego "
            "borrarla liberando licencia (transferir datos antes). Si es una cuenta "
            "de servicio, documentarla y monitorizarla. Automatizar la detección."
        ),
        reference="CIS Google Workspace Benchmark v1.3 §1.4; proceso de offboarding",
        affected_count=len(affected),
    )
    return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME, findings=[finding])
