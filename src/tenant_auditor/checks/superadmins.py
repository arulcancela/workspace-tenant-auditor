"""Check: superadministradores del tenant.

Riesgo: un número elevado de superadmins amplía la superficie de ataque. Las
guías recomiendan entre 2 y 4 superadmins, todos con 2SV obligatorio, y evitar
cuentas de servicio o de uso diario como superadmin.

Referencia: CIS Google Workspace Benchmark v1.3 §1.2; Google Best Practices
for Super Admin accounts.

Nota de diseño: si no se ha recopilado la lista de superadmins (vacía y sin
haber leído la API), no emitimos hallazgo para no generar falsos positivos.
"""

from __future__ import annotations

from tenant_auditor.models import CheckResult, Finding, Severity, TenantData

CHECK_ID = "superadmins"
CHECK_NAME = "Superadministradores del tenant"

RECOMMENDED_MIN = 2
RECOMMENDED_MAX = 4


def run(data: TenantData, settings) -> CheckResult:  # noqa: ANN001, ARG001
    """Audita el número y la postura de seguridad de los superadmins."""
    findings: list[Finding] = []
    admins: list[dict] = []

    for user in data.super_admins:
        entry = {
            "email": user.get("primaryEmail"),
            "isEnrolledIn2Sv": user.get("isEnrolledIn2Sv", False),
            "lastLoginTime": user.get("lastLoginTime"),
        }
        admins.append(entry)

    count = len(admins)

    # Sin datos recopilados: no podemos afirmar nada. Sin hallazgo.
    if count == 0:
        return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME)

    # Hallazgo 1: número de superadmins fuera de rango.
    if count > RECOMMENDED_MAX:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name=CHECK_NAME,
                severity=Severity.HIGH,
                description=(
                    f"Hay {count} superadmins (recomendado: {RECOMMENDED_MIN}-"
                    f"{RECOMMENDED_MAX}). Cada superadmin es un objetivo de máximo "
                    "valor para un atacante."
                ),
                evidence=admins,
                recommendation=(
                    "Reducir a 2-4 superadmins. Usar roles administrativos delegados "
                    "(p.ej. Administrador de Helpdesk, Administrador de Servicios) "
                    "para tareas operativas en lugar de superadmin."
                ),
                reference="CIS Google Workspace Benchmark v1.3 §1.2",
                affected_count=count,
            )
        )
    elif count < RECOMMENDED_MIN:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name=CHECK_NAME,
                severity=Severity.LOW,
                description=(
                    f"Solo hay {count} superadmin(s). Riesgo de bloqueo total si la "
                    "cuenta pierde acceso (enfermedad, baja, olvido de credenciales)."
                ),
                evidence=admins,
                recommendation=(
                    "Mantener al menos 2 superadmins para garantizar continuidad. "
                    "Usar una cuenta 'break-glass' documentada y custodiada."
                ),
                reference="Google Super Admin Best Practices",
                affected_count=count,
            )
        )

    # Hallazgo 2: superadmins sin 2SV (crítico, siempre).
    without_2sv = [a for a in admins if not a["isEnrolledIn2Sv"]]
    if without_2sv:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name=CHECK_NAME,
                severity=Severity.CRITICAL,
                description=(
                    f"{len(without_2sv)} superadmin(s) no tienen 2SV. Un superadmin "
                    "sin 2SV es el peor escenario de compromiso posible."
                ),
                evidence=without_2sv,
                recommendation=(
                    "Impedir el acceso hasta que activen 2SV. Considerar llaves de "
                    "seguridad hardware (FIDO2) para superadmins."
                ),
                reference="CIS Google Workspace Benchmark v1.3 §1.2; Google FIDO2 for admins",
                affected_count=len(without_2sv),
            )
        )

    if not findings:
        return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME)

    return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME, findings=findings)
