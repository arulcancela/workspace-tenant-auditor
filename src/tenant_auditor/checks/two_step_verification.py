"""Check: usuarios sin verificación en dos pasos (2SV).

Riesgo: las cuentas sin 2SV son el vector más explotado en compromisos de
identidad (phishing + credential stuffing). Google recomienda Enrollment
automático (2SV) para toda la organización.

Referencia: Google Workspace Security Best Practices — "Enforce 2-Step
Verification" y CIS Google Workspace Benchmark v1.3 (control 1.1).
"""

from __future__ import annotations

from tenant_auditor.models import CheckResult, Finding, Severity, TenantData

CHECK_ID = "2sv"
CHECK_NAME = "Usuarios sin verificación en dos pasos (2SV)"


def run(data: TenantData, settings) -> CheckResult:  # noqa: ANN001, ARG001
    """Detecta usuarios activos sin 2SV enrolado."""
    affected: list[dict] = []
    for user in data.users:
        if user.get("suspended"):
            continue  # las cuentas suspendidas no representan riesgo activo
        is_enrolled = user.get("isEnrolledIn2Sv", False)
        enforced = user.get("isEnforcedIn2Sv", False)
        if not is_enrolled and not enforced:
            affected.append(
                {
                    "email": user.get("primaryEmail"),
                    "lastLoginTime": user.get("lastLoginTime"),
                    "suspended": user.get("suspended", False),
                }
            )

    if not affected:
        return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME)

    severity = Severity.CRITICAL if len(affected) > 5 else Severity.HIGH
    finding = Finding(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        severity=severity,
        description=(
            f"{len(affected)} usuario(s) activo(s) no tienen la verificación en "
            "dos pasos enrolada. Un robo de credenciales daría acceso completo "
            "a su correo, Drive y cualquier app federada."
        ),
        evidence=affected[:50],  # limitamos evidencia para no inflar el informe
        recommendation=(
            "Activar 'Enrollment automático' (2SV) para toda la organización en "
            "Consola Admin > Seguridad > Autenticación > Verificación en dos pasos. "
            "Comenzar con un periodo de gracia de 7-14 días y comunicar a los usuarios."
        ),
        reference="CIS Google Workspace Benchmark v1.3 §1.1; Google 2SV Best Practices",
        affected_count=len(affected),
    )
    return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME, findings=[finding])
