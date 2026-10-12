"""Check: usuarios sin unidad organizativa asignada o mal clasificados.

Riesgo: las Unidades Organizativas (OUs) gobiernan qué políticas se aplican a
cada usuario (2SV, acceso a servicios, retención...). Un usuario en la OU raíz
hereda la configuración más permisiva y suele indicar un alta mal hecha o un
offboarding incompleto. La clasificación correcta es la base de todo el modelo
de seguridad por defecto de Workspace.

Referencia: CIS Google Workspace Benchmark v1.3 §2 (Organizational Units);
Google — "Structure your organization's users with organizational units".
"""

from __future__ import annotations

from tenant_auditor.models import CheckResult, Finding, Severity, TenantData

CHECK_ID = "ou"
CHECK_NAME = "Usuarios sin OU asignada o mal clasificados"


def run(data: TenantData, settings) -> CheckResult:  # noqa: ANN001, ARG001
    """Detecta usuarios en la OU raíz o con orgUnitPath vacío/sospechoso."""
    affected: list[dict] = []

    for user in data.users:
        ou = user.get("orgUnitPath", None)
        # orgUnitPath vacío se representa como "/" o ausente en la API.
        if ou in (None, "", "/"):
            affected.append(
                {
                    "email": user.get("primaryEmail"),
                    "orgUnitPath": ou or "/",
                    "suspended": user.get("suspended", False),
                }
            )

    if not affected:
        return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME)

    severity = Severity.MEDIUM if len(affected) > 5 else Severity.LOW
    finding = Finding(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        severity=severity,
        description=(
            f"{len(affected)} usuario(s) están en la OU raíz (o sin OU). Heredan la "
            "configuración más permisiva y probablemente no tengan las políticas "
            "adecuadas aplicadas."
        ),
        evidence=affected[:50],
        recommendation=(
            "Definir una estructura de OUs clara (p.ej. por departamento o tipo de "
            "cuenta) y mover estos usuarios a su OU correspondiente. Revisar altas "
            "recientes y procesos de offboarding. Considerar una OU por defecto para "
            "invitados y cuentas de servicio."
        ),
        reference="CIS Google Workspace Benchmark v1.3 §2; Google OU Best Practices",
        affected_count=len(affected),
    )
    return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME, findings=[finding])
