"""Check: delegación de dominio y acceso delegado a buzones.

Riesgo: la delegación de dominio permite que cuentas y apps externas actúen en
nombre de toda la organización. La delegación de buzón da acceso al correo de
otro usuario sin conocer su contraseña. Ambas son potentes y a menudo se
configuran una vez y se olvidan.

Referencia: CIS Google Workspace Benchmark v1.3 §1.3 (Domain Delegation);
Google Best Practices — "Review domain-wide delegation".
"""

from __future__ import annotations

from tenant_auditor.models import CheckResult, Finding, Severity, TenantData

CHECK_ID = "delegations"
CHECK_NAME = "Delegación de dominio y acceso delegado"


def run(data: TenantData, settings) -> CheckResult:  # noqa: ANN001, ARG001
    """Analiza las cuentas con acceso delegado y su alcance."""
    findings: list[Finding] = []
    delegated = data.delegated_accounts or []

    if delegated:
        # Detectar delegaciones de gran alcance o a cuentas no administradas.
        broad = [d for d in delegated if d.get("scope_count", 0) > 5 or d.get("wildcard")]
        evidence = [
            {
                "delegate": d.get("primaryEmail") or d.get("delegate"),
                "delegator": d.get("delegator"),
                "scope": d.get("scope"),
                "scope_count": d.get("scope_count", 0),
            }
            for d in delegated[:50]
        ]

        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name=CHECK_NAME,
                severity=Severity.HIGH if broad else Severity.MEDIUM,
                description=(
                    f"{len(delegated)} cuenta(s) con delegación configurada. "
                    + (
                        f"{len(broad)} tienen alcance amplio (muchos scopes o wildcard)."
                        if broad
                        else "Revisar que todas siguen siendo necesarias."
                    )
                ),
                evidence=evidence,
                recommendation=(
                    "Revisar la lista de delegaciones en Consola Admin > Seguridad > "
                    "Controles de API > Delegación de todo el dominio. Eliminar las "
                    "que no tengan caso de uso vigente y acotar los scopes al mínimo."
                ),
                reference="CIS Google Workspace Benchmark v1.3 §1.3; Google DWD review guidance",
                affected_count=len(delegated),
            )
        )

    if not findings:
        return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME)

    return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME, findings=findings)
