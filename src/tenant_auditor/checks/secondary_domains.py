"""Check: aliases y dominios secundarios configurados.

Riesgo: los dominios secundarios y aliases amplían el espacio de identidad y de
nombres de correo. Un dominio secundario mal gestionado (sin SPF/DKIM/DMARC,
sin supervisión) puede usarse para suplantar a la organización. Los aliases
pueden desviar correo de forma inesperada.

Referencia: CIS Google Workspace Benchmark v1.3 §8 (Domains); buenas prácticas
de correo (SPF/DKIM/DMARC).
"""

from __future__ import annotations

from tenant_auditor.models import CheckResult, Finding, Severity, TenantData

CHECK_ID = "aliases"
CHECK_NAME = "Aliases y dominios secundarios"


def run(data: TenantData, settings) -> CheckResult:  # noqa: ANN001, ARG001
    """Lista dominios secundarios y aliases, señalando los que requieren revisión."""
    findings: list[Finding] = []
    domains = data.domains or []
    secondary = [d for d in domains if not d.get("isPrimary", False)]
    aliases = data.aliases or []

    domain_evidence = [
        {
            "domainName": d.get("domainName"),
            "isPrimary": d.get("isPrimary", False),
            "verified": d.get("verified", None),
        }
        for d in domains
    ]

    if secondary:
        unverified = [d for d in secondary if d.get("verified") is False]
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name=CHECK_NAME,
                severity=Severity.HIGH if unverified else Severity.MEDIUM,
                description=(
                    f"Hay {len(secondary)} dominio(s) secundario(s) configurado(s)"
                    + (f", {len(unverified)} sin verificar." if unverified else ".")
                    + " Cada dominio secundario es una superficie de identidad que "
                    "debe mantener SPF/DKIM/DMARC y supervisión."
                ),
                evidence=domain_evidence,
                recommendation=(
                    "Verificar el propósito de cada dominio secundario. Asegurar "
                    "SPF/DKIM/DMARC en cada uno y eliminar los que ya no se usen. "
                    "Documentar cuál es el dominio canónico de la organización."
                ),
                reference="CIS Google Workspace Benchmark v1.3 §8; RFC 7489 (DMARC)",
                affected_count=len(secondary),
            )
        )

    if aliases:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name=CHECK_NAME,
                severity=Severity.LOW,
                description=(
                    f"{len(aliases)} alias de correo configurados. Los aliases "
                    "pueden desviar correo de forma no evidente y deben revisarse "
                    "periódicamente."
                ),
                evidence=aliases[:50] if isinstance(aliases[0], dict) else aliases[:50],
                recommendation=(
                    "Revisar la lista de aliases y eliminar los obsoletos. Evitar "
                    "aliases genéricos que puedan generar confusión o suplantación."
                ),
                reference="Google Workspace — Managing nicknames and domains",
                affected_count=len(aliases),
            )
        )

    if not findings:
        return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME)

    return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME, findings=findings)
