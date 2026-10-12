"""Check: grupos con miembros externos al dominio.

Riesgo: los grupos de distribución suelen usarse para compartir documentos,
calendarios y correo. Si un grupo incluye miembros externos, estos heredan
esos accesos y pueden ver información interna. Especialmente grave en grupos
con nombre crítico (finanzas, dirección, RRHH).

Referencia: CIS Google Workspace Benchmark v1.3 §3 (Groups); Google Best
Practices — "Restrict external group membership".
"""

from __future__ import annotations

from tenant_auditor.models import CheckResult, Finding, Severity, TenantData

CHECK_ID = "external_groups"
CHECK_NAME = "Grupos con miembros externos"

SENSITIVE_KEYWORDS = (
    "admin",
    "finance",
    "finanzas",
    "hr",
    "rrhh",
    "direct",
    "legal",
    "security",
    "secur",
    "ti",
    "it",
    "payroll",
)


def run(data: TenantData, settings) -> CheckResult:  # noqa: ANN001, ARG001
    """Identifica grupos que contienen miembros fuera del dominio."""
    domain = data.domain.lower()
    affected: list[dict] = []

    for group in data.groups:
        group_email = (group.get("email") or "").lower()
        members = group.get("_members", [])
        external = [
            m.get("email")
            for m in members
            if m.get("email") and not m.get("email", "").lower().endswith(f"@{domain}")
        ]
        if external:
            name = str(group.get("name", "")) + " " + group_email
            sensitive = any(kw in name.lower() for kw in SENSITIVE_KEYWORDS)
            affected.append(
                {
                    "group": group_email,
                    "group_name": group.get("name"),
                    "external_members": external[:20],
                    "external_count": len(external),
                    "sensitive": sensitive,
                }
            )

    if not affected:
        return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME)

    sensitive_groups = [a for a in affected if a["sensitive"]]
    if sensitive_groups:
        severity = Severity.HIGH
    elif len(affected) > 3:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW

    finding = Finding(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        severity=severity,
        description=(
            f"{len(affected)} grupo(s) incluyen miembros externos"
            + (
                f", {len(sensitive_groups)} de ellos con nombre sensible."
                if sensitive_groups
                else "."
            )
            + " Los externos heredan accesos a recursos compartidos con el grupo."
        ),
        evidence=sorted(affected, key=lambda x: x["external_count"], reverse=True)[:50],
        recommendation=(
            "Revisar la pertenencia externa de cada grupo. Para grupos sensibles, "
            "restringir la pertenencia al dominio o usar grupos con permiso de "
            "'solo dominio'. Auditar qué recursos están compartidos con esos grupos."
        ),
        reference="CIS Google Workspace Benchmark v1.3 §3; Google Groups Best Practices",
        affected_count=len(affected),
    )
    return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME, findings=[finding])
