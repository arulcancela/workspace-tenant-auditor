"""Check: compartición externa en Drive.

Riesgo: si el nivel de compartición por defecto permite compartir con
'cualquier persona con el enlace' o con dominios externos, los datos corporativos
se exponen a filtraciones y filtrado de información. La recomendación es que el
valor por defecto sea 'Restringido' y que la compartición externa sea una
excepción controlada.

Referencia: CIS Google Workspace Benchmark v1.3 §4.1 (Drive sharing settings);
Google Drive Sharing Best Practices.

Nota de diseño: si el nivel es 'unknown' (dato no recopilado), el check NO
emite hallazgo. Preferimos no reportar un riesgo que no podemos evidenciar
antes que generar un falso positivo que erosiona la confianza en el informe.
"""

from __future__ import annotations

from tenant_auditor.models import CheckResult, Finding, Severity, TenantData

CHECK_ID = "drive"
CHECK_NAME = "Compartición externa en Drive"

# Niveles ordenados de más peligroso a más seguro.
RISKY_LEVELS = {
    "public": ("Público (cualquiera con el enlace)", Severity.CRITICAL),
    "anyone": ("Público (cualquiera con el enlace)", Severity.CRITICAL),
    "external": ("Cualquiera en dominios externos", Severity.HIGH),
    "domain": ("Compartir dentro del dominio", Severity.LOW),
    "restricted": ("Restringido", Severity.INFO),
}


def run(data: TenantData, settings) -> CheckResult:  # noqa: ANN001, ARG001
    """Evalúa el nivel de compartición por defecto configurado en el tenant."""
    policy = data.drive_policies or {}
    level = str(policy.get("sharing_default", "unknown")).lower()

    # Niveles seguros o desconocidos: sin hallazgo.
    if level in {"restricted", "domain", "unknown"}:
        return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME)

    label, severity = RISKY_LEVELS.get(level, ("Desconocido", Severity.INFO))

    finding = Finding(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        severity=severity,
        description=(
            f"El nivel de compartición por defecto en Drive es '{label}'. "
            + (
                "Permitir enlaces públicos expone datos corporativos a cualquiera "
                "que obtenga el enlace."
                if severity in (Severity.CRITICAL, Severity.HIGH)
                else "Revisar si el nivel configurado responde a una política real."
            )
        ),
        evidence=[{"sharing_default": level, "raw": policy.get("raw", {})}],
        recommendation=(
            "Establecer el nivel por defecto a 'Restringido' en Consola Admin > "
            "Aplicaciones > Google Drive > Compartición. Activar alertas para "
            "comparticiones externas y permitir dominios de confianza explícitos."
        ),
        reference="CIS Google Workspace Benchmark v1.3 §4.1",
        affected_count=1,
    )
    return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME, findings=[finding])
