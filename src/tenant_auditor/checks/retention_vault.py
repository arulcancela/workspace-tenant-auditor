"""Check: política de retención y Vault.

Riesgo: sin una política de retención y sin Google Vault activo, la
organización puede perder evidencia, no cumplir con obligaciones legales o
regulatorias (retención de correo, retención por litigios) y no poder investigar
incidentes. Vault también es clave para eDiscovery y suspensión legal.

Referencia: CIS Google Workspace Benchmark v1.3 §9 (Vault);
requisitos comunes de cumplimiento (GDPR, HIPAA, SOX).

Nota de diseño: si la configuración de Vault no se recopiló (vacía), no
emitimos hallazgo, para no afirmar un incumplimiento sin evidencia.
"""

from __future__ import annotations

from tenant_auditor.models import CheckResult, Finding, Severity, TenantData

CHECK_ID = "vault"
CHECK_NAME = "Política de retención y Vault"


def run(data: TenantData, settings) -> CheckResult:  # noqa: ANN001, ARG001
    """Comprueba si Vault está activo y si existe una política de retención."""
    vault = data.vault_config or {}

    # Sin datos de Vault recopilados: no podemos afirmar nada. Sin hallazgo.
    if not vault or "enabled" not in vault:
        return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME)

    findings: list[Finding] = []
    enabled = vault.get("enabled", False)
    retention_policies = vault.get("retention_policies", [])
    retention_days = vault.get("retention_days")

    if not enabled:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name=CHECK_NAME,
                severity=Severity.HIGH,
                description=(
                    "Google Vault no está activo o no se detectó su configuración. "
                    "Sin Vault no hay retención garantizada, ni eDiscovery, ni "
                    "suspensión legal ante litigios o auditorías."
                ),
                evidence=[{"vault_enabled": False, "raw": vault}],
                recommendation=(
                    "Activar Google Vault (incluido en ediciones Business/Enterprise). "
                    "Definir políticas de retención por servicio (Gmail, Drive, Chat) "
                    "alineadas con las obligaciones legales de la organización."
                ),
                reference="CIS Google Workspace Benchmark v1.3 §9; requisitos de cumplimiento",
                affected_count=1,
            )
        )
    elif not retention_policies:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name=CHECK_NAME,
                severity=Severity.MEDIUM,
                description=(
                    "Vault está activo pero no se detectaron políticas de retención "
                    "configuradas. La retención por defecto puede no cumplir los "
                    "requisitos legales."
                ),
                evidence=[{"vault_enabled": True, "retention_days": retention_days}],
                recommendation=(
                    "Configurar políticas de retención explícitas en Vault para los "
                    "servicios relevantes, con plazos acordes a la normativa aplicable."
                ),
                reference="Google Vault Best Practices",
                affected_count=1,
            )
        )

    if not findings:
        return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME)

    return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME, findings=findings)
