"""Modelos de datos del auditor.

Define las estructuras centrales que circulan por todo el pipeline:

    ServiceAccountConfig -> TenantData (recopilado) -> Finding (check)
        -> AuditReport (agregado) -> informe HTML/PDF/JSON

Se utiliza Pydantic v2 por su validación en tiempo de ejecución, serialización
robusta y tipado estricto, lo que hace el motor de checks testeable y
predecible.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Niveles de severidad de un hallazgo, ordenados de mayor a menor impacto."""

    CRITICAL = "critica"
    HIGH = "alta"
    MEDIUM = "media"
    LOW = "baja"
    INFO = "informativa"

    @property
    def weight(self) -> int:
        """Peso numérico para ordenar/priorizar hallazgos."""
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]

    @property
    def color(self) -> str:
        """Color asociado para la representación visual en el informe."""
        return {
            Severity.CRITICAL: "#b71c1c",
            Severity.HIGH: "#e65100",
            Severity.MEDIUM: "#f9a825",
            Severity.LOW: "#2e7d32",
            Severity.INFO: "#1565c0",
        }[self]


class Finding(BaseModel):
    """Un hallazgo individual producido por un check.

    Cada hallazgo es autocontenido: incluye su identificador, la severidad, una
    descripción legible, evidencia cruda verificable, una recomendación
    accionable y la referencia a la buena práctica que lo respalda.
    """

    check_id: str = Field(..., description="Identificador único del check, ej. '2sv'.")
    check_name: str = Field(..., description="Nombre legible del check.")
    severity: Severity = Field(..., description="Severidad del hallazgo.")
    description: str = Field(..., description="Descripción del riesgo encontrado.")
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Evidencia cruda minimal (datos de soporte del hallazgo).",
    )
    recommendation: str = Field(..., description="Acción correctiva recomendada.")
    reference: str = Field(..., description="Referencia a buena práctica o documentación.")
    affected_count: int = Field(
        default=0, description="Número de elementos afectados por el hallazgo."
    )
    compliant: bool = Field(
        default=False,
        description="True si el check pasó sin hallazgos (cumple la política).",
    )


class CheckResult(BaseModel):
    """Resultado de ejecutar un único check sobre los datos del tenant.

    Un check puede producir cero, uno o varios hallazgos. Además se registra
    el tiempo de ejecución y si hubo error (para informar al usuario sin
    abortar la auditoría completa).
    """

    check_id: str
    check_name: str
    findings: list[Finding] = Field(default_factory=list)
    executed: bool = True
    error: str | None = None
    duration_ms: float = 0.0


class TenantData(BaseModel):
    """Instantánea de los datos recopilados del tenant.

    Es el contrato entre la capa de recopilación (auth/) y el motor de
    checks (checks/). Modelar los datos de forma explícita permite:
      - Testear los checks sin red (inyectando TenantData de ejemplo).
      - Ejecutar el modo --dry-run con un fixture.
      - Cargar/guardar instantáneas para auditorías offline.
    """

    domain: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    users: list[dict[str, Any]] = Field(default_factory=list)
    groups: list[dict[str, Any]] = Field(default_factory=list)
    domains: list[dict[str, Any]] = Field(default_factory=list)
    super_admins: list[dict[str, Any]] = Field(default_factory=list)
    delegated_accounts: list[dict[str, Any]] = Field(default_factory=list)
    drive_policies: dict[str, Any] = Field(default_factory=dict)
    oauth_tokens: list[dict[str, Any]] = Field(default_factory=list)
    aliases: list[dict[str, Any]] = Field(default_factory=list)
    vault_config: dict[str, Any] = Field(default_factory=dict)
    login_activities: dict[str, Any] = Field(default_factory=dict)

    errors: list[str] = Field(default_factory=list)


class AuditReport(BaseModel):
    """Informe agregado final, listo para renderizar."""

    domain: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tool_version: str
    mode: str = Field(default="live", description="live | dry-run")

    results: list[CheckResult] = Field(default_factory=list)
    execution_errors: list[str] = Field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        """Todos los hallazgos no conformes, aplanados."""
        return [f for r in self.results for f in r.findings if not f.compliant]

    @property
    def total_checks(self) -> int:
        return len(self.results)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def counts_by_severity(self) -> dict[str, int]:
        """Conteo de hallazgos por severidad, para el resumen ejecutivo."""
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def overall_score(self) -> int:
        """Puntuación de postura de seguridad 0-100.

        Heurística simple y transparente: se parte de 100 y se resta un peso
        por cada hallazgo según su severidad. El objetivo es dar una señal
        ejecutiva, no una métrica de certificación.
        """
        penalty = {
            Severity.CRITICAL: 15,
            Severity.HIGH: 8,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        score = 100 - sum(penalty[f.severity] for f in self.findings)
        return max(0, score)


class ServiceAccountConfig(BaseModel):
    """Configuración de autenticación resuelta para la Service Account."""

    credentials_path: str
    delegated_admin_email: str
    scopes: list[str]
    domain: str
