"""Motor de checks de auditoría.

Exporta el registro de checks y utilidades de ejecución. Cada check es una
función pura `(TenantData) -> CheckResult` sin dependencias de red, lo que
los hace rápidos y trivialmente testeables.
"""

from tenant_auditor.checks.registry import CHECKS, run_checks

__all__ = ["CHECKS", "run_checks"]
