"""Check: aplicaciones OAuth de terceros con scopes peligrosos.

Riesgo: cuando un usuario autoriza una app de terceros, esta obtiene tokens
con los scopes concedidos. Si la app es maliciosa o sufre un compromiso, esos
tokens permiten leer correo, Drive, contactos... Los scopes 'amplios' (mail
completo, drive completo) y los permisos de administración son especialmente
peligrosos.

Referencia: CIS Google Workspace Benchmark v1.3 §6 (Third-party apps);
Google — "Control which apps can access user data".
"""

from __future__ import annotations

from tenant_auditor.models import CheckResult, Finding, Severity, TenantData

CHECK_ID = "oauth"
CHECK_NAME = "Aplicaciones OAuth de terceros y scopes"

# Scopes considerados de alto riesgo (acceso amplio a datos).
DANGEROUS_SCOPE_PATTERNS = {
    "https://mail.google.com/": ("Acceso total a Gmail", Severity.CRITICAL),
    "https://www.googleapis.com/auth/gmail.readonly": ("Lectura de Gmail", Severity.MEDIUM),
    "https://www.googleapis.com/auth/gmail.send": ("Envío de correo", Severity.HIGH),
    "https://www.googleapis.com/auth/drive": ("Acceso total a Drive", Severity.CRITICAL),
    "https://www.googleapis.com/auth/drive.readonly": ("Lectura de Drive", Severity.MEDIUM),
    "https://www.googleapis.com/auth/contacts": ("Acceso a contactos", Severity.MEDIUM),
    "https://www.googleapis.com/auth/admin.directory.user": (
        "Administración de usuarios",
        Severity.CRITICAL,
    ),
    "https://www.googleapis.com/auth/apps.groups.settings": (
        "Configuración de grupos",
        Severity.HIGH,
    ),
}


def _classify_scopes(scopes: list[str]) -> list[tuple[str, str, Severity]]:
    """Devuelve los scopes peligrosos encontrados con su etiqueta y severidad."""
    hits: list[tuple[str, str, Severity]] = []
    for scope in scopes:
        for pattern, (label, severity) in DANGEROUS_SCOPE_PATTERNS.items():
            if scope.startswith(pattern):
                hits.append((scope, label, severity))
    return hits


def run(data: TenantData, settings) -> CheckResult:  # noqa: ANN001, ARG001
    """Detecta apps de terceros con scopes peligrosos concedidos."""
    affected: list[dict] = []
    worst = Severity.INFO

    for token in data.oauth_tokens:
        # La Reports API anuncia los scopes en distintos campos según el tipo;
        # soportamos las variantes conocidas.
        scopes = token.get("scopes") or token.get("scope") or []
        if isinstance(scopes, str):
            scopes = scopes.split()
        client_id = token.get("client_id") or token.get("clientId") or "desconocido"
        user = token.get("userKey") or token.get("email") or "desconocido"

        hits = _classify_scopes(scopes)
        if not hits:
            continue

        worst = max([worst, *[h[2] for h in hits]], key=lambda s: s.weight)
        affected.append(
            {
                "client_id": client_id,
                "user": user,
                "dangerous_scopes": [{"scope": s, "risk": label} for s, label, _ in hits],
                "all_scope_count": len(scopes),
            }
        )

    if not affected:
        return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME)

    finding = Finding(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        severity=worst,
        description=(
            f"{len(affected)} concesión(es) OAuth incluyen scopes de alto riesgo "
            "(p.ej. acceso total a Gmail o Drive). Una app comprometida podría "
            "leer o exfiltrar datos corporativos en masa."
        ),
        evidence=affected[:50],
        recommendation=(
            "Revisar las apps en Consola Admin > Seguridad > Acceso a la API > "
            "Controles de aplicaciones. Marcar las no confiables como 'Bloqueada', "
            "limitar las de confianza y revocar tokens de apps no usadas. "
            "Evaluar 'API Control' para restringir scopes por app."
        ),
        reference="CIS Google Workspace Benchmark v1.3 §6; Google API Controls",
        affected_count=len(affected),
    )
    return CheckResult(check_id=CHECK_ID, check_name=CHECK_NAME, findings=[finding])
