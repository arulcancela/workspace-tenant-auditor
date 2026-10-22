"""Nombres canónicos de las APIs de Google Workspace que usa la herramienta.

Se centralizan aquí para que no exista una segunda fuente de verdad: el cliente
real (``auth/google_client.py``) y el diagnóstico de la build
(``diagnostics.py``) leen exactamente las mismas tuplas.

Nota importante sobre la Reports API: **no** es un servicio de discovery
independiente. No existe ``build("reports", "v1")``; se consume a través del
cliente del Admin SDK como ``build("admin", "reports_v1")``. El nombre
incorrecto provoca ``UnknownApiNameOrVersion`` (404 en el discovery).
"""

from __future__ import annotations

#: Admin SDK - Directory API (usuarios, grupos, dominios, tokens OAuth).
DIRECTORY_API: tuple[str, str] = ("admin", "directory_v1")

#: Admin SDK - Reports API (actividades de login y auditoría).
REPORTS_API: tuple[str, str] = ("admin", "reports_v1")


def api_label(api: tuple[str, str]) -> str:
    """Devuelve la etiqueta legible de una API, p.ej. ``admin:reports_v1``."""
    return f"{api[0]}:{api[1]}"
