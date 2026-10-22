"""Identificación de la build que se está ejecutando.

Motivación
==========
Un informe generado con código antiguo es indistinguible de uno generado con
el código actual si la herramienta solo muestra un número de versión fijo. Ese
fue exactamente el problema al diagnosticar el bug de ``reports:v1``: el
operador ejecutaba una copia anterior al arreglo y no había forma de saberlo
desde fuera.

Este módulo responde a las preguntas que faltaban:

- ¿Desde qué ruta se está ejecutando el paquete?
- ¿Qué commit hay detrás y hay cambios sin commitear?
- ¿Existe otra versión instalada en el entorno que pueda estar ganando?
- ¿Qué nombre de API usa el cliente de Reports en esta build?

``tenant-auditor version`` y la cabecera de ``audit`` muestran este resumen.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, distribution
from importlib.metadata import version as package_version
from pathlib import Path

from tenant_auditor import __version__
from tenant_auditor.apis import DIRECTORY_API, REPORTS_API, api_label

_DIST_NAME = "workspace-tenant-auditor"
_GIT_TIMEOUT_SECONDS = 3


@dataclass(frozen=True)
class BuildInfo:
    """Resumen de la build en ejecución."""

    version: str
    package_path: Path
    install_kind: str
    git_commit: str | None
    git_dirty: bool
    package_date: str | None
    installed_version: str | None
    directory_api: str
    reports_api: str

    @property
    def short_id(self) -> str:
        """Identificador corto para cabeceras: commit o fecha del paquete."""
        if self.git_commit:
            suffix = "-dirty" if self.git_dirty else ""
            return f"git {self.git_commit}{suffix}"
        return self.package_date or "sin identificar"

    @property
    def version_mismatch(self) -> bool:
        """True si el entorno tiene instalada otra versión del paquete."""
        return bool(self.installed_version and self.installed_version != self.version)


def _run_git(root: Path, *args: str) -> str | None:
    """Ejecuta un comando git y devuelve su salida, o None si no es posible."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def _find_git_root(start: Path) -> Path | None:
    """Sube por el árbol de directorios buscando la raíz de un repositorio git."""
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _install_kind(package_path: Path) -> str:
    """Distingue una ejecución desde el código fuente de un paquete instalado.

    Se comprueba el directorio contenedor además de ``site-packages`` porque
    instalaciones con ``--target``, ``--prefix`` o gestores tipo pipx dejan el
    paquete en rutas que no se llaman así, pero siempre con su ``*.dist-info``
    al lado.
    """
    parts = {part.lower() for part in package_path.parts}
    if "site-packages" in parts or "dist-packages" in parts:
        return "paquete instalado"
    parent = package_path.parent
    if any(parent.glob("*.dist-info")) or any(parent.glob("*.egg-info")):
        return "paquete instalado"
    return "código fuente"


def _package_date(package_path: Path) -> str | None:
    """Fecha de la copia del paquete en disco (instalación o checkout)."""
    marker = package_path / "__init__.py"
    try:
        stamp = marker.stat().st_mtime
    except OSError:
        return None
    return datetime.fromtimestamp(stamp).strftime("%Y-%m-%d %H:%M")


def _short_commit(raw: str | None) -> str | None:
    """Extrae el commit corto de un ``direct_url.json`` (PEP 610).

    Cuando el paquete se instala con ``pip install git+...`` no hay repositorio
    en disco, pero pip deja constancia de la URL y del commit exacto del que
    salió el wheel. Sin esto, una instalación desde git solo podría identificarse
    por la fecha de la copia.
    """
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    commit = (data.get("vcs_info") or {}).get("commit_id")
    if not isinstance(commit, str) or not commit:
        return None
    return commit[:7]


def _commit_from_metadata() -> str | None:
    """Commit registrado por el gestor de paquetes al instalar desde un VCS."""
    try:
        dist = distribution(_DIST_NAME)
        return _short_commit(dist.read_text("direct_url.json"))
    except (PackageNotFoundError, OSError):
        return None


def _installed_version() -> str | None:
    """Versión registrada por el gestor de paquetes, si existe."""
    try:
        return package_version(_DIST_NAME)
    except PackageNotFoundError:
        return None


@lru_cache(maxsize=1)
def build_info() -> BuildInfo:
    """Devuelve (y cachea) la información de la build en ejecución."""
    package_path = Path(__file__).resolve().parent
    git_root = _find_git_root(package_path)

    commit: str | None = None
    dirty = False
    if git_root is not None:
        commit = _run_git(git_root, "rev-parse", "--short", "HEAD")
        dirty = bool(_run_git(git_root, "status", "--porcelain", "--untracked-files=no"))
    if commit is None:
        commit = _commit_from_metadata()

    return BuildInfo(
        version=__version__,
        package_path=package_path,
        install_kind=_install_kind(package_path),
        git_commit=commit,
        git_dirty=dirty,
        package_date=_package_date(package_path),
        installed_version=_installed_version(),
        directory_api=api_label(DIRECTORY_API),
        reports_api=api_label(REPORTS_API),
    )
