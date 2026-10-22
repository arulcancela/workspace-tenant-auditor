"""Tests del diagnóstico de build (qué código y qué APIs se ejecutan)."""

from __future__ import annotations

import json
from pathlib import Path

from tenant_auditor.diagnostics import BuildInfo, _short_commit, build_info


def test_build_info_declara_las_apis_reales() -> None:
    """El diagnóstico debe reflejar el nombre correcto de la Reports API."""
    info = build_info()
    assert info.reports_api == "admin:reports_v1"
    assert info.directory_api == "admin:directory_v1"


def test_build_info_apunta_al_paquete_en_ejecucion() -> None:
    info = build_info()
    assert info.package_path.is_dir()
    assert info.package_path.name == "tenant_auditor"
    assert (info.package_path / "auth" / "google_client.py").is_file()


def test_short_id_nunca_queda_vacio() -> None:
    """La cabecera siempre debe poder identificar la build."""
    assert build_info().short_id


def test_version_mismatch_detecta_instalacion_distinta() -> None:
    info = BuildInfo(
        version="1.1.0",
        package_path=Path("/tmp/tenant_auditor"),
        install_kind="código fuente",
        git_commit="abc1234",
        git_dirty=False,
        package_date="2026-10-22 10:00",
        installed_version="1.0.0",
        directory_api="admin:directory_v1",
        reports_api="admin:reports_v1",
    )
    assert info.version_mismatch is True
    assert info.short_id == "git abc1234"


def test_version_mismatch_falso_si_coincide_o_no_hay_instalacion() -> None:
    base = {
        "package_path": Path("/tmp/tenant_auditor"),
        "install_kind": "código fuente",
        "git_commit": None,
        "git_dirty": False,
        "package_date": "2026-10-22 10:00",
        "directory_api": "admin:directory_v1",
        "reports_api": "admin:reports_v1",
    }
    assert BuildInfo(version="1.1.0", installed_version="1.1.0", **base).version_mismatch is False
    assert BuildInfo(version="1.1.0", installed_version=None, **base).version_mismatch is False


def test_short_commit_lee_el_direct_url_de_pip() -> None:
    """Una instalación con ``pip install git+...`` no tiene .git, solo metadatos."""
    raw = json.dumps(
        {
            "url": "https://github.com/arulcancela/workspace-tenant-auditor.git",
            "vcs_info": {
                "vcs": "git",
                "commit_id": "f5f0c60abc123",
                "requested_revision": "v1.1.0",
            },
        }
    )
    assert _short_commit(raw) == "f5f0c60"


def test_short_commit_tolera_metadatos_ausentes_o_no_vcs() -> None:
    assert _short_commit(None) is None
    assert _short_commit("no es json") is None
    assert (
        _short_commit(json.dumps({"url": "file:///tmp/x", "dir_info": {"editable": True}})) is None
    )
    assert _short_commit(json.dumps({"vcs_info": {"commit_id": ""}})) is None
