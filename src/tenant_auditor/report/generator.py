"""Generación del informe ejecutivo en HTML, PDF y JSON.

Flujo:
    AuditReport (modelo) -> Jinja2 (HTML autónomo) -> WeasyPrint (PDF)
                                   \\-> JSON (consumo programático)

Decisiones:
  - **HTML con CSS embebido**: un único fichero HTML autocontenido, sin CDN
    obligatorio, para que funcione offline y sea portable (se puede enviar por
    correo). Chart.js se embebe de forma opcional; si no hay red se muestra
    igualmente la tabla y la gráfica de barras en CSS (que sí sale en el PDF).
  - **WeasyPrint** en lugar de navegador headless: es puro Python, sin Chrome,
    cabe en Docker y da PDFs reproducibles. Limitación: no ejecuta JS, así que
    las gráficas del PDF usan CSS, no Chart.js.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from tenant_auditor.models import AuditReport, Severity

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    """Genera los informes a partir de un AuditReport."""

    def __init__(self, template_dir: Path | None = None) -> None:
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir or TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.env.globals["Severity"] = Severity
        self.env.filters["fmt_dt"] = self._fmt_dt

    @staticmethod
    def _fmt_dt(value: datetime) -> str:
        return value.strftime("%Y-%m-%d %H:%M UTC") if value else "—"

    # ------------------------------------------------------------------ #
    # Render
    # ------------------------------------------------------------------ #
    def render_html(self, report: AuditReport) -> str:
        """Renderiza el informe HTML completo."""
        template = self.env.get_template("report.html.j2")
        return template.render(
            report=report,
            findings_by_severity=self._group_by_severity(report),
            counts=report.counts_by_severity(),
            score=report.overall_score(),
            generated_at=datetime.now(UTC),
        )

    def render_json(self, report: AuditReport) -> str:
        """Serializa el informe a JSON (incluye evidencia y metadatos)."""
        return report.model_dump_json(indent=2)

    def write_all(self, report: AuditReport, output_dir: str, formats: list[str]) -> dict[str, str]:
        """Escribe todos los formatos solicitados y devuelve las rutas generadas."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        stem = f"audit_{report.domain}_{report.generated_at.strftime('%Y%m%d_%H%M%S')}"
        written: dict[str, str] = {}

        if "html" in formats:
            html_path = out / f"{stem}.html"
            html_path.write_text(self.render_html(report), encoding="utf-8")
            written["html"] = str(html_path)
            logger.info("Informe HTML escrito en %s", html_path)

            if "pdf" in formats:
                pdf_path = self._write_pdf(str(html_path), out / f"{stem}.pdf")
                if pdf_path:
                    written["pdf"] = pdf_path

        if "json" in formats:
            json_path = out / f"{stem}.json"
            json_path.write_text(self.render_json(report), encoding="utf-8")
            written["json"] = str(json_path)
            logger.info("Informe JSON escrito en %s", json_path)

        return written

    def _write_pdf(self, html_path: str, pdf_path: Path) -> str | None:
        """Convierte el HTML a PDF con WeasyPrint.

        La exportación a PDF es opcional: si WeasyPrint o sus dependencias de
        sistema (pango, cairo) no están instaladas, se degrada con un aviso en
        lugar de fallar toda la ejecución.
        """
        try:
            from weasyprint import HTML

            HTML(filename=html_path).write_pdf(str(pdf_path))
            logger.info("Informe PDF escrito en %s", pdf_path)
            return str(pdf_path)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "No se pudo generar el PDF (%s). ¿Faltan dependencias de sistema "
                "de WeasyPrint? El HTML y JSON sí se generaron.",
                exc,
            )
            return None

    @staticmethod
    def _group_by_severity(report: AuditReport) -> dict[str, list]:
        """Agrupa hallazgos por severidad, respetando el orden de gravedad."""
        grouped: dict[str, list] = {s.value: [] for s in Severity}
        for finding in report.findings:
            grouped[finding.severity.value].append(finding)
        return grouped
