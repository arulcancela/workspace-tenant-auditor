"""Interfaz de línea de comandos (Typer).

Comandos:
    audit        Ejecuta una auditoría y genera los informes.
    list-checks  Lista los checks disponibles y su descripción.

Ejemplos:
    tenant-auditor audit --domain ejemplo.com --output ./reports
    tenant-auditor audit --domain ejemplo.com --checks 2sv,oauth,inactive
    tenant-auditor audit --dry-run              # sin credenciales reales
    tenant-auditor list-checks
"""

from __future__ import annotations

import logging
import sys

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from tenant_auditor import __version__
from tenant_auditor.checks import CHECKS, run_checks
from tenant_auditor.checks.registry import resolve_check_ids
from tenant_auditor.config import Settings, get_settings
from tenant_auditor.models import AuditReport, TenantData

app = typer.Typer(
    name="tenant-auditor",
    help="Auditor de seguridad y cumplimiento para tenants de Google Workspace.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


def _setup_logging(level: str) -> None:
    """Configura logging estructurado y legible con Rich."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )


@app.command()
def version() -> None:
    """Muestra la versión de la herramienta."""
    console.print(f"workspace-tenant-auditor [bold]v{__version__}[/bold]")


@app.command("list-checks")
def list_checks() -> None:
    """Lista los checks disponibles y su descripción."""
    table = Table(title="Checks disponibles", show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Nombre")
    for check_id, (name, _) in sorted(CHECKS.items()):
        table.add_row(check_id, name)
    console.print(table)


@app.command()
def audit(
    domain: str = typer.Option(
        None, "--domain", "-d", help="Dominio del tenant a auditar. Por defecto, TENANT_DOMAIN."
    ),
    output: str = typer.Option(
        "./reports", "--output", "-o", help="Directorio donde escribir los informes."
    ),
    checks: str = typer.Option(
        "all", "--checks", "-c", help="Checks a ejecutar, separados por comas. 'all' por defecto."
    ),
    formats: str = typer.Option(
        None, "--formats", "-f", help="Formatos de salida: html,pdf,json. Por defecto, la config."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Usa datos de ejemplo y no llama a ninguna API real."
    ),
) -> None:
    """Ejecuta la auditoría y genera los informes."""
    settings = get_settings()
    if dry_run:
        settings = settings.model_copy(update={"dry_run": True})
    _setup_logging(settings.log_level)

    resolved_domain = domain or settings.tenant_domain
    resolved_formats = (
        [f.strip().lower() for f in formats.split(",") if f.strip()]
        if formats
        else settings.formats_list
    )

    # 1. Resolver selección de checks (con error claro si hay IDs inválidos).
    try:
        check_ids = resolve_check_ids(checks)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    console.print(
        f"[bold]workspace-tenant-auditor[/bold] v{__version__} — "
        f"dominio [cyan]{resolved_domain}[/cyan] — "
        f"{'[yellow]MODO DEMO[/yellow]' if dry_run else 'modo real'}"
    )
    console.print(f"Checks a ejecutar: [cyan]{', '.join(check_ids)}[/cyan]")

    # 2. Recopilar datos (real o demo).
    data = _collect(dry_run, settings, resolved_domain)
    if data.errors:
        console.print(f"[yellow]{len(data.errors)} aviso(s) durante la recopilación.[/yellow]")

    # 3. Ejecutar checks.
    with console.status("[bold green]Ejecutando checks..."):
        results = run_checks(data, check_ids, settings)

    # 4. Construir informe.
    report = AuditReport(
        domain=resolved_domain,
        tool_version=__version__,
        mode="dry-run" if dry_run else "live",
        results=results,
        execution_errors=data.errors,
    )

    _print_summary(report)

    # 5. Escribir informes.
    from tenant_auditor.report import ReportGenerator

    written = ReportGenerator().write_all(report, output, resolved_formats)
    for fmt, path in written.items():
        console.print(f"[green]✓[/green] {fmt.upper()}: {path}")

    # Código de salida: 1 si hay hallazgos críticos/altos (útil en CI).
    if any(f.severity.weight >= 4 for f in report.findings):
        raise typer.Exit(code=1)


def _collect(dry_run: bool, settings: Settings, domain: str) -> TenantData:
    """Recopila datos reales o carga el fixture de demostración."""
    if dry_run or settings.dry_run:
        from tenant_auditor.demo_data import load_demo_data

        console.print("[yellow]Modo demo:[/yellow] usando datos de ejemplo (sin credenciales).")
        return load_demo_data(domain)

    from tenant_auditor.auth.collector import collect_tenant_data
    from tenant_auditor.auth.google_client import AuthError, build_service_account_config

    try:
        config = build_service_account_config(settings)
        with console.status("[bold green]Recopilando datos del tenant..."):
            return collect_tenant_data(config, settings)
    except AuthError as exc:
        console.print(f"[bold red]Error de autenticación:[/bold red] {exc}")
        console.print("Sugerencia: prueba con [cyan]--dry-run[/cyan] para usar datos de ejemplo.")
        raise typer.Exit(code=3) from exc


def _print_summary(report: AuditReport) -> None:
    """Imprime un resumen ejecutivo en consola."""
    counts = report.counts_by_severity()
    score = report.overall_score()
    color = "red" if score < 50 else ("yellow" if score < 80 else "green")

    table = Table(title="Resumen de la auditoría", show_header=False)
    table.add_column("Métrica", style="bold")
    table.add_column("Valor")
    table.add_row("Postura de seguridad", f"[{color}]{score}/100[/{color}]")
    table.add_row("Checks ejecutados", str(report.total_checks))
    table.add_row("Hallazgos totales", str(report.total_findings))
    table.add_row("Críticos", f"[red]{counts['critica']}[/red]")
    table.add_row("Altos", f"[orange1]{counts['alta']}[/orange1]")
    table.add_row("Medios", f"[yellow]{counts['media']}[/yellow]")
    table.add_row("Bajos", str(counts["baja"]))
    table.add_row("Informativos", str(counts["informativa"]))
    console.print(table)


def main() -> None:
    """Punto de entrada robusto (maneja KeyboardInterrupt)."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrumpido por el usuario.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
