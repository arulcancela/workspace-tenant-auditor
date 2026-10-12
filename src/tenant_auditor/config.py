"""Configuración centralizada mediante Pydantic Settings.

Lee variables de entorno (y opcionalmente un fichero .env) y las valida.
Toda la aplicación obtiene su configuración desde aquí: no hay valores
mágicos dispersos por el código, lo que facilita el testeo y la operación.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuración de la aplicación, cargada desde entorno/.env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Dominio y autenticación
    tenant_domain: str = Field(default="ejemplo.com")
    google_application_credentials: str = Field(default="")
    delegated_admin_email: str = Field(default="")
    google_scopes: str = Field(
        default=(
            "https://www.googleapis.com/auth/admin.directory.user.readonly "
            "https://www.googleapis.com/auth/admin.directory.group.readonly "
            "https://www.googleapis.com/auth/admin.directory.domain.readonly "
            "https://www.googleapis.com/auth/admin.reports.audit.readonly"
        )
    )

    # Comportamiento
    output_dir: str = Field(default="./reports")
    output_formats: str = Field(default="html,pdf,json")
    max_workers: int = Field(default=4, ge=1, le=16)
    log_level: str = Field(default="INFO")

    # Umbrales
    inactive_days_threshold: int = Field(default=90, ge=1)
    password_max_age_days: int = Field(default=180, ge=1)

    # Modo demo
    dry_run: bool = Field(default=False)

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"log_level debe ser uno de {allowed}")
        return v.upper()

    @property
    def scopes_list(self) -> list[str]:
        """Scopes como lista, filtrando cadenas vacías."""
        return [s for s in self.google_scopes.split() if s]

    @property
    def formats_list(self) -> list[str]:
        """Formatos de salida normalizados a minúsculas."""
        return [f.strip().lower() for f in self.output_formats.split(",") if f.strip()]


@lru_cache
def get_settings() -> Settings:
    """Devuelve una instancia cacheada de Settings (patrón singleton)."""
    return Settings()
