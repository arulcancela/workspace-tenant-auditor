# Changelog

Todas las modificaciones relevantes de este proyecto se documentan en este
archivo. El formato está basado en [Keep a Changelog](https://keepachangelog.com/es/1.1.0/)
y el proyecto sigue [Versionado Semántico](https://semver.org/lang/es/).

## [No publicado]

### Corregido

- **Paginación rota en la recopilación** (`auth/collector.py`): los endpoints
  `groups`, `members` y `domains` devolvían listas vacías porque `_paginate()`
  extraía siempre la clave `users`. Ahora `_paginate()` acepta `response_key`
  por API y lee la clave correcta de cada respuesta (`users`, `groups`,
  `members`, `domains`).
- **Checks de aliases**: se eliminó código muerto (`if False`) y ahora se
  extraen los **aliases reales** del campo `aliases` de cada usuario
  (`projection=full`, aplanado a `[{primaryEmail, alias}]`).
- **Recolección de tokens OAuth**: se sustituyó el uso incorrecto de
  `reports.userUsageReport()` por la Admin SDK Tokens API
  (`directory.tokens().list(userKey=...)`), que refleja las concesiones OAuth
  activas por usuario junto con sus scopes y client IDs.
- **Template HTML** (`report/templates/report.html.j2`): corregido carácter
  malformado `</strong›` → `</strong>` y movido el `<canvas>` de Chart.js
  dentro del layout para que no rompa la estructura del informe.
- **Cliente de la Reports API construido con un nombre de API inválido**
  (`auth/google_client.py`): `get_reports_service()` llamaba a
  `build("reports", "v1")`, que devuelve `UnknownApiNameOrVersion` (HTTP 404 en
  el endpoint de discovery) y hacía que la auditoría real abortara con un falso
  «error de autenticación» (código de salida `3`). La Reports API de Google
  Workspace se consume a través del cliente del Admin SDK, por lo que ahora se
  construye como `build("admin", "reports_v1")`. Verificado en un tenant real
  (Service Account + Domain-Wide Delegation).
- **La construcción del cliente de Reports ya no aborta la auditoría**
  (`auth/collector.py`): dicho cliente se creaba fuera del bloque tolerante a
  fallos (`_safe`), de modo que cualquier problema al construirlo —como el bug
  anterior de `reports:v1`— tumbaba la auditoría completa con código de salida
  `3`. Ahora se construye dentro de `_safe`: si falla, se registra como aviso no
  fatal en `execution_errors` y la auditoría continúa con el resto de checks
  (los de login/inactividad quedan sin datos, pero el informe se genera). El
  cliente de Directory sigue siendo imprescindible y, si falla, se propaga un
  `AuthError` con mensaje accionable.

### Notas

- Verificación: 64/64 tests ✅ · `ruff` limpio ✅ · `tenant-auditor audit --dry-run` ✅
  · auditoría real end-to-end contra un tenant de Google Workspace ✅.

## [1.0.0] - versión inicial

### Añadido

- Motor de auditoría con 12 checks sobre un tenant de Google Workspace.
- Autenticación con Service Account + Domain-Wide Delegation (solo lectura).
- Modo demo (`--dry-run`) sin credenciales.
- Informes ejecutivos en HTML, PDF (WeasyPrint) y JSON.
- CLI `tenant-auditor` (Typer), CI con ruff + pytest, imagen Docker.

[No publicado]: https://github.com/arulcancela/workspace-tenant-auditor/compare/86c86d6...HEAD
[1.0.0]: https://github.com/arulcancela/workspace-tenant-auditor/releases/tag/v1.0.0
