# Changelog

Todas las modificaciones relevantes de este proyecto se documentan en este
archivo. El formato está basado en [Keep a Changelog](https://keepachangelog.com/es/1.1.0/)
y el proyecto sigue [Versionado Semántico](https://semver.org/lang/es/).

## [1.1.2] - 2026-10-22

### Corregido

- **Detección del modo de instalación**: `origen` solo reconocía
  `site-packages`/`dist-packages`, así que instalaciones con `--target`,
  `--prefix` o un entorno gestionado (pipx) se reportaban como «código
  fuente». Ahora también se detecta el `*.dist-info` contiguo al paquete.

## [1.1.1] - 2026-10-22

### Corregido

- **Identificación del commit en instalaciones desde git**: cuando el paquete
  se instala con `pip install git+...` no hay repositorio en disco y `build`
  caía a la fecha de la copia. Ahora se lee el commit de `direct_url.json`
  (PEP 610), que pip escribe en la instalación, de modo que cada ejecución se
  puede atribuir al commit exacto del que salió.

## [1.1.0] - 2026-10-22

### Añadido

- **Identificación de la build en ejecución** (`diagnostics.py`): `tenant-auditor
  version` y el nuevo flag `--version` muestran la versión, el commit (o la
  fecha de la copia), la ruta desde la que se ejecuta el paquete, si procede de
  un checkout o de un paquete instalado, y los nombres de API en uso
  (`admin:directory_v1`, `admin:reports_v1`). Además avisa si los metadatos del
  entorno declaran otra versión distinta de la que se está ejecutando, que es
  la firma de una instalación antigua o duplicada.
- **Cabecera de `audit` con la build**: cada ejecución imprime
  `v1.1.0 (git 9af9ed5)` en lugar de solo el número de versión, para que un
  informe se pueda atribuir al código que lo generó.
- **Códigos de salida diferenciados**: `4` para fallo al construir el cliente
  de una API, separado del `3` de credenciales.

### Corregido

- **Errores de construcción de cliente ya no se etiquetan como «Error de
  autenticación»** (`auth/google_client.py`): nueva excepción
  `ClientBuildError`, distinta de `AuthError`, con la causa clasificada
  (nombre de API inexistente, API deshabilitada en el proyecto, discovery
  inaccesible) y una sugerencia accionable. Antes, un fallo de discovery
  mandaba al operador a revisar credenciales que estaban bien.
- **Los avisos no fatales incluyen la sugerencia** (`auth/collector.py`): el
  registro de `TenantData.errors` incorpora el hint del error, de modo que un
  informe generado parcialmente explica cómo recuperar los checks que faltan.

### Notas

- Los nombres de API se centralizan en `apis.py` para que cliente y diagnóstico
  no puedan divergir.

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
