# Seguridad

`workspace-tenant-auditor` accede a datos sensibles de un tenant de Google
Workspace (usuarios, grupos, configuración de seguridad). Este documento
describe el modelo de seguridad de la herramienta y las buenas prácticas para
operarla sin exponer la organización.

## Principio de mínimo privilegio

- **Solo lectura.** Todos los scopes son `*.readonly`. La herramienta nunca
  modifica la configuración del tenant.

  ```
  https://www.googleapis.com/auth/admin.directory.user.readonly
  https://www.googleapis.com/auth/admin.directory.group.readonly
  https://www.googleapis.com/auth/admin.directory.domain.readonly
  https://www.googleapis.com/auth/admin.reports.audit.readonly
  ```

- **No concedas scopes que no necesites.** En la Delegación de todo el dominio,
  autoriza exactamente la lista anterior. Un scope de administración completo
  (`admin.directory.user`) daría permisos de escritura innecesarios.

- **Cuenta delegada dedicada.** Idealmente, `DELEGATED_ADMIN_EMAIL` no es el
  superadmin personal de una persona, sino una **cuenta de servicio de auditoría**
  con el rol mínimo necesario (p. ej. un rol personalizado de solo lectura).
  Si tu edición lo permite, evita que sea superadmin.

## Manejo de secretos

| Secreto | Riesgo | Recomendación |
|---------|--------|---------------|
| JSON de la Service Account | Acceso completo si se filtra | Guardarlo **fuera del repo**, `chmod 600`, en un gestor de secretos (Vault, AWS/GCP Secret Manager, 1Password). |
| Fichero `.env` | Contiene rutas y emails | Nunca subirlo a Git (ya está en `.gitignore`). Usar `.env.example` como plantilla. |
| Tokens en logs | Fuga en logs de CI | La herramienta no imprime credenciales. En CI, evita `set -x` sobre variables sensibles. |

**Nunca** pongas el JSON de credenciales en el repositorio, en una imagen Docker
pública ni en un artefacto de CI. Cárgalo en tiempo de ejecución desde un
volumen montado en solo lectura:

```bash
docker run --rm \
  -v /etc/tenant-auditor/sa.json:/secrets/sa.json:ro \
  -e GOOGLE_APPLICATION_CREDENTIALS=/secrets/sa.json \
  -e DELEGATED_ADMIN_EMAIL=auditoria@ejemplo.com \
  -e TENANT_DOMAIN=ejemplo.com \
  workspace-tenant-auditor audit
```

## Revocación de accesos

Rotar y revocar es tan importante como conceder. Si sospechas de una fuga:

1. **Eliminar la clave de la Service Account** en la consola de GCP
   (IAM > Cuentas de servicio > Claves > Eliminar). Crear una nueva si hace falta.
2. **Retirar la autorización de Domain-Wide Delegation** en
   Consola Admin > Seguridad > Controles de la API > Delegación de todo el dominio.
3. **Revisar los logs de auditoría** del tenant para ver qué se consultó.
4. **Rotar** cualquier credencial que hubiera estado en el mismo entorno.

## Datos sensibles en los informes

- Los informes contienen **PII**: correos de empleados, cuentas, grupos.
  - Trátalos como material confidencial.
  - No los subas a repositorios, wikis públicas ni chats no corporativos.
  - `reports/` está en `.gitignore` por defecto.
- La **evidencia** se limita (p. ej. primeros 50 elementos) para reducir el
  volumen y la exposición, manteniendo trazabilidad mínima.
- Considera **redactar** dominios/correos si compartes el informe fuera de la
  organización (función de redacción en el roadmap).

## Alcance y limitaciones

- El informe refleja **lo observable vía APIs**. No sustituye una auditoría de
  seguridad formal ni un análisis de cumplimiento legal.
- Una auditoría **parcial** (algunos checks con error) se indica en la sección
  de avisos del informe: no asumas "sin hallazgos" si hubo errores de recogida.
- La herramienta usa **solo lectura**; cualquier remediación es manual (o vía
  GAM / otra automatización) tras revisar el informe.

## Reportar una vulnerabilidad

Si encuentras un problema de seguridad en esta herramienta, abre un *issue*
privado o contacta al mantenedor antes de divulgarlo públicamente.
