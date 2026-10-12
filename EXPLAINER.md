# EXPLAINER — workspace-tenant-auditor (explicado sin jerga)

> Este documento explica el proyecto **en lenguaje sencillo**, pensado para
> perfiles de negocio, responsables de seguridad o cualquier persona que quiera
> entender **qué resuelve y por qué importa** sin entrar en detalles técnicos.
> Para el detalle técnico, ver [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Qué hace el proyecto en una frase

**Es una herramienta que revisa automáticamente si la configuración de
seguridad de un Google Workspace está bien puesta y entrega un informe con los
problemas encontrados, ordenados por gravedad, y cómo arreglarlos.**

---

## Qué problema de negocio resuelve y por qué importa

Imagina una empresa con 800 empleados usando Google Workspace (correo, Drive,
calendario...). Con el tiempo, sin que nadie lo haga a propósito, se acumulan
agujeros de seguridad:

- Gente que entra **sin doble verificación** (solo usuario y contraseña: si le
  roban la clave, entran).
- Cuentas de personas que **ya se fueron** pero siguen activas.
- Enlaces de Drive mal configurados que **cualquiera con el enlace puede abrir**.
- Aplicaciones externas con **permisos enormes** sobre el correo.

Detectar esto a mano es lentísimo, no se hace con regularidad y no queda
registrado. Si la empresa sufre un incidente (o una auditoría legal), no hay ni
rastro de cuándo se revisó.

**Esta herramienta convierte esa revisión en un solo comando que se puede
repetir cuando se quiera.** Deja evidencia escrita y señala por dónde empezar a
arreglar. Ahorra tiempo, reduce el riesgo de un incidente grave y genera un
documento que sirve para enseñar a dirección, a un cliente o a un auditor.

**Por qué importa a una empresa:** un solo correo comprometido puede ser la
puerta de entrada a un robo de datos (con sanciones regulatorias y daño
reputacional) y a un fraude económico. Prevenir eso es mucho más barato que
reaccionar.

---

## Las 5 decisiones clave (y por qué se tomaron)

### 1. Autenticación con Service Account + Domain-Wide Delegation
**Qué es:** en lugar de que un humano introduzca su usuario y contraseña para
autorizar la herramienta, se usa una "identidad de máquina" (una cuenta técnica)
a la que el administrador autoriza una vez.
**Por qué:** una tarea automática no puede depender de que alguien pulse
"permitir". Así puede correr sola, de noche, sin que nadie esté delante. Es el
estándar en empresas grandes.

### 2. Modelos de datos tipados (Pydantic)
**Qué es:** antes de trabajar con cualquier dato, se define "qué forma tiene":
un usuario tiene email, si tiene doble verificación, etc.
**Por qué:** si los datos vienen mal, el sistema avisa al momento en lugar de
fallar más tarde y de forma confusa. Y como los datos están tipados, es muy
fácil probar la herramienta sin conectarse a nada real.

### 3. Cada comprobación es independiente
**Qué es:** cada revisión (doble verificación, cuentas inactivas, etc.) es un
bloque aislado que solo recibe datos y devuelve hallazgos.
**Por qué:** se pueden probar una a una sin tocar internet, y añadir una revisión
nueva es trivial (una función y registrarla). Esto es lo que hace que el proyecto
sea **mantenible** en el tiempo.

### 4. Informes en tres formatos (HTML + PDF + JSON)
**Qué es:** el informe se construye en tres formatos: una página web (que se ve
bien y se puede enviar), un PDF (para imprimir o firmar) y un JSON (para que
otras herramientas lo lean).
**Por qué:** distintos públicos necesitan distintos formatos. El HTML y el PDF
son para personas; el JSON es para automatizar (por ejemplo, en un sistema de
control). Se eligió una tecnología de PDF que no necesita un navegador, para que
quepa en cualquier contenedor y dé resultados idénticos siempre.

### 5. Tolerancia a fallos por diseño
**Qué es:** si una parte de la consulta a Google falla, la herramienta **no se
cae**: anota el aviso y sigue con el resto.
**Por qué:** en una auditoría, obtener el 90% de la información es mucho mejor
que no obtener nada. Y el informe deja claro qué no se pudo comprobar, para no
dar una falsa sensación de seguridad.

---

## Cómo ayuda a distintos perfiles

| Perfil | Qué obtiene |
|--------|-------------|
| **Dirección / CISO** | Una puntuación de postura (0-100) y un resumen ejecutivo que entiende en 1 minuto. |
| **Equipo de seguridad** | Hallazgos priorizados por severidad, con evidencia y recomendación accionable. |
| **Consultores / MSP** | Un informe de partida y de cierre, repetible, que se puede entregar a un cliente. |
| **Auditoría / compliance** | Evidencia documentada y repetible, lista para adjuntar a un proceso de cumplimiento. |

---

## Posibles mejoras futuras (y su porqué)

### 1. Detección de cambios entre ejecuciones ("drift")
**Qué:** comparar el informe de hoy con el de la semana pasada y avisar solo de
lo que ha empeorado.
**Por qué:** evita alarmar por lo mismo de siempre y ayuda a priorizar: "esto
apareció desde ayer" es mucho más útil que una lista fija.

### 2. Fichero de políticas configurable
**Qué:** que la empresa defina en un documento sus propias reglas (por ejemplo,
"contraseñas de 90 días", "máximo 3 superadmins") y la herramienta las aplique.
**Por qué:** cada organización tiene sus normas. Así la herramienta se adapta a
cada cliente sin tocar código.

### 3. Redacción de datos personales en el informe
**Qué:** poder generar un informe "limpio" que oculte los correos reales.
**Por qué:** permite compartir el resultado (con un proveedor, en una presentación,
en una demo pública) sin exponer datos personales de empleados, algo crítico en
materia de privacidad.
