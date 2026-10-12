# Imágenes para la documentación

Capturas del informe generadas con Chrome headless en modo demo:

- `executive_summary.png` — Cabecera y resumen ejecutivo del informe HTML.
- `report_screenshot.png` — Informe completo (tabla de hallazgos y detalle).

Se referencian desde el README.md. Para regenerarlas:

```bash
# 1. Genera un informe de ejemplo
tenant-auditor audit --dry-run --output ./reports --formats html

# 2. Captura en alta resolución con Chrome headless (2x)
HTML=$(ls reports/*.html | head -1)
google-chrome --headless --hide-scrollbars --force-device-scale-factor=2 \
  --window-size=1100,900 --screenshot=docs/img/executive_summary.png \
  "file://$PWD/$HTML"
```
