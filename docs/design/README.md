# Diseño de la interfaz

Guía del estilo de las tres pantallas (Consola, Simulación y Modelos), para que cualquier cambio
mantenga el mismo aspecto, el mismo contraste y la misma accesibilidad.

## Principios

- **Sobrio y denso:** consola de seguridad con superficies planas, bordes finos y tablas compactas.
  El color se reserva para lo que tiene significado: severidad, avisos y acciones.
- **La severidad nunca depende solo del color:** siempre lleva su ícono y su texto.
- **Contraste AA en claro y oscuro:** texto de al menos 4,5:1 e íconos, bordes y barras de al menos
  3:1 (WCAG 2.2). Lo comprueba `uv run pytest`.
- **Sin recursos externos:** fuentes del sistema; los íconos de Lucide están copiados en el proyecto.
- **El frontend muestra, no calcula:** alertas, severidades y métricas llegan de la API tal cual.

## Dónde está cada cosa

| Qué | Dónde |
|---|---|
| Colores (variables de los dos modos), tamaños y componentes | `src/threat_detector/app/static/styles.css` |
| Textos en español, formato de números, íconos y panel lateral | `src/threat_detector/app/static/js/common.js` |
| Íconos y logo | `src/threat_detector/app/static/assets/` |
| Prueba de contraste de los colores | `tests/test_app.py` (`CONTRAST_CHECKS`) |

## Reglas para cambiar algo

1. Ningún color va escrito en un componente: se usa o se agrega una variable de `styles.css`, en
   los dos modos.
2. Un color nuevo para texto o figuras se agrega también a `CONTRAST_CHECKS`.
3. Los íconos salen solo de `assets/icons.svg` (ver `icons.md`).
4. Todo texto para el usuario va en español; los nombres de variables, en `FEATURE_LABELS`.
5. Lo que viene de la API o de un archivo se escribe con `textContent`, nunca con `innerHTML`.
6. Antes de terminar: `uv run pytest` completo y una revisión en claro, oscuro y celular.

## Archivos de esta carpeta

| Archivo | Contenido |
|---|---|
| `colors.md` | Paleta en claro y oscuro, contrastes y simulación de daltonismo |
| `typography-and-spacing.md` | Fuentes, tamaños, espacios, alturas, anchos de corte y movimiento |
| `components.md` | Cada componente: uso, partes, estados y accesibilidad |
| `icons.md` | Los 26 íconos, su significado y cómo agregar otro |
| `screenshots/` | Las tres pantallas en claro y oscuro, en computador y celular |
