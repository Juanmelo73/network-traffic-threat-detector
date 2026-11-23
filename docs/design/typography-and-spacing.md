# Tipografía, tamaños y espacios

## Fuentes

Fuentes del sistema; no se descarga ninguna.

- **Texto:** `system-ui, -apple-system, "Segoe UI", Roboto, Ubuntu, "Helvetica Neue", Arial, sans-serif`.
- **Monoespaciada:** `ui-monospace, "Cascadia Mono", "Ubuntu Mono", Menlo, Consolas, monospace`, para
  títulos de página, ids, nombres técnicos, valores de flujos y números de indicadores y tablas, con
  números de ancho fijo (`tabular-nums`).

## Tamaños

| Parte | Tamaño |
|---|---|
| Texto general (párrafos, avisos, datos del panel, menú) | 14 px, interlineado 1,5 |
| Introducción de cada pantalla | 15 px |
| Tablas (cola, registro, comparación y detalle de Modelos) | 13 px, filas de unos 34 px |
| Encabezados de tabla | 12 px, seminegrita |
| Insignias y chips | 13 px; el número del chip, 12 px monoespaciado |
| Explicación del panel | 13 px |
| Probabilidad grande del panel | 28 px monoespaciado |
| Indicadores: etiqueta / valor / nota | 13 / 26 / 12 px (valor 22 px en celular) |
| Botones normales / pequeños | 14 px / 13 px |
| Títulos: página / tarjeta / bloque | 24 px monoespaciado (21 en celular) / 16 px / 14 px |
| Título de sección (mayúsculas) | 12 px |
| Ayuda y texto secundario | 13 px |
| Mínimo (nombre técnico al pasar el cursor, leyendas) | 12 px |
| Selector de orden | 13 px; 16 px en celular (abajo) |

**El selector a 16 px en celular:** Safari en iPhone amplía la página al tocar un campo de formulario
con letra de menos de 16 px. No es documentación oficial de Apple; lo describen:
- Telerik, "Disable Auto Zoom for Input Controls on iPhone Safari Browser" (campos de entrada):
  https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/common-disable-autozoom-input-safari-iphone
- GitLab, merge request "Fix iOS input zoom on mobile devices" (campos de entrada):
  https://gitlab.com/gitlab-org/gitlab/-/merge_requests/220666
- Nuxt UI, pull request #6040, que aplica el mismo arreglo al select: https://github.com/nuxt/ui/issues/6040

## Espacios y formas

| | Valores |
|---|---|
| Escala de espacios | 4, 8, 12, 16, 24 y 32 px (`--space-1` a `--space-6`) |
| Radios | 4, 6 y 10 px (`--radius-sm`, `--radius`, `--radius-lg`) |
| Alturas | botones 44 px; controles pequeños 36 px (44 en pantallas táctiles); cabecera 60 px (104 en celular) |
| Panel lateral | 460 px; pantalla completa en celular |
| Contenido | ancho máximo 1440 px |

## Anchos de corte

| Ancho | Cambio |
|---|---|
| Hasta 1100 px | El detalle de Modelos pasa a una columna |
| Hasta 900 px | Zona de carga y registro de la simulación en una columna |
| Hasta 760 px | Menú en una segunda fila, panel a pantalla completa, escenario vertical, un dato por línea en la barra del análisis |
| Pantalla táctil (`pointer: coarse`) | Controles pequeños de 44 px de alto |

En ningún ancho la página se desplaza de lado: las tablas anchas se desplazan dentro de su recuadro
(lo comprueban las pruebas a 320 y 375 px).

## Movimiento

- Transiciones de 150 y 220 ms (`--dur-fast`, `--dur`) en hover y al abrir el panel.
- Con `prefers-reduced-motion`, sin animaciones ni transiciones; la simulación no dibuja puntos.
