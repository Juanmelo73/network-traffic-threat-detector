# Colores

La paleta parte del prototipo de referencia del equipo, con una corrección: `--border-strong` se
oscureció en claro y se aclaró en oscuro para llegar a 3:1. Todos los colores son variables de
`styles.css`: el tema claro en `:root, [data-theme="light"]` y el oscuro en `[data-theme="dark"]`.

## Variables

| Variable | Claro | Oscuro | Uso |
|---|---|---|---|
| `--bg` | `#F4F6F9` | `#0A111E` | Fondo de la página |
| `--surface` | `#FFFFFF` | `#101A2B` | Tarjetas, cabecera y panel lateral |
| `--surface-2` | `#F0F3F7` | `#16223A` | Zonas sombreadas: encabezados de tabla, columnas reales, hover |
| `--surface-3` | `#E5EAF0` | `#1E2C48` | Fondo de barras y del interruptor apagado |
| `--border` | `#D4DBE4` | `#25344F` | Bordes de tarjetas y líneas de tabla |
| `--border-strong` | `#8A96A6` | `#5B6E8F` | Borde de los controles y carriles de la animación |
| `--text` | `#0F1B2D` | `#E6EDF6` | Texto principal |
| `--text-muted` | `#4B5768` | `#9EACC1` | Texto secundario y punto "sin evaluar" |
| `--primary` | `#0369A1` | `#4FB8F0` | Acción principal, enlaces y elemento activo |
| `--primary-hover` | `#075985` | `#7CCBF5` | Botón principal al pasar el cursor |
| `--on-primary` | `#FFFFFF` | `#06121F` | Texto sobre `--primary` |
| `--primary-soft` | `#E1F0FA` | `rgba(79, 184, 240, .14)` | Fila seleccionada y nodo Modelo |
| `--focus` | `#0369A1` | `#7CCBF5` | Contorno del foco del teclado |
| `--sev-critical` / `-bg` | `#B42318` / `#FEE4E2` | `#FF9289` / `rgba(240, 68, 56, .18)` | Severidad crítica, errores y destino «Alertas» |
| `--sev-high` / `-bg` | `#B93815` / `#FFEAD5` | `#FDB67E` / `rgba(247, 144, 9, .16)` | Severidad alta |
| `--sev-medium` / `-bg` | `#855400` / `#FEF3C7` | `#F2D36B` / `rgba(234, 179, 8, .14)` | Severidad media |
| `--sev-low` / `-bg` | `#1D4ED8` / `#E0E9FF` | `#A3C2FF` / `rgba(59, 130, 246, .18)` | Severidad baja |
| `--sev-normal` / `-bg` | `#475467` / `#EDF0F4` | `#A6B3C5` / `rgba(148, 163, 184, .12)` | Sin alerta y destino «Tráfico normal» |
| `--push-attack` | `#C4320A` | `#FF936E` | Explicación: empuja hacia «ataque» |
| `--push-normal` | `#0F766E` | `#4FD1C5` | Explicación: empuja hacia «normal» |
| `--ok` / `--bad` | `#067647` / `#B42318` | `#5BD69A` / `#FF9289` | Resultado correcto o incorrecto, mejor valor |
| `--warn-bg` / `-border` / `-text` | `#FFF6E0` / `#E9B949` / `#6E4400` | `rgba(245, 180, 40, .10)` / `rgba(245, 180, 40, .45)` / `#F5D27A` | Avisos y modelo simulado |
| `--info-bg` / `-border` | `#E1F0FA` / `#7DB9DD` | `rgba(79, 184, 240, .10)` / `rgba(79, 184, 240, .40)` | Recuadro informativo |
| `--heat` / `--heat-max` | `3, 105, 161` / `0.75` | `79, 184, 240` / `0.55` | Mapa de calor 9×9: color e intensidad máxima |
| `--logo-ink` / `--logo-signal` | `#0B3D66` / `#EA580C` | `#E6EDF6` / `#EA580C` | Logo: mitad sólida y bloques |

## Reglas

- **Severidad:** color + ícono + texto (ver `components.md`). El color solo no basta.
- **Modelo simulado:** usa los colores de aviso; **error:** los de severidad crítica.
- **Mapa de calor:** la intensidad de una celda nunca pasa de `--heat-max`, para que su número, en
  `--text`, mantenga 4,5:1.
- **Logo en oscuro:** la mitad sólida pasa a `#E6EDF6` (sobre la cabecera, 14,78:1); el naranja
  `#EA580C` no cambia (4,90:1).

## Contraste (WCAG 2.2)

Fórmulas de luminancia relativa y razón de contraste del glosario de WCAG 2.2; mínimos de 4,5:1 para
texto (criterio 1.4.3) y 3:1 para íconos, bordes y barras (criterio 1.4.11). Los valores salen de
`tests/test_app.py`, que falla si alguno baja del mínimo.

| Comprobación | Mínimo | Claro | Oscuro |
|---|---|---|---|
| Texto sobre el fondo / tarjeta / zona sombreada | 4,5 | 15,96 / 17,28 / 15,53 | 16,02 / 14,78 / 13,45 |
| Texto secundario sobre tarjeta / zona sombreada / fondo | 4,5 | 7,34 / 6,59 / 6,78 | 7,57 / 6,89 / 8,21 |
| Enlace sobre una tarjeta · texto del botón principal | 4,5 | 5,93 · 5,93 | 7,84 · 8,48 |
| Texto sobre la fila seleccionada | 4,5 | 14,85 | 11,45 |
| Foco sobre fondo · sobre tarjeta | 3 | 5,48 · 5,93 | 10,54 · 9,73 |
| Borde de los controles | 3 | 3,00 | 3,38 |
| Texto de la insignia: crítica / alta / media / baja / normal | 4,5 | 5,45 / 4,94 / 5,78 / 5,51 / 6,72 | 6,79 / 7,84 / 9,17 / 7,69 / 6,75 |
| Ícono y borde de severidad: crítica / alta / media / baja / normal | 3 | 6,57 / 5,77 / 6,43 / 6,70 / 7,69 | 8,07 / 10,10 / 11,87 / 9,73 / 8,20 |
| Explicación, números: «ataque» · «normal» | 4,5 | 5,52 · 5,47 | 8,01 · 9,35 |
| Explicación, barras: «ataque» · «normal» | 3 | 4,96 · 4,92 | 7,29 · 8,50 |
| Resultado correcto · incorrecto | 4,5 | 5,69 · 6,57 | 9,57 · 8,07 |
| Aviso: texto · título · modelo simulado | 4,5 | 16,06 · 7,84 · 7,84 | 12,34 · 9,97 · 9,97 |
| Recuadro informativo · error | 4,5 | 14,85 · 14,33 | 12,42 · 12,43 |
| Matriz: número sobre la celda más intensa | 4,5 | 4,80 | 4,51 |
| Animación: punto sin evaluar · carriles | 3 | 7,34 · 3,00 | 7,57 · 3,38 |
| Animación: nodo Modelo, texto · borde | 4,5 · 3 | 14,85 · 5,93 | 11,45 · 7,84 |
| Animación: «Alertas», texto · borde | 4,5 · 3 | 5,45 · 6,57 | 6,79 · 8,07 |
| Animación: «Tráfico normal», texto · borde | 4,5 · 3 | 6,72 · 7,69 | 6,75 · 8,20 |

## Daltonismo

Simulación con las matrices de severidad 1,0 de Machado, Oliveira y Fernandes (2009), tabla 1 de
https://www.inf.ufrgs.br/~oliveira/pubs_files/CVD_Simulation/CVD_Simulation.html, aplicadas sobre RGB
lineal (la página no lo dice explícitamente; el artículo construye las matrices a partir de la
distribución espectral de los primarios RGB, que es lineal en la luz). La diferencia entre dos
severidades se mide con CIEDE2000 (Sharma, Wu y Dalal, 2005; la implementación se comprobó con sus
datos de prueba). Cuanto más bajo el valor, más se parecen dos colores; no hay un umbral oficial.

Par de severidades más parecido (ΔE00):

| | Visión normal | Protanopia | Deuteranopia | Tritanopia |
|---|---|---|---|---|
| Claro, texto e ícono | 5,18 | 2,51 | 1,96 | 3,87 |
| Claro, relleno de la insignia | 7,49 | 5,15 | 5,23 | 2,10 |
| Oscuro, texto e ícono | 11,12 | 8,53 | 5,43 | 8,31 |
| Oscuro, relleno de la insignia | 6,34 | 0,58 | 0,53 | 4,85 |

Con protanopia y deuteranopia algunas severidades casi se confunden por el color. Por eso cada una
tiene un ícono de forma distinta y su nombre escrito.

## Agregar o cambiar un color

1. Definir la variable en los dos temas de `styles.css` (la prueba exige que los dos tengan las mismas).
2. Si se usa para texto o figuras, agregar sus combinaciones a `CONTRAST_CHECKS`.
3. Correr `uv run pytest` y revisar las pantallas en claro y oscuro.
