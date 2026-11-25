# Componentes

Cada componente está en `styles.css`; los que se arman con datos, en `js/common.js` o en el script
de su pantalla.

## Cabecera

Logo, menú (Consola, Simulación, Modelos) con la página actual marcada (`aria-current`), píldora
"Modelo en uso" con la etiqueta "Simulado" si el modelo lo es, y botón de claro u oscuro con
`aria-label` ("Cambiar a modo oscuro" o "Cambiar a modo claro"). El modo se aplica en el `<head>`,
antes de los estilos, para que no parpadee.

## Severidad

| `severity` | Texto | Ícono | Clase |
|---|---|---|---|
| `critical` | Crítica | octagon-alert | `.sev-critical` |
| `high` | Alta | triangle-alert | `.sev-high` |
| `medium` | Media | circle-alert | `.sev-medium` |
| `low` | Baja | circle-minus | `.sev-low` |
| `normal` | Normal | circle-check | `.sev-normal` |

La clase `.sev-*` da el color (`--c`) y el fondo (`--b`) a cualquier componente: insignia, chip,
indicador, fila del registro, punto de la animación.

## Formato de números (contrato, sección 2)

- Probabilidades y tasas (detección, falsas alarmas, precisión, recall, exactitud): porcentaje con un
  decimal, "96,4%" (`formatPercent`).
- Puntajes (F1, PR-AUC, ROC-AUC, F1 macro): decimal con tres cifras, "0,987" (`formatScore`).
- Enteros con punto de miles, "82.332"; umbral con dos decimales, "0,31".
- Valor que falta: "—". Solo se redondea al mostrar.

## Textos fijos

- **Variables:** las 35 etiquetas de `FEATURE_LABELS` (fuente: `NUSW-NB15_features.csv`), siempre con
  "del origen / del destino"; el nombre técnico aparece al pasar el cursor o con el foco (`.feat`).
- **Tipos de ataque:** se muestran con el nombre del dataset y una descripción en `title`
  (`ATTACK_TYPE_DESCRIPTIONS`), basada en Koroniotis, Moustafa, Sitnikova y Slay (2017),
  arXiv:1711.02825, que la atribuye a Moustafa y Slay (2016), *Information Security Journal: A Global
  Perspective*, 25(1-3), 18-31.

## Avisos

| Tipo | Clase | Ícono | Uso |
|---|---|---|---|
| Información | `.notice-info` | info | Métricas oficiales en Modelos; archivo analizado con otro modelo (consola) |
| Aviso / modelo simulado | `.notice-warn` | flask-conical | "**Modelo simulado.** Sus probabilidades, tipos y explicaciones son inventados: sirven para probar la aplicación, no para evaluar el tráfico." (consola y simulación); "**Métricas inventadas.** No sirven para evaluar el modelo." (Modelos) |
| Error | `.notice-error`, `role="alert"` | circle-x | El `message` de la API tal cual |
| Correcto | `.notice-ok`, `role="status"` | circle-check | "Análisis listo." |
| Aviso breve | `.toast`, `role="status"` | — | "Enlace copiado", modelo elegido |

El aviso de modelo simulado aparece solo si `GET /api/models` dice que el modelo es simulado; si el
modelo no está en la lista, se muestra su nombre sin etiqueta y sin aviso.

**La muestra sigue al modelo elegido:** si la consola va a abrir la muestra de demostración de un
modelo distinto del elegido (al volver por el menú o con «Atrás», o por un enlace), abre la muestra
del modelo elegido, en el mismo modo (con o sin etiquetas) y con el mismo flujo si el enlace trae
`&flow=`. Así los indicadores, sus ayudas y la cola son siempre del modelo de la cabecera
(`followChosenModel` en `js/analysis.js`). Si el navegador restaura la consola desde su caché de
páginas (bfcache) al ir «Atrás», la consola se recarga para aplicar esta regla.

**Archivo analizado con otro modelo:** elegir otro modelo no cambia un archivo ya analizado, porque
no se puede volver a analizar sin el archivo. Si el análisis abierto se hizo con un modelo distinto
del elegido, el título del resumen pasa a "Resumen del análisis con <modelo del análisis>" y un
aviso dice: "Este análisis se hizo con **<modelo del análisis>**. El modelo elegido ahora es
**<modelo elegido>**: los análisis nuevos lo usarán. Para analizarlo con <modelo elegido>, vuelve a
cargar el archivo." Si los dos modelos coinciden, no hay aviso. Va en `#modelSlot` de `index.html`
(`renderModelNotice` en `js/analysis.js`).

**Único error propio del frontend — `network_error`:** cuando el navegador no recibe respuesta del
servidor (la app detenida, la conexión cortada o el WebSocket cerrado sin `end` ni `error`). La API
nunca lo devuelve. Mensaje: "No se pudo conectar con el servidor. Revisa que la aplicación esté en
ejecución y vuelve a intentarlo."

## Estados

- **Cargando:** barra indeterminada con un texto ("Analizando el archivo…") y `role="status"`; los
  botones se deshabilitan.
- **Vacío:** explica por qué no hay nada y ofrece la acción siguiente ("No hay alertas de severidad
  crítica en este análisis." + "Ver todas las alertas").
- **Error:** recuadro de error con el mensaje y, si aplica, "Reintentar".

## Indicadores

Tarjeta con etiqueta, valor y nota. Las de severidad llevan borde izquierdo de color e ícono. Las de
detección y falsas alarmas van sombreadas; sin dato muestran "—" con su motivo ("Requiere etiquetas
reales", "Se calcula al terminar", "No hay ataques reales en el archivo"). Con dato, llevan un ícono
info y una ayuda que aparece al pasar el mouse, con el foco o al tocarlas: sobre qué flujos se calcula
la tasa ("226 de 316 ataques reales dieron alerta…") y que las dos no suman 100 %.

## Botones y controles

- Botón principal (`.btn-primary`), secundario (`.btn-secondary`), pequeño (`.btn-sm`), enlace
  (`.link-btn`) y de solo ícono (`.icon-btn`, siempre con `aria-label`).
- **Filtros y velocidades:** grupo `role="radiogroup"` de selección única; las flechas cambian la
  opción y solo la marcada entra en el orden de tabulación. Un filtro con 0 sigue activo.
- **Interruptor:** `role="switch"` con `aria-checked`.

## Tabla de la cola

25 filas por página; columnas reales sombreadas cuando hay etiquetas; fila marcada al abrir su panel;
encabezado fijo; cada fila se abre con clic o Enter. La consola recuerda su último análisis en la
pestaña (`sessionStorage`): al volver por el menú o el logo lo muestra de nuevo, y si ya no existe,
muestra el mensaje del contrato y lo olvida.

## Panel lateral

Tarjeta de probabilidad con severidad y umbral, datos del flujo, resultado si hay etiquetas, y
explicación con barras centradas en cero (10 variables y "Ver todas"). Al abrir, el foco pasa al
título; Esc lo cierra y devuelve el foco a quien lo abrió. En celular ocupa toda la pantalla.

## Valores que se muestran con otro texto

El valor `unas` de `proto` se muestra como **unassigned**. Al pasar el mouse aparece "Valor en el
archivo: unas". Se cambia en la columna Protocolo de la cola, en los datos y la explicación del panel
lateral, y en el registro y la última alerta de la simulación. Es solo presentación: los CSV, la
API, el preprocesamiento y los modelos siguen usando `unas`. La tabla de equivalencias está en
`DISPLAY_VALUES` de `js/common.js`.

La descripción oficial de UNSW-NB15 (`NUSW-NB15_features.csv`) no explica este valor; solo
describe `proto` como "Transaction protocol". La fuente es el código de Argus: en la función
`ArgusPrintProto` de `common/argus_util.c` (github.com/openargus/clients), cuando el número de
protocolo IP no tiene nombre en su tabla, se escribe `unas`.

## Gráficos de Modelos (sin librerías)

- **Barras horizontales:** el ancho es el valor y el número siempre va escrito; la exactitud, en gris.
- **Matriz 2×2:** conteos con su nombre ("Verdaderos positivos"…).
- **Matriz 9×9:** tabla con el número en cada celda, intensidad según la parte de la fila (hasta
  `--heat-max`), diagonal con borde y leyenda "Menos — Más".
- **Mejor valor:** estrella con el texto oculto "mejor valor", solo entre dos o más modelos
  entrenados, nunca el simulado.

## Animación de la simulación

Escenario con Archivo, Modelo, «Alertas» y «Tráfico normal». Cada punto sale al llegar un mensaje
`flow`, viaja gris hasta el modelo y toma el color de su severidad camino a su destino según
`is_alert`. El viaje dura el 80 % de la pausa entre flujos y un punto nunca llega antes que el
anterior. Conteos, indicadores, registro y última alerta se actualizan cuando el punto llega. Con
`prefers-reduced-motion` o la pestaña oculta no se dibujan puntos y todo se aplica al llegar cada
mensaje. El escenario es decorativo (`aria-hidden`): la misma información está en los indicadores, el
registro y un mensaje de estado que se actualiza cada 10 flujos.
