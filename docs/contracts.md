# Contratos del proyecto

Este documento define cómo se comunican las partes de **Network Traffic Threat Detector**. Se escribe antes de programarlas para que cada parte pueda avanzar por separado: si todas cumplen el contrato, encajan al unirlas.

## 1. Propósito y alcance

La aplicación analiza flujos de red ya extraídos, en el formato de UNSW-NB15 (no tráfico en vivo). Los datos pasan por las partes en este orden:

```
data/raw/  →  ml/  →  artifacts/  →  app/ (backend)  →  navegador (frontend)
```

Hay dos contratos, uno por cada frontera:

| Contrato | Entre | Qué define | Secciones |
|---|---|---|---|
| **API** | Frontend (navegador) ↔ backend (FastAPI) | Qué recibe y qué devuelve cada ruta: `POST /api/predict`, `GET /api/analysis/{analysis_id}`, `GET /api/explain/{id}`, `GET /api/models`, `GET /api/metrics` y `WS /ws/simulate`. | 2 a 9 |
| **Artefactos** | `ml/` ↔ `app/` | Cómo se guarda cada modelo entrenado en `artifacts/models/<model_name>/` y qué contiene `artifacts/registry.json`. | 10 a 13 |

### Quién usa cada contrato

- **Frontend:** con las secciones 2 a 9 sabe qué enviar y cómo leer cada respuesta, sin conocer el código del backend.
- **Backend:** responde siempre en esos formatos, tanto con modelos reales como con el modelo simulado.
- **`ml/`:** exporta cada modelo como dicen las secciones 10 a 12. `ml/` y `app/` no se importan entre sí: la app solo conoce de un modelo lo que está en `artifacts/`.

### Qué no define

- Cómo se entrena ni qué modelos se usan.
- El diseño visual de las pantallas.
- La organización interna del código de cada parte.

### Reglas del documento

- **El documento manda.** Si el código no coincide con el contrato, se corrige el código. Si lo que hay que cambiar es el contrato, primero se acuerda con el equipo y se actualiza este documento, y después el código.
- **Agregar no rompe; cambiar sí.** Un campo nuevo en una respuesta no afecta a quien no lo usa. Renombrar o quitar un campo, o cambiar su tipo, rompe a la otra parte, así que siempre se acuerda antes.
- **Los nombres no se inventan aquí.** Los nombres de columnas y los parámetros salen de `src/threat_detector/dataset.py` y `src/threat_detector/config.py`. Este documento los cita, no los redefine.

## 2. Convenciones generales

Estas reglas valen para todas las secciones siguientes.

### Formato

- Las respuestas de la API y los mensajes de `WS /ws/simulate` son **JSON en UTF-8**. La única excepción es el archivo que se sube a `POST /api/predict`, que es un CSV (sección 4).
- `model.json` y `registry.json` también son JSON en UTF-8.

### Idioma

- **Nombres de campos:** en inglés y en `snake_case` (por ejemplo, `attack_probability`).
- **Valores fijos** (severidad, tipos de ataque, nombres de modelos y de variables): en inglés. El frontend decide cómo mostrarlos en español.
- **Textos para el usuario** (mensajes de error, nombre para mostrar de un modelo): en español, listos para mostrarse tal cual.

### Campos vacíos

- **Un campo nunca se omite.** Si no tiene valor, viene con `null`. Así el frontend siempre encuentra los mismos campos y solo revisa si el valor es `null`.
- `null` significa "no se puede saber con los datos recibidos". Por ejemplo, la etiqueta real de un flujo cuando el archivo no trae etiquetas.

### Números

- **Probabilidades y métricas:** van de 0 a 1, nunca en porcentaje (`0.95`, no `95`). El frontend las convierte a porcentaje al mostrarlas.
- **Sin redondear:** el backend no redondea; el frontend redondea solo al mostrar.
- **Cálculos que no se repiten:** la alerta y la severidad las calcula solo el backend. El frontend las muestra tal como llegan y nunca las recalcula a partir de la probabilidad.

### Identificador de un flujo

El `id` de un flujo es el valor de la columna `id` (`ID_COL` en `dataset.py`) del archivo analizado: un número entero. Solo es único dentro de un archivo, así que para ubicar un flujo hacen falta dos datos: el `id` y el análisis al que pertenece.

### Análisis y `analysis_id`

- **Qué es un análisis:** el resultado de pasar un archivo por un modelo con `POST /api/predict`. Cada análisis tiene un `analysis_id` (texto) que lo identifica.
- **Recuerda si tiene etiquetas:** el análisis guarda su valor de `has_labels` (sección 4). Todas las rutas que lo usan respetan ese modo: si se creó sin etiquetas, ninguna devuelve las etiquetas reales.
- **Dónde se usa:** `GET /api/analysis/{analysis_id}` (sección 4), `GET /api/explain/{id}` (sección 5) y `WS /ws/simulate` (sección 8) trabajan sobre un análisis y reciben su `analysis_id`.
- **Dónde se guarda:** el backend guarda en memoria **los últimos análisis**, para calcular la explicación de un flujo solo cuando se pide. El número de análisis guardados se decide junto con el tamaño máximo de archivo.
- **Si un análisis ya no existe:** porque el servidor se reinició o porque se borró para dar lugar a otros, la API responde con un error que pide volver a cargar el archivo (sección 9).
- **La muestra de demostración no se pierde:** su análisis tiene un `analysis_id` fijo, que depende del modelo y del modo:
  - `"sample-<model_name>"` con etiquetas (por ejemplo, `"sample-mock"`).
  - `"sample-<model_name>-unlabeled"` sin etiquetas (por ejemplo, `"sample-mock-unlabeled"`).

  Como `sample_flows.csv` es un archivo fijo del servidor, si ese análisis ya no está en memoria el backend lo vuelve a generar en vez de responder con un error.
- **Archivos subidos:** su `analysis_id` es un texto aleatorio que genera el backend. El frontend no debe interpretarlo, solo devolverlo tal cual.

### Enlace directo a una alerta

```
index.html?analysis=<analysis_id>&flow=<id>
```

Lleva los dos datos que identifican un flujo. Funciona mientras su análisis esté en memoria; con la muestra de demostración funciona siempre.

### Severidad

`severity` solo puede tomar estos cinco valores. La regla para calcularla está en la sección 3.

| Valor | Se muestra como | Probabilidad de ataque | Constante en `config.py` |
|---|---|---|---|
| `"critical"` | Crítica | ≥ 0,90 | `SEVERITY_CRITICAL` |
| `"high"` | Alta | ≥ 0,75 | `SEVERITY_HIGH` |
| `"medium"` | Media | ≥ 0,60 | `SEVERITY_MEDIUM` |
| `"low"` | Baja | ≥ umbral del modelo | — (el umbral está en `model.json`) |
| `"normal"` | Normal | < umbral del modelo | — |

### Tipos de ataque

Los tipos de ataque usan exactamente los valores de la columna `attack_cat` (`ATTACK_CAT` en `dataset.py`), con sus mayúsculas:

`"Normal"`, `"Generic"`, `"Exploits"`, `"Fuzzers"`, `"DoS"`, `"Reconnaissance"`, `"Analysis"`, `"Backdoor"`, `"Shellcode"`, `"Worms"`.

No hay que confundir `"Normal"` (tipo de ataque, con mayúscula, como en el dataset) con `"normal"` (severidad, en minúscula).

### Nombres de variables

Las variables se nombran con su **nombre técnico**, igual que las columnas de `RAW_COLUMNS` en `dataset.py` (por ejemplo, `sttl` o `sbytes`). El frontend las traduce con las etiquetas en español definidas para la interfaz.

### Nombres de modelos

- **`name`:** identifica al modelo. Va en minúsculas y `snake_case`, y es el mismo nombre de su carpeta en `artifacts/models/<model_name>/`.
- **`display_name`:** es el nombre en español que se muestra en la interfaz.

## 3. El flujo predicho

Es el resultado de analizar un flujo. Tiene **el mismo formato** en la lista de flujos de `POST /api/predict` (sección 4) y en cada flujo que envía `WS /ws/simulate` (sección 8).

### Campos

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `id` | entero | No | Valor de la columna `id` del archivo (sección 2). |
| `proto` | texto | Sí | Valor de la columna `proto` del archivo, tal como viene. `null` si la celda está vacía. |
| `service` | texto | Sí | Valor de la columna `service` del archivo, tal como viene (incluido `"-"`). `null` si la celda está vacía. |
| `state` | texto | Sí | Valor de la columna `state` del archivo, tal como viene. `null` si la celda está vacía. |
| `attack_probability` | número de 0 a 1 | No | Probabilidad de que el flujo sea un ataque, según el modelo. |
| `is_alert` | booleano | No | `true` si `attack_probability` es mayor o igual que el umbral del modelo. |
| `severity` | texto | No | `"critical"`, `"high"`, `"medium"`, `"low"` o `"normal"` (regla abajo). |
| `predicted_attack_cat` | texto | Sí | Si el flujo es alerta, el tipo de ataque más probable entre los 9 (nunca `"Normal"`). `null` si no es alerta. |
| `true_label` | entero (0 o 1) | Sí | Valor de la columna `label` del archivo. `null` si el archivo no trae etiquetas. |
| `true_attack_cat` | texto | Sí | Valor de la columna `attack_cat` del archivo. `null` si el archivo no trae etiquetas. |

Los campos de valores reales usan los nombres de las columnas de `dataset.py` (`TARGET` = `label`, `ATTACK_CAT` = `attack_cat`) con el prefijo `true_`, para no confundirlos con lo que predice el modelo.

`proto`, `service` y `state` (`CATEGORICAL_COLS` en `dataset.py`) identifican la conexión en la cola de alertas, la simulación y el panel lateral. Se envían **antes** de agrupar las categorías raras en `other`: el analista ve el protocolo real (por ejemplo, `"gre"`), aunque el modelo lo haya tratado como `other`.

### Regla del tipo probable

- **Si el flujo es alerta:** `predicted_attack_cat` es el tipo de ataque más probable entre los 9, sin contar `"Normal"`. Así una alerta nunca dice "tipo probable: Normal", aunque la probabilidad de ataque y el tipo vengan de cálculos distintos.
- **Si no es alerta:** `predicted_attack_cat` es `null`. Que el flujo se considera normal ya lo dice `severity: "normal"`.

### Regla de la severidad

El backend la calcula en este orden, con el umbral del modelo (`threshold` en su `model.json`, sección 11) y los cortes de `config.py`:

1. Si `attack_probability` es menor que el umbral → `"normal"` (no es alerta).
2. Si no:
   - ≥ `SEVERITY_CRITICAL` (0,90) → `"critical"`
   - ≥ `SEVERITY_HIGH` (0,75) → `"high"`
   - ≥ `SEVERITY_MEDIUM` (0,60) → `"medium"`
   - en otro caso → `"low"`

Siempre se cumple que `is_alert` es `true` si y solo si `severity` es distinta de `"normal"`.

Si el umbral de un modelo es mayor que 0,60, algunos niveles pueden quedar vacíos (con umbral 0,70 no hay flujos `"low"`). Es correcto y no se ajusta.

### Ejemplos

Flujo con alerta, de un archivo con etiquetas (umbral del modelo: 0,31):

```json
{
  "id": 1532,
  "proto": "tcp",
  "service": "http",
  "state": "FIN",
  "attack_probability": 0.9731,
  "is_alert": true,
  "severity": "critical",
  "predicted_attack_cat": "Exploits",
  "true_label": 1,
  "true_attack_cat": "Exploits"
}
```

Flujo sin alerta, de un archivo sin etiquetas (mismo modelo):

```json
{
  "id": 40877,
  "proto": "udp",
  "service": "dns",
  "state": "CON",
  "attack_probability": 0.1204,
  "is_alert": false,
  "severity": "normal",
  "predicted_attack_cat": null,
  "true_label": null,
  "true_attack_cat": null
}
```

## 4. `POST /api/predict`

Analiza un archivo CSV de flujos con un modelo y devuelve el resultado de cada flujo y los indicadores de la consola.

### Qué se envía

Un formulario `multipart/form-data` con:

| Campo | Tipo | Obligatorio | Qué es |
|---|---|---|---|
| `file` | archivo CSV | Sí, salvo con `use_sample` | Los flujos a analizar, en formato UNSW-NB15. |
| `use_sample` | booleano | No | `false` por defecto. Con `true` no se envía `file`: el backend analiza su propio `sample_flows.csv`, y el análisis recibe el `analysis_id` fijo de la muestra (sección 2). |
| `model` | texto | No | `name` del modelo que se usa (sección 6). Si no se envía, se usa el modelo por defecto de `registry.json`. |
| `use_labels` | booleano | No | `true` por defecto. Con `false`, la app ignora `label` y `attack_cat` aunque el archivo los traiga: es el modo **sin etiquetas** de la consola. |

### Qué debe traer el archivo

- **Columnas obligatorias:** `id`, `proto`, `service`, `state` y las variables numéricas que usa el modelo elegido (su lista está en `model.json`, sección 11). Las demás columnas se ignoran, así que un archivo con todas las columnas de `RAW_COLUMNS` siempre sirve.
- **`id`:** entero y sin repetirse dentro del archivo, porque identifica cada flujo (sección 2).
- **Variables numéricas:** no pueden estar vacías, ni tener texto ni valores negativos. Un flujo así no se corrige: el archivo se rechaza con un mensaje que dice qué columnas y qué filas fallan.
- **Categóricas:** una categoría desconocida o vacía nunca causa rechazo; el modelo la trata como `other`.
- **Etiquetas:** el archivo **trae etiquetas** si tiene las dos columnas, `label` y `attack_cat`, y `use_labels` es `true`. `label` solo puede valer 0 o 1, y `attack_cat` uno de los 10 valores de la sección 2.
- **Una sola etiqueta:** si `use_labels` es `true` y el archivo tiene solo una de las dos columnas, se rechaza con un mensaje que dice cuál falta. Con `use_labels` = `false` no se rechaza, porque las dos columnas se ignoran.

Los casos de rechazo y sus mensajes están en la sección 9.

### Qué devuelve

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `analysis_id` | texto | No | Identifica este análisis (sección 2). Se usa en `GET /api/explain/{id}`, en `WS /ws/simulate` y en el enlace directo. |
| `model` | objeto | No | El modelo usado: `name`, `display_name` y `threshold`. |
| `has_labels` | booleano | No | Si el resultado usa etiquetas reales (regla de arriba). |
| `summary` | objeto | No | Los indicadores de la consola (tabla siguiente). |
| `flows` | lista | No | Un flujo predicho (sección 3) por cada fila del archivo, en el mismo orden del archivo. |

Campos de `summary`:

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `total_flows` | entero | No | Flujos analizados. |
| `alerts` | entero | No | Flujos con `is_alert` = `true`. |
| `alerts_by_severity` | objeto | No | Alertas por severidad: `critical`, `high`, `medium` y `low`. Siempre trae las cuatro, con 0 si no hay. |
| `detection_rate` | número de 0 a 1 | Sí | Detección: de los flujos con `label` = 1, la parte que es alerta. |
| `false_alarm_rate` | número de 0 a 1 | Sí | Falsas alarmas: de los flujos con `label` = 0, la parte que es alerta. |

`detection_rate` y `false_alarm_rate` son `null` cuando `has_labels` es `false`. También son `null` si el archivo trae etiquetas pero no hay ningún flujo del tipo que se divide: sin ataques reales no hay detección que calcular, y sin flujos normales no hay falsas alarmas.

### Paginación y filtros

El backend devuelve **todos** los flujos en una sola respuesta. La paginación, los filtros por severidad y el orden de la cola de alertas los hace el frontend.

### Ejemplo de respuesta

Muestra de demostración (500 flujos, con etiquetas), pedida con `use_sample` = `true`. La lista `flows` está recortada a un flujo:

```json
{
  "analysis_id": "sample-mock",
  "model": {
    "name": "mock",
    "display_name": "Modelo simulado",
    "threshold": 0.31
  },
  "has_labels": true,
  "summary": {
    "total_flows": 500,
    "alerts": 287,
    "alerts_by_severity": {
      "critical": 151,
      "high": 64,
      "medium": 39,
      "low": 33
    },
    "detection_rate": 0.9512,
    "false_alarm_rate": 0.1318
  },
  "flows": [
    {
      "id": 1532,
      "proto": "tcp",
      "service": "http",
      "state": "FIN",
      "attack_probability": 0.9731,
      "is_alert": true,
      "severity": "critical",
      "predicted_attack_cat": "Exploits",
      "true_label": 1,
      "true_attack_cat": "Exploits"
    }
  ]
}
```

Con un archivo subido, `analysis_id` es un texto aleatorio, por ejemplo `"a3f9c2e17b4d"`. La misma muestra con `use_labels` = `false` devuelve `"analysis_id": "sample-mock-unlabeled"`, `"has_labels": false`, `"detection_rate": null`, `"false_alarm_rate": null`, y `true_label` y `true_attack_cat` en `null` en cada flujo.

### Recuperar un análisis guardado: `GET /api/analysis/{analysis_id}`

Ruta de **solo lectura** que devuelve un análisis ya hecho, sin recalcular nada. La usa la consola cuando entra por un enlace directo (`index.html?analysis=<analysis_id>&flow=<id>`) para reconstruir la cola de alertas, por ejemplo desde el botón "Abrir en la cola de alertas" de la simulación.

- **Qué se envía:** el `analysis_id` en la ruta. Por ejemplo: `GET /api/analysis/a3f9c2e17b4d`.
- **Qué devuelve:** exactamente lo mismo que devolvió `POST /api/predict` al crear ese análisis, con los mismos campos y el mismo modo de etiquetas.
- **Muestra de demostración:** si su análisis no está en memoria, el backend lo vuelve a generar (sección 2).
- **Análisis que ya no existe:** error que pide volver a cargar el archivo (sección 9).

## 5. `GET /api/explain/{id}`

Explica por qué el modelo le dio a un flujo su probabilidad de ataque: cuánto empujó cada variable hacia "ataque" o hacia "normal". La explicación se calcula solo cuando se pide, con el modelo que hizo el análisis.

### Qué se envía

| Parámetro | Dónde va | Tipo | Obligatorio | Qué es |
|---|---|---|---|---|
| `id` | en la ruta | entero | Sí | `id` del flujo (sección 2). |
| `analysis_id` | en la consulta (`?analysis_id=...`) | texto | Sí | Análisis al que pertenece el flujo (sección 2). |

Por ejemplo: `GET /api/explain/1532?analysis_id=sample-mock`.

### Qué devuelve

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `analysis_id` | texto | No | El mismo que se envió. |
| `flow` | objeto | No | El flujo predicho (sección 3), para abrir el panel lateral aunque la página no tenga el análisis, como al entrar por un enlace directo. |
| `can_explain` | booleano | No | Si el modelo del análisis puede explicar sus decisiones (`can_explain` en su `model.json`, sección 11). |
| `contributions` | lista | Sí | Una entrada por variable (tabla siguiente). `null` si `can_explain` es `false`. |

Cada entrada de `contributions`:

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `feature` | texto | No | Nombre técnico de la variable, como en `RAW_COLUMNS` (sección 2). |
| `value` | número o texto | Sí | Valor del flujo en el archivo, antes de cualquier transformación. Texto para `proto`, `service` y `state`; `null` si la celda está vacía. |
| `contribution` | número | No | Cuánto empujó esa variable. **Positivo:** hacia "ataque". **Negativo:** hacia "normal". |

### Reglas

- **Una entrada por variable original:** las columnas one-hot de `proto`, `service` y `state` se **suman** y aparecen como una sola entrada con el nombre de la variable. El analista ve `proto`, no `proto_tcp` ni `proto_other`.
- **Solo las variables que usa el modelo:** un modelo sin TTL no devuelve `sttl`, `dttl` ni `ct_state_ttl`. Las columnas eliminadas en la preparación (por ejemplo, `swin`) nunca aparecen.
- **Orden:** de mayor a menor efecto, es decir, por el valor absoluto de `contribution`. El frontend decide cuántas mostrar.
- **Cómo se leen los números:** el signo y el tamaño relativo entre variables de un mismo flujo. La escala depende del método de explicación de cada modelo, así que no se comparan contribuciones entre modelos distintos.
- **Qué se explica:** la probabilidad de ataque (`attack_probability`), no el tipo probable.
- **Cualquier flujo:** se puede explicar un flujo aunque no sea alerta.
- **Modelo sin explicación:** si `can_explain` es `false`, la respuesta no es un error: trae `contributions` = `null` y el frontend muestra que ese modelo no explica sus decisiones.

### Ejemplo de respuesta

Lista `contributions` recortada a cuatro variables:

```json
{
  "analysis_id": "sample-mock",
  "flow": {
    "id": 1532,
    "proto": "tcp",
    "service": "http",
    "state": "FIN",
    "attack_probability": 0.9731,
    "is_alert": true,
    "severity": "critical",
    "predicted_attack_cat": "Exploits",
    "true_label": 1,
    "true_attack_cat": "Exploits"
  },
  "can_explain": true,
  "contributions": [
    { "feature": "sttl", "value": 254, "contribution": 2.41 },
    { "feature": "ct_srv_src", "value": 12, "contribution": 0.87 },
    { "feature": "service", "value": "http", "contribution": 0.35 },
    { "feature": "dmean", "value": 1306, "contribution": -0.42 }
  ]
}
```

Los errores posibles (análisis que ya no existe, flujo que no está en el análisis) están en la sección 9.

## 6. `GET /api/models`

Devuelve los modelos disponibles y cuál es el modelo por defecto. Con esta lista el frontend arma los selectores de modelo y sabe qué puede hacer cada uno. No trae métricas: esas están en `GET /api/metrics` (sección 7).

### Qué se envía

Nada.

### Qué devuelve

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `default_model` | texto | No | `name` del modelo por defecto, según `registry.json` (sección 12). |
| `models` | lista | No | Un objeto por modelo disponible, en el orden de `registry.json` (tabla siguiente). |

Cada modelo de `models`:

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `name` | texto | No | Identificador del modelo (sección 2). Es el valor que se envía en el campo `model` de `POST /api/predict`. |
| `display_name` | texto | No | Nombre en español para la interfaz. |
| `is_mock` | booleano | No | `true` si es el modelo simulado (sección 13), cuyas respuestas son inventadas. |
| `can_explain` | booleano | No | Si puede explicar sus decisiones con `GET /api/explain/{id}`. Mismo campo y nombre que en `model.json`. |
| `use_ttl` | booleano | No | Si usa las variables de TTL (`sttl`, `dttl`, `ct_state_ttl`). |
| `threshold` | número de 0 a 1 | No | Umbral de alerta del modelo, tomado de su `model.json`. |

Todos los campos salen de `registry.json` y del `model.json` de cada modelo. La app los lee una sola vez, al arrancar.

### Ejemplo de respuesta

Mientras no haya modelos reales, el único modelo es el simulado:

```json
{
  "default_model": "mock",
  "models": [
    {
      "name": "mock",
      "display_name": "Modelo simulado",
      "is_mock": true,
      "can_explain": true,
      "use_ttl": true,
      "threshold": 0.31
    }
  ]
}
```

### Elegir el modelo por defecto

La pantalla Modelos permite elegir qué modelo usar. La elección **se guarda en el navegador** (`localStorage`), no en el servidor:

- **`default_model` es solo el modelo inicial:** se usa mientras la persona no haya elegido otro en ese navegador.
- **El frontend envía el modelo elegido:** en el campo `model` de cada `POST /api/predict`. La simulación (sección 8) no recibe un modelo: reproduce un análisis que el frontend creó con el modelo elegido. Así la consola y la simulación usan siempre el mismo modelo.
- **Modelo que ya no existe:** si el modelo guardado en el navegador ya no está en la lista de `GET /api/models`, el frontend usa `default_model`.
- **Sin rutas de escritura:** la API no tiene ninguna ruta que cambie el modelo por defecto. `registry.json` solo lo escribe `ml/` al registrar modelos.
- **Por navegador:** la elección vale solo en ese navegador. En otro computador se empieza otra vez con `default_model`.

## 7. `GET /api/metrics`

Devuelve las métricas oficiales de cada modelo para la pantalla Modelos. Salen de la evaluación sobre el **conjunto de prueba completo** (82.332 flujos), guardada en el `model.json` de cada modelo (sección 11). No dependen del archivo cargado en la consola: esas son las de `summary` en `POST /api/predict`.

### Qué se envía

Nada.

### Qué devuelve

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `models` | lista | No | Un objeto por modelo, en el orden de `registry.json` (tabla siguiente). |

Cada modelo de `models`:

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `name` | texto | No | Identificador del modelo (sección 2). |
| `display_name` | texto | No | Nombre en español para la interfaz. |
| `is_mock` | booleano | No | `true` si es el modelo simulado: sus métricas son inventadas y la pantalla debe advertirlo. |
| `test_flows` | entero | No | Flujos de prueba con los que se evaluó. |
| `detection` | objeto | No | Métricas de la detección de ataques (tarea binaria). |
| `attack_type` | objeto | No | Métricas del tipo de ataque (tarea multiclase). |
| `complexity` | objeto | Sí | Tiempos de entrenamiento y predicción y tamaño del modelo, tal como están en `model.json` (sección 11). `null` en el modelo simulado, que no se entrena. |

### Métricas de la detección (`detection`)

Comparan `is_alert` con `label` en todos los flujos de prueba, con el umbral del modelo. Un ataque real con alerta es un verdadero positivo (`tp`); un flujo normal con alerta, un falso positivo (`fp`).

| Campo | Tipo | Qué mide |
|---|---|---|
| `detection_rate` | número de 0 a 1 | De los ataques reales, la parte que es alerta: `tp / (tp + fn)`. Es el criterio del umbral. |
| `false_alarm_rate` | número de 0 a 1 | De los flujos normales reales, la parte que es alerta: `fp / (fp + tn)`. Mismo significado que en `POST /api/predict`. |
| `precision` | número de 0 a 1 | De las alertas, la parte que son ataques reales: `tp / (tp + fp)`. |
| `f1` | número de 0 a 1 | Media armónica de `precision` y `detection_rate`. |
| `pr_auc` | número de 0 a 1 | Área bajo la curva de precisión y detección (*average precision*). No depende del umbral: es la métrica para comparar modelos sin umbral en la pantalla Modelos. |
| `roc_auc` | número de 0 a 1 | Área bajo la curva ROC. No depende del umbral; se incluye para comparar con la literatura. |
| `accuracy` | número de 0 a 1 | Parte de los flujos clasificados bien. **Solo de referencia**, para comparar con artículos que la reportan: no se usa para decidir ni se muestra como métrica principal. |
| `confusion` | objeto | Conteos `tp`, `fp`, `tn` y `fn`, para mostrar números absolutos. |

`precision` es `null` si no hay ninguna alerta, porque sin alertas no hay sobre qué calcularla; en ese caso `f1` es 0. Estas métricas se calculan solo con datos que traen flujos normales y ataques reales (validación y prueba). Con una sola clase, `ml/` lanza un error.

### Métricas del tipo de ataque (`attack_type`)

Se miden **solo sobre los ataques reales que dieron alerta**, porque el tipo probable solo existe en las alertas (sección 3). Se compara `predicted_attack_cat` con `attack_cat` entre los 9 tipos de ataque, sin `"Normal"`.

| Campo | Tipo | Qué mide |
|---|---|---|
| `evaluated_flows` | entero | Flujos evaluados: los ataques reales con alerta. Siempre es igual a `detection.confusion.tp`. |
| `macro_f1` | número de 0 a 1 | Promedio de `f1` de los 9 tipos, cada uno con el mismo peso. Así un tipo pequeño como `Worms` pesa lo mismo que `Generic`. |
| `per_class` | lista | Una entrada por cada uno de los 9 tipos: `attack_cat`, `precision`, `recall`, `f1` y `support` (flujos reales de ese tipo evaluados). Siempre trae los 9, en el orden de la sección 2. |
| `confusion` | objeto | Matriz de confusión entre los 9 tipos: `labels` (los 9 tipos, en orden) y `matrix` (9 filas de 9 enteros). La fila es el tipo real y la columna el tipo predicho. |

En `per_class`, una métrica es `null` cuando no se puede calcular: `precision` si el tipo nunca se predijo, `recall` si no tiene flujos reales (`support` = 0) y `f1` si el tipo no aparece ni en lo real ni en lo predicho. Si un tipo tiene flujos pero nunca se predijo, su `f1` es 0. `macro_f1` promedia solo los `f1` que se pueden calcular, así que un tipo ausente no cuenta como 0. Si no hay ningún flujo evaluado, `macro_f1` es `null`.

### Ejemplo de respuesta

Métricas inventadas del modelo simulado. Los conteos de cada tipo salen de los flujos reales de la prueba, para que los números sean coherentes entre sí. `complexity` es `null` porque el modelo simulado no se entrena; un modelo real trae aquí los campos de la sección 11:

```json
{
  "models": [
    {
      "name": "mock",
      "display_name": "Modelo simulado",
      "is_mock": true,
      "test_flows": 82332,
      "detection": {
        "detection_rate": 0.9493,
        "false_alarm_rate": 0.1452,
        "precision": 0.889,
        "f1": 0.9182,
        "pr_auc": 0.9611,
        "roc_auc": 0.9705,
        "accuracy": 0.9068,
        "confusion": { "tp": 43034, "fp": 5372, "tn": 31628, "fn": 2298 }
      },
      "attack_type": {
        "evaluated_flows": 43034,
        "macro_f1": 0.8526,
        "per_class": [
          { "attack_cat": "Generic", "precision": 0.9999, "recall": 0.99, "f1": 0.9949, "support": 18897 },
          { "attack_cat": "Exploits", "precision": 0.804, "recall": 0.87, "f1": 0.8357, "support": 10575 },
          { "attack_cat": "Fuzzers", "precision": 0.9177, "recall": 0.9099, "f1": 0.9138, "support": 4850 },
          { "attack_cat": "DoS", "precision": 0.719, "recall": 0.6102, "f1": 0.6601, "support": 3925 },
          { "attack_cat": "Reconnaissance", "precision": 0.892, "recall": 0.9099, "f1": 0.9009, "support": 3251 },
          { "attack_cat": "Analysis", "precision": 0.8226, "recall": 0.7997, "f1": 0.811, "support": 609 },
          { "attack_cat": "Backdoor", "precision": 0.7914, "recall": 0.7288, "f1": 0.7588, "support": 531 },
          { "attack_cat": "Shellcode", "precision": 1.0, "recall": 0.8817, "f1": 0.9371, "support": 355 },
          { "attack_cat": "Worms", "precision": 1.0, "recall": 0.7561, "f1": 0.8611, "support": 41 }
        ],
        "confusion": {
          "labels": ["Generic", "Exploits", "Fuzzers", "DoS", "Reconnaissance", "Analysis", "Backdoor", "Shellcode", "Worms"],
          "matrix": [
            [18708,  189,    0,    0,    0,   0,   0,   0,  0],
            [    0, 9200,  317,  846,  212,   0,   0,   0,  0],
            [    0,  291, 4413,    0,  146,   0,   0,   0,  0],
            [    0, 1374,    0, 2395,    0,  78,  78,   0,  0],
            [    0,  228,   65,    0, 2958,   0,   0,   0,  0],
            [    0,   61,    0,   37,    0, 487,  24,   0,  0],
            [    0,   64,    0,   53,    0,  27, 387,   0,  0],
            [    0,   28,   14,    0,    0,   0,   0, 313,  0],
            [    2,    8,    0,    0,    0,   0,   0,   0, 31]
          ]
        }
      },
      "complexity": null
    }
  ]
}
```

## 8. `WS /ws/simulate`

Reproduce un análisis flujo por flujo, para la pantalla Simulación. Es un WebSocket: el navegador abre la conexión, envía mensajes para controlar la reproducción y recibe un mensaje por cada flujo.

La simulación **no analiza archivos**: reproduce un análisis que ya existe (sección 2), creado antes con `POST /api/predict` (por ejemplo, la muestra de demostración con `use_sample`). Por eso cada flujo que envía es el mismo de ese análisis, y el panel lateral y el botón "Abrir en la cola de alertas" funcionan con su `analysis_id`.

### Mensajes del navegador al servidor

Todos son JSON con un campo `type`.

| `type` | Otros campos | Qué hace |
|---|---|---|
| `"start"` | `analysis_id` (texto, obligatorio) y `speed` (entero, opcional: 1, 2 o 4; 1 por defecto) | Empieza a reproducir el análisis desde el primer flujo, con el modelo de ese análisis. |
| `"pause"` | — | Deja de enviar flujos. El frontend la envía con el botón Pausar y al hacer clic en un flujo para abrir el panel lateral. |
| `"resume"` | — | Sigue enviando desde el flujo siguiente al último enviado. |
| `"set_speed"` | `speed` (entero: 1, 2 o 4) | Cambia la velocidad en plena simulación, con los botones 1×, 2× y 4×. Vale desde el flujo siguiente. |

### Mensajes del servidor al navegador

| `type` | Otros campos | Cuándo llega |
|---|---|---|
| `"started"` | `analysis_id`, `model` (`name`, `display_name` y `threshold` del modelo del análisis), `has_labels`, `total_flows` y `speed` | Una vez, al aceptar el `"start"`. Con estos datos la pantalla prepara sus indicadores. |
| `"flow"` | `position` (entero, desde 1), `total_flows` y `flow` (flujo predicho, sección 3) | Uno por cada flujo, en el orden del análisis. |
| `"end"` | `total_flows` | Una vez, después del último flujo. Luego el servidor cierra la conexión. |
| `"error"` | `error` (formato de la sección 9) | Si algo falla. Luego el servidor cierra la conexión. |

### Reglas

- **Mismo formato que la consola:** `flow` es exactamente el flujo predicho de la sección 3, igual al de `POST /api/predict` para ese análisis.
- **Mismo modo de etiquetas:** los flujos respetan el `has_labels` del análisis. Si se creó sin etiquetas, `true_label` y `true_attack_cat` llegan en `null`.
- **El modelo es el del análisis:** la simulación no recibe un modelo, así que no puede usar uno distinto al de la consola. El frontend crea el análisis con el modelo elegido (sección 6) antes de abrir la simulación.
- **Muestra de demostración:** si su análisis no está en memoria, el backend lo vuelve a generar (sección 2).
- **Análisis que ya no existe:** mensaje `"error"` que pide volver a cargar el archivo (sección 9).
- **Ritmo:** el servidor envía los flujos uno a uno. La pausa entre flujos es `SIMULATION_INTERVAL_SECONDS` (1 segundo) dividido entre `speed`, y las velocidades permitidas son las de `SIMULATION_SPEEDS` (1, 2 y 4). Las dos constantes van en `config.py`:

  | `speed` | Botón | Pausa entre flujos |
  |---|---|---|
  | 1 | 1× | 1 segundo |
  | 2 | 2× | 0,5 segundos |
  | 4 | 4× | 0,25 segundos |

- **Velocidad no válida:** un `speed` que no esté en `SIMULATION_SPEEDS` se responde con un mensaje `"error"` (sección 9).
- **Reiniciar:** el botón Reiniciar cierra la conexión y abre una nueva, con otro `"start"`.

### Ejemplo de una sesión

```json
{ "type": "start", "analysis_id": "sample-mock" }
```

```json
{
  "type": "started",
  "analysis_id": "sample-mock",
  "model": { "name": "mock", "display_name": "Modelo simulado", "threshold": 0.31 },
  "has_labels": true,
  "total_flows": 500,
  "speed": 1
}
```

```json
{
  "type": "flow",
  "position": 1,
  "total_flows": 500,
  "flow": {
    "id": 1532,
    "proto": "tcp",
    "service": "http",
    "state": "FIN",
    "attack_probability": 0.9731,
    "is_alert": true,
    "severity": "critical",
    "predicted_attack_cat": "Exploits",
    "true_label": 1,
    "true_attack_cat": "Exploits"
  }
}
```

```json
{ "type": "pause" }
```

```json
{ "type": "resume" }
```

```json
{ "type": "set_speed", "speed": 4 }
```

```json
{ "type": "end", "total_flows": 500 }
```

## 9. Errores de la API

Todos los errores tienen el mismo formato, para que el frontend los muestre igual en cualquier pantalla.

### Formato

En las rutas HTTP, el cuerpo de la respuesta es:

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `error.code` | texto | No | Identificador fijo del error, en inglés y `snake_case` (tabla de abajo). El frontend lo usa para decidir qué hacer; nunca lo muestra. |
| `error.message` | texto | No | Mensaje en español para el usuario, listo para mostrarse tal cual. Dice qué pasó y qué hacer. |
| `error.details` | objeto | Sí | Datos para ubicar el problema (columnas, filas). `null` si el error no los necesita. |

En `WS /ws/simulate`, el mismo objeto `error` llega dentro de un mensaje `{"type": "error", "error": {...}}`, y después el servidor cierra la conexión.

### Reglas

- **Un tipo de error a la vez, completo:** si un archivo tiene varios tipos de problema, se informa el primero en el orden de la tabla; al corregirlo, el siguiente intento muestra el que siga. Dentro de un mismo tipo se informa todo junto: por ejemplo, `missing_columns` lista **todas** las columnas que faltan en un solo error, no una por una.
- **Filas como en el archivo:** las filas se cuentan como líneas del archivo, con el encabezado en la línea 1. Así coinciden con lo que se ve al abrirlo en una hoja de cálculo o un editor de texto.
- **Se listan pocas filas:** `details` trae como máximo las 5 primeras filas con problemas, y el total en otro campo.
- **Listas en texto legible:** en `message`, las columnas y filas se escriben separadas por comas (`sbytes, dbytes`), no como listas de Python (`['sbytes', 'dbytes']`). En `details` sí van como listas JSON.
- **Sin detalles técnicos:** un error inesperado nunca muestra al usuario el error de Python. El detalle queda en el registro del servidor.
- **Mismo formato siempre:** los errores de validación que FastAPI genera por defecto también se convierten a este formato.

### Códigos HTTP

| Código | Cuándo |
|---|---|
| 400 | El pedido o el archivo tienen un problema que el usuario puede corregir. |
| 404 | Lo que se pide no existe: un análisis o un flujo. |
| 413 | El archivo supera el tamaño máximo. |
| 500 | Error inesperado del servidor. |

### Errores de `POST /api/predict`

| `code` | HTTP | Cuándo | Mensaje | `details` |
|---|---|---|---|---|
| `no_file` | 400 | No se envió `file` y `use_sample` no es `true`. | "No se recibió ningún archivo. Selecciona un archivo CSV para analizar." | `null` |
| `file_and_sample` | 400 | Se envió `file` y además `use_sample` = `true`. | "Envía un archivo o pide la muestra de demostración, pero no los dos a la vez." | `null` |
| `file_too_large` | 413 | El archivo supera el tamaño máximo. | "El archivo pesa más de {límite} MB, que es el máximo permitido." | `max_mb` |
| `unreadable_file` | 400 | El archivo no se puede leer como CSV. | "No se pudo leer el archivo. Revisa que sea un CSV separado por comas, con una fila de encabezado." | `null` |
| `empty_file` | 400 | El archivo solo tiene encabezado o está vacío. | "El archivo no tiene flujos para analizar." | `null` |
| `unknown_model` | 400 | `model` no está en `registry.json`. | "El modelo «{model}» no está disponible. Elige otro en la pantalla Modelos." | `model` |
| `missing_columns` | 400 | Faltan columnas obligatorias (sección 4). | "Al archivo le faltan columnas obligatorias: {columnas}." Lista todas las que faltan. | `missing_columns` (lista con todas) |
| `missing_label_column` | 400 | `use_labels` = `true` y el archivo trae solo una de las dos etiquetas. | "El archivo trae la columna {presente} pero no la columna {faltante}. Agrega la columna que falta o analízalo sin etiquetas." | `missing_column` |
| `invalid_ids` | 400 | Algún `id` está vacío, no es un entero o se repite. | "Hay {total} flujo(s) con un id vacío, que no es un número entero o que está repetido. Primeras filas afectadas: {filas}." | `rows`, `total_rows` |
| `invalid_values` | 400 | Alguna variable numérica está vacía, no es un número o es negativa. | "Hay {total} flujo(s) con valores {vacíos o no numéricos / negativos} en las columnas {columnas}. Primeras filas afectadas: {filas}." | `reason`, `columns`, `rows`, `total_rows` |
| `invalid_labels` | 400 | Con etiquetas: `label` no es 0 o 1, o `attack_cat` no es uno de los 10 valores de la sección 2 (o alguna está vacía). | "Hay {total} flujo(s) con etiquetas no válidas en la columna {columna}. Primeras filas afectadas: {filas}." | `column`, `rows`, `total_rows` |

En `invalid_values`, `reason` vale `"empty_or_not_numeric"` o `"negative"`, que son las dos revisiones de valores de `validate_flows` en `dataset.py`. Los infinitos cuentan como `"empty_or_not_numeric"`.

### Errores de `GET /api/analysis/{analysis_id}`, `GET /api/explain/{id}` y `WS /ws/simulate`

| `code` | HTTP | Dónde | Cuándo | Mensaje | `details` |
|---|---|---|---|---|---|
| `missing_analysis_id` | 400 | explain | No se envió `analysis_id`. | "Falta indicar a qué análisis pertenece el flujo." | `null` |
| `analysis_not_found` | 404 | las tres | El análisis ya no está en memoria (y no es la muestra de demostración). | "Este análisis ya no está disponible. Vuelve a cargar el archivo para analizarlo de nuevo." | `analysis_id` |
| `flow_not_found` | 404 | explain | El `id` no está en ese análisis. | "El flujo {id} no está en este análisis." | `id` |
| `invalid_message` | — | simulación | El mensaje no es JSON, su `type` no existe o le falta un campo obligatorio. | "La simulación recibió un mensaje que no entiende. Reinicia la simulación." | `null` |
| `invalid_speed` | — | simulación | `speed` no está en `SIMULATION_SPEEDS`. | "La velocidad debe ser 1×, 2× o 4×." | `speed` |

En la simulación no hay código HTTP: el error llega como mensaje `"error"` (sección 8).

### Error inesperado

| `code` | HTTP | Mensaje | `details` |
|---|---|---|---|
| `internal_error` | 500 | "Ocurrió un error inesperado en el servidor. Intenta de nuevo; si se repite, avisa al equipo." | `null` |

### Ejemplos

Archivo con valores negativos:

```json
{
  "error": {
    "code": "invalid_values",
    "message": "Hay 2 flujo(s) con valores negativos en las columnas sbytes. Primeras filas afectadas: 14, 230.",
    "details": {
      "reason": "negative",
      "columns": ["sbytes"],
      "rows": [14, 230],
      "total_rows": 2
    }
  }
}
```

Análisis que ya no existe, en la simulación (por eso el objeto `error` va dentro de un mensaje `"error"`):

```json
{
  "type": "error",
  "error": {
    "code": "analysis_not_found",
    "message": "Este análisis ya no está disponible. Vuelve a cargar el archivo para analizarlo de nuevo.",
    "details": { "analysis_id": "a3f9c2e17b4d" }
  }
}
```

## 10. Carpeta de cada modelo

Aquí empieza el contrato de artefactos: lo que `ml/` deja en `artifacts/` y lo que `app/` lee de ahí. `ml/` y `app/` no se importan entre sí.

### Contenido de la carpeta

Cada modelo entrenado vive en `artifacts/models/<model_name>/`, donde `<model_name>` es su `name` (sección 2). La carpeta tiene exactamente dos archivos (la única excepción es el modelo simulado, abajo):

| Archivo | Qué contiene | Quién lo escribe | Quién lo lee |
|---|---|---|---|
| `model.joblib` | El modelo entrenado, con su preparación de datos. | `ml/` | `app/` |
| `model.json` | La descripción del modelo: variables, umbral, métricas y más (sección 11). | `ml/` | `app/` |

Un modelo existe para la app solo si además está registrado en `artifacts/registry.json` (sección 12).

**Excepción: el modelo simulado.** Un modelo con `is_mock: true` en su `model.json` tiene `model.json` pero **no** `model.joblib`. La app usa `mock.py` en su lugar (sección 13).

### Qué guarda `model.joblib`

Un diccionario, guardado con `joblib`, con dos claves:

| Clave | Qué es | Qué devuelve su `predict_proba` |
|---|---|---|
| `"detector"` | `Pipeline` que da la probabilidad de ataque. | Una columna por clase de `detector.classes_`. |
| `"attack_type_classifier"` | `Pipeline` que da la probabilidad de cada tipo de ataque. | Una columna por clase de `attack_type_classifier.classes_`. |

Si la detección y el tipo salen de un solo modelo multiclase, las dos claves apuntan al **mismo** `Pipeline` (joblib lo guarda una sola vez).

### Cómo deben estar hechos los pipelines

- **Llevan la preparación adentro.** Cada `Pipeline` recibe los flujos con sus columnas originales, tal como vienen en el archivo, y hace por dentro toda la preparación aprobada en el análisis exploratorio. Así la preparación del entrenamiento y la de la app son siempre la misma:
  - `log1p` a las variables asimétricas, con `FunctionTransformer(np.log1p)`.
  - Agrupación y one-hot de `CATEGORICAL_COLS`, con `OneHotEncoder(min_frequency=MIN_CATEGORY_FRACTION, handle_unknown="infrequent_if_exist", sparse_output=False)`. `MIN_CATEGORY_FRACTION` es `MIN_CATEGORY_COUNT / TRAIN_ROWS` (≈ 0,57 %): el mismo mínimo del análisis exploratorio, expresado como proporción. Así, al ajustar con la parte de entrenamiento, se conservan las mismas 18 categorías. Las categorías raras, las nuevas y las celdas vacías van a la misma columna "infrecuente" (`<variable>_infrequent_sklearn`).
  - Escalado según el método de preprocesamiento (`preprocessing_method`, sección 11): `StandardScaler` sobre las numéricas en M2 y M3, después de `log1p`; las columnas one-hot no se escalan.
  - Las columnas eliminadas en el análisis exploratorio no se usan.
- **Solo piezas de scikit-learn.** Para cargar `model.joblib` basta con scikit-learn y joblib; nunca hace falta importar código de `threat_detector`. Si no fuera así, la app dependería de `ml/`.
- **Otras librerías.** Un modelo puede usar otra librería que siga la interfaz de scikit-learn (`fit`, `predict_proba`, `classes_`). En ese caso, esa librería **debe estar en `requirements-prod.txt`**, porque la app la necesita para cargar el modelo.
- **Tamaño máximo.** Cada `model.joblib` debe pesar **menos de 50 MB**. `artifacts/` se sube a git para que la app funcione al clonar el repo, y git no está hecho para archivos grandes. `ml/` lo vigila con `model_size_mb` de `model.json` (sección 11); si un modelo supera el límite, el equipo lo revisa antes de subirlo.

### Cómo usa la app el modelo

1. **Valida el archivo** con las columnas que pide `model.json` (secciones 4 y 9). El `Pipeline` solo recibe flujos válidos. La validación la hace `validate_flows` de `dataset.py`, porque el `Pipeline` no valida.
2. **Calcula `attack_probability` con el detector.** Lo hace según el tipo de detector que declara `model.json` (sección 11); nunca lo deduce:

   | Tipo de detector | `attack_probability` |
   |---|---|
   | Binario (clases 0 y 1) | La probabilidad de la clase `1`. |
   | Multiclase (los 10 valores de `attack_cat`) | 1 − la probabilidad de la clase `"Normal"`. |

3. **Aplica el umbral y la severidad** con `threshold` de `model.json` y los cortes de `config.py` (sección 3), con `is_alert` y `severity` de `artifacts.py`, que `ml/` también usa.
4. **Calcula `predicted_attack_cat`**, solo para las alertas: el tipo con mayor probabilidad del clasificador entre los 9 tipos de ataque, sin contar `"Normal"` aunque esté entre sus clases (sección 3).

**Las clases se ubican por su nombre, nunca por su posición.** La app busca la columna de `1`, de `"Normal"` o de cada tipo de ataque en `classes_`. Así no importa en qué orden las haya guardado scikit-learn.

### Versión de scikit-learn

Un modelo guardado con una versión de scikit-learn puede comportarse distinto, o no cargar, con otra. Por eso:

- `model.json` guarda la versión de scikit-learn con la que se entrenó (sección 11).
- Al cargar el modelo, la app la compara con la versión instalada. Si no coinciden, **avisa** en el registro del servidor, con el nombre del modelo y las dos versiones.

### Carga

- La app carga cada modelo registrado **una sola vez, al arrancar**, y lo mantiene en memoria.
- **Si un modelo registrado no se puede cargar** (falta un archivo, está dañado o falta una librería), **la app no arranca** y muestra un error claro con el nombre del modelo y la causa. Así el problema se ve de inmediato y nunca hay una pantalla Modelos con datos a medias.
- La app **nunca entrena** ni modifica nada dentro de `artifacts/`.
- **El modelo simulado no cuenta como un modelo que no se pudo cargar:** si `model.json` dice `is_mock: true`, la app no busca `model.joblib` y usa `mock.py` en su lugar (sección 13). Que falte su `model.joblib` es lo esperado, no un error.

## 11. `model.json`

Describe un modelo entrenado. Lo escribe `ml/` al exportar el modelo y lo lee la app al arrancar. De aquí salen el umbral, las columnas que se validan, los datos de `GET /api/models` y las métricas de `GET /api/metrics`.

### Identificación

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `name` | texto | No | Identificador del modelo; igual al nombre de su carpeta (sección 2). |
| `display_name` | texto | No | Nombre en español para la interfaz. |
| `is_mock` | booleano | No | `true` solo para el modelo simulado (sección 13). Un modelo con `is_mock: true` tiene `model.json` pero no `model.joblib`: la app usa `mock.py` en su lugar, y eso no cuenta como un modelo que no se pudo cargar (sección 10). |
| `trained_at` | texto | Solo en el simulado | Fecha y hora del entrenamiento, en formato ISO 8601 y hora UTC (por ejemplo, `"2026-11-20T15:42:10Z"`). `null` en el modelo simulado, que no se entrena. |

### Formato del modelo

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `sklearn_version` | texto | Solo en el simulado | Versión de scikit-learn con la que se entrenó. La app la compara con la instalada (sección 10). `null` en el modelo simulado. |
| `detector_type` | texto | No | `"binary"` si el detector predice `label` (clases 0 y 1); `"multiclass"` si predice `attack_cat` (los 10 valores). La app lo lee aquí y nunca lo deduce (sección 10). |

### Variables

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `preprocessing_method` | texto | Solo en el simulado | Método de preprocesamiento con el que se entrenó el modelo: `"m1"`, `"m2"` o `"m3"`, una de las claves de `PREPROCESSING_METHODS` en `ml/preprocessing.py`. Es informativo: la app no lo usa, porque la preparación ya está dentro del `Pipeline`. `null` en el modelo simulado, que no se preprocesa. |
| `use_ttl` | booleano | No | Si el modelo usa las variables de TTL (`sttl`, `dttl`, `ct_state_ttl`). |
| `numeric_cols` | lista de textos | No | Variables numéricas que recibe el modelo, con su nombre técnico. Son las que la app exige y valida en el archivo (secciones 4 y 9). |
| `categorical_cols` | lista de textos | No | Variables categóricas que recibe el modelo: siempre `CATEGORICAL_COLS` (`proto`, `service`, `state`). Se exigen, pero una categoría desconocida o vacía nunca causa rechazo. |
| `log_cols` | lista de textos | No | Variables a las que el `Pipeline` les aplica `log1p`. Es informativo: la app no la usa, porque la transformación ya está dentro del `Pipeline`. |
| `feature_groups` | objeto | No | Para cada variable original, las columnas que salen de la preparación del `Pipeline` (los nombres de `get_feature_names_out`). Una variable numérica tiene una sola columna; una categórica, una por categoría más la columna "infrecuente". La app lo usa para sumar las contribuciones por variable (sección 5). |

Los nombres de `numeric_cols`, `categorical_cols`, `log_cols` y `use_ttl` son los mismos de `fit_preparation` en el análisis exploratorio.

`use_ttl` y `preprocessing_method` deben coincidir: `"m3"` va con `use_ttl: false`; `"m1"` y `"m2"`, con `use_ttl: true`.

### Umbral

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `threshold` | número de 0 a 1 | No | Umbral de alerta del modelo (secciones 3 y 10). |
| `threshold_rule` | objeto | Solo en el simulado | Con qué regla se calculó el umbral (tabla siguiente). `null` en el modelo simulado, cuyo umbral es fijo e inventado. |

Campos de `threshold_rule`:

| Campo | Tipo | Qué es |
|---|---|---|
| `target_recall` | número de 0 a 1 | Detección mínima exigida: `TARGET_RECALL` de `config.py` (0,95). |
| `computed_on` | texto | Siempre `"validation"`: el umbral nunca se calcula con la prueba. |
| `validation_flows` | entero | Flujos de validación usados. |
| `validation_detection_rate` | número de 0 a 1 | Detección lograda en validación con ese umbral (al menos `target_recall`). |
| `validation_false_alarm_rate` | número de 0 a 1 | Falsas alarmas en validación con ese umbral. |

La regla es la de `CLAUDE.md`: el umbral más alto que deja al menos el 95 % de los ataques reales de validación por encima.

### Explicación

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `can_explain` | booleano | No | Si el modelo puede explicar sus decisiones. Mismo nombre que en `GET /api/models` y `GET /api/explain/{id}`. |
| `explanation_method` | texto | Sí | Método con que se calculan las contribuciones. Sirve para saber en qué escala están (sección 5). `null` si `can_explain` es `false`. Los valores posibles se definen junto con los modelos; en el ejemplo, `"pending_method"` es provisional. |

### Métricas de prueba

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `test_metrics` | objeto | No | Resultado de la evaluación sobre el conjunto de prueba completo: `test_flows`, `detection` y `attack_type`, con exactamente los campos de la sección 7. `GET /api/metrics` los devuelve tal cual. |

Un modelo se registra en `registry.json` (sección 12) **solo después** de su evaluación final, así que en un modelo registrado `test_metrics` nunca es `null`.

### Complejidad

Para el análisis de complejidad del artículo. Todo se mide en `ml/`, al entrenar y evaluar; la app nunca mide nada. Los tiempos se toman con `time.perf_counter()`.

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `complexity` | objeto | Sí | Los campos de la tabla siguiente. `null` solo en el modelo simulado, que no se entrena ni tiene `model.joblib`. |

Campos de `complexity`:

| Campo | Tipo | Qué es | Cómo se mide |
|---|---|---|---|
| `training_seconds` | número | Tiempo de entrenamiento, en segundos. | Solo el `fit` del modelo final sobre la parte de entrenamiento. Si el detector y el clasificador son distintos, se suman los dos; si son el mismo `Pipeline`, se mide una vez. No incluye cargar datos, calcular el umbral ni evaluar. |
| `training_flows` | entero | Flujos usados para entrenar. | Filas que recibió el `fit`. |
| `prediction_ms_per_1000_flows` | número | Tiempo de predicción, en milisegundos por cada 1.000 flujos. | Se calculan `attack_probability` y el tipo para los 82.332 flujos de la prueba completa, con la preparación del `Pipeline` incluida. Se repite 5 veces y se toma la **mediana**; el resultado se divide entre 82,332. No incluye leer ni validar el CSV. |
| `model_size_mb` | número | Tamaño de `model.joblib`, en MB. | Tamaño del archivo en disco, justo después de guardarlo, dividido entre 1.000.000. |
| `hardware` | texto | Equipo donde se midió. | Procesador y número de núcleos, con `platform` y `os.cpu_count()`. Los tiempos solo se comparan entre modelos medidos en el mismo equipo. |

### Ejemplo

Valores inventados, pero con las listas de variables reales que salen de las decisiones del análisis exploratorio (32 numéricas, 21 con `log1p` y 53 columnas finales). La versión de scikit-learn y los valores de `complexity` son provisionales:

```json
{
  "name": "example_model",
  "display_name": "Modelo de ejemplo",
  "is_mock": false,
  "trained_at": "2026-11-20T15:42:10Z",
  "sklearn_version": "1.7.2",
  "detector_type": "binary",
  "preprocessing_method": "m1",
  "use_ttl": true,
  "numeric_cols": ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit", "synack", "ackdat", "smean", "dmean", "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst"],
  "categorical_cols": ["proto", "service", "state"],
  "log_cols": ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit", "dmean", "response_body_len", "ct_srv_src", "ct_dst_ltm", "ct_dst_src_ltm", "ct_src_ltm", "ct_srv_dst"],
  "feature_groups": {
    "dur": ["dur"],
    "spkts": ["spkts"],
    "dpkts": ["dpkts"],
    "sbytes": ["sbytes"],
    "dbytes": ["dbytes"],
    "rate": ["rate"],
    "sttl": ["sttl"],
    "dttl": ["dttl"],
    "sload": ["sload"],
    "dload": ["dload"],
    "sloss": ["sloss"],
    "dloss": ["dloss"],
    "sinpkt": ["sinpkt"],
    "dinpkt": ["dinpkt"],
    "sjit": ["sjit"],
    "djit": ["djit"],
    "synack": ["synack"],
    "ackdat": ["ackdat"],
    "smean": ["smean"],
    "dmean": ["dmean"],
    "trans_depth": ["trans_depth"],
    "response_body_len": ["response_body_len"],
    "ct_srv_src": ["ct_srv_src"],
    "ct_state_ttl": ["ct_state_ttl"],
    "ct_dst_ltm": ["ct_dst_ltm"],
    "ct_src_dport_ltm": ["ct_src_dport_ltm"],
    "ct_dst_sport_ltm": ["ct_dst_sport_ltm"],
    "ct_dst_src_ltm": ["ct_dst_src_ltm"],
    "ct_ftp_cmd": ["ct_ftp_cmd"],
    "ct_flw_http_mthd": ["ct_flw_http_mthd"],
    "ct_src_ltm": ["ct_src_ltm"],
    "ct_srv_dst": ["ct_srv_dst"],
    "proto": ["proto_arp", "proto_ospf", "proto_sctp", "proto_tcp", "proto_udp", "proto_unas", "proto_infrequent_sklearn"],
    "service": ["service_-", "service_dns", "service_ftp", "service_ftp-data", "service_http", "service_pop3", "service_smtp", "service_ssh", "service_infrequent_sklearn"],
    "state": ["state_CON", "state_FIN", "state_INT", "state_REQ", "state_infrequent_sklearn"]
  },
  "threshold": 0.31,
  "threshold_rule": {
    "target_recall": 0.95,
    "computed_on": "validation",
    "validation_flows": 35068,
    "validation_detection_rate": 0.9501,
    "validation_false_alarm_rate": 0.1387
  },
  "can_explain": true,
  "explanation_method": "pending_method",
  "test_metrics": {
    "test_flows": 82332,
    "detection": {
      "detection_rate": 0.9493,
      "false_alarm_rate": 0.1452,
      "precision": 0.889,
      "f1": 0.9182,
      "pr_auc": 0.9611,
      "roc_auc": 0.9705,
      "accuracy": 0.9068,
      "confusion": { "tp": 43034, "fp": 5372, "tn": 31628, "fn": 2298 }
    },
    "attack_type": {
      "evaluated_flows": 43034,
      "macro_f1": 0.8526,
      "per_class": [
        { "attack_cat": "Generic", "precision": 0.9999, "recall": 0.99, "f1": 0.9949, "support": 18897 },
        { "attack_cat": "Exploits", "precision": 0.804, "recall": 0.87, "f1": 0.8357, "support": 10575 },
        { "attack_cat": "Fuzzers", "precision": 0.9177, "recall": 0.9099, "f1": 0.9138, "support": 4850 },
        { "attack_cat": "DoS", "precision": 0.719, "recall": 0.6102, "f1": 0.6601, "support": 3925 },
        { "attack_cat": "Reconnaissance", "precision": 0.892, "recall": 0.9099, "f1": 0.9009, "support": 3251 },
        { "attack_cat": "Analysis", "precision": 0.8226, "recall": 0.7997, "f1": 0.811, "support": 609 },
        { "attack_cat": "Backdoor", "precision": 0.7914, "recall": 0.7288, "f1": 0.7588, "support": 531 },
        { "attack_cat": "Shellcode", "precision": 1.0, "recall": 0.8817, "f1": 0.9371, "support": 355 },
        { "attack_cat": "Worms", "precision": 1.0, "recall": 0.7561, "f1": 0.8611, "support": 41 }
      ],
      "confusion": {
        "labels": ["Generic", "Exploits", "Fuzzers", "DoS", "Reconnaissance", "Analysis", "Backdoor", "Shellcode", "Worms"],
        "matrix": [
          [18708, 189, 0, 0, 0, 0, 0, 0, 0],
          [0, 9200, 317, 846, 212, 0, 0, 0, 0],
          [0, 291, 4413, 0, 146, 0, 0, 0, 0],
          [0, 1374, 0, 2395, 0, 78, 78, 0, 0],
          [0, 228, 65, 0, 2958, 0, 0, 0, 0],
          [0, 61, 0, 37, 0, 487, 24, 0, 0],
          [0, 64, 0, 53, 0, 27, 387, 0, 0],
          [0, 28, 14, 0, 0, 0, 0, 313, 0],
          [2, 8, 0, 0, 0, 0, 0, 0, 31]
        ]
      }
    }
  },
  "complexity": {
    "training_seconds": 48.3,
    "training_flows": 140273,
    "prediction_ms_per_1000_flows": 12.6,
    "model_size_mb": 4.8,
    "hardware": "Equipo de ejemplo, 8 núcleos"
  }
}
```

## 12. `registry.json`

Lista los modelos que la app puede usar y cuál es el modelo por defecto. Está en `artifacts/registry.json`.

### Campos

| Campo | Tipo | Puede ser `null` | Qué es |
|---|---|---|---|
| `default_model` | texto | No | `name` del modelo por defecto. Es solo el modelo inicial: cada navegador puede elegir otro (sección 6). |
| `models` | lista | No | Un objeto por modelo registrado, con su `name`. El orden de esta lista es el orden de `GET /api/models` y de `GET /api/metrics`. |

Cada modelo de `models` tiene por ahora un solo campo, `name`. Es un objeto y no un texto suelto para poder agregarle campos después sin romper el formato.

### Reglas

- **Quién lo escribe:** solo `ml/`, al registrar un modelo después de su evaluación final (sección 11). La app solo lo lee, una vez, al arrancar.
- **Sin rutas en el archivo:** la carpeta de cada modelo siempre es `artifacts/models/<name>/`, así que el registro guarda solo el nombre. Así no aparece ninguna ruta del computador de quien entrenó.
- **Nombres únicos:** un `name` no puede repetirse en `models`.
- **Todo debe coincidir:** cada `name` registrado tiene su carpeta con `model.json` (y `model.joblib`, salvo el modelo simulado), y el `name` de ese `model.json` es el mismo. `default_model` es uno de los `name` de `models`.
- **Si algo no coincide, la app no arranca:** muestra un error claro que dice qué falta o qué no coincide, igual que con un modelo que no se puede cargar (sección 10). Esto también aplica si falta `registry.json`.
- **Modelos sin registrar:** una carpeta en `artifacts/models/` que no está en `models` se ignora. Así se puede guardar un modelo antes de su evaluación final sin que aparezca en la app.
- **Registrar no cambia el modelo por defecto:** agregar un modelo a `models` no cambia `default_model`. Cambiarlo es una decisión del equipo.
- **Mientras no haya modelos reales:** el único modelo registrado es el simulado, y es el modelo por defecto.

### Ejemplos

Mientras no haya modelos reales:

```json
{
  "default_model": "mock",
  "models": [
    { "name": "mock" }
  ]
}
```

Con un modelo real registrado (nombre de ejemplo). El simulado puede seguir en la lista o quitarse cuando el equipo lo decida:

```json
{
  "default_model": "example_model",
  "models": [
    { "name": "example_model" },
    { "name": "mock" }
  ]
}
```

## 13. El modelo simulado

Permite programar y probar la app completa antes de tener modelos reales. Responde con valores **inventados**, pero en el formato definitivo de este contrato, así que al llegar los modelos reales no hay que cambiar el frontend ni las rutas.

### Cómo existe

- **Carpeta:** `artifacts/models/mock/`, con solo `model.json` y **sin** `model.joblib` (sección 10).
- **Registro:** está en `registry.json` y, mientras no haya modelos reales, es el único modelo y el modelo por defecto (sección 12).
- **Código:** las predicciones las calcula `app/mock.py`, no un `Pipeline`. La app lo usa porque `model.json` dice `is_mock: true`.
- **En la interfaz:** `is_mock` llega en `GET /api/models` y en `GET /api/metrics`, y la interfaz debe advertir que los resultados son inventados mientras se use este modelo.

### Su `model.json`

Tiene todos los campos de la sección 11, con estas particularidades:

| Campo | Valor en el modelo simulado |
|---|---|
| `name` | `"mock"` |
| `display_name` | `"Modelo simulado"` |
| `is_mock` | `true` |
| `trained_at`, `sklearn_version`, `preprocessing_method`, `threshold_rule`, `complexity` | `null`, porque no se entrena. |
| `detector_type` | `"binary"` |
| `use_ttl` | `true` |
| `numeric_cols`, `categorical_cols`, `log_cols`, `feature_groups` | Los mismos de un modelo real con TTL (ejemplo de la sección 11). Así la app valida los archivos exactamente igual que con un modelo real. |
| `threshold` | `0.31`, fijo e inventado. |
| `can_explain` | `true`, para poder probar el panel de explicación. |
| `explanation_method` | `"mock"` |
| `test_metrics` | Inventadas: las del ejemplo de la sección 7. |

### Cómo responde

- **Mismo formato:** cada flujo predicho, cada explicación y cada mensaje de la simulación tienen exactamente el formato de las secciones 3 a 8. La regla de severidad, el umbral y la del tipo probable se aplican igual que con un modelo real.
- **Siempre lo mismo para el mismo flujo:** el mismo flujo da siempre la misma probabilidad, el mismo tipo y la misma explicación. Así se puede probar la app con resultados repetibles, y el análisis regenerado de la muestra de demostración (sección 2) sale idéntico al original.
- **No mira las etiquetas:** calcula todo solo con las variables del flujo, nunca con `label` ni `attack_cat`. Así el mismo archivo da los mismos resultados con y sin etiquetas, como pasará con un modelo real.
- **Explicación inventada:** una contribución por cada variable de `feature_groups`, con su valor real del archivo y ordenadas de mayor a menor efecto, como en la sección 5.
