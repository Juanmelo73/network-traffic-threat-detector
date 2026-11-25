# Network Traffic Threat Detector

Sistema de detección de intrusiones de red (IDS) con *machine learning*, entrenado con el dataset **UNSW-NB15** y con una interfaz web. Es un prototipo: analiza flujos de red **ya extraídos** en el formato de UNSW-NB15, no tráfico en vivo.

Proyecto académico de la Especialización en Inteligencia Artificial de la Universidad Autónoma de Occidente.

## Qué hace

Para cada flujo de un archivo CSV, el sistema calcula:

- la **probabilidad de ataque** (de 0 a 1) y si el flujo es una **alerta**, comparando esa probabilidad con el umbral del modelo;
- la **severidad** de la alerta (crítica, alta, media o baja), a partir de la probabilidad;
- el **tipo de ataque más probable** entre los 9 del dataset;
- cuando el modelo lo permite, la **contribución de cada variable** a la decisión.

La interfaz web tiene tres pantallas: la **consola**, con la cola de alertas y filtros por severidad; **Simulación**, que reproduce un análisis flujo a flujo con una animación; y **Modelos**, que compara las métricas de los modelos y permite elegir cuál usar. Funciona en modo claro y oscuro, en computador y en celular.

## Estructura del proyecto

```
network-traffic-threat-detector/
├── src/threat_detector/      Código del proyecto (paquete de Python)
│   ├── config.py             Rutas y parámetros generales
│   ├── dataset.py            Columnas del dataset, carga y validación de flujos, muestra de demostración
│   ├── artifacts.py          Carga de los modelos y reglas para leer su salida (alerta, severidad, tipo)
│   ├── ml/                   Preparación de datos, umbral, métricas y exportación de modelos
│   └── app/                  Aplicación web: API con FastAPI y, en static/, los archivos de la interfaz
├── data/                     Dataset: los CSV no están en el repositorio (ver data/README.md)
├── notebooks/                Exploración de los datos y pruebas de cada parte del código
├── artifacts/                Modelos exportados, registro de modelos y figuras
├── docs/contracts.md         Contratos entre las partes: API web y formato de los modelos exportados
├── docs/design/              Guía de diseño de la interfaz: colores, tipografía, componentes e íconos
├── pyproject.toml, uv.lock   Definición del proyecto y versiones exactas de las dependencias
├── requirements-prod.txt     Dependencias de la aplicación
└── requirements.txt          Dependencias de desarrollo (incluye las de la aplicación)
```

Los datos pasan por las partes en este orden: `data/raw/` → `ml/` → `artifacts/` → `app/`. `ml/` y `app/` solo se comunican a través de `artifacts/`.

| Notebook | Contenido |
|---|---|
| `01_exploration.ipynb` | Análisis exploratorio de UNSW-NB15 y decisiones de preparación de los datos |
| `dataset_presentation.ipynb` | Resumen del análisis exploratorio |
| `02_data_splits.ipynb` | Rutas, parámetros, carga de los datos, separación de entrenamiento y validación, y muestra de demostración |
| `03_preprocessing.ipynb` | Validación de flujos y los tres métodos de preprocesamiento |
| `04_threshold_and_artifacts.ipynb` | Umbral de alerta, severidad, métricas y formato de los modelos exportados |
| `05_models.ipynb` | Búsqueda de modelos en validación: barrido de las familias con sus valores por defecto, búsqueda de hiperparámetros y tablas para el artículo, en `artifacts/model_search/` |
| `06_final_training.ipynb` | Entrenamiento final: entrena los modelos elegidos y los de referencia, los evalúa una sola vez en la partición de prueba y registra en la app los 4 modelos |

## Instalación

Requisitos: [uv](https://docs.astral.sh/uv/). El proyecto usa Python 3.13, fijado en `.python-version`; si no está instalado, uv lo descarga.

Desde la raíz del repositorio:

```bash
uv sync
```

Esto crea el entorno virtual en `.venv/` con las versiones exactas de `uv.lock`. Las dependencias se instalan siempre con uv, no con `pip install`.

El código se ejecuta con `uv run`. Por ejemplo, para comprobar que el archivo de entrenamiento está bien copiado:

```bash
uv run python -c "from threat_detector.dataset import load_train; print(len(load_train()))"
```

Para los notebooks, se elige como kernel el entorno `.venv` del proyecto.

Las pruebas se corren con `uv run pytest`. Las de la interfaz usan un navegador; se instala una vez con `uv run playwright install --with-deps chromium` (pide la contraseña de `sudo` para las librerías del sistema). Sin ese navegador, esas pruebas se saltan solas.

## Datos

Los CSV de UNSW-NB15 no están en el repositorio. [data/README.md](data/README.md) explica de dónde descargarlos, dónde copiarlos (`data/raw/`), qué contiene cada archivo y cómo citar el dataset.

La muestra de demostración de la aplicación (`src/threat_detector/app/static/sample_flows.csv`, 500 flujos) sí está en el repositorio.

## Modelos

La aplicación tiene 4 modelos. Los 3 primeros se eligieron con la parte de validación, entre 8 familias de scikit-learn y sus hiperparámetros, dentro de 50 MB por modelo; la regresión logística es el modelo base. Cada modelo tiene dos partes: un **detector** (normal o ataque) y un **clasificador del tipo de ataque**.

Métricas en la partición oficial de prueba (82.332 flujos), usada una sola vez después de elegir los modelos:

| Modelo | Preprocesamiento | Recall (detección) | Falsas alarmas | Precisión | F1 | PR-AUC | F1 macro de tipos |
|---|---|---|---|---|---|---|---|
| HistGradientBoosting (por defecto) | M1 | 96,5 % | 16,5 % | 87,7 % | 0,919 | 0,988 | 0,560 |
| Random Forest | M2 | 97,1 % | 16,9 % | 87,5 % | 0,921 | 0,989 | 0,540 |
| Red neuronal (MLP) | M2 | 96,2 % | 19,4 % | 85,9 % | 0,907 | 0,984 | 0,462 |
| Regresión logística (modelo base) | M2 | 94,5 % | 24,6 % | 82,5 % | 0,881 | 0,972 | 0,366 |

- El umbral de alerta de cada modelo se calculó con la validación, para detectar al menos el 95 % de los ataques; en prueba, el recall queda un poco arriba o abajo de ese valor.
- El F1 macro de tipos se mide sobre los ataques reales que dieron alerta.
- HistGradientBoosting, Random Forest y la regresión logística explican cada decisión con la contribución de cada variable; la red neuronal no.

La búsqueda de modelos está en `notebooks/05_models.ipynb`; el entrenamiento final, la evaluación en prueba y el registro, en `notebooks/06_final_training.ipynb`. Los resultados completos, con las tablas y figuras para el artículo, están en `artifacts/model_search/` (ver su `README.md`).

## Arrancar la aplicación

Desde la raíz del repositorio:

```bash
uv run fastapi dev
```

La aplicación queda en http://127.0.0.1:8000 y se reinicia sola al guardar cambios en el código. La documentación interactiva de la API está en http://127.0.0.1:8000/docs. Se detiene con Ctrl+C.

Al arrancar, la aplicación carga los modelos de `artifacts/`. Si alguno falta o está dañado, no arranca, y el mensaje dice cuál es el problema.

## Estado actual

Terminado:

1. **Base compartida:** rutas, parámetros y carga del dataset.
2. **Contratos** de la API web y del formato de los modelos exportados (`docs/contracts.md`).
3. **Conjuntos de datos:** separación de entrenamiento y validación (80 % / 20 %, por grupos de flujos idénticos y estratificada por tipo de ataque) y muestra de demostración.
4. **Preprocesamiento:** validación de los flujos y tres métodos de preparación: M1 sin escalar, M2 con estandarización y M3 sin las variables de TTL.
5. **Umbral y métricas:** umbral de alerta calculado con la validación (detección mínima del 95 %), severidad y métricas de evaluación.
6. **Artefactos:** exportación, registro y carga de los modelos, y un modelo simulado que permite programar la aplicación antes de tener modelos reales.
7. **Pruebas automatizadas** con pytest (`uv run pytest`).
8. **Backend:** API con FastAPI que analiza archivos CSV, explica la decisión sobre cada flujo, entrega los modelos y sus métricas, y reproduce un análisis flujo por flujo.
9. **Frontend:** consola, simulación con animación y comparación de modelos, en HTML, CSS y JavaScript sin frameworks, en modo claro y oscuro.
10. **Modelos:** búsqueda en validación de 8 familias de modelos y sus hiperparámetros, entrenamiento final, evaluación en la partición de prueba y registro de los 4 modelos de la aplicación (ver [Modelos](#modelos)).

## Autores

- Juan José Melo
- Juana López
- Wilson Navia
- Jaiber Obando
- Eduardo Sarmiento

## Licencia

El código está bajo la licencia MIT (ver `LICENSE`). La licencia no cubre el dataset UNSW-NB15, que es de uso académico y debe citarse como indica `data/README.md`.
