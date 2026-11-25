"""Rutas del proyecto y parámetros generales: todo el código los lee desde aquí."""

from pathlib import Path

# Raíz del proyecto: este archivo está en <raíz>/src/threat_detector/config.py.
ROOT = Path(__file__).resolve().parents[2]

RAW_DIR = ROOT / "data" / "raw"

TRAIN_CSV = RAW_DIR / "UNSW_NB15_training-set.csv"
TEST_CSV = RAW_DIR / "UNSW_NB15_testing-set.csv"
# "NUSW" no es un error: es el nombre que usa la fuente oficial.
FEATURES_CSV = RAW_DIR / "NUSW-NB15_features.csv"

# Filas de la partición oficial; otro número indica una descarga incompleta u otra versión.
TRAIN_ROWS = 175_341
TEST_ROWS = 82_332

ARTIFACTS_DIR = ROOT / "artifacts"
MODELS_DIR = ARTIFACTS_DIR / "models"
FIGURES_DIR = ARTIFACTS_DIR / "figures"
# Resultados de la búsqueda de modelos en validación: una fila por candidato (ml/training.py).
MODEL_SEARCH_DIR = ARTIFACTS_DIR / "model_search"
MODEL_SEARCH_CSV = MODEL_SEARCH_DIR / "search_results.csv"
# Para el artículo: errores que ningún modelo puede evitar porque hay flujos idénticos con
# etiquetas distintas (ml/evaluation.py); los escribe el notebook 05.
UNAVOIDABLE_TYPE_ERRORS_CSV = MODEL_SEARCH_DIR / "unavoidable_type_errors.csv"
LABEL_MIXED_GROUPS_CSV = MODEL_SEARCH_DIR / "label_mixed_groups.csv"
# Resultados del entrenamiento final, para el artículo (train_final_models de ml/training.py).
TEST_RESULTS_CSV = MODEL_SEARCH_DIR / "test_results.csv"
TEST_PER_TYPE_CSV = MODEL_SEARCH_DIR / "test_per_type.csv"
OOB_CSV = MODEL_SEARCH_DIR / "oob_vs_validation.csv"
# Resumen de los resultados finales para el artículo, armado desde test_results.csv y registry.json.
FINAL_RESULTS_JSON = MODEL_SEARCH_DIR / "final_results.json"
REGISTRY_PATH = ARTIFACTS_DIR / "registry.json"

# Archivos de la carpeta de cada modelo, artifacts/models/<model_name>/ (contrato, sección 10).
MODEL_JOBLIB = "model.joblib"
MODEL_JSON = "model.json"
# Peso máximo de un model.joblib, en MB: artifacts/ se sube a git (contrato, sección 10).
MAX_MODEL_SIZE_MB = 50
# Tamaños en MB: 1 MB = 1.000.000 bytes (contrato, sección 11).
BYTES_PER_MB = 1_000_000

STATIC_DIR = ROOT / "src" / "threat_detector" / "app" / "static"

# Separación de entrenamiento y validación.
RANDOM_STATE = 42
VALIDATION_SIZE = 0.20

# Las categorías con menos flujos que este mínimo en entrenamiento se agrupan en una columna
# infrecuente por variable.
MIN_CATEGORY_COUNT = 1000
# El mismo mínimo como proporción del archivo de entrenamiento completo (≈ 0,57 %). Así, al ajustar
# con solo una parte del entrenamiento, se conservan las mismas categorías que decidió el EDA.
MIN_CATEGORY_FRACTION = MIN_CATEGORY_COUNT / TRAIN_ROWS

# El umbral de alerta debe dejar por encima al menos esta parte de los ataques de validación.
TARGET_RECALL = 0.95

# Al elegir entre combinaciones de modelos, dos puntajes (PR-AUC o F1 macro) empatan si su
# diferencia con el mejor es menor que esto: el tercer decimal que muestra la app.
SCORE_TIE_TOLERANCE = 0.001

# Probabilidad de ataque mínima de cada severidad. La baja empieza en el umbral de cada modelo.
SEVERITY_CRITICAL = 0.90
SEVERITY_HIGH = 0.75
SEVERITY_MEDIUM = 0.60

# Muestra de demostración de la app (sample_flows.csv), tomada del conjunto de prueba.
DEMO_SAMPLE_SIZE = 500
DEMO_MIN_PER_ATTACK = 10
DEMO_SAMPLE_CSV = STATIC_DIR / "sample_flows.csv"

# Máximo de filas con problemas que se listan en un error de validación (contrato, sección 9).
MAX_ERROR_ROWS = 5

# App web (contrato, secciones 2, 8 y 9).
# Tamaño máximo del CSV que se sube a POST /api/predict, en MB.
MAX_UPLOAD_MB = 25
# Análisis de archivos subidos que se guardan en memoria; los de la muestra de demostración no
# cuentan, porque se regeneran solos.
MAX_STORED_ANALYSES = 15
# Los modelos entrenados predicen los archivos subidos por bloques de este número de flujos: así la
# memoria temporal de la predicción no crece con el archivo. HistGradientBoosting da exactamente lo
# mismo que con todo el archivo de una vez; la MLP y la regresión logística, probabilidades que difieren
# en menos de 1e-15 (alertas, severidad y tipo iguales), como el ruido que Random Forest ya tiene.
PREDICTION_BATCH_ROWS = 10_000
# Pausa entre flujos de la simulación con velocidad 1, en segundos; con velocidad s es este valor / s.
SIMULATION_INTERVAL_SECONDS = 1.0
SIMULATION_SPEEDS = (1, 2, 4)
