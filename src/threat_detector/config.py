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
# Pausa entre flujos de la simulación con velocidad 1, en segundos; con velocidad s es este valor / s.
SIMULATION_INTERVAL_SECONDS = 1.0
SIMULATION_SPEEDS = (1, 2, 4)
