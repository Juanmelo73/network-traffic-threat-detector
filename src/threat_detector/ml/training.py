"""Exportación de los modelos entrenados a artifacts/ (contrato, secciones 10 a 12)."""

import json
import os
import re
import warnings
from datetime import timezone

import joblib
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

from threat_detector.artifacts import (
    DETECTOR_TYPES,
    PIPELINE_STEPS,
    check_model,
    check_model_info,
    load_model,
    read_model_info,
    read_registry,
)
from threat_detector.config import (
    ARTIFACTS_DIR,
    BYTES_PER_MB,
    MAX_MODEL_SIZE_MB,
    MODEL_JOBLIB,
    MODEL_JSON,
    MODELS_DIR,
    REGISTRY_PATH,
)
from threat_detector.dataset import CATEGORICAL_COLS, INPUT_COLS
from threat_detector.ml.preprocessing import (
    LOG_COLS,
    PREPROCESSING_METHODS,
    build_preprocessor,
    numeric_input_cols,
)

# Campos de complexity que se miden al entrenar; model_size_mb lo agrega export_model al guardar.
COMPLEXITY_INPUTS = {
    "training_seconds",
    "training_flows",
    "prediction_ms_per_1000_flows",
    "hardware",
}

# name de un modelo: minúsculas y snake_case, porque también es el nombre de su carpeta (contrato, sección 2).
MODEL_NAME_PATTERN = r"[a-z][a-z0-9_]*"
# Nombre del modelo simulado, que se escribe a mano: ml/ nunca lo exporta ni lo sobrescribe.
MOCK_MODEL_NAME = "mock"

# Sufijo del archivo temporal con que se escribe registry.json antes de reemplazarlo.
TEMP_SUFFIX = ".tmp"


def _piece_names(transformer):
    """Nombres de las piezas de una parte del ColumnTransformer, por ejemplo ["FunctionTransformer", "StandardScaler"]."""
    if isinstance(transformer, str):
        return [transformer]
    if isinstance(transformer, Pipeline):
        return [type(step).__name__ for _, step in transformer.steps]
    return [type(transformer).__name__]


def _preprocessor_structure(preprocessor):
    """Estructura de un preprocesador: cada parte con sus piezas y sus columnas."""
    if not isinstance(preprocessor, ColumnTransformer):
        return None
    return [
        (name, _piece_names(transformer), list(cols))
        for name, transformer, cols in preprocessor.transformers
    ]


def feature_groups(preprocessor):
    """Para cada variable original, las columnas que salen del preprocesador ya ajustado.

    Las claves van en el orden del contrato: primero las numéricas, en el orden del archivo, y
    después CATEGORICAL_COLS. Una numérica tiene una sola columna, con su mismo nombre; una
    categórica, una por categoría más la columna "infrecuente".
    """
    columns = {name: list(cols) for name, _, cols in preprocessor.transformers_}
    numeric = set(columns["log"]) | set(columns["plain"])
    groups = {c: [c] for c in INPUT_COLS if c in numeric}

    # Las columnas one-hot se reparten por su prefijo <variable>_. Solo se buscan entre las de la
    # parte categórica, así que una numérica como ct_state_ttl no se confunde con state.
    encoded = list(
        preprocessor.named_transformers_["categorical"].get_feature_names_out()
    )
    for col in columns["categorical"]:
        groups[col] = [name for name in encoded if name.startswith(f"{col}_")]

    # Cada columna de salida debe quedar en exactamente un grupo.
    grouped = [name for names in groups.values() for name in names]
    if sorted(grouped) != sorted(preprocessor.get_feature_names_out()):
        raise ValueError(
            "Las columnas del preprocesador no se pudieron repartir entre las variables originales."
        )
    return groups


def build_model_info(
    name,
    display_name,
    model,
    detector_type,
    preprocessing_method,
    threshold,
    threshold_rule,
    can_explain,
    explanation_method,
    test_metrics,
    complexity,
    trained_at,
):
    """Arma model.json como diccionario, con los campos en el orden del contrato (sección 11).

    model es el diccionario de model.joblib, ya entrenado. trained_at es un datetime con zona
    horaria y se escribe en UTC. complexity trae los campos medidos al entrenar; model_size_mb
    queda en None hasta que export_model guarda el modelo. Lanza ValueError si el modelo no está
    hecho como pide el contrato (sección 10).
    """
    if detector_type not in DETECTOR_TYPES:
        raise ValueError(
            f"Tipo de detector desconocido: {detector_type}. Usa uno de: {', '.join(DETECTOR_TYPES)}."
        )
    expected_structure = _preprocessor_structure(
        build_preprocessor(preprocessing_method)
    )

    # Los dos Pipelines con los pasos de nombre fijo y el preprocesador del método declarado: así
    # el método de model.json es el verdadero y el detector y el clasificador usan el mismo.
    for key in ("detector", "attack_type_classifier"):
        pipeline = model[key]
        if (
            not isinstance(pipeline, Pipeline)
            or list(pipeline.named_steps) != PIPELINE_STEPS
        ):
            raise ValueError(
                f"{key} debe ser un Pipeline con los pasos {' y '.join(PIPELINE_STEPS)}, en ese orden."
            )
        if _preprocessor_structure(pipeline["preprocessor"]) != expected_structure:
            raise ValueError(
                f"El preprocesador de {key} no es el del método {preprocessing_method}: "
                "el detector y el clasificador deben usar el método declarado."
            )

    if trained_at.utcoffset() is None:
        raise ValueError(
            "trained_at debe traer zona horaria para poder escribirlo en UTC."
        )
    if set(complexity) != COMPLEXITY_INPUTS:
        raise ValueError(
            f"complexity debe traer exactamente: {', '.join(sorted(COMPLEXITY_INPUTS))}."
        )

    use_ttl = PREPROCESSING_METHODS[preprocessing_method]["use_ttl"]
    numeric_cols = numeric_input_cols(use_ttl)
    return {
        "name": name,
        "display_name": display_name,
        "is_mock": False,
        "trained_at": trained_at.astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "sklearn_version": sklearn.__version__,
        "detector_type": detector_type,
        "preprocessing_method": preprocessing_method,
        "use_ttl": use_ttl,
        "numeric_cols": numeric_cols,
        "categorical_cols": list(CATEGORICAL_COLS),
        "log_cols": [c for c in numeric_cols if c in LOG_COLS],
        "feature_groups": feature_groups(model["detector"]["preprocessor"]),
        "threshold": float(threshold),
        "threshold_rule": threshold_rule,
        "can_explain": can_explain,
        "explanation_method": explanation_method,
        "test_metrics": test_metrics,
        "complexity": {
            "training_seconds": complexity["training_seconds"],
            "training_flows": complexity["training_flows"],
            "prediction_ms_per_1000_flows": complexity["prediction_ms_per_1000_flows"],
            "model_size_mb": None,
            "hardware": complexity["hardware"],
        },
    }


def check_model_size(size_mb):
    """Avisa si model.joblib pesa MAX_MODEL_SIZE_MB o más. No es un error: el equipo lo revisa (contrato, sección 10)."""
    if size_mb >= MAX_MODEL_SIZE_MB:
        warnings.warn(
            f"{MODEL_JOBLIB} pesa {size_mb:.2f} MB y el límite es {MAX_MODEL_SIZE_MB} MB. "
            "El equipo debe revisarlo antes de subirlo a git.",
            stacklevel=2,
        )


def _json_text(data):
    """Texto de un JSON de artifacts/: UTF-8 legible, sangría de 2 espacios y sin NaN ni infinitos."""
    return json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def _model_json_text(info):
    """Texto de model.json; ValueError si no es un JSON válido (por ejemplo, con NaN o tipos de numpy)."""
    try:
        return _json_text(info)
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"El {MODEL_JSON} de {info['name']} no se puede escribir como JSON válido: tiene un NaN, "
            "un infinito o un valor que no es de Python (por ejemplo, un número de numpy)."
        ) from error


def export_model(model, info, artifacts_dir=ARTIFACTS_DIR):
    """Guarda un modelo en artifacts_dir/models/<name>/: model.joblib y model.json (contrato, sección 10).

    info es el model.json que arma build_model_info. Si la carpeta ya existe, sus dos archivos se
    reemplazan. No registra el modelo. Devuelve el model.json tal como quedó escrito, con
    model_size_mb; el diccionario info recibido no se modifica.
    """
    name = info["name"]
    if not re.fullmatch(MODEL_NAME_PATTERN, name):
        raise ValueError(
            f"El nombre {name} no es válido: debe ir en minúsculas y snake_case (por ejemplo, random_forest)."
        )
    if name == MOCK_MODEL_NAME:
        raise ValueError(
            f"El nombre {MOCK_MODEL_NAME} es del modelo simulado, que se escribe a mano; usa otro nombre."
        )

    # Las mismas comprobaciones que hace la app al cargar (ArtifactError si fallan), para que un
    # modelo exportado siempre se pueda cargar. test_metrics puede faltar si el modelo aún no está
    # registrado; si ya lo está, se exige, porque sin él la app no podría arrancar. Sin registry.json
    # (por ejemplo, en una carpeta de pruebas) ningún modelo está registrado.
    registered = (artifacts_dir / REGISTRY_PATH.name).is_file() and name in [
        m["name"] for m in read_registry(artifacts_dir)["models"]
    ]
    check_model_info(info, name, require_test_metrics=registered)
    if info["is_mock"]:
        raise ValueError(
            "export_model solo guarda modelos entrenados; el modelo simulado se escribe a mano."
        )
    check_model(model, info, name)

    # Antes de escribir cualquier archivo se comprueba que model.json se puede escribir. Si fallara
    # después de guardar model.joblib, la carpeta quedaría con el modelo nuevo y la descripción vieja.
    # model_size_mb, lo único que cambia después, es siempre un número válido.
    _model_json_text(info)

    model_dir = artifacts_dir / MODELS_DIR.name / name
    model_dir.mkdir(parents=True, exist_ok=True)
    joblib_path = model_dir / MODEL_JOBLIB
    joblib.dump(model, joblib_path)

    size_mb = joblib_path.stat().st_size / BYTES_PER_MB
    check_model_size(size_mb)
    written = {**info, "complexity": {**info["complexity"], "model_size_mb": size_mb}}
    (model_dir / MODEL_JSON).write_text(_model_json_text(written), encoding="utf-8")
    return written


def register_model(name, artifacts_dir=ARTIFACTS_DIR):
    """Agrega un modelo exportado a registry.json, después de su evaluación final (contrato, sección 12).

    Solo registra un modelo que la app podría cargar, con test_metrics. Si ya está registrado, no
    hace nada. Si no, lo agrega antes del modelo simulado (si está) o al final; default_model no
    cambia. Devuelve el registro. registry.json debe existir: es un archivo del proyecto.
    """
    registry = read_registry(artifacts_dir)
    load_model(name, read_model_info(name, artifacts_dir), artifacts_dir)

    names = [m["name"] for m in registry["models"]]
    if name in names:
        return registry
    position = names.index(MOCK_MODEL_NAME) if MOCK_MODEL_NAME in names else len(names)
    models = [
        *registry["models"][:position],
        {"name": name},
        *registry["models"][position:],
    ]
    registry = {**registry, "models": models}

    # Primero un archivo temporal en la misma carpeta y luego os.replace, que cambia un archivo por
    # otro de una vez: si algo falla al escribir, registry.json queda como estaba, nunca a medias.
    path = artifacts_dir / REGISTRY_PATH.name
    temp_path = path.with_name(path.name + TEMP_SUFFIX)
    temp_path.write_text(_json_text(registry), encoding="utf-8")
    os.replace(temp_path, path)
    return registry
