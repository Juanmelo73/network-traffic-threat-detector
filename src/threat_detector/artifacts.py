"""Carga de los modelos de artifacts/ y reglas para leer su salida, compartidas por ml/ y app/."""

import json
import logging

import joblib
import numpy as np
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from threat_detector.config import (
    ARTIFACTS_DIR,
    MODEL_JOBLIB,
    MODEL_JSON,
    MODELS_DIR,
    REGISTRY_PATH,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)
from threat_detector.dataset import ATTACK_TYPES, NORMAL_CAT

logger = logging.getLogger(__name__)

# Valores de detector_type en model.json (contrato, sección 11).
DETECTOR_TYPES = ("binary", "multiclass")

# Claves del diccionario que se guarda en model.joblib (contrato, sección 10).
MODEL_KEYS = {"detector", "attack_type_classifier"}

# Pasos de cada Pipeline, con nombre fijo: el preprocesador y el estimador.
PIPELINE_STEPS = ["preprocessor", "model"]

# Campos de model.json, en el orden del contrato (sección 11).
MODEL_INFO_FIELDS = [
    "name",
    "display_name",
    "is_mock",
    "trained_at",
    "sklearn_version",
    "detector_type",
    "preprocessing_method",
    "use_ttl",
    "numeric_cols",
    "categorical_cols",
    "log_cols",
    "feature_groups",
    "threshold",
    "threshold_rule",
    "can_explain",
    "explanation_method",
    "test_metrics",
    "complexity",
]
# Campos que solo pueden ser null en el modelo simulado, que no se entrena (contrato, sección 11).
MOCK_ONLY_NULL_FIELDS = [
    "trained_at",
    "sklearn_version",
    "preprocessing_method",
    "threshold_rule",
    "complexity",
]


class ArtifactError(Exception):
    """Un archivo de artifacts/ falta, está dañado o no coincide con el contrato (secciones 10 a 12).

    Si pasa al arrancar, la app no arranca y muestra este mensaje.
    """


def is_alert(attack_probability, threshold):
    """Indica si la probabilidad de ataque es alerta: mayor o igual que el umbral del modelo.

    Con un solo flujo (un número) devuelve un bool de Python, que se puede poner directamente en
    un JSON; con muchos (una lista o un arreglo) devuelve un arreglo con un valor por flujo.
    """
    alerts = np.asarray(attack_probability) >= threshold
    return bool(alerts) if alerts.ndim == 0 else alerts


def severity(attack_probability, threshold):
    """Severidad de un flujo: "critical", "high", "medium", "low" o "normal" (contrato, sección 3)."""
    if not is_alert(attack_probability, threshold):
        return "normal"
    if attack_probability >= SEVERITY_CRITICAL:
        return "critical"
    if attack_probability >= SEVERITY_HIGH:
        return "high"
    if attack_probability >= SEVERITY_MEDIUM:
        return "medium"
    return "low"


def detection_rate(y_true, alerts):
    """De los ataques reales (label = 1), la parte que es alerta; None si no hay ataques reales."""
    attacks = np.asarray(y_true) == 1
    return float(np.asarray(alerts)[attacks].mean()) if attacks.any() else None


def false_alarm_rate(y_true, alerts):
    """De los flujos normales reales (label = 0), la parte que es alerta; None si no hay normales."""
    normals = np.asarray(y_true) == 0
    return float(np.asarray(alerts)[normals].mean()) if normals.any() else None


def _class_column(classes, wanted):
    """Posición de la clase `wanted` en classes (el classes_ del modelo); ValueError si no la tiene."""
    # Comparación de Python, no de numpy: np.int64(1) == 1 es verdadero, y comparar un número
    # con "Normal" da False sin avisos.
    positions = [i for i, c in enumerate(classes) if c == wanted]
    if not positions:
        raise ValueError(
            f"El modelo no tiene la clase {wanted} entre sus clases: {', '.join(map(str, classes))}."
        )
    return positions[0]


def _check_proba(proba, classes):
    """Convierte la salida de predict_proba en arreglo y comprueba que trae una columna por clase."""
    proba = np.asarray(proba, dtype=float)
    if proba.ndim != 2 or proba.shape[1] != len(classes):
        raise ValueError(
            f"Las probabilidades deben traer una fila por flujo y una columna por clase "
            f"({len(classes)} clases); llegaron con forma {proba.shape}."
        )
    return proba


def attack_probability_from_proba(proba, classes, detector_type):
    """Probabilidad de ataque de cada flujo a partir de predict_proba del detector (contrato, sección 10).

    proba trae una columna por clase, en el orden de classes (detector.classes_). Las clases se
    buscan por su nombre, nunca por su posición. detector_type viene de model.json y no se deduce:
    "binary" usa la columna de la clase 1; "multiclass", 1 menos la columna de "Normal".
    """
    proba = _check_proba(proba, classes)
    if detector_type == "binary":
        return proba[:, _class_column(classes, 1)]
    if detector_type == "multiclass":
        return 1 - proba[:, _class_column(classes, NORMAL_CAT)]
    raise ValueError(
        f"Tipo de detector desconocido: {detector_type}. Usa uno de: {', '.join(DETECTOR_TYPES)}."
    )


def attack_cat_from_proba(proba, classes):
    """Tipo de ataque más probable de cada flujo entre los 9 de ATTACK_TYPES (contrato, sección 3).

    La columna de "Normal" no se mira, aunque esté entre las clases: una alerta nunca dice
    "Normal". Las columnas se ordenan como ATTACK_TYPES, así que en un empate gana el primero
    en ese orden, sin importar el orden de classes.
    """
    proba = _check_proba(proba, classes)
    columns = [_class_column(classes, attack_cat) for attack_cat in ATTACK_TYPES]
    best = proba[:, columns].argmax(axis=1)
    return np.asarray(ATTACK_TYPES, dtype=object)[best]


def predict_flows(model, info, flows):
    """Predice los flujos con un modelo cargado: (attack_probability, alerts, predicted_attack_cat).

    model es el diccionario de model.joblib e info su model.json. Los flujos ya vienen validados
    con validate_flows. El tipo probable se calcula solo para las alertas; en los demás flujos es
    None (contrato, sección 3). Si el detector y el clasificador son el mismo Pipeline, predict_proba
    se ejecuta una sola vez.
    """
    detector = model["detector"]
    classifier = model["attack_type_classifier"]

    detector_proba = detector.predict_proba(flows)
    attack_probability = attack_probability_from_proba(
        detector_proba, detector.classes_, info["detector_type"]
    )
    alerts = is_alert(attack_probability, info["threshold"])

    predicted_attack_cat = np.full(len(attack_probability), None, dtype=object)
    if alerts.any():
        # Mismo Pipeline: sus probabilidades ya están calculadas. Si no, el clasificador solo
        # recibe las alertas.
        if classifier is detector:
            type_proba = detector_proba[alerts]
        else:
            type_proba = classifier.predict_proba(flows[alerts])
        predicted_attack_cat[alerts] = attack_cat_from_proba(
            type_proba, classifier.classes_
        )
    return attack_probability, alerts, predicted_attack_cat


def _where(name, file_name):
    """Ruta de un archivo del modelo relativa a artifacts/, para los mensajes: nunca la del computador."""
    return f"{MODELS_DIR.name}/{name}/{file_name}"


def _reject_constant(value):
    """json.loads acepta NaN e Infinity por defecto; un JSON válido no los admite."""
    raise ValueError(f"{value} no es un valor JSON válido")


def _read_json(path, where):
    """Lee un JSON de artifacts/; ArtifactError si no es válido (where es su ruta relativa)."""
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), parse_constant=_reject_constant
        )
    except ValueError as error:
        # ValueError incluye un JSON mal formado y un archivo que no está en UTF-8.
        raise ArtifactError(f"{where} está dañado: no es un JSON válido.") from error


def check_model_info(info, name, require_test_metrics=True):
    """Comprueba que un model.json cumple el contrato (sección 11); si no, lanza ArtifactError.

    name es el nombre de la carpeta. Un campo de más no es error: agregar campos no rompe el
    contrato. require_test_metrics exige la evaluación final, como en todo modelo registrado.
    """
    where = _where(name, MODEL_JSON)
    if not isinstance(info, dict):
        raise ArtifactError(f"{where} debe ser un objeto JSON.")
    missing = [field for field in MODEL_INFO_FIELDS if field not in info]
    if missing:
        raise ArtifactError(f"A {where} le faltan campos: {', '.join(missing)}.")
    if info["name"] != name:
        raise ArtifactError(
            f"{where} dice name = {info['name']}, pero su carpeta se llama {name}."
        )
    if not isinstance(info["is_mock"], bool):
        raise ArtifactError(f"En {where}, is_mock debe ser true o false.")
    if info["detector_type"] not in DETECTOR_TYPES:
        raise ArtifactError(
            f"En {where}, detector_type = {info['detector_type']}; debe ser uno de: {', '.join(DETECTOR_TYPES)}."
        )
    threshold = info["threshold"]
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not 0 <= threshold <= 1
    ):
        raise ArtifactError(
            f"En {where}, threshold = {threshold}; debe ser un número entre 0 y 1."
        )
    if not info["is_mock"]:
        nulls = [field for field in MOCK_ONLY_NULL_FIELDS if info[field] is None]
        if nulls:
            raise ArtifactError(
                f"En {where} son null {', '.join(nulls)}, y solo pueden serlo en el modelo simulado."
            )
    if require_test_metrics and info["test_metrics"] is None:
        raise ArtifactError(
            f"{where} no tiene test_metrics: un modelo registrado debe tener su evaluación final."
        )


def _input_columns(preprocessor):
    """Columnas que usa un ColumnTransformer: las del one-hot son categóricas y las demás, numéricas."""
    columns = {"numeric": set(), "categorical": set()}
    for _, transformer, cols in preprocessor.transformers:
        if isinstance(transformer, str) and transformer == "drop":
            continue
        last_step = (
            transformer.steps[-1][1]
            if isinstance(transformer, Pipeline)
            else transformer
        )
        columns[
            "categorical" if isinstance(last_step, OneHotEncoder) else "numeric"
        ].update(cols)
    return columns


def check_model(model, info, name):
    """Comprueba que el contenido de model.joblib cumple el contrato (sección 10) y corresponde a su model.json.

    Revisa las dos claves, los pasos de cada Pipeline, que cada preprocesador use exactamente las
    columnas de numeric_cols y categorical_cols, y que las clases sean las que se buscan por
    nombre: 1 o "Normal" en el detector, según detector_type, y los 9 tipos en el clasificador.
    """
    where = _where(name, MODEL_JOBLIB)
    if not isinstance(model, dict) or set(model) != MODEL_KEYS:
        raise ArtifactError(
            f"{where} debe guardar un diccionario con las claves {' y '.join(sorted(MODEL_KEYS))}."
        )

    for key in ("detector", "attack_type_classifier"):
        pipeline = model[key]
        if (
            not isinstance(pipeline, Pipeline)
            or list(pipeline.named_steps) != PIPELINE_STEPS
        ):
            raise ArtifactError(
                f"En {where}, {key} debe ser un Pipeline con los pasos {' y '.join(PIPELINE_STEPS)}, en ese orden."
            )
        if not isinstance(pipeline["preprocessor"], ColumnTransformer):
            raise ArtifactError(
                f"En {where}, el paso preprocessor de {key} debe ser un ColumnTransformer."
            )

        # Un model.json que no es el de este model.joblib declara otras columnas.
        used = _input_columns(pipeline["preprocessor"])
        problems = []
        for field, kind in (
            ("numeric_cols", "numeric"),
            ("categorical_cols", "categorical"),
        ):
            declared = set(info[field])
            extra = sorted(declared - used[kind])
            lacking = sorted(used[kind] - declared)
            if extra:
                problems.append(
                    f"{field} trae {', '.join(extra)}, que el modelo no usa"
                )
            if lacking:
                problems.append(
                    f"a {field} le falta {', '.join(lacking)}, que el modelo sí usa"
                )
        if problems:
            raise ArtifactError(
                f"El {MODEL_JSON} de {name} no corresponde a su {MODEL_JOBLIB} ({key}): {'; '.join(problems)}."
            )

    wanted = {
        "detector": [1 if info["detector_type"] == "binary" else NORMAL_CAT],
        "attack_type_classifier": ATTACK_TYPES,
    }
    for key, classes in wanted.items():
        try:
            for wanted_class in classes:
                _class_column(model[key].classes_, wanted_class)
        except (AttributeError, ValueError) as error:
            raise ArtifactError(
                f"En {where}, {key} no tiene las clases que pide el contrato "
                f"(detector_type = {info['detector_type']}): {error}"
            ) from error


def read_model_info(name, artifacts_dir=ARTIFACTS_DIR, require_test_metrics=True):
    """Lee y comprueba el model.json de un modelo; lanza ArtifactError si falta, está dañado o no cumple el contrato."""
    path, where = artifacts_dir / MODELS_DIR.name / name / MODEL_JSON, _where(
        name, MODEL_JSON
    )
    if not path.is_file():
        raise ArtifactError(f"Falta {where}: el modelo {name} no tiene su descripción.")
    info = _read_json(path, where)
    check_model_info(info, name, require_test_metrics)
    return info


def load_model(name, info, artifacts_dir=ARTIFACTS_DIR):
    """Carga model.joblib de un modelo y lo comprueba con check_model; None si es el modelo simulado.

    Si la versión de scikit-learn con la que se entrenó no es la instalada, solo avisa en el
    registro del servidor (contrato, sección 10). Si falta el archivo, está dañado o falta una
    librería que usa el modelo, lanza ArtifactError con la causa original encadenada.
    """
    if info["is_mock"]:
        # El modelo simulado no tiene model.joblib: la app usa mock.py (contrato, sección 13).
        return None

    if info["sklearn_version"] != sklearn.__version__:
        logger.warning(
            "El modelo %s se entrenó con scikit-learn %s y está instalada la versión %s; "
            "puede comportarse distinto.",
            name,
            info["sklearn_version"],
            sklearn.__version__,
        )

    path, where = artifacts_dir / MODELS_DIR.name / name / MODEL_JOBLIB, _where(
        name, MODEL_JOBLIB
    )
    if not path.is_file():
        raise ArtifactError(f"Falta {where}: el modelo {name} no se puede cargar.")
    try:
        model = joblib.load(path)
    except Exception as error:
        # Un archivo dañado o una librería que falta lanzan errores de tipos muy distintos.
        if isinstance(error, ModuleNotFoundError):
            cause = f"falta la librería {error.name}, que debe estar en requirements-prod.txt"
        else:
            cause = "el archivo está dañado"
        raise ArtifactError(f"No se pudo cargar {where}: {cause}.") from error
    check_model(model, info, name)
    return model


def read_registry(artifacts_dir=ARTIFACTS_DIR):
    """Lee y comprueba registry.json (contrato, sección 12); lanza ArtifactError si falta o no cumple el contrato."""
    where = REGISTRY_PATH.name
    path = artifacts_dir / where
    if not path.is_file():
        raise ArtifactError(f"Falta {where}: la app no sabe qué modelos puede usar.")
    registry = _read_json(path, where)

    if not isinstance(registry, dict):
        raise ArtifactError(f"{where} debe ser un objeto JSON.")
    missing = [field for field in ("default_model", "models") if field not in registry]
    if missing:
        raise ArtifactError(f"A {where} le faltan campos: {', '.join(missing)}.")
    models = registry["models"]
    if not isinstance(models, list) or not all(
        isinstance(m, dict) and isinstance(m.get("name"), str) for m in models
    ):
        raise ArtifactError(
            f"En {where}, models debe ser una lista de objetos, cada uno con su name."
        )
    names = [m["name"] for m in models]
    repeated = sorted({n for n in names if names.count(n) > 1})
    if repeated:
        raise ArtifactError(f"En {where} hay modelos repetidos: {', '.join(repeated)}.")
    if registry["default_model"] not in names:
        raise ArtifactError(
            f"En {where}, default_model = {registry['default_model']} no es uno de los modelos de models."
        )
    return registry


def load_artifacts(artifacts_dir=ARTIFACTS_DIR):
    """Lee registry.json y carga cada modelo registrado: lo que hace la app una sola vez, al arrancar.

    Devuelve (registry, models). models es {name: {"info": model.json, "model": modelo o None}},
    en el orden de registry.json; "model" es None en el modelo simulado. Cada modelo registrado
    debe tener test_metrics. Las carpetas de artifacts/models/ que no están registradas se ignoran.
    Si algo falta o no coincide, lanza ArtifactError y la app no debe arrancar (contrato, secciones 10 y 12).
    """
    registry = read_registry(artifacts_dir)
    models = {}
    for entry in registry["models"]:
        name = entry["name"]
        info = read_model_info(name, artifacts_dir)
        models[name] = {"info": info, "model": load_model(name, info, artifacts_dir)}
    return registry, models
