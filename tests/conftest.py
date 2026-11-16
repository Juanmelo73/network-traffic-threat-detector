"""Fixtures compartidos por las pruebas.

Las pruebas usan sample_flows.csv, datos escritos a mano y modelos de prueba diminutos. Las que
necesitan los CSV completos de data/raw/ usan train_partition, test_partition o train_split: se
saltan solas si falta el archivo y quedan marcadas con "dataset".
"""

import json
import re
from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier

from threat_detector.artifacts import MOCK_ONLY_NULL_FIELDS, attack_probability_from_proba, predict_flows
from threat_detector.config import (
    ARTIFACTS_DIR,
    DEMO_SAMPLE_CSV,
    MODEL_JSON,
    MODELS_DIR,
    RANDOM_STATE,
    REGISTRY_PATH,
    ROOT,
    TEST_CSV,
    TRAIN_CSV,
)
from threat_detector.dataset import ATTACK_CAT, TARGET, load_test, load_train
from threat_detector.ml.evaluation import (
    attack_type_metrics,
    compute_threshold,
    detection_metrics,
    threshold_rule,
)
from threat_detector.ml.preprocessing import build_preprocessor, split_train_validation
from threat_detector.ml.training import build_model_info, export_model

DATA_DIR = ROOT / "data"
CONTRACT_PATH = ROOT / "docs" / "contracts.md"

# Fixtures que leen los CSV completos; las pruebas que los usan quedan marcadas con "dataset".
DATASET_FIXTURES = {"train_partition", "test_partition", "train_split"}

# Profundidad de los árboles de prueba, para que den probabilidades intermedias.
TINY_TREE_DEPTH = 5

# Fecha de entrenamiento inventada: 10:42:10 en Colombia (UTC−5), es decir, 15:42:10 en UTC.
TRAINED_AT = datetime(2026, 11, 20, 10, 42, 10, tzinfo=timezone(timedelta(hours=-5)))
TRAINED_AT_UTC = "2026-11-20T15:42:10Z"


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(items):
    """Marca con "dataset" las pruebas que usan los CSV completos, para poder excluirlas con -m "not dataset"."""
    for item in items:
        if DATASET_FIXTURES & set(getattr(item, "fixturenames", ())):
            item.add_marker(pytest.mark.dataset)


def _files_snapshot(folder):
    """Ruta, tamaño y fecha de modificación de cada archivo dentro de una carpeta."""
    return {
        path.relative_to(folder): (path.stat().st_size, path.stat().st_mtime_ns)
        for path in folder.rglob("*")
        if path.is_file()
    }


@pytest.fixture(scope="session", autouse=True)
def protect_project_files():
    """Falla si alguna prueba crea, cambia o borra algo en artifacts/ o data/: esas carpetas solo se leen."""
    before = {folder: _files_snapshot(folder) for folder in (ARTIFACTS_DIR, DATA_DIR)}
    yield
    for folder, files in before.items():
        assert _files_snapshot(folder) == files, f"Una prueba modificó {folder.relative_to(ROOT)}/."


def write_json(path, data):
    """Escribe un JSON a mano (para preparar casos de prueba)."""
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_json(path):
    """Lee un JSON de una carpeta de prueba."""
    return json.loads(path.read_text(encoding="utf-8"))


# Datos


@pytest.fixture(scope="session")
def sample_flows_once():
    """sample_flows.csv leído una sola vez por sesión; las pruebas no deben modificarlo."""
    return pd.read_csv(DEMO_SAMPLE_CSV)


@pytest.fixture
def sample_flows(sample_flows_once):
    """Copia de sample_flows.csv para cada prueba, que puede modificarla."""
    return sample_flows_once.copy()


def _require(path):
    """Salta la prueba si falta un CSV de data/raw/."""
    if not path.is_file():
        pytest.skip(f"Falta {path.relative_to(ROOT)}; ver data/README.md para descargarlo.")


@pytest.fixture(scope="session")
def train_partition():
    """Partición oficial de entrenamiento completa (necesita el CSV)."""
    _require(TRAIN_CSV)
    return load_train()


@pytest.fixture(scope="session")
def test_partition():
    """Partición oficial de prueba completa (necesita el CSV)."""
    _require(TEST_CSV)
    return load_test()


@pytest.fixture(scope="session")
def train_split(train_partition):
    """Separación real de entrenamiento y validación, calculada una sola vez porque tarda varios segundos."""
    return split_train_validation(train_partition)


# Modelos de prueba


def _tiny_pipeline(method, estimator):
    """Pipeline de prueba con los dos pasos de nombre fijo."""
    return Pipeline([("preprocessor", build_preprocessor(method)), ("model", estimator)])


def _tiny_tree():
    return DecisionTreeClassifier(max_depth=TINY_TREE_DEPTH, random_state=RANDOM_STATE)


@pytest.fixture(scope="session")
def tiny_models(sample_flows_once):
    """Modelos de prueba diminutos entrenados con sample_flows.csv; no son modelos del proyecto.

    Tres formas, como en el notebook 04: "a9" (detector binario de regresión logística y
    clasificador de árbol con solo los 9 tipos de ataque, M2), "a10" (el mismo detector y un
    clasificador con las 10 clases, M2) y "b" (un solo árbol multiclase en las dos claves, M3).
    Cada forma trae su umbral, calculado con compute_threshold sobre los mismos flujos.
    """
    flows = sample_flows_once
    attacks = flows[flows[TARGET] == 1]
    detector = _tiny_pipeline("m2", LogisticRegression(max_iter=1000)).fit(flows, flows[TARGET])
    classifier_9 = _tiny_pipeline("m2", _tiny_tree()).fit(attacks, attacks[ATTACK_CAT])
    classifier_10 = _tiny_pipeline("m2", _tiny_tree()).fit(flows, flows[ATTACK_CAT])
    multiclass = _tiny_pipeline("m3", _tiny_tree()).fit(flows, flows[ATTACK_CAT])

    forms = {
        "a9": ({"detector": detector, "attack_type_classifier": classifier_9}, "binary", "m2"),
        "a10": ({"detector": detector, "attack_type_classifier": classifier_10}, "binary", "m2"),
        "b": ({"detector": multiclass, "attack_type_classifier": multiclass}, "multiclass", "m3"),
    }
    tiny = {}
    for form, (model, detector_type, method) in forms.items():
        detector_proba = model["detector"].predict_proba(flows)
        probability = attack_probability_from_proba(detector_proba, model["detector"].classes_, detector_type)
        tiny[form] = {
            "model": model,
            "detector_type": detector_type,
            "method": method,
            "threshold": compute_threshold(flows[TARGET], probability),
        }
    return tiny


@pytest.fixture
def make_model_info(tiny_models, sample_flows_once):
    """Devuelve una función que arma el model.json de un modelo de prueba con build_model_info.

    Las métricas se calculan con las funciones de evaluation.py sobre sample_flows.csv; el nombre,
    la fecha y complexity son inventados. Los argumentos con nombre reemplazan los de build_model_info.
    """

    def make(form="a9", **changes):
        tiny = tiny_models[form]
        flows = sample_flows_once
        info = {"detector_type": tiny["detector_type"], "threshold": tiny["threshold"]}
        probability, alerts, types = predict_flows(tiny["model"], info, flows)
        args = {
            "name": f"test_model_{form}",
            "display_name": f"Modelo de prueba {form.upper()} (árbol de decisión)",
            "model": tiny["model"],
            "detector_type": tiny["detector_type"],
            "preprocessing_method": tiny["method"],
            "threshold": tiny["threshold"],
            "threshold_rule": threshold_rule(flows[TARGET], probability, tiny["threshold"]),
            "can_explain": False,
            "explanation_method": None,
            "test_metrics": {
                "test_flows": len(flows),
                "detection": detection_metrics(flows[TARGET], probability, tiny["threshold"]),
                "attack_type": attack_type_metrics(flows[ATTACK_CAT], types, alerts),
            },
            "complexity": {
                "training_seconds": 1.0,
                "training_flows": len(flows),
                "prediction_ms_per_1000_flows": 1.0,
                "hardware": "Equipo de prueba",
            },
            "trained_at": TRAINED_AT,
        }
        return build_model_info(**{**args, **changes})

    return make


@pytest.fixture
def exported(tmp_path, tiny_models, make_model_info):
    """Carpeta temporal que hace de artifacts/, con model_a (forma a9) y model_b (forma b) exportados,
    un modelo simulado mínimo (solo model.json) y un registry.json con los tres (mock por defecto).
    """
    info_a = export_model(tiny_models["a9"]["model"], make_model_info("a9", name="model_a"), tmp_path)
    export_model(tiny_models["b"]["model"], make_model_info("b", name="model_b"), tmp_path)

    mock_dir = tmp_path / MODELS_DIR.name / "mock"
    mock_dir.mkdir()
    mock_info = {**info_a, "name": "mock", "display_name": "Modelo simulado", "is_mock": True}
    mock_info.update({field: None for field in MOCK_ONLY_NULL_FIELDS})
    write_json(mock_dir / MODEL_JSON, mock_info)

    write_json(
        tmp_path / REGISTRY_PATH.name,
        {"default_model": "mock", "models": [{"name": "model_a"}, {"name": "model_b"}, {"name": "mock"}]},
    )
    return tmp_path


# Contrato


@pytest.fixture(scope="session")
def contract_blocks():
    """Bloques JSON de docs/contracts.md, sin interpretar: [(número de sección, texto), ...]."""
    text = CONTRACT_PATH.read_text(encoding="utf-8")
    blocks, section = [], None
    for match in re.finditer(r"^## (\d+)\.[^\n]*$|^```json\n(.*?)^```", text, re.MULTILINE | re.DOTALL):
        if match.group(1):
            section = match.group(1)
        else:
            blocks.append((section, match.group(2)))
    return blocks


@pytest.fixture(scope="session")
def contract_examples(contract_blocks):
    """Ejemplos JSON del contrato por número de sección: {"7": [ejemplo, ...], ...}."""
    examples = {}
    for section, block in contract_blocks:
        examples.setdefault(section, []).append(json.loads(block))
    return examples


def structure(value):
    """Estructura de un valor JSON: claves y orden de los objetos, sin los valores."""
    if isinstance(value, dict):
        return [(key, structure(item)) for key, item in value.items()]
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return [structure(item) for item in value]
    return "valor"
