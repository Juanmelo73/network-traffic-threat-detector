"""Pruebas de artifacts.py: alerta, severidad, clases por nombre, predict_flows y carga de modelos."""

import importlib
import json
import logging
import re
import shutil
import sys

import joblib
import numpy as np
import pytest
import sklearn
from conftest import read_json, write_json

from threat_detector.artifacts import (
    ArtifactError,
    attack_cat_from_proba,
    attack_probability_from_proba,
    detection_rate,
    false_alarm_rate,
    is_alert,
    load_artifacts,
    load_model,
    predict_flows,
    read_model_info,
    read_registry,
    severity,
)
from threat_detector.config import MODEL_JOBLIB, MODEL_JSON, MODELS_DIR, RANDOM_STATE, REGISTRY_PATH
from threat_detector.dataset import ATTACK_TYPES, NORMAL_CAT
from threat_detector.ml.training import export_model

# Alerta y severidad


def test_is_alert_returns_a_python_bool_for_one_flow_and_an_array_for_many():
    assert is_alert(0.31, 0.31) is True
    assert is_alert(0.3099, 0.31) is False
    alerts = is_alert([0.1, 0.31, 0.9], 0.31)
    assert isinstance(alerts, np.ndarray)
    np.testing.assert_array_equal(alerts, [False, True, True])


@pytest.mark.parametrize(
    "probability, threshold, expected",
    [
        (0.0, 0.31, "normal"), (0.3099, 0.31, "normal"), (0.31, 0.31, "low"), (0.5999, 0.31, "low"),
        (0.60, 0.31, "medium"), (0.7499, 0.31, "medium"), (0.75, 0.31, "high"), (0.8999, 0.31, "high"),
        (0.90, 0.31, "critical"), (1.0, 0.31, "critical"),
        # Con umbral 0,70 no hay alertas "low": la primera alerta ya es "medium" (CLAUDE.md, severidad).
        (0.6999, 0.70, "normal"), (0.70, 0.70, "medium"), (0.75, 0.70, "high"),
    ],
)
def test_severity_limits(probability, threshold, expected):
    assert severity(probability, threshold) == expected


@pytest.mark.parametrize("threshold", [0.31, 0.70])
def test_alert_if_and_only_if_severity_is_not_normal(threshold):
    for probability in np.linspace(0, 1, 1001):
        assert is_alert(probability, threshold) == (severity(probability, threshold) != "normal")


def test_rates_and_their_none_cases():
    y_true = [1, 1, 1, 1, 0, 0, 0, 0, 0]
    alerts = [True, True, True, False, True, False, False, False, False]
    assert detection_rate(y_true, alerts) == 0.75
    assert false_alarm_rate(y_true, alerts) == 0.2
    assert detection_rate([0, 0], [True, False]) is None
    assert false_alarm_rate([1, 1], [True, False]) is None


# Clases por nombre

# Tres flujos multiclase (las clases que no aparecen tienen probabilidad 0). En el primero
# "Normal" es la más probable; en el tercero Exploits y DoS empatan.
ROWS = [
    {"Normal": 0.70, "Generic": 0.20, "DoS": 0.10},
    {"Normal": 0.10, "Exploits": 0.50, "Fuzzers": 0.40},
    {"Normal": 0.05, "Exploits": 0.40, "DoS": 0.40, "Worms": 0.15},
]
EXPECTED_TYPES = ["Generic", "Exploits", "Exploits"]
ALPHABETICAL = sorted([NORMAL_CAT, *ATTACK_TYPES])


def to_proba(rows, classes):
    """Matriz de probabilidades con una columna por clase, en el orden de classes (0 si no aparece)."""
    return np.array([[row.get(c, 0.0) for c in classes] for row in rows])


def test_binary_probability_is_the_column_of_class_1_in_any_order():
    attack_column = np.array([0.8, 0.3, 0.05])
    proba = np.column_stack([1 - attack_column, attack_column])
    np.testing.assert_array_equal(attack_probability_from_proba(proba, np.array([0, 1]), "binary"), attack_column)
    np.testing.assert_array_equal(attack_probability_from_proba(proba[:, ::-1], np.array([1, 0]), "binary"), attack_column)


@pytest.mark.parametrize("classes", [ALPHABETICAL, ALPHABETICAL[::-1]], ids=["alphabetical", "reversed"])
def test_multiclass_probability_and_type_do_not_depend_on_class_order(classes):
    proba = to_proba(ROWS, classes)
    classes = np.array(classes, dtype=object)
    np.testing.assert_array_equal(
        attack_probability_from_proba(proba, classes, "multiclass"), 1 - np.array([0.70, 0.10, 0.05])
    )
    # El tipo nunca es "Normal", aunque sea la clase más probable, y el empate lo gana Exploits,
    # que va antes que DoS en ATTACK_TYPES.
    assert list(attack_cat_from_proba(proba, classes)) == EXPECTED_TYPES


def test_type_with_a_classifier_without_normal():
    classes = ATTACK_TYPES[::-1]
    proba = to_proba(ROWS, classes)
    proba = proba / proba.sum(axis=1, keepdims=True)
    assert list(attack_cat_from_proba(proba, np.array(classes, dtype=object))) == EXPECTED_TYPES


@pytest.mark.parametrize(
    "call, message",
    [
        (lambda: attack_probability_from_proba(np.ones((1, 2)), np.array([0, 2]), "binary"), "no tiene la clase 1"),
        (lambda: attack_probability_from_proba(to_proba(ROWS, ATTACK_TYPES), np.array(ATTACK_TYPES, dtype=object),
                                               "multiclass"), "no tiene la clase Normal"),
        (lambda: attack_cat_from_proba(to_proba(ROWS, ALPHABETICAL[:-1]), np.array(ALPHABETICAL[:-1], dtype=object)),
         "no tiene la clase Worms"),
        (lambda: attack_probability_from_proba(np.ones((1, 2)), np.array([0, 1]), "binario"), "Tipo de detector desconocido"),
        (lambda: attack_probability_from_proba(np.ones((1, 2)), np.array([0, 1, 2]), "binary"), "una columna por clase"),
    ],
    ids=["binary_without_1", "multiclass_without_normal", "missing_type", "unknown_detector_type", "wrong_columns"],
)
def test_class_lookup_errors(call, message):
    with pytest.raises(ValueError, match=message):
        call()


# predict_flows


class CountingModel:
    """Envoltorio de prueba: se comporta como el Pipeline y cuenta las llamadas a predict_proba."""

    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.classes_ = pipeline.classes_
        self.calls = 0

    def predict_proba(self, flows):
        self.calls += 1
        return self.pipeline.predict_proba(flows)


def counting(model):
    """El modelo con envoltorios que cuentan; si es el mismo Pipeline, el mismo envoltorio en las dos claves."""
    detector = CountingModel(model["detector"])
    same = model["attack_type_classifier"] is model["detector"]
    classifier = detector if same else CountingModel(model["attack_type_classifier"])
    return {"detector": detector, "attack_type_classifier": classifier}


@pytest.mark.parametrize("form", ["a9", "a10", "b"])
def test_predict_flows(form, tiny_models, sample_flows):
    tiny = tiny_models[form]
    info = {"detector_type": tiny["detector_type"], "threshold": tiny["threshold"]}
    wrapped = counting(tiny["model"])
    probability, alerts, types = predict_flows(wrapped, info, sample_flows)

    detector = tiny["model"]["detector"]
    expected = attack_probability_from_proba(detector.predict_proba(sample_flows), detector.classes_, tiny["detector_type"])
    np.testing.assert_array_equal(probability, expected)
    np.testing.assert_array_equal(alerts, probability >= tiny["threshold"])
    assert alerts.any() and not alerts.all()
    # El tipo es None exactamente en los flujos sin alerta, y en las alertas es uno de los 9 tipos.
    np.testing.assert_array_equal([t is None for t in types], ~alerts)
    assert set(types[alerts]) <= set(ATTACK_TYPES)

    if form == "b":
        assert wrapped["detector"].calls == 1  # el mismo Pipeline: una sola llamada
    else:
        assert (wrapped["detector"].calls, wrapped["attack_type_classifier"].calls) == (1, 1)


def test_predict_flows_with_10_classes_never_gives_normal(tiny_models, sample_flows):
    tiny = tiny_models["a10"]
    info = {"detector_type": "binary", "threshold": tiny["threshold"]}
    _, alerts, types = predict_flows(tiny["model"], info, sample_flows)
    # Hay alertas en las que el clasificador de 10 clases cree que lo más probable es "Normal".
    classifier = tiny["model"]["attack_type_classifier"]
    assert (classifier.predict(sample_flows[alerts]) == NORMAL_CAT).any()
    assert NORMAL_CAT not in set(types[alerts])


def test_predict_flows_without_alerts_does_not_call_the_classifier(tiny_models, sample_flows):
    wrapped = counting(tiny_models["a9"]["model"])
    _, alerts, types = predict_flows(wrapped, {"detector_type": "binary", "threshold": 1.01}, sample_flows)
    assert not alerts.any() and all(t is None for t in types)
    assert wrapped["attack_type_classifier"].calls == 0


def test_predict_flows_result_is_json_ready(tiny_models, sample_flows):
    tiny = tiny_models["a9"]
    probability, alerts, types = predict_flows(
        tiny["model"], {"detector_type": "binary", "threshold": tiny["threshold"]}, sample_flows
    )
    flows = [{"attack_probability": p, "is_alert": a, "predicted_attack_cat": t}
             for p, a, t in zip(probability.tolist(), alerts.tolist(), types.tolist())]
    assert json.loads(json.dumps(flows)) == flows


# Cargar un modelo


def load(name, artifacts_dir):
    """Carga un modelo como lo hará la app: read_model_info y luego load_model."""
    return load_model(name, read_model_info(name, artifacts_dir), artifacts_dir)


@pytest.mark.parametrize("name, form", [("model_a", "a9"), ("model_b", "b")])
def test_loaded_model_predicts_like_the_original(name, form, exported, tiny_models, sample_flows):
    info = read_model_info(name, exported)
    loaded = load_model(name, info, exported)
    original = predict_flows(tiny_models[form]["model"], info, sample_flows)
    again = predict_flows(loaded, info, sample_flows)
    for a, b in zip(original, again):
        np.testing.assert_array_equal(a, b)


def test_shared_pipeline_is_still_one_object_after_loading(exported):
    loaded = load("model_b", exported)
    assert loaded["detector"] is loaded["attack_type_classifier"]


def test_mock_model_has_no_joblib_and_loads_as_none(exported):
    assert not (exported / MODELS_DIR.name / "mock" / MODEL_JOBLIB).exists()
    assert load("mock", exported) is None


def test_test_metrics_are_required_only_when_asked(exported, tiny_models, make_model_info):
    export_model(tiny_models["a9"]["model"], make_model_info("a9", name="pending", test_metrics=None), exported)
    assert read_model_info("pending", exported, require_test_metrics=False)["test_metrics"] is None
    with pytest.raises(ArtifactError, match="no tiene test_metrics"):
        read_model_info("pending", exported)


def test_other_sklearn_version_only_warns(exported, caplog):
    folder = exported / MODELS_DIR.name / "model_a"
    write_json(folder / MODEL_JSON, {**read_json(folder / MODEL_JSON), "sklearn_version": "1.0.0"})
    with caplog.at_level(logging.WARNING, logger="threat_detector.artifacts"):
        assert load("model_a", exported) is not None
    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert "model_a" in message and "1.0.0" in message and sklearn.__version__ in message


# Errores de carga: cada caso copia un modelo exportado a la carpeta "broken" y lo daña.


def edit_info(folder, remove=(), **changes):
    info = {**read_json(folder / MODEL_JSON), **changes}
    for field in remove:
        del info[field]
    write_json(folder / MODEL_JSON, info)


def cut_half(path):
    data = path.read_bytes()
    path.write_bytes(data[: len(data) // 2])


def missing_library(folder, tmp_path, monkeypatch):
    """Guarda en model.joblib objetos de un módulo temporal y borra el módulo antes de cargar."""
    module_dir = tmp_path / "fake_library_dir"
    module_dir.mkdir()
    (module_dir / "fake_library_for_tests.py").write_text("class FakeEstimator:\n    pass\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(module_dir))
    module = importlib.import_module("fake_library_for_tests")
    joblib.dump({"detector": module.FakeEstimator(), "attack_type_classifier": module.FakeEstimator()},
                folder / MODEL_JOBLIB)
    sys.path.remove(str(module_dir))
    del sys.modules["fake_library_for_tests"]
    shutil.rmtree(module_dir)
    importlib.invalidate_caches()


def json_m3_with_joblib_m2(folder, tmp_path, monkeypatch):
    """El model.json de model_b (M3, declarado binary) junto al model.joblib de model_a (M2)."""
    shutil.copy(folder.parent / "model_b" / MODEL_JSON, folder / MODEL_JSON)
    edit_info(folder, name="broken", detector_type="binary")


LOAD_ERRORS = [
    # (id, carpeta de origen, cómo se daña, mensaje esperado, tipo de la causa original)
    ("missing_json", "model_a", lambda f, *_: (f / MODEL_JSON).unlink(), "Falta models/broken/model.json", None),
    ("cut_json", "model_a", lambda f, *_: cut_half(f / MODEL_JSON), "no es un JSON válido", json.JSONDecodeError),
    ("nan_in_json", "model_a",
     lambda f, *_: (f / MODEL_JSON).write_text(
         re.sub(r'"pr_auc": [^,\n]+', '"pr_auc": NaN', (f / MODEL_JSON).read_text(encoding="utf-8"), count=1),
         encoding="utf-8"),
     "no es un JSON válido", ValueError),
    ("name_mismatch", "model_a", lambda f, *_: edit_info(f, name="model_a"), "su carpeta se llama broken", None),
    ("missing_field", "model_a", lambda f, *_: edit_info(f, remove=["feature_groups"]), "le faltan campos: feature_groups", None),
    ("null_method", "model_a", lambda f, *_: edit_info(f, preprocessing_method=None), "solo pueden serlo en el modelo simulado", None),
    ("bad_detector_type", "model_a", lambda f, *_: edit_info(f, detector_type="binario"), "detector_type = binario", None),
    ("bad_threshold", "model_a", lambda f, *_: edit_info(f, threshold=1.5), "entre 0 y 1", None),
    ("missing_joblib", "model_a", lambda f, *_: (f / MODEL_JOBLIB).unlink(), "Falta models/broken/model.joblib", None),
    ("random_joblib", "model_a",
     lambda f, *_: (f / MODEL_JOBLIB).write_bytes(np.random.default_rng(RANDOM_STATE).bytes(1000)),
     "el archivo está dañado", Exception),
    ("cut_joblib", "model_a", lambda f, *_: cut_half(f / MODEL_JOBLIB), "el archivo está dañado", Exception),
    ("wrong_keys", "model_a",
     lambda f, *_: joblib.dump({"detector": None, "classifier": None}, f / MODEL_JOBLIB), "claves", None),
    ("binary_without_1", "model_b", lambda f, *_: edit_info(f, detector_type="binary"), "no tiene la clase 1", ValueError),
    ("missing_library", "model_a", missing_library, "falta la librería fake_library_for_tests", ModuleNotFoundError),
    ("json_m3_with_joblib_m2", "model_a", json_m3_with_joblib_m2,
     "a numeric_cols le falta ct_state_ttl, dttl, sttl", None),
]


@pytest.mark.parametrize("source, damage, message, cause", [case[1:] for case in LOAD_ERRORS],
                         ids=[case[0] for case in LOAD_ERRORS])
def test_load_errors(source, damage, message, cause, exported, tmp_path, monkeypatch):
    folder = exported / MODELS_DIR.name / "broken"
    shutil.copytree(exported / MODELS_DIR.name / source, folder)
    edit_info(folder, name="broken")
    damage(folder, tmp_path, monkeypatch)

    with pytest.raises(ArtifactError, match=message) as error:
        load("broken", exported)
    # Cuando el error viene de otro, la causa original queda encadenada.
    if cause is None:
        assert error.value.__cause__ is None
    else:
        assert isinstance(error.value.__cause__, cause)


# registry.json y load_artifacts


def test_load_artifacts_loads_registered_models_in_order(exported):
    # Una carpeta sin registrar se ignora.
    shutil.copytree(exported / MODELS_DIR.name / "model_a", exported / MODELS_DIR.name / "unregistered")
    registry, models = load_artifacts(exported)
    assert list(models) == ["model_a", "model_b", "mock"]
    assert registry["default_model"] == "mock"
    assert models["mock"]["model"] is None
    assert models["model_a"]["info"] == read_model_info("model_a", exported)


@pytest.mark.parametrize(
    "content, message",
    [
        (None, "Falta registry.json"),
        ('{"default_model": "mock", "models": [', "no es un JSON válido"),
        ({"models": [{"name": "mock"}]}, "le faltan campos: default_model"),
        ({"default_model": "mock", "models": [{"name": "mock"}, {"name": "mock"}]}, "modelos repetidos: mock"),
        ({"default_model": "model_a", "models": [{"name": "mock"}]}, "default_model = model_a no es uno"),
        ({"default_model": "mock", "models": [{"name": "mock"}, {"model": "model_a"}]}, "cada uno con su name"),
    ],
    ids=["missing", "invalid_json", "missing_default_model", "repeated", "default_not_in_models", "model_without_name"],
)
def test_registry_errors(content, message, exported):
    path = exported / REGISTRY_PATH.name
    if content is None:
        path.unlink()
    elif isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        write_json(path, content)
    with pytest.raises(ArtifactError, match=message):
        read_registry(exported)


@pytest.mark.parametrize("extra, message", [("ghost", "Falta models/ghost/model.json"),
                                            ("pending", "no tiene test_metrics")])
def test_load_artifacts_errors(extra, message, exported, tiny_models, make_model_info):
    export_model(tiny_models["a9"]["model"], make_model_info("a9", name="pending", test_metrics=None), exported)
    write_json(exported / REGISTRY_PATH.name, {"default_model": "mock", "models": [{"name": "mock"}, {"name": extra}]})
    with pytest.raises(ArtifactError, match=message):
        load_artifacts(exported)
