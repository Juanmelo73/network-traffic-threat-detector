"""Pruebas de ml/training.py: model.json, exportar y registrar modelos (siempre en carpetas temporales)."""

import json
import warnings
from datetime import datetime

import pytest
import sklearn
from conftest import TRAINED_AT_UTC, read_json, write_json
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

from threat_detector.artifacts import MODEL_INFO_FIELDS, ArtifactError, read_registry
from threat_detector.config import BYTES_PER_MB, MAX_MODEL_SIZE_MB, MODEL_JOBLIB, MODEL_JSON, MODELS_DIR, REGISTRY_PATH
from threat_detector.dataset import CATEGORICAL_COLS
from threat_detector.ml.preprocessing import LOG_COLS, build_preprocessor, numeric_input_cols
from threat_detector.ml.training import (
    TEMP_SUFFIX,
    check_model_size,
    export_model,
    feature_groups,
    register_model,
)


def folder_state(folder):
    """Contenido y fecha de modificación de cada archivo de una carpeta, para saber si cambió."""
    return {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in folder.iterdir()}


# feature_groups


def test_feature_groups_cover_each_output_column_once(sample_flows):
    preprocessor = build_preprocessor("m1").fit(sample_flows)
    groups = feature_groups(preprocessor)
    assert list(groups) == [*numeric_input_cols(), *CATEGORICAL_COLS]
    grouped = [name for names in groups.values() for name in names]
    assert sorted(grouped) == sorted(preprocessor.get_feature_names_out())
    # ct_state_ttl es numérica: no se confunde con las columnas one-hot de state.
    assert groups["ct_state_ttl"] == ["ct_state_ttl"]
    assert all(name.startswith("state_") for name in groups["state"])


# build_model_info


@pytest.mark.parametrize("form, use_ttl", [("a9", True), ("b", False)])
def test_model_info_has_the_contract_fields_and_derived_values(form, use_ttl, make_model_info, tiny_models):
    info = make_model_info(form)
    assert list(info) == MODEL_INFO_FIELDS
    assert info["is_mock"] is False
    assert info["sklearn_version"] == sklearn.__version__
    assert info["use_ttl"] is use_ttl
    assert info["numeric_cols"] == numeric_input_cols(use_ttl)
    assert info["categorical_cols"] == CATEGORICAL_COLS
    assert info["log_cols"] == [c for c in info["numeric_cols"] if c in LOG_COLS]
    assert info["feature_groups"] == feature_groups(tiny_models[form]["model"]["detector"]["preprocessor"])
    assert info["complexity"]["model_size_mb"] is None
    assert info["trained_at"] == TRAINED_AT_UTC
    assert json.loads(json.dumps(info)) == info


def test_model_info_errors(make_model_info, tiny_models):
    detector = tiny_models["a9"]["model"]["detector"]
    cases = [
        ({"preprocessing_method": "m1"}, "no es el del método m1"),
        ({"model": {"detector": detector, "attack_type_classifier": tiny_models["b"]["model"]["detector"]}},
         "attack_type_classifier no es el del método m2"),
        ({"model": {"detector": make_pipeline(build_preprocessor("m2"), LogisticRegression()),
                    "attack_type_classifier": detector}}, "debe ser un Pipeline con los pasos preprocessor y model"),
        ({"detector_type": "binario"}, "Tipo de detector desconocido"),
        ({"preprocessing_method": "m4"}, "Método de preprocesamiento desconocido"),
        ({"trained_at": datetime(2026, 11, 20, 15, 42, 10)}, "debe traer zona horaria"),
        ({"complexity": {"training_seconds": 1.0}}, "complexity debe traer exactamente"),
    ]
    for changes, message in cases:
        with pytest.raises(ValueError, match=message):
            make_model_info("a9", **changes)


# check_model_size


@pytest.mark.parametrize("size_mb, warns", [(MAX_MODEL_SIZE_MB - 0.01, False), (MAX_MODEL_SIZE_MB, True),
                                            (MAX_MODEL_SIZE_MB + 0.01, True)])
def test_model_size_warning(size_mb, warns):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        check_model_size(size_mb)
    assert len(caught) == int(warns)
    if warns:
        assert "revisarlo antes de subirlo a git" in str(caught[0].message)


# export_model


def test_export_writes_exactly_the_two_files(tmp_path, tiny_models, make_model_info):
    info = make_model_info("a9", name="model_a")
    written = export_model(tiny_models["a9"]["model"], info, tmp_path)
    folder = tmp_path / MODELS_DIR.name / "model_a"
    assert sorted(p.name for p in folder.iterdir()) == [MODEL_JOBLIB, MODEL_JSON]
    assert written["complexity"]["model_size_mb"] == (folder / MODEL_JOBLIB).stat().st_size / BYTES_PER_MB
    assert written["complexity"]["model_size_mb"] < MAX_MODEL_SIZE_MB
    assert read_json(folder / MODEL_JSON) == written
    # El info recibido no cambia, y las tildes quedan legibles en el archivo.
    assert info["complexity"]["model_size_mb"] is None
    assert info["display_name"] in (folder / MODEL_JSON).read_text(encoding="utf-8")


def test_export_again_replaces_the_files(tmp_path, tiny_models, make_model_info):
    model = tiny_models["a9"]["model"]
    info = make_model_info("a9", name="model_a")
    export_model(model, info, tmp_path)
    export_model(model, {**info, "threshold": 0.5}, tmp_path)
    folder = tmp_path / MODELS_DIR.name / "model_a"
    assert read_json(folder / MODEL_JSON)["threshold"] == 0.5
    assert len(list(folder.iterdir())) == 2


def test_export_with_nan_leaves_the_folder_as_it_was(tmp_path, tiny_models, make_model_info):
    info = make_model_info("a9", name="model_a")
    export_model(tiny_models["a9"]["model"], info, tmp_path)
    folder = tmp_path / MODELS_DIR.name / "model_a"
    before = folder_state(folder)
    nan_info = json.loads(json.dumps(info))
    nan_info["test_metrics"]["detection"]["pr_auc"] = float("nan")
    # Con otro modelo: si se alcanzara a guardar model.joblib, su contenido cambiaría.
    with pytest.raises(ValueError, match="no se puede escribir como JSON válido"):
        export_model(tiny_models["a10"]["model"], nan_info, tmp_path)
    assert folder_state(folder) == before


@pytest.mark.parametrize(
    "changes, model_change, error, message",
    [
        ({"name": "mock"}, None, ValueError, "es del modelo simulado"),
        ({"name": "Modelo-A"}, None, ValueError, "minúsculas y snake_case"),
        ({"is_mock": True}, None, ValueError, "solo guarda modelos entrenados"),
        ({}, "missing_key", ArtifactError, "claves"),
        ({"detector_type": "binary"}, "form_b", ArtifactError, "no tiene la clase 1"),
    ],
    ids=["mock_name", "not_snake_case", "is_mock", "missing_key", "classes_do_not_fit"],
)
def test_export_errors_write_nothing(changes, model_change, error, message, tmp_path, tiny_models, make_model_info):
    model = tiny_models["a9"]["model"]
    info = make_model_info("a9", name="model_x")
    if model_change == "missing_key":
        model = {"detector": model["detector"]}
    elif model_change == "form_b":
        model = tiny_models["b"]["model"]
        info = make_model_info("b", name="model_x")
    with pytest.raises(error, match=message):
        export_model(model, {**info, **changes}, tmp_path)
    assert not (tmp_path / MODELS_DIR.name).exists()


def test_registered_model_cannot_be_exported_without_test_metrics(exported, tiny_models, make_model_info):
    folder = exported / MODELS_DIR.name / "model_a"
    before = folder_state(folder)
    info = make_model_info("a9", name="model_a", test_metrics=None)
    with pytest.raises(ArtifactError, match="no tiene test_metrics"):
        export_model(tiny_models["a9"]["model"], info, exported)
    assert folder_state(folder) == before


def test_without_registry_no_model_is_registered(tmp_path, tiny_models, make_model_info):
    info = make_model_info("a9", name="model_a", test_metrics=None)
    assert export_model(tiny_models["a9"]["model"], info, tmp_path)["test_metrics"] is None


def test_export_with_damaged_registry_fails(exported, tiny_models, make_model_info):
    (exported / REGISTRY_PATH.name).write_text("{", encoding="utf-8")
    with pytest.raises(ArtifactError, match="registry.json está dañado"):
        export_model(tiny_models["a9"]["model"], make_model_info("a9", name="model_a"), exported)


# register_model


@pytest.fixture
def mock_only(exported):
    """La carpeta de exported con un registry.json que solo tiene el simulado."""
    write_json(exported / REGISTRY_PATH.name, {"default_model": "mock", "models": [{"name": "mock"}]})
    return exported


def registry_state(artifacts_dir):
    path = artifacts_dir / REGISTRY_PATH.name
    return path.read_bytes(), path.stat().st_mtime_ns


def test_register_adds_before_mock_and_keeps_the_default(mock_only):
    register_model("model_a", mock_only)
    registry = register_model("model_b", mock_only)
    assert [m["name"] for m in registry["models"]] == ["model_a", "model_b", "mock"]
    assert registry["default_model"] == "mock"
    assert read_registry(mock_only) == registry
    assert not (mock_only / (REGISTRY_PATH.name + TEMP_SUFFIX)).exists()


def test_register_again_does_not_touch_the_file(mock_only):
    register_model("model_a", mock_only)
    before = registry_state(mock_only)
    register_model("model_a", mock_only)
    assert registry_state(mock_only) == before


def test_register_without_mock_adds_at_the_end(exported):
    write_json(exported / REGISTRY_PATH.name, {"default_model": "model_b", "models": [{"name": "model_b"}]})
    assert [m["name"] for m in register_model("model_a", exported)["models"]] == ["model_b", "model_a"]


def test_register_rejects_models_the_app_could_not_load(mock_only, tiny_models, make_model_info):
    export_model(tiny_models["a9"]["model"], make_model_info("a9", name="pending", test_metrics=None), mock_only)
    (mock_only / MODELS_DIR.name / "model_b" / MODEL_JOBLIB).write_bytes(b"not a model")
    before = registry_state(mock_only)
    for name, message in (("pending", "no tiene test_metrics"), ("model_b", "está dañado"), ("ghost", "Falta")):
        with pytest.raises(ArtifactError, match=message):
            register_model(name, mock_only)
    assert registry_state(mock_only) == before


def test_registry_is_unchanged_if_writing_the_temporary_file_fails(mock_only):
    # Una carpeta con el nombre del archivo temporal impide escribirlo.
    (mock_only / (REGISTRY_PATH.name + TEMP_SUFFIX)).mkdir()
    before = registry_state(mock_only)
    with pytest.raises(OSError):
        register_model("model_a", mock_only)
    assert registry_state(mock_only) == before


def test_register_needs_an_existing_registry(exported):
    (exported / REGISTRY_PATH.name).unlink()
    with pytest.raises(ArtifactError, match="Falta registry.json"):
        register_model("model_a", exported)
