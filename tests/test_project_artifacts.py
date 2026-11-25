"""Pruebas del artifacts/ real (los 4 modelos registrados, el registro y el simulado) y de los ejemplos JSON del contrato. Solo leen."""

import json

import numpy as np
import pytest
from conftest import structure

from threat_detector.artifacts import MODEL_INFO_FIELDS, load_artifacts, read_model_info
from threat_detector.config import BYTES_PER_MB, MAX_MODEL_SIZE_MB, MODEL_JOBLIB, MODEL_JSON, MODELS_DIR, TEST_ROWS
from threat_detector.dataset import ATTACK_CAT, ATTACK_TYPES, CATEGORICAL_COLS, NORMAL_CAT
from threat_detector.ml.preprocessing import LOG_COLS, build_preprocessor, numeric_input_cols
from threat_detector.ml.training import feature_groups

# Las métricas del contrato y del simulado tienen 4 decimales.
DECIMALS = 4

# Valores fijos del model.json del simulado (contrato, sección 13).
MOCK_TABLE = {
    "name": "mock", "display_name": "Modelo simulado", "is_mock": True, "trained_at": None,
    "sklearn_version": None, "preprocessing_method": None, "threshold_rule": None, "complexity": None,
    "detector_type": "binary", "use_ttl": True, "threshold": 0.31, "can_explain": True,
    "explanation_method": "mock",
}


@pytest.fixture(scope="module")
def project():
    """registry.json y modelos del artifacts/ real, cargados como lo hará la app."""
    return load_artifacts()


@pytest.fixture(scope="module")
def mock():
    """El model.json del simulado. Ya no está registrado, pero se conserva para las pruebas de la app."""
    return read_model_info("mock")


# Contrato


def test_contract_json_examples_are_valid(contract_blocks):
    assert contract_blocks
    for section, block in contract_blocks:
        try:
            json.loads(block)
        except json.JSONDecodeError as error:
            pytest.fail(f"Ejemplo JSON inválido en la sección {section} del contrato: {error}")


def test_model_info_has_the_structure_of_the_contract_example(make_model_info, contract_examples):
    # Mismas claves, en el mismo orden y en cada nivel; los valores del contrato son inventados.
    assert structure(make_model_info("a9")) == structure(contract_examples["11"][0])


# artifacts/ del proyecto


# Los 4 modelos registrados (decisiones de la etapa 10): los 3 elegidos, en el orden de la
# selección, y el modelo base. (name, display_name, método, método de explicación)
REGISTERED = [
    ("hist_gradient_boosting", "HistGradientBoosting", "m1", "shap_tree"),
    ("random_forest", "Random Forest", "m2", "shap_tree"),
    ("mlp", "Red neuronal (MLP)", "m2", None),
    ("logistic_regression", "Regresión logística (modelo base)", "m2", "linear_logit"),
]


def test_project_registers_the_four_models(project):
    registry, models = project
    assert registry == {
        "default_model": "hist_gradient_boosting",
        "models": [{"name": name} for name, *_ in REGISTERED],
    }
    for name, display_name, method, explanation in REGISTERED:
        info = models[name]["info"]
        assert models[name]["model"] is not None
        assert (info["display_name"], info["preprocessing_method"], info["is_mock"]) == (display_name, method, False)
        assert (info["can_explain"], info["explanation_method"]) == (explanation is not None, explanation)
        assert info["test_metrics"] is not None and info["test_metrics"]["test_flows"] == TEST_ROWS
        assert info["trained_at"] is not None and info["complexity"]["hardware"]
        # Entrenados con la parte de entrenamiento: 140.273 flujos (decisión de la etapa 10).
        assert info["complexity"]["training_flows"] == 140_273
        size_mb = (MODELS_DIR / name / MODEL_JOBLIB).stat().st_size / BYTES_PER_MB
        assert size_mb < MAX_MODEL_SIZE_MB
        assert info["complexity"]["model_size_mb"] == pytest.approx(size_mb)


def test_mock_is_kept_but_not_registered(project):
    registry, models = project
    assert "mock" not in models and registry["default_model"] != "mock"
    assert (MODELS_DIR / "mock" / MODEL_JSON).is_file()
    assert not (MODELS_DIR / "mock" / MODEL_JOBLIB).exists()


def test_registry_of_the_app_tests_is_the_contract_example(mock_artifacts, contract_examples):
    # Las pruebas de la app arrancan con solo el simulado registrado: el primer ejemplo de la sección 12.
    assert json.loads((mock_artifacts / "registry.json").read_text(encoding="utf-8")) == contract_examples["12"][0]


def test_mock_model_json_follows_the_contract(mock, contract_examples):
    assert list(mock) == MODEL_INFO_FIELDS
    assert {field: mock[field] for field in MOCK_TABLE} == MOCK_TABLE
    model_example = contract_examples["11"][0]
    for field in ("numeric_cols", "categorical_cols", "log_cols", "feature_groups"):
        assert mock[field] == model_example[field], field
    metrics_example = contract_examples["7"][0]["models"][0]
    assert mock["test_metrics"] == {k: metrics_example[k] for k in ("test_flows", "detection", "attack_type")}
    models_example = contract_examples["6"][0]["models"][0]
    assert {k: mock[k] for k in models_example} == models_example


def test_mock_variables_match_the_code(mock, make_model_info):
    assert mock["numeric_cols"] == numeric_input_cols(use_ttl=True)
    assert mock["categorical_cols"] == CATEGORICAL_COLS
    assert mock["log_cols"] == [c for c in mock["numeric_cols"] if c in LOG_COLS]
    assert structure(mock["test_metrics"]) == structure(make_model_info("a9")["test_metrics"])


def test_mock_metrics_are_consistent(mock):
    detection = mock["test_metrics"]["detection"]
    attack_type = mock["test_metrics"]["attack_type"]
    assert mock["test_metrics"]["test_flows"] == TEST_ROWS

    # Desde la matriz de confusión entre tipos: per_class, macro_f1 y evaluated_flows.
    matrix = np.array(attack_type["confusion"]["matrix"])
    assert attack_type["confusion"]["labels"] == ATTACK_TYPES
    f1_values = []
    for i, entry in enumerate(attack_type["per_class"]):
        tp, support, predicted = matrix[i, i], matrix[i].sum(), matrix[:, i].sum()
        f1_values.append(2 * tp / (support + predicted))
        assert entry == {
            "attack_cat": ATTACK_TYPES[i],
            "precision": round(tp / predicted, DECIMALS),
            "recall": round(tp / support, DECIMALS),
            "f1": round(f1_values[-1], DECIMALS),
            "support": int(support),
        }
    assert attack_type["macro_f1"] == round(float(np.mean(f1_values)), DECIMALS)

    # Desde confusion: las métricas de detección. pr_auc y roc_auc necesitan las probabilidades.
    tp, fp, tn, fn = (detection["confusion"][k] for k in ("tp", "fp", "tn", "fn"))
    assert attack_type["evaluated_flows"] == matrix.sum() == tp
    assert tp + fp + tn + fn == TEST_ROWS
    assert {k: detection[k] for k in ("detection_rate", "false_alarm_rate", "precision", "f1", "accuracy")} == {
        "detection_rate": round(tp / (tp + fn), DECIMALS),
        "false_alarm_rate": round(fp / (fp + tn), DECIMALS),
        "precision": round(tp / (tp + fp), DECIMALS),
        "f1": round(2 * tp / (2 * tp + fp + fn), DECIMALS),
        "accuracy": round((tp + tn) / TEST_ROWS, DECIMALS),
    }


# Con los CSV completos


def test_mock_metrics_are_possible_for_the_real_test_set(mock, test_partition):
    counts = test_partition[ATTACK_CAT].value_counts()
    confusion = mock["test_metrics"]["detection"]["confusion"]
    assert confusion["tp"] + confusion["fn"] == counts.drop(NORMAL_CAT).sum()
    assert confusion["fp"] + confusion["tn"] == counts[NORMAL_CAT]
    # Cada tipo evaluado no puede tener más flujos que los reales; los que faltan son ataques sin alerta.
    supports = {c["attack_cat"]: c["support"] for c in mock["test_metrics"]["attack_type"]["per_class"]}
    missing = {attack_cat: counts[attack_cat] - support for attack_cat, support in supports.items()}
    assert all(value >= 0 for value in missing.values()), missing
    assert sum(missing.values()) == confusion["fn"]


def test_mock_feature_groups_match_a_preprocessor_fitted_on_the_train_part(mock, train_split):
    preprocessor = build_preprocessor("m2").fit(train_split[0])
    assert list(feature_groups(preprocessor).items()) == list(mock["feature_groups"].items())
