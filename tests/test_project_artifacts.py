"""Pruebas del artifacts/ real (modelo simulado y registro) y de los ejemplos JSON del contrato. Solo leen."""

import json

import numpy as np
import pytest
from conftest import structure

from threat_detector.artifacts import MODEL_INFO_FIELDS, load_artifacts
from threat_detector.config import MODEL_JOBLIB, MODELS_DIR, TEST_ROWS
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
def mock(project):
    return project[1]["mock"]["info"]


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


def test_project_artifacts_have_only_the_mock_model(project):
    registry, models = project
    assert list(models) == ["mock"]
    assert models["mock"]["model"] is None
    assert not (MODELS_DIR / "mock" / MODEL_JOBLIB).exists()


def test_registry_is_the_contract_example(project, contract_examples):
    assert project[0] == contract_examples["12"][0]


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
