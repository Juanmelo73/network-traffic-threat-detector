"""Pruebas de ml/preprocessing.py: métodos de preprocesamiento y separación de entrenamiento y validación."""

import numpy as np
import pandas as pd
import pytest

from threat_detector.config import TRAIN_ROWS, VALIDATION_SIZE
from threat_detector.dataset import ATTACK_CAT, CATEGORICAL_COLS, ID_COL, TARGET_COLS
from threat_detector.ml.preprocessing import (
    DROPPED_COLS,
    LOG_COLS,
    PREPROCESSING_METHODS,
    TTL_COLS,
    build_preprocessor,
    flow_pattern_ids,
    numeric_input_cols,
    split_train_validation,
)

METHODS = list(PREPROCESSING_METHODS)

# Columnas finales con la parte de entrenamiento completa: 32 numéricas (29 sin TTL) y 21 one-hot.
ONE_HOT_COLUMNS = 21
EXPECTED_COLUMNS = {"m1": 53, "m2": 53, "m3": 50}
# Tamaño de la separación real (CLAUDE.md, conjuntos de datos).
TRAIN_PART_ROWS, VALIDATION_ROWS = 140_273, 35_068


def fit_transform(method, flows):
    """Ajusta el preprocesador de un método con los flujos y los transforma."""
    preprocessor = build_preprocessor(method).fit(flows)
    return preprocessor, preprocessor.transform(flows)


def one_hot_columns(preprocessor):
    return list(preprocessor.named_transformers_["categorical"].get_feature_names_out())


# build_preprocessor


def test_unknown_method_is_rejected():
    with pytest.raises(ValueError, match="Método de preprocesamiento desconocido: m4"):
        build_preprocessor("m4")


@pytest.mark.parametrize("method", METHODS)
def test_numeric_outputs_are_the_numeric_input_cols(method, sample_flows):
    preprocessor, out = fit_transform(method, sample_flows)
    use_ttl = PREPROCESSING_METHODS[method]["use_ttl"]
    numeric_out = [c for c in out.columns if c not in one_hot_columns(preprocessor)]
    assert set(numeric_out) == set(numeric_input_cols(use_ttl))
    assert all(c in out.columns for c in TTL_COLS) == use_ttl
    assert out.columns.is_unique


@pytest.mark.parametrize("method", METHODS)
def test_dropped_columns_id_and_labels_never_reach_the_model(method, sample_flows):
    _, out = fit_transform(method, sample_flows)
    assert not set(out.columns) & {*DROPPED_COLS, ID_COL, *TARGET_COLS, *CATEGORICAL_COLS}


def test_m1_and_m2_have_the_same_columns_and_m3_drops_only_ttl(sample_flows):
    columns = {method: list(fit_transform(method, sample_flows)[1].columns) for method in METHODS}
    assert columns["m1"] == columns["m2"]
    assert columns["m3"] == [c for c in columns["m1"] if c not in TTL_COLS]


def test_m1_applies_log1p_and_does_not_scale(sample_flows):
    _, out = fit_transform("m1", sample_flows)
    for col in numeric_input_cols():
        expected = np.log1p(sample_flows[col]) if col in LOG_COLS else sample_flows[col]
        np.testing.assert_allclose(out[col], expected)


def test_m2_standardizes_numeric_columns_but_not_one_hot(sample_flows):
    preprocessor, out = fit_transform("m2", sample_flows)
    for col in numeric_input_cols():
        assert out[col].mean() == pytest.approx(0, abs=1e-9)
        assert out[col].std(ddof=0) == pytest.approx(1)
    one_hot = out[one_hot_columns(preprocessor)]
    assert set(np.unique(one_hot)) <= {0, 1}


@pytest.mark.parametrize("method", METHODS)
def test_each_flow_has_exactly_one_category_per_variable(method, sample_flows):
    preprocessor, out = fit_transform(method, sample_flows)
    for col in CATEGORICAL_COLS:
        columns = [c for c in one_hot_columns(preprocessor) if c.startswith(f"{col}_")]
        assert (out[columns].sum(axis=1) == 1).all()


def test_unknown_and_empty_categories_go_to_the_infrequent_column(sample_flows):
    preprocessor = build_preprocessor("m1").fit(sample_flows)
    # En la muestra hay protocolos raros, así que proto tiene columna infrecuente.
    assert "proto_infrequent_sklearn" in one_hot_columns(preprocessor)
    new_flows = sample_flows.iloc[:2].copy()
    new_flows["proto"] = ["protocolo_nuevo", np.nan]
    out = preprocessor.transform(new_flows)
    assert (out["proto_infrequent_sklearn"] == 1).all()


def test_extra_columns_are_ignored(sample_flows):
    preprocessor = build_preprocessor("m2").fit(sample_flows)
    with_extra = sample_flows.assign(extra=1.0)
    pd.testing.assert_frame_equal(preprocessor.transform(with_extra), preprocessor.transform(sample_flows))


# flow_pattern_ids


def test_flow_pattern_ids_depend_only_on_input_values(sample_flows):
    copy = sample_flows.iloc[[0]].copy()
    copy[ID_COL] = 999_999
    copy[TARGET_COLS] = [1 - copy["label"].iloc[0], "Worms"]
    changed = sample_flows.iloc[[0]].copy()
    changed["dur"] = changed["dur"] + 1
    ids = flow_pattern_ids(pd.concat([sample_flows.iloc[[0]], copy, changed]))
    assert ids.iloc[0] == ids.iloc[1]
    assert ids.iloc[0] != ids.iloc[2]


# split_train_validation


@pytest.fixture
def flows_with_repeats(sample_flows):
    """sample_flows.csv con 150 flujos repetidos (con otro id), para tener grupos de flujos idénticos."""
    repeats = pd.concat([sample_flows.iloc[:100], sample_flows.iloc[:50]])
    flows = pd.concat([sample_flows, repeats], ignore_index=True)
    flows[ID_COL] = np.arange(len(flows))
    return flows


def test_split_keeps_each_group_of_identical_flows_together(flows_with_repeats):
    train, validation = split_train_validation(flows_with_repeats)
    patterns = flow_pattern_ids(flows_with_repeats)
    assert not set(patterns[train.index]) & set(patterns[validation.index])


def test_split_uses_each_flow_once_and_is_repeatable(flows_with_repeats):
    train, validation = split_train_validation(flows_with_repeats)
    assert sorted([*train.index, *validation.index]) == list(flows_with_repeats.index)
    again_train, again_validation = split_train_validation(flows_with_repeats)
    assert train.index.equals(again_train.index) and validation.index.equals(again_validation.index)


def test_split_validation_is_close_to_validation_size(flows_with_repeats):
    _, validation = split_train_validation(flows_with_repeats)
    assert len(validation) / len(flows_with_repeats) == pytest.approx(VALIDATION_SIZE, abs=0.05)


# Con los CSV completos


def test_real_split_sizes(train_split):
    train, validation = train_split
    assert (len(train), len(validation)) == (TRAIN_PART_ROWS, VALIDATION_ROWS)
    assert len(train) + len(validation) == TRAIN_ROWS
    assert set(validation[ATTACK_CAT]) == set(train[ATTACK_CAT])


@pytest.mark.parametrize("method", METHODS)
def test_train_part_gives_the_agreed_columns(method, train_split, contract_examples):
    preprocessor, out = fit_transform(method, train_split[0])
    assert out.shape[1] == EXPECTED_COLUMNS[method]
    one_hot = one_hot_columns(preprocessor)
    assert len(one_hot) == ONE_HOT_COLUMNS
    # Las mismas categorías del ejemplo de model.json del contrato (sección 11).
    contract_groups = contract_examples["11"][0]["feature_groups"]
    assert one_hot == [c for col in CATEGORICAL_COLS for c in contract_groups[col]]
