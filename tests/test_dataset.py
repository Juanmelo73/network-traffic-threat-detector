"""Pruebas de dataset.py y de las constantes de config.py."""

import io
import json
import re

import numpy as np
import pandas as pd
import pytest
from conftest import CONTRACT_PATH

from threat_detector.config import (
    DEMO_MIN_PER_ATTACK,
    DEMO_SAMPLE_CSV,
    DEMO_SAMPLE_SIZE,
    MAX_ERROR_ROWS,
    MIN_CATEGORY_COUNT,
    MIN_CATEGORY_FRACTION,
    TEST_ROWS,
    TRAIN_ROWS,
)
from threat_detector.dataset import (
    ATTACK_CAT,
    ATTACK_TYPES,
    CATEGORICAL_COLS,
    ID_COL,
    INPUT_COLS,
    NORMAL_CAT,
    RAW_COLUMNS,
    TARGET,
    TARGET_COLS,
    FlowValidationError,
    load_flows,
    make_demo_sample,
    validate_flows,
    validate_ids,
    validate_labels,
)
from threat_detector.ml.preprocessing import numeric_input_cols

NUMERIC_COLS = numeric_input_cols()


def validate(flows):
    """validate_flows con las columnas de un modelo con TTL."""
    return validate_flows(flows, NUMERIC_COLS, CATEGORICAL_COLS)


# Constantes


def test_input_cols_are_the_file_columns_without_id_and_labels():
    assert len(INPUT_COLS) == 42
    assert ID_COL not in INPUT_COLS and not set(TARGET_COLS) & set(INPUT_COLS)
    assert INPUT_COLS == [c for c in RAW_COLUMNS if c in INPUT_COLS]


def test_attack_types_follow_the_contract_order():
    # Sección 2 del contrato: la línea con los 10 valores de attack_cat, en orden.
    text = CONTRACT_PATH.read_text(encoding="utf-8")
    line = next(line for line in text.splitlines() if line.startswith('`"Normal"`'))
    assert re.findall(r'`"([^"]+)"`', line) == [NORMAL_CAT, *ATTACK_TYPES]
    assert len(set(ATTACK_TYPES)) == 9


def test_min_category_fraction_is_the_eda_minimum_as_a_fraction():
    assert MIN_CATEGORY_FRACTION == MIN_CATEGORY_COUNT / TRAIN_ROWS


# validate_flows


def test_valid_flows_pass_and_are_not_modified(sample_flows):
    original = sample_flows.copy()
    assert validate(sample_flows) is None
    pd.testing.assert_frame_equal(sample_flows, original)


def test_empty_file_is_rejected(sample_flows):
    with pytest.raises(ValueError, match="El archivo no tiene flujos para analizar"):
        validate(sample_flows.iloc[0:0])


def test_all_missing_columns_are_listed_together(sample_flows):
    with pytest.raises(ValueError, match="faltan columnas obligatorias: sttl, proto"):
        validate(sample_flows.drop(columns=["sttl", "proto"]))


@pytest.mark.parametrize(
    "bad_value", [np.nan, "abc", np.inf], ids=["empty", "not_numeric", "infinite"]
)
def test_empty_non_numeric_and_infinite_values_are_rejected(sample_flows, bad_value):
    sample_flows["sbytes"] = sample_flows["sbytes"].astype(object)
    sample_flows.loc[[3, 7], "sbytes"] = bad_value
    # Posición 3 y 7 = líneas 5 y 9 del archivo (el encabezado es la línea 1).
    with pytest.raises(
        ValueError,
        match=r"2 flujo\(s\) con valores vacíos o no numéricos en las columnas sbytes\. "
        r"Primeras filas afectadas: 5, 9\.",
    ):
        validate(sample_flows)


def test_negative_values_are_rejected(sample_flows):
    sample_flows.loc[0, "dbytes"] = -1
    with pytest.raises(
        ValueError, match="valores negativos en las columnas dbytes.*: 2\\."
    ):
        validate(sample_flows)


def test_empty_values_are_reported_before_negative_ones(sample_flows):
    sample_flows.loc[0, "dbytes"] = -1
    sample_flows.loc[5, "dur"] = np.nan
    with pytest.raises(ValueError, match="vacíos o no numéricos en las columnas dur"):
        validate(sample_flows)


def test_rows_are_counted_by_position_not_by_index(sample_flows):
    # Un índice desordenado no cambia la numeración: posición + 2 = línea del archivo.
    sample_flows.index = np.random.default_rng(0).permutation(
        np.arange(1000, 1000 + len(sample_flows))
    )
    sample_flows.iloc[10, sample_flows.columns.get_loc("rate")] = -5
    with pytest.raises(ValueError, match="Primeras filas afectadas: 12\\."):
        validate(sample_flows)


def test_only_the_first_max_error_rows_are_listed(sample_flows):
    bad_rows = MAX_ERROR_ROWS + 5
    sample_flows.loc[: bad_rows - 1, "dur"] = -1
    expected_lines = ", ".join(str(position + 2) for position in range(MAX_ERROR_ROWS))
    with pytest.raises(
        ValueError,
        match=f"Hay {bad_rows} flujo.*Primeras filas afectadas: {expected_lines}\\.",
    ):
        validate(sample_flows)


def test_empty_categorical_value_is_not_rejected(sample_flows):
    sample_flows.loc[0, "service"] = np.nan
    assert validate(sample_flows) is None


def raised(call, flows):
    """El FlowValidationError que lanza call(flows)."""
    with pytest.raises(FlowValidationError) as error:
        call(flows)
    return error.value


def test_validation_errors_carry_code_and_json_ready_details(sample_flows):
    # Cada revisión de validate_flows lanza su código de la sección 9 del contrato, con details en JSON.
    negative = sample_flows.copy()
    negative.loc[[3, 7], "sbytes"] = -1
    cases = [
        (sample_flows.iloc[0:0], "empty_file", None),
        (sample_flows.drop(columns=["sttl", "proto"]), "missing_columns", {"missing_columns": ["sttl", "proto"]}),
        (negative, "invalid_values", {"reason": "negative", "columns": ["sbytes"], "rows": [5, 9], "total_rows": 2}),
    ]
    for flows, code, details in cases:
        error = raised(validate, flows)
        assert isinstance(error, ValueError)
        assert (error.code, error.details) == (code, details)
        assert json.loads(json.dumps(error.details)) == details


def test_empty_or_not_numeric_reason(sample_flows):
    sample_flows["dur"] = sample_flows["dur"].astype(object)
    sample_flows.loc[0, "dur"] = "abc"
    assert raised(validate, sample_flows).details["reason"] == "empty_or_not_numeric"


# validate_ids


def test_valid_ids_pass(sample_flows):
    assert validate_ids(sample_flows) is None
    # 3.0 es el id 3: un entero escrito con decimales.
    sample_flows[ID_COL] = sample_flows[ID_COL].astype(float)
    assert validate_ids(sample_flows) is None


@pytest.mark.parametrize("bad_value", [np.nan, 3.5, "abc"], ids=["empty", "not_integer", "not_a_number"])
def test_empty_non_integer_and_non_numeric_ids_are_rejected(sample_flows, bad_value):
    sample_flows[ID_COL] = sample_flows[ID_COL].astype(object)
    sample_flows.loc[4, ID_COL] = bad_value
    error = raised(validate_ids, sample_flows)
    assert error.code == "invalid_ids"
    assert error.details == {"rows": [6], "total_rows": 1}
    assert str(error) == ("Hay 1 flujo(s) con un id vacío, que no es un número entero o que está repetido. "
                          "Primeras filas afectadas: 6.")


def test_repeated_ids_mark_every_row_with_that_id(sample_flows):
    # 1 y 1.0 son el mismo id: se marcan las dos filas.
    sample_flows[ID_COL] = sample_flows[ID_COL].astype(object)
    sample_flows.loc[2, ID_COL] = 1
    sample_flows.loc[9, ID_COL] = "1.0"
    assert raised(validate_ids, sample_flows).details == {"rows": [4, 11], "total_rows": 2}


# validate_labels


def test_valid_labels_pass(sample_flows):
    assert validate_labels(sample_flows) is None


def test_label_is_compared_as_a_number(sample_flows):
    # Con una celda vacía, pandas lee la columna como decimal: 0.0 y 1.0 siguen siendo válidos y
    # el error lista solo la fila vacía.
    sample_flows.loc[6, TARGET] = np.nan
    assert sample_flows[TARGET].dtype == float
    error = raised(validate_labels, sample_flows)
    assert error.code == "invalid_labels"
    assert error.details == {"column": TARGET, "rows": [8], "total_rows": 1}
    assert str(error) == ("Hay 1 flujo(s) con etiquetas no válidas en la columna label. "
                          "Primeras filas afectadas: 8.")


@pytest.mark.parametrize(
    "column, bad_value",
    [(TARGET, 2), (ATTACK_CAT, "worms"), (ATTACK_CAT, np.nan)],
    ids=["label_2", "attack_cat_lowercase", "attack_cat_empty"],
)
def test_invalid_labels_are_rejected(sample_flows, column, bad_value):
    sample_flows.loc[[1, 3], column] = bad_value
    assert raised(validate_labels, sample_flows).details == {"column": column, "rows": [3, 5], "total_rows": 2}


def test_label_is_checked_before_attack_cat(sample_flows):
    sample_flows.loc[0, ATTACK_CAT] = "worms"
    sample_flows.loc[5, TARGET] = 2
    assert raised(validate_labels, sample_flows).details["column"] == TARGET


# load_flows


def test_load_flows_missing_file_points_to_data_readme(tmp_path):
    with pytest.raises(FileNotFoundError, match="data/README.md"):
        load_flows(tmp_path / "missing.csv", TRAIN_ROWS)


def test_load_flows_checks_columns_and_rows(tmp_path, sample_flows):
    path = tmp_path / "flows.csv"
    sample_flows.to_csv(path, index=False)
    assert len(load_flows(path, DEMO_SAMPLE_SIZE)) == DEMO_SAMPLE_SIZE
    with pytest.raises(ValueError, match="se esperaban"):
        load_flows(path, TRAIN_ROWS)
    sample_flows.drop(columns=["rate"]).to_csv(path, index=False)
    with pytest.raises(ValueError, match="no tiene las columnas esperadas"):
        load_flows(path, DEMO_SAMPLE_SIZE)


# sample_flows.csv


def test_demo_sample_has_the_agreed_shape(sample_flows):
    assert list(sample_flows.columns) == RAW_COLUMNS
    assert len(sample_flows) == DEMO_SAMPLE_SIZE
    counts = sample_flows[ATTACK_CAT].value_counts()
    assert set(counts.index) == {NORMAL_CAT, *ATTACK_TYPES}
    assert (counts[ATTACK_TYPES] >= DEMO_MIN_PER_ATTACK).all()
    assert (sample_flows[TARGET] == (sample_flows[ATTACK_CAT] != NORMAL_CAT)).all()


# Con los CSV completos


def test_official_partitions_have_expected_rows_and_labels(
    train_partition, test_partition
):
    for flows, rows in ((train_partition, TRAIN_ROWS), (test_partition, TEST_ROWS)):
        assert len(flows) == rows and list(flows.columns) == RAW_COLUMNS
        assert set(flows[ATTACK_CAT]) == {NORMAL_CAT, *ATTACK_TYPES}
        assert (flows[TARGET] == (flows[ATTACK_CAT] != NORMAL_CAT)).all()


def test_demo_sample_regenerates_identically(test_partition):
    # Se compara como CSV: así cuentan igual los tipos y decimales que se leen del archivo.
    regenerated = pd.read_csv(
        io.StringIO(make_demo_sample(test_partition).to_csv(index=False))
    )
    pd.testing.assert_frame_equal(regenerated, pd.read_csv(DEMO_SAMPLE_CSV))
