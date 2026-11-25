"""Pruebas de ml/training.py: búsqueda de modelos, model.json, exportar y registrar (siempre en carpetas temporales)."""

import json
import platform
import shutil
import warnings
from datetime import datetime

import numpy as np
import pandas as pd
import pytest
import sklearn
from conftest import TRAINED_AT_UTC, read_json, write_json
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline, make_pipeline

from threat_detector.artifacts import (
    MODEL_INFO_FIELDS,
    ArtifactError,
    attack_cat_from_proba,
    attack_probability_from_proba,
    read_registry,
)
from threat_detector.artifacts import load_artifacts
from threat_detector.config import BYTES_PER_MB, MAX_MODEL_SIZE_MB, MODEL_JOBLIB, MODEL_JSON, MODELS_DIR, REGISTRY_PATH, SCORE_TIE_TOLERANCE
from threat_detector.dataset import ATTACK_CAT, CATEGORICAL_COLS, INPUT_COLS, TARGET
from threat_detector.ml import training as training_module
from threat_detector.ml.evaluation import attack_type_metrics, detection_metrics, threshold_rule
from threat_detector.ml.preprocessing import LOG_COLS, PREPROCESSING_METHODS, build_preprocessor, numeric_input_cols
from threat_detector.ml.training import (
    RESULT_COLUMNS,
    TEMP_SUFFIX,
    apply_simplicity_rule,
    check_model_size,
    complexity,
    export_model,
    feature_groups,
    CURVE_PHASE,
    MODEL_FAMILIES,
    PHASE2_GRIDS,
    SEARCH_VERSION,
    TASKS,
    fit_candidate,
    fixed_params,
    curve_candidates,
    phase1_candidates,
    phase2_candidates,
    read_search_results,
    final_model_specs,
    hardware_description,
    oob_comparison,
    oob_per_type,
    register_model,
    run_search,
    select_candidates,
    set_default_model,
    train_final_models,
    unregister_model,
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


# Búsqueda de modelos

# Columnas de cada tarea en una fila de resultados; las de la otra tarea quedan en None.
DETECTOR_COLUMNS = [
    "pr_auc", "roc_auc", "threshold", "detection_rate", "false_alarm_rate", "precision", "f1", "tp", "fp", "tn", "fn",
    "train_pr_auc", "train_false_alarm_rate",
]
TYPE_COLUMNS = RESULT_COLUMNS[RESULT_COLUMNS.index("macro_f1"):]
# Diferencia máxima aceptada entre dos cálculos de las mismas probabilidades (redondeo).
PROBA_TOLERANCE = 1e-12
# Columnas que cambian entre dos corridas iguales: la hora y los tiempos medidos.
TIMING_COLUMNS = {"run_at", "search_seconds", "predict_ms_per_1000_flows"}


@pytest.fixture
def split(sample_flows):
    """Entrenamiento y validación pequeños, con todos los tipos de ataque en las dos partes."""
    train = sample_flows.groupby(ATTACK_CAT, group_keys=False).sample(frac=0.8, random_state=42)
    return train, sample_flows.drop(train.index)


@pytest.fixture
def small_ensembles(monkeypatch):
    """Ensambles que crecen de 2 en 2 hasta 6, para que las pruebas sean rápidas."""
    monkeypatch.setattr(training_module, "TREE_COUNT_STEP", 2)
    monkeypatch.setattr(training_module, "MAX_TREE_COUNT", 6)
    monkeypatch.setattr(training_module, "BOOSTING_ITERATION_STEP", 2)
    monkeypatch.setattr(training_module, "MAX_BOOSTING_ITERATIONS", 6)


@pytest.mark.parametrize("task", ["detector", "attack_type"])
def test_candidate_row_has_the_agreed_columns(task, split):
    train, validation = split
    _, row = fit_candidate(1, task, "decision_tree", "m2", {"model__max_depth": 4}, train, validation)

    assert list(row) == RESULT_COLUMNS
    # En el clasificador, la precisión de un tipo que nunca se predice es None (attack_type_metrics).
    own = DETECTOR_COLUMNS if task == "detector" else ["macro_f1", "min_type_f1", "train_macro_f1", "type_confusion", "generic_support"]
    other = TYPE_COLUMNS if task == "detector" else DETECTOR_COLUMNS
    assert all(row[c] is not None for c in own)
    assert all(row[c] is None for c in other)
    assert (row["phase"], row["task"], row["family"], row["method"]) == (1, task, "decision_tree", "m2")
    assert json.loads(row["params"]) == {"model__max_depth": 4}
    assert row["sklearn_version"] == sklearn.__version__
    assert row["search_version"] == SEARCH_VERSION
    assert row["model_size_mb"] > 0 and row["predict_ms_per_1000_flows"] > 0
    # El clasificador entrena y se mide solo con los ataques.
    rows = train if task == "detector" else train[train[TARGET] == 1]
    assert row["train_flows"] == len(rows)


def test_detector_row_follows_the_threshold_rule(split):
    train, validation = split
    pipeline, row = fit_candidate(1, "detector", "random_forest", "m1", {}, train, validation)

    proba = pipeline.predict_proba(validation[INPUT_COLS])
    attack_probability = attack_probability_from_proba(proba, pipeline.classes_, "binary")
    rule = threshold_rule(validation[TARGET], attack_probability, row["threshold"])
    assert row["detection_rate"] == rule["validation_detection_rate"] >= 0.95
    assert row["false_alarm_rate"] == rule["validation_false_alarm_rate"]


def test_classifier_row_has_macro_f1_and_its_worst_type(split):
    train, validation = split
    _, row = fit_candidate(1, "attack_type", "decision_tree", "m1", {}, train, validation)

    f1_values = [row[f"{t.lower()}_f1"] for t in training_module.ATTACK_TYPES]
    assert row["macro_f1"] == pytest.approx(np.mean(f1_values))
    assert row["min_type_f1"] == min(f1_values)
    matrix = json.loads(row["type_confusion"])
    assert np.array(matrix).shape == (9, 9)
    assert np.array(matrix).sum() == row["validation_flows"] == int((validation[TARGET] == 1).sum())


@pytest.mark.parametrize("family", ["decision_tree", "random_forest"])
def test_training_metrics_use_the_training_part_and_the_validation_threshold(family, split, small_ensembles):
    train, validation = split
    detector, detector_row = fit_candidate(1, "detector", family, "m1", {}, train, validation)
    classifier, classifier_row = fit_candidate(1, "attack_type", family, "m1", {}, train, validation)

    proba = detector.predict_proba(train[INPUT_COLS])
    attack_probability = attack_probability_from_proba(proba, detector.classes_, "binary")
    detection = detection_metrics(train[TARGET], attack_probability, detector_row["threshold"])
    assert detector_row["train_pr_auc"] == detection["pr_auc"]
    assert detector_row["train_false_alarm_rate"] == detection["false_alarm_rate"]

    attacks = train[train[TARGET] == 1]
    predicted = attack_cat_from_proba(classifier.predict_proba(attacks[INPUT_COLS]), classifier.classes_)
    types = attack_type_metrics(attacks[ATTACK_CAT], predicted, np.ones(len(attacks), dtype=bool))
    assert classifier_row["train_macro_f1"] == types["macro_f1"]
    # Un árbol sin límite de profundidad casi memoriza el entrenamiento.
    if family == "decision_tree":
        assert detector_row["train_pr_auc"] >= detector_row["pr_auc"]
        assert classifier_row["train_macro_f1"] >= classifier_row["macro_f1"]


def test_classifier_keeps_the_categories_of_all_training_flows(split):
    train, validation = split
    # Una categoría que solo tienen los flujos normales: ajustado solo con ataques, se perdería.
    normal_rows = train.index[train[TARGET] == 0][:10]
    train.loc[normal_rows, "proto"] = "only_in_normal"

    pipeline, _ = fit_candidate(1, "attack_type", "decision_tree", "m1", {}, train, validation)

    all_flows = build_preprocessor("m1").fit(train[INPUT_COLS]).get_feature_names_out()
    only_attacks = build_preprocessor("m1").fit(train.loc[train[TARGET] == 1, INPUT_COLS]).get_feature_names_out()
    assert "proto_only_in_normal" in all_flows and "proto_only_in_normal" not in only_attacks
    assert list(pipeline["preprocessor"].get_feature_names_out()) == list(all_flows)


@pytest.mark.parametrize("task", ["detector", "attack_type"])
def test_ensemble_measures_every_block_and_keeps_the_best(task, split, small_ensembles, monkeypatch):
    monkeypatch.setattr(training_module, "MAX_TREE_COUNT", 12)
    original = training_module._task_metrics
    # Puntajes de los bloques de 2, 4, ..., 12 árboles: baja dos veces y después mejora. El mejor
    # es el de 8; el de 12 empata con él y no lo reemplaza, porque se prefiere el menor.
    scores = iter([0.5, 0.4, 0.3, 0.7, 0.6, 0.7])
    measured = []

    def fake_metrics(*args):
        measured.append(len(args[1].estimators_))
        return original(*args)[0], next(scores)

    monkeypatch.setattr(training_module, "_task_metrics", fake_metrics)
    train, validation = split
    pipeline, row = fit_candidate(1, task, "random_forest", "m1", {}, train, validation)

    assert measured == [2, 4, 6, 8, 10, 12]
    assert row["best_iteration"] == 8
    assert len(pipeline["model"].estimators_) == 8


@pytest.mark.parametrize(
    "family, estimator_class, parameter, class_weight",
    [
        ("random_forest", RandomForestClassifier, "n_estimators", "balanced"),
        ("random_forest", RandomForestClassifier, "n_estimators", "balanced_subsample"),
        ("extra_trees", ExtraTreesClassifier, "n_estimators", "balanced"),
        ("extra_trees", ExtraTreesClassifier, "n_estimators", "balanced_subsample"),
        ("hist_gradient_boosting", HistGradientBoostingClassifier, "max_iter", "balanced"),
    ],
)
@pytest.mark.parametrize("task", ["detector", "attack_type"])
def test_grown_ensemble_equals_a_fresh_fit_with_its_best_iteration(
    family, estimator_class, parameter, class_weight, task, split, small_ensembles
):
    # También con pesos de clase: el aviso de scikit-learn sobre warm_start no aplica aquí.
    train, validation = split
    pipeline, row = fit_candidate(1, task, family, "m1", {"model__class_weight": class_weight}, train, validation)

    fresh = training_module._candidate_estimator(family).set_params(
        warm_start=False, class_weight=class_weight, **{parameter: row["best_iteration"]}
    )
    rows = train if task == "detector" else train[train[TARGET] == 1]
    target = rows[TARGET] if task == "detector" else rows[ATTACK_CAT]
    fresh.fit(pipeline["preprocessor"].transform(rows[INPUT_COLS]), target)
    assert isinstance(pipeline["model"], estimator_class)
    assert not pipeline["model"].warm_start
    # Los árboles son idénticos. Las probabilidades se comparan con tolerancia: con n_jobs=-1 los
    # árboles se promedian en paralelo y el orden de la suma cambia el redondeo (~1e-16).
    for grown_tree, fresh_tree in zip(getattr(pipeline["model"], "estimators_", []), getattr(fresh, "estimators_", [])):
        np.testing.assert_array_equal(grown_tree.tree_.threshold, fresh_tree.tree_.threshold)
        np.testing.assert_array_equal(grown_tree.tree_.value, fresh_tree.tree_.value)
    features = pipeline["preprocessor"].transform(validation[INPUT_COLS])
    np.testing.assert_allclose(pipeline["model"].predict_proba(features), fresh.predict_proba(features), rtol=0, atol=PROBA_TOLERANCE)


def test_search_caps_are_the_scikit_learn_defaults():
    assert training_module.MAX_TREE_COUNT == RandomForestClassifier().n_estimators == ExtraTreesClassifier().n_estimators
    assert training_module.MAX_BOOSTING_ITERATIONS == HistGradientBoostingClassifier().max_iter
    assert training_module.MLP_MAX_ITER == MLPClassifier().max_iter


@pytest.mark.parametrize(
    "family, params, expected",
    [
        ("logistic_regression", {}, {"max_iter": 1000}),
        # Si max_iter se busca, ya no es un valor fijo.
        ("logistic_regression", {"model__max_iter": 50}, {}),
        ("hist_gradient_boosting", {}, {"early_stopping": False}),
        ("mlp", {}, {"early_stopping": True}),
        ("random_forest", {}, {}),
        ("extra_trees", {}, {}),
        ("decision_tree", {}, {}),
        ("gaussian_nb", {}, {}),
        ("dummy", {}, {}),
    ],
)
def test_fixed_params_note_the_exceptions_to_the_defaults(family, params, expected):
    assert fixed_params(family, params) == expected


def test_convergence_warning_is_recorded_and_not_shown(split):
    train, validation = split
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        _, row = fit_candidate(1, "detector", "logistic_regression", "m1", {"model__max_iter": 1}, train, validation)

    assert not [w for w in emitted if issubclass(w.category, ConvergenceWarning)]
    assert not row["converged"]
    assert "lbfgs failed to converge" in row["convergence_warnings"]
    assert row["best_iteration"] == 1


def test_mlp_retries_m1_with_m2_if_it_does_not_converge(split, monkeypatch):
    monkeypatch.setattr(training_module, "MLP_MAX_ITER", 1)
    train, validation = split
    _, row = fit_candidate(1, "detector", "mlp", "m1", {"model__hidden_layer_sizes": (8,)}, train, validation)

    assert row["mlp_scaled_fallback"]
    assert (row["requested_method"], row["method"]) == ("m1", "m2")
    assert "Maximum iterations" in row["convergence_warnings"]


@pytest.mark.parametrize("task", ["detector", "attack_type"])
def test_candidate_is_repeatable(task, split, small_ensembles):
    train, validation = split
    first, second = (
        fit_candidate(1, task, "random_forest", "m2", {}, train, validation)[1] for _ in range(2)
    )
    for column in RESULT_COLUMNS:
        if column in TIMING_COLUMNS:
            continue
        # Los números se comparan con la misma tolerancia que las probabilidades (ver arriba).
        if isinstance(first[column], float):
            assert first[column] == pytest.approx(second[column], rel=0, abs=PROBA_TOLERANCE), column
        else:
            assert first[column] == second[column], column


@pytest.mark.parametrize(
    "task, family, params, message",
    [
        ("other", "decision_tree", {}, "Tarea desconocida"),
        ("detector", "svc", {}, "Modelo desconocido"),
        ("detector", "decision_tree", {"max_depth": 4}, "deben empezar con model__"),
    ],
)
def test_candidate_errors(task, family, params, message, split):
    train, validation = split
    with pytest.raises(ValueError, match=message):
        fit_candidate(1, task, family, "m1", params, train, validation)


# run_search

# Tres candidatos rápidos: las dos tareas y dos familias.
CANDIDATES = [
    (1, "detector", "decision_tree", "m1", {}),
    (1, "attack_type", "decision_tree", "m1", {}),
    (1, "detector", "gaussian_nb", "m2", {}),
]


def csv_lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def test_run_search_writes_the_header_once_and_one_row_per_candidate(split, tmp_path):
    train, validation = split
    path = tmp_path / "search" / "results.csv"
    results = run_search(CANDIDATES, train, validation, path)

    lines = csv_lines(path)
    assert lines[0] == ",".join(RESULT_COLUMNS)
    assert len(lines) == 1 + len(CANDIDATES)
    assert list(results.columns) == RESULT_COLUMNS
    assert list(results["family"]) == ["decision_tree", "decision_tree", "gaussian_nb"]
    assert (results["search_version"] == SEARCH_VERSION).all()


def test_run_search_skips_the_candidates_already_saved(split, tmp_path, monkeypatch):
    train, validation = split
    path = tmp_path / "results.csv"
    run_search(CANDIDATES[:2], train, validation, path)
    first_rows = csv_lines(path)

    trained = []
    original = training_module.fit_candidate
    monkeypatch.setattr(training_module, "fit_candidate", lambda *args: trained.append(args[:5]) or original(*args))
    # Un candidato repetido en la misma lista tampoco se entrena dos veces.
    results = run_search([*CANDIDATES, CANDIDATES[2]], train, validation, path)

    assert trained == [CANDIDATES[2][:5]]
    assert csv_lines(path)[: len(first_rows)] == first_rows
    assert len(results) == len(CANDIDATES)


def test_rows_already_written_survive_a_failed_candidate(split, tmp_path, monkeypatch):
    train, validation = split
    path = tmp_path / "results.csv"
    original = training_module.fit_candidate

    def fail_on_second(*args):
        if args[2] == "gaussian_nb":
            raise RuntimeError("corte simulado")
        return original(*args)

    monkeypatch.setattr(training_module, "fit_candidate", fail_on_second)
    with pytest.raises(RuntimeError, match="corte simulado"):
        run_search(CANDIDATES, train, validation, path)
    saved = csv_lines(path)
    assert len(saved) == 3

    monkeypatch.setattr(training_module, "fit_candidate", original)
    run_search(CANDIDATES, train, validation, path)
    assert csv_lines(path)[:3] == saved
    assert len(csv_lines(path)) == 4


def test_file_with_other_columns_is_rejected(split, tmp_path):
    train, validation = split
    path = tmp_path / "results.csv"
    path.write_text("model,validation_pr_auc\nrandom_forest,0.99\n", encoding="utf-8")
    with pytest.raises(ValueError, match="otras columnas"):
        run_search(CANDIDATES, train, validation, path)
    assert csv_lines(path) == ["model,validation_pr_auc", "random_forest,0.99"]


def test_incomplete_last_line_is_rejected(split, tmp_path):
    train, validation = split
    path = tmp_path / "results.csv"
    run_search(CANDIDATES[:1], train, validation, path)
    with path.open("a", encoding="utf-8") as file:
        file.write("2026-11-24T00:00:00Z,1,1,detector")
    with pytest.raises(ValueError, match="la 3\\) está incompleta"):
        run_search(CANDIDATES, train, validation, path)


def test_line_with_missing_values_is_rejected(split, tmp_path):
    train, validation = split
    path = tmp_path / "results.csv"
    run_search(CANDIDATES[:1], train, validation, path)
    with path.open("a", encoding="utf-8") as file:
        file.write("2026-11-24T00:00:00Z,1,1,detector\n")
    with pytest.raises(ValueError, match="La línea 3 .* tiene 4 valores"):
        run_search(CANDIDATES, train, validation, path)


def edit_saved_column(path, column, value):
    rows = pd.read_csv(path, dtype=str, keep_default_na=False)
    rows[column] = value
    rows.to_csv(path, index=False, lineterminator="\n")


@pytest.mark.parametrize("column", ["search_version", "sklearn_version", "train_flows", "validation_flows"])
def test_rows_of_another_run_are_not_mixed(column, split, tmp_path, monkeypatch):
    train, validation = split
    path = tmp_path / "results.csv"
    run_search(CANDIDATES[:2], train, validation, path)
    saved = path.read_text(encoding="utf-8")

    if column == "search_version":
        monkeypatch.setattr(training_module, "SEARCH_VERSION", SEARCH_VERSION + 1)
    elif column == "sklearn_version":
        edit_saved_column(path, column, "0.0.0")
        saved = path.read_text(encoding="utf-8")
    elif column == "train_flows":
        train = train.drop(train.index[0])
    else:
        validation = validation.drop(validation.index[0])

    with pytest.raises(ValueError, match=f"No se mezclan resultados: .* {column} = "):
        run_search(CANDIDATES, train, validation, path)
    assert path.read_text(encoding="utf-8") == saved


@pytest.mark.parametrize(
    "change, message",
    [
        ("no_worms", "no contiene estos tipos de ataque: Worms"),
        ("only_normal_validation", "La validación debe tener flujos normales y ataques"),
        ("bad_label", "etiquetas no válidas"),
    ],
)
def test_search_data_is_checked_before_training(change, message, split, tmp_path):
    train, validation = split
    if change == "no_worms":
        train = train[train[ATTACK_CAT] != "Worms"]
    elif change == "only_normal_validation":
        validation = validation[validation[TARGET] == 0]
    else:
        train.loc[train.index[0], TARGET] = 2
    path = tmp_path / "results.csv"
    with pytest.raises(ValueError, match=message):
        run_search(CANDIDATES, train, validation, path)
    assert not path.exists()


# phase1_candidates y select_candidates


def test_phase1_has_every_family_method_and_task_with_default_values():
    candidates = phase1_candidates()
    assert len(candidates) == len(MODEL_FAMILIES) * len(PREPROCESSING_METHODS) * len(TASKS) == 48
    assert {(f, m, t) for _, t, f, m, _ in candidates} == {
        (f, m, t) for f in MODEL_FAMILIES for m in PREPROCESSING_METHODS for t in TASKS
    }
    assert all(phase == 1 and params == {} for phase, *_, params in candidates)


def detector(family, method, pr_auc, far, size=1.0, converged=True, phase=1, params="{}"):
    """Fila de detector escrita a mano, con solo las columnas que usa select_candidates."""
    return {"phase": phase, "task": "detector", "family": family, "method": method, "params": params,
            "converged": converged, "model_size_mb": size, "pr_auc": pr_auc, "false_alarm_rate": far,
            "macro_f1": None, "min_type_f1": None}


def classifier(family, method, macro_f1, worst=0.1, size=1.0, converged=True, phase=1, params="{}"):
    """Fila de clasificador escrita a mano."""
    return {"phase": phase, "task": "attack_type", "family": family, "method": method, "params": params,
            "converged": converged, "model_size_mb": size, "pr_auc": None, "false_alarm_rate": None,
            "macro_f1": macro_f1, "min_type_f1": worst}


def choice(rows, family="random_forest", **kwargs):
    """La fila de select_candidates de una familia."""
    table = select_candidates(pd.DataFrame(rows), **kwargs)
    return table[table["family"] == family].iloc[0]


def test_tolerance_is_the_third_decimal():
    assert SCORE_TIE_TOLERANCE == 0.001


@pytest.mark.parametrize(
    "scores, chosen",
    [
        # Empatan en PR-AUC (diferencia 0,0005): gana la menor tasa de falsas alarmas.
        ([(0.9960, 0.06, "a"), (0.9955, 0.05, "b")], "b"),
        # Diferencia real (0,0015): gana la mayor PR-AUC aunque tenga más falsas alarmas.
        ([(0.9960, 0.06, "a"), (0.9945, 0.05, "b")], "a"),
        # El empate se mide contra la mejor, no en cadena: c queda a 0,0013 de a.
        ([(0.9964, 0.06, "a"), (0.9958, 0.05, "b"), (0.9951, 0.01, "c")], "b"),
        # Una diferencia de exactamente 0,001 no es empate, aunque en binario la resta dé 0,000999…
        ([(0.0021, 0.06, "a"), (0.0011, 0.05, "b")], "a"),
    ],
)
def test_detector_rule_within_a_method(scores, chosen):
    rows = [detector("random_forest", "m1", pr, far, params=name) for pr, far, name in scores]
    rows.append(classifier("random_forest", "m1", 0.6))
    assert choice(rows)["detector_params"] == chosen


@pytest.mark.parametrize(
    "scores, chosen",
    [
        # Empatan en F1 macro: gana el que tiene mejor su peor tipo.
        ([(0.6000, 0.10, "a"), (0.5995, 0.20, "b")], "b"),
        ([(0.6000, 0.10, "a"), (0.5980, 0.20, "b")], "a"),
    ],
)
def test_classifier_rule_within_a_method(scores, chosen):
    rows = [classifier("random_forest", "m1", f1, worst, params=name) for f1, worst, name in scores]
    rows.append(detector("random_forest", "m1", 0.99, 0.05))
    assert choice(rows)["classifier_params"] == chosen


@pytest.mark.parametrize(
    "m1, m2, chosen",
    [
        # El detector distingue (0,0020): manda aunque el clasificador de m2 sea mucho mejor.
        ((0.9970, 0.05, 0.50), (0.9950, 0.05, 0.70), "m1"),
        # El detector empata (0,0005): decide el F1 macro del clasificador del mismo método.
        ((0.9960, 0.05, 0.58), (0.9955, 0.06, 0.62), "m2"),
        # Empatan detector y clasificador: decide la menor tasa de falsas alarmas.
        ((0.9960, 0.05, 0.6000), (0.9955, 0.06, 0.6005), "m1"),
    ],
)
def test_method_rule_within_a_family(m1, m2, chosen):
    rows = []
    for method, (pr_auc, far, macro_f1) in (("m1", m1), ("m2", m2)):
        rows += [detector("random_forest", method, pr_auc, far), classifier("random_forest", method, macro_f1)]
    # m3 queda fuera por PR-AUC aunque su clasificador sea el mejor.
    rows += [detector("random_forest", "m3", 0.9900, 0.01), classifier("random_forest", "m3", 0.90)]
    assert choice(rows)["method"] == chosen


def test_classifier_uses_the_method_of_the_detector():
    rows = [
        detector("random_forest", "m1", 0.999, 0.05), classifier("random_forest", "m1", 0.55, params="m1"),
        detector("random_forest", "m3", 0.990, 0.05), classifier("random_forest", "m3", 0.75, params="m3"),
    ]
    chosen = choice(rows)
    assert (chosen["method"], chosen["classifier_params"]) == ("m1", "m1")


def test_rows_that_did_not_converge_are_never_chosen():
    rows = [
        detector("random_forest", "m1", 0.999, 0.01, converged=False, params="a"),
        detector("random_forest", "m1", 0.990, 0.05, params="b"),
        classifier("random_forest", "m1", 0.6),
    ]
    assert choice(rows)["detector_params"] == "b"


def test_family_without_a_converged_method_is_listed_without_rank():
    rows = [
        detector("mlp", "m1", 0.999, 0.01, converged=False), classifier("mlp", "m1", 0.6),
        detector("random_forest", "m1", 0.99, 0.05), classifier("random_forest", "m1", 0.6),
    ]
    mlp = choice(rows, family="mlp")
    assert pd.isna(mlp["method"]) and pd.isna(mlp["rank"]) and pd.isna(mlp["app_rank"])


def test_families_are_ranked_and_heavy_ones_stay_out_of_the_app():
    rows = []
    # (familia, PR-AUC, falsas alarmas, F1 macro, MB del detector)
    for family, pr_auc, far, macro_f1, size in (
        ("logistic_regression", 0.9928, 0.09, 0.50, 0.1),
        ("random_forest", 0.9961, 0.05, 0.62, MAX_MODEL_SIZE_MB),
        ("extra_trees", 0.9956, 0.055, 0.60, 1.0),
        ("hist_gradient_boosting", 0.9964, 0.054, 0.61, 0.4),
    ):
        rows += [detector(family, "m1", pr_auc, far, size=size), classifier(family, "m1", macro_f1, size=0.5)]
    table = select_candidates(pd.DataFrame(rows))

    # Empatan HistGradientBoosting, Random Forest y Extra Trees en PR-AUC; Random Forest tiene el
    # mejor F1 macro, pero pesa 50 MB o más con el clasificador: queda en la tabla, fuera de la app.
    assert list(table["family"]) == ["random_forest", "hist_gradient_boosting", "extra_trees", "logistic_regression"]
    assert list(table["rank"]) == [1, 2, 3, 4]
    assert list(table["fits_app"]) == [False, True, True, True]
    assert table["app_rank"].tolist()[1:] == [1, 2, 3] and pd.isna(table["app_rank"].iloc[0])
    assert table["model_size_mb"].iloc[0] == MAX_MODEL_SIZE_MB + 0.5


def test_phases_limit_the_rows_used():
    rows = [
        detector("random_forest", "m1", 0.990, 0.05, params="defaults"),
        detector("random_forest", "m1", 0.999, 0.01, phase=2, params="tuned"),
        classifier("random_forest", "m1", 0.6),
        classifier("random_forest", "m1", 0.6, phase=2),
    ]
    assert choice(rows, phases=[1])["detector_params"] == "defaults"
    assert choice(rows)["detector_params"] == "tuned"


def test_selection_points_to_the_chosen_rows_of_the_results():
    rows = [
        detector("random_forest", "m1", 0.990, 0.05), classifier("random_forest", "m1", 0.5),
        detector("random_forest", "m1", 0.999, 0.05), classifier("random_forest", "m1", 0.6),
    ]
    chosen = choice(rows)
    assert (chosen["detector_row"], chosen["classifier_row"]) == (2, 3)


@pytest.mark.parametrize(
    "rows, message",
    [
        ([detector("random_forest", "m1", 0.99, 0.05)], "A random_forest le faltan filas de: attack_type"),
        ([detector("svc", "m1", 0.99, 0.05)], "Familias desconocidas en los resultados: svc"),
    ],
)
def test_selection_errors(rows, message):
    with pytest.raises(ValueError, match=message):
        select_candidates(pd.DataFrame(rows))


# Tope del crecimiento, pesos por flujo, búsqueda de hiperparámetros y curvas

PHASE2_METHODS = {"random_forest": "m2", "extra_trees": "m2", "hist_gradient_boosting": "m1", "mlp": "m2"}


def test_cap_in_params_limits_the_growth(split, small_ensembles, monkeypatch):
    original = training_module._task_metrics
    measured = []

    def record(*args):
        measured.append(len(args[1].estimators_))
        return original(*args)

    monkeypatch.setattr(training_module, "_task_metrics", record)
    train, validation = split
    pipeline, row = fit_candidate(2, "detector", "random_forest", "m1", {"model__n_estimators": 4}, train, validation)
    assert measured == [2, 4]
    assert row["best_iteration"] in (2, 4)
    assert json.loads(row["fixed_params"]) == {}


@pytest.mark.parametrize(
    "family, params",
    [("random_forest", {"model__n_estimators": 5}), ("hist_gradient_boosting", {"model__max_iter": 1})],
)
def test_cap_must_be_a_multiple_of_the_step(family, params, split, small_ensembles):
    train, validation = split
    with pytest.raises(ValueError, match="debe ser un múltiplo de 2"):
        fit_candidate(2, "detector", family, "m1", params, train, validation)


@pytest.mark.parametrize("task", ["detector", "attack_type"])
def test_balanced_sample_weight_is_the_same_as_balanced_class_weight(task, split):
    # En un árbol, class_weight="balanced" multiplica cada flujo por el mismo peso que
    # compute_sample_weight("balanced"); así se comprueba que los pesos llegan a fit.
    train, validation = split
    weighted, weighted_row = fit_candidate(2, task, "decision_tree", "m1", {"sample_weight": "balanced"}, train, validation)
    balanced, _ = fit_candidate(2, task, "decision_tree", "m1", {"model__class_weight": "balanced"}, train, validation)
    plain, _ = fit_candidate(2, task, "decision_tree", "m1", {"sample_weight": None}, train, validation)
    inputs = validation[INPUT_COLS]
    np.testing.assert_array_equal(weighted.predict_proba(inputs), balanced.predict_proba(inputs))
    assert not np.array_equal(weighted.predict_proba(inputs), plain.predict_proba(inputs))
    assert json.loads(weighted_row["params"]) == {"sample_weight": "balanced"}


def test_sample_weight_errors_and_fixed_params(split):
    train, validation = split
    with pytest.raises(ValueError, match='sample_weight debe ser None o "balanced"'):
        fit_candidate(2, "detector", "mlp", "m2", {"sample_weight": "inverse"}, train, validation)
    assert fixed_params("mlp", {"sample_weight": "balanced"}) == {"early_stopping": True}


def test_phase2_has_the_approved_grid():
    candidates = phase2_candidates(PHASE2_METHODS)
    assert len(candidates) == 228
    counts = {}
    for phase, task, family, method, params in candidates:
        assert phase == 2 and method == PHASE2_METHODS[family]
        counts[(family, task)] = counts.get((family, task), 0) + 1
    assert counts == {
        ("random_forest", "detector"): 32, ("random_forest", "attack_type"): 48,
        ("extra_trees", "detector"): 32, ("extra_trees", "attack_type"): 32,
        ("hist_gradient_boosting", "detector"): 24, ("hist_gradient_boosting", "attack_type"): 24,
        ("mlp", "detector"): 18, ("mlp", "attack_type"): 18,
    }
    weights = {(f, t): {p.get("model__class_weight", p.get("sample_weight")) for _, t2, f2, _, p in candidates if (f2, t2) == (f, t)}
               for f, t in counts}
    assert weights[("random_forest", "attack_type")] == {None, "balanced", "balanced_subsample"}
    assert weights[("extra_trees", "attack_type")] == {None, "balanced"}
    assert all(p.get("model__max_iter") == 200 for _, _, f, _, p in candidates if f == "hist_gradient_boosting")
    assert all("sample_weight" in p for _, _, f, _, p in candidates if f == "mlp")
    assert not any("sample_weight" in p for _, _, f, _, p in candidates if f != "mlp")
    # Todos los topes son múltiplos del paso de crecimiento.
    for _, _, family, _, params in candidates:
        training_module._growth(family, params)


def test_phase2_needs_the_method_of_every_family():
    with pytest.raises(ValueError, match="Falta el método de: mlp"):
        phase2_candidates({k: v for k, v in PHASE2_METHODS.items() if k != "mlp"})


def test_curves_vary_one_parameter_from_the_chosen_rows():
    results = pd.DataFrame({"params": [
        json.dumps({"model__min_samples_leaf": 10, "model__n_estimators": 50}, sort_keys=True),
        json.dumps({"model__class_weight": "balanced"}),
        "{}", "{}", "{}", "{}",
    ]})
    selection = pd.DataFrame([
        {"family": "random_forest", "method": "m2", "detector_row": 0, "classifier_row": 1},
        {"family": "hist_gradient_boosting", "method": "m1", "detector_row": 2, "classifier_row": 3},
        {"family": "mlp", "method": "m2", "detector_row": 4, "classifier_row": 5},
        {"family": "extra_trees", "method": None, "detector_row": None, "classifier_row": None},
    ])
    candidates = curve_candidates(results, selection)

    assert len(candidates) == 2 * 14 + 2 * 6
    assert {c[0] for c in candidates} == {CURVE_PHASE}
    forest_detector = [c[4] for c in candidates if c[1:3] == ("detector", "random_forest")]
    assert {"model__max_depth": 5, "model__min_samples_leaf": 10, "model__n_estimators": 50} in forest_detector
    assert {"model__max_depth": None, "model__min_samples_leaf": 50, "model__n_estimators": 50} not in forest_detector
    assert {"model__min_samples_leaf": 50, "model__n_estimators": 50} in forest_detector
    assert all(c[3] == "m1" for c in candidates if c[2] == "hist_gradient_boosting")


def test_size_limit_chooses_the_best_pair_that_fits():
    rows = [
        detector("random_forest", "m2", 0.9990, 0.05, size=40, params="A"),
        detector("random_forest", "m2", 0.9985, 0.06, size=10, params="B"),
        classifier("random_forest", "m2", 0.60, size=30, params="C"),
        classifier("random_forest", "m2", 0.55, size=5, params="D"),
    ]
    free = choice(rows)
    assert (free["detector_params"], free["classifier_params"], free["model_size_mb"]) == ("A", "C", 70)
    assert not free["fits_app"]
    # Dentro de 50 MB: A + D (45), B + C (40) y B + D (15). Los detectores empatan en PR-AUC
    # (0,0005), así que decide el F1 macro: B + C.
    limited = choice(rows, max_size_mb=MAX_MODEL_SIZE_MB)
    assert (limited["detector_params"], limited["classifier_params"], limited["model_size_mb"]) == ("B", "C", 40)
    assert limited["fits_app"] and limited["app_rank"] == 1
    assert pd.isna(choice(rows, max_size_mb=10)["method"])


def test_results_keep_numeric_and_curve_phases(split, tmp_path):
    train, validation = split
    path = tmp_path / "results.csv"
    run_search(
        [(1, "detector", "decision_tree", "m1", {}), (1, "attack_type", "decision_tree", "m1", {}),
         (CURVE_PHASE, "detector", "decision_tree", "m1", {"model__max_depth": 3})],
        train, validation, path,
    )
    results = read_search_results(path)
    assert list(results["phase"]) == [1, 1, CURVE_PHASE]
    assert list(select_candidates(results, phases=[1])["family"]) == ["decision_tree"]


# Regla de simplicidad


def forest_row(task, depth, leaf, trees, score, size, far=0.05, phase=2, converged=True):
    """Fila de Random Forest escrita a mano para la regla de simplicidad."""
    params = {"model__max_depth": depth, "model__min_samples_leaf": leaf, "model__n_estimators": 50}
    is_detector = task == "detector"
    return {
        "phase": phase, "task": task, "family": "random_forest", "method": "m2",
        "params": json.dumps(params, sort_keys=True), "converged": converged, "best_iteration": trees,
        "model_size_mb": size, "pr_auc": score if is_detector else None,
        "false_alarm_rate": far if is_detector else None,
        "macro_f1": None if is_detector else score, "min_type_f1": None if is_detector else 0.1,
    }


def simplify(rows, **kwargs):
    results = pd.DataFrame(rows)
    selection = select_candidates(results, phases=[1, 2], max_size_mb=MAX_MODEL_SIZE_MB)
    return results, apply_simplicity_rule(results, selection, **kwargs).iloc[0]


def test_complexity_dimensions():
    assert complexity("random_forest", {"params": "{}", "best_iteration": 75}) == {
        "max_depth": float("inf"), "min_samples_leaf": -1, "iterations": 75}
    assert complexity("hist_gradient_boosting", {"params": '{"model__max_leaf_nodes": 63}', "best_iteration": 180}) == {
        "max_leaf_nodes": 63, "min_samples_leaf": -20, "iterations": 180}
    assert complexity("mlp", {"params": '{"model__hidden_layer_sizes": [100, 50], "model__alpha": 0.01}'}) == {
        "neurons": 150, "layers": 2, "alpha": -0.01}
    assert complexity("logistic_regression", {"params": "{}"}) == {}


def test_simpler_tied_classifier_replaces_the_chosen_one():
    rows = [
        forest_row("detector", 20, 5, 50, 0.9964, 12.2),
        forest_row("attack_type", None, 1, 25, 0.6028, 31.5),                 # la elegida
        forest_row("attack_type", 30, 1, 25, 0.6031, 31.2, phase="curve"),   # más simple, empata: gana
        forest_row("attack_type", 20, 1, 25, 0.5966, 30.0, phase="curve"),   # más simple, no empata
        forest_row("attack_type", 25, 1, 50, 0.6025, 20.0),                  # más árboles: no es más simple
    ]
    results, chosen = simplify(rows)
    assert chosen["classifier_row"] == 2 and chosen["classifier_simplified"]
    assert not chosen["detector_simplified"]
    assert chosen["macro_f1"] == 0.6031
    assert chosen["model_size_mb"] == pytest.approx(12.2 + 31.2)
    assert json.loads(chosen["classifier_params"])["model__max_depth"] == 30


def test_rule_picks_the_smallest_and_respects_the_size_limit():
    rows = [
        forest_row("detector", 20, 5, 50, 0.9964, 30.0),
        forest_row("attack_type", None, 1, 25, 0.6028, 15.0),
        forest_row("attack_type", 30, 1, 25, 0.6030, 12.0),
        forest_row("attack_type", 25, 2, 25, 0.6020, 10.0),   # la más chica de las que empatan
    ]
    assert simplify(rows)[1]["classifier_row"] == 3
    # Con un límite de 41 MB el par 30 + 12 = 42 no cabe, pero 30 + 10 = 40 sí.
    assert simplify(rows, max_size_mb=41)[1]["classifier_row"] == 3
    assert simplify(rows, max_size_mb=40)[1]["classifier_row"] == 1


def test_detector_needs_no_more_false_alarms_and_a_converged_row():
    rows = [
        forest_row("detector", None, 1, 50, 0.9964, 12.0, far=0.050),
        forest_row("detector", 20, 1, 50, 0.9962, 10.0, far=0.051),                   # más falsas alarmas
        forest_row("detector", 15, 1, 50, 0.9963, 9.0, far=0.050, converged=False),   # no convergió
        forest_row("attack_type", None, 1, 25, 0.60, 10.0),
    ]
    chosen = simplify(rows)[1]
    assert chosen["detector_row"] == 0 and not chosen["detector_simplified"]
    # Con las mismas falsas alarmas, select_candidates se queda con la primera (empate total) y la
    # regla la cambia por la más simple.
    rows[1]["false_alarm_rate"] = 0.050
    chosen = simplify(rows)[1]
    assert chosen["detector_row"] == 1 and chosen["detector_simplified"]



# Registro: modelo por defecto y quitar modelos


def test_set_default_and_unregister_in_the_agreed_order(mock_only):
    register_model("model_a", mock_only)
    # El simulado es el modelo por defecto: no se puede quitar antes de cambiarlo.
    with pytest.raises(ValueError, match="mock es el modelo por defecto"):
        unregister_model("mock", mock_only)
    with pytest.raises(ValueError, match="model_b no está registrado"):
        set_default_model("model_b", mock_only)
    set_default_model("model_a", mock_only)
    registry = unregister_model("mock", mock_only)
    assert registry == {"default_model": "model_a", "models": [{"name": "model_a"}]}
    assert read_registry(mock_only) == registry
    assert (mock_only / MODELS_DIR.name / "mock" / MODEL_JSON).is_file()
    assert not (mock_only / (REGISTRY_PATH.name + TEMP_SUFFIX)).exists()
    # Repetir no cambia el archivo.
    before = registry_state(mock_only)
    set_default_model("model_a", mock_only)
    unregister_model("mock", mock_only)
    assert registry_state(mock_only) == before


def test_hardware_description(tmp_path, monkeypatch):
    cpuinfo = tmp_path / "cpuinfo"
    cpuinfo.write_text("processor\t: 0\nmodel name\t: Procesador de prueba @ 1.00GHz\n", encoding="utf-8")
    monkeypatch.setattr(training_module.os, "cpu_count", lambda: 8)
    assert hardware_description(cpuinfo) == "Procesador de prueba @ 1.00GHz, 8 núcleos lógicos"
    assert hardware_description(tmp_path / "no_existe") == f"{platform.machine()}, 8 núcleos lógicos"


# Entrenamiento final


def final_table(rows):
    """Tabla como la de apply_simplicity_rule, escrita a mano, para final_model_specs."""
    return pd.DataFrame([
        {"rank": rank, "app_rank": rank, "family": family, "method": "m2", "detector_row": 2 * i, "classifier_row": 2 * i + 1}
        for i, (rank, family) in enumerate(rows)
    ])


def test_final_specs_register_the_three_chosen_and_the_base_model():
    specs = final_model_specs(final_table([
        (1, "hist_gradient_boosting"), (2, "random_forest"), (3, "mlp"), (4, "extra_trees"),
        (5, "logistic_regression"), (6, "dummy"),
    ]))
    assert [(s["name"], s["kind"], s["register"], s["method"]) for s in specs] == [
        ("hist_gradient_boosting", "elegido", True, "m2"),
        ("random_forest", "elegido", True, "m2"),
        ("mlp", "elegido", True, "m2"),
        ("logistic_regression", "modelo base", True, "m2"),
        ("extra_trees", "referencia", False, "m2"),
        ("dummy", "referencia", False, "m2"),
        ("hist_gradient_boosting_m3", "m3", False, "m3"),
        ("random_forest_m3", "m3", False, "m3"),
        ("mlp_m3", "m3", False, "m3"),
    ]
    assert specs[3]["display_name"] == "Regresión logística (modelo base)"
    assert specs[6]["detector_row"] == specs[0]["detector_row"]


def test_final_specs_when_the_base_model_is_one_of_the_chosen():
    specs = final_model_specs(final_table([(1, "logistic_regression"), (2, "dummy"), (3, "decision_tree"), (4, "gaussian_nb")]))
    assert [s["name"] for s in specs if s["register"]] == ["logistic_regression", "dummy", "decision_tree"]
    assert [s["kind"] for s in specs].count("modelo base") == 0


FINAL_FAMILIES = ("dummy", "logistic_regression", "decision_tree", "random_forest", "gaussian_nb")


@pytest.fixture(scope="module")
def final_search(tmp_path_factory, sample_flows_once):
    """Búsqueda pequeña con sample_flows.csv: 5 familias, M1 y M2, guardada en una carpeta temporal."""
    flows = sample_flows_once
    train = flows.groupby(ATTACK_CAT, group_keys=False).sample(frac=0.8, random_state=42)
    validation = flows.drop(train.index)
    path = tmp_path_factory.mktemp("final_search") / "search_results.csv"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(training_module, "TREE_COUNT_STEP", 2)
        patch.setattr(training_module, "MAX_TREE_COUNT", 4)
        candidates = [c for c in phase1_candidates() if c[2] in FINAL_FAMILIES and c[3] != "m3"]
        run_search(candidates, train, validation, path)
    return path, train, validation, flows


@pytest.fixture
def final_run(final_search, tmp_path, monkeypatch):
    """Un artifacts/ temporal con solo el simulado registrado, y una función que corre el entrenamiento final."""
    path, train, validation, test = final_search
    artifacts_dir = tmp_path / "artifacts"
    (artifacts_dir / MODELS_DIR.name / "mock").mkdir(parents=True)
    shutil.copy(MODELS_DIR / "mock" / MODEL_JSON, artifacts_dir / MODELS_DIR.name / "mock" / MODEL_JSON)
    write_json(artifacts_dir / REGISTRY_PATH.name, {"default_model": "mock", "models": [{"name": "mock"}]})
    output_dir = tmp_path / "model_search"
    evaluated = []
    original = training_module._evaluate

    def count_evaluations(model, threshold, flows):
        evaluated.append(len(flows))
        return original(model, threshold, flows)

    monkeypatch.setattr(training_module, "_evaluate", count_evaluations)

    def run():
        return train_final_models(path, artifacts_dir, output_dir, train, validation, test, verbose=False)

    results = read_search_results(path)
    final = training_module.apply_simplicity_rule(
        results, select_candidates(results, phases=[1, 2], max_size_mb=MAX_MODEL_SIZE_MB), max_size_mb=MAX_MODEL_SIZE_MB
    )
    return run, artifacts_dir, output_dir, final_model_specs(final), evaluated


def test_final_training_evaluates_exports_and_registers(final_run, monkeypatch):
    run, artifacts_dir, output_dir, specs, evaluated = final_run
    calls = []
    for function in ("register_model", "set_default_model", "unregister_model"):
        original = getattr(training_module, function)
        monkeypatch.setattr(training_module, function, lambda name, folder, f=function, o=original: calls.append((f, name)) or o(name, folder))
    table = run()

    assert list(table["name"]) == [s["name"] for s in specs]
    registered = [s["name"] for s in specs if s["register"]]
    # El orden acordado: registrar, fijar el modelo por defecto y al final quitar el simulado.
    assert calls == [*[("register_model", n) for n in registered], ("set_default_model", registered[0]), ("unregister_model", "mock")]
    registry, models = load_artifacts(artifacts_dir)
    assert registry == {"default_model": registered[0], "models": [{"name": n} for n in registered]}
    for spec in specs:
        row = table.set_index("name").loc[spec["name"]]
        assert row["kind"] == spec["kind"] and bool(row["registered"]) == spec["register"]
        assert 0 <= row["test_recall"] <= 1 and 0 <= row["validation_recall"] <= 1
        folder = artifacts_dir / MODELS_DIR.name / spec["name"]
        assert folder.is_dir() == spec["register"]
    for name in registered:
        info = models[name]["info"]
        saved = table.set_index("name").loc[name]
        assert info["test_metrics"] == json.loads(saved["test_metrics_json"])
        assert info["threshold"] == saved["threshold"]
        assert info["complexity"]["hardware"] == hardware_description()
        family = name
        assert info["can_explain"] == (family in training_module.EXPLANATION_METHODS)
        assert info["explanation_method"] == training_module.EXPLANATION_METHODS.get(family)
        assert info["display_name"] == training_module.DISPLAY_NAMES[family]
    per_type = pd.read_csv(output_dir / "test_per_type.csv")
    assert len(per_type) == len(specs) * 2 * 9
    # Cada modelo se evalúa una vez en validación y una en prueba.
    assert len(evaluated) == 2 * len(specs)
    oob = pd.read_csv(output_dir / "oob_vs_validation.csv")
    assert list(oob["task"]) == ["detector", "attack_type"] and (oob["flows_without_oob"] >= 0).all()


def test_final_training_uses_the_training_part_and_the_search_sizes(final_run, final_search):
    run, artifacts_dir, _, specs, _ = final_run
    table = run().set_index("name")
    train = final_search[1]
    assert (table["training_flows"] == len(train)).all()
    registry, models = load_artifacts(artifacts_dir)
    results = read_search_results(final_search[0])
    for spec in (s for s in specs if s["register"]):
        info = models[spec["name"]]["info"]
        assert info["complexity"]["training_flows"] == len(train)
        detector = models[spec["name"]]["model"]["detector"]["model"]
        iterations = results.loc[spec["detector_row"], "best_iteration"]
        if spec["family"] == "random_forest":
            assert len(detector.estimators_) == iterations


def test_second_run_does_not_touch_the_test_set(final_run):
    run, artifacts_dir, output_dir, specs, evaluated = final_run
    run()
    before = {path.name: path.read_bytes() for path in output_dir.iterdir() if path.suffix == ".csv" and path.name != "oob_vs_validation.csv"}
    evaluations = len(evaluated)
    run()
    assert len(evaluated) == evaluations
    assert {name: (output_dir / name).read_bytes() for name in before} == before


def test_missing_export_is_redone_without_the_test_set(final_run):
    run, artifacts_dir, output_dir, specs, evaluated = final_run
    run()
    name = next(s["name"] for s in specs if s["register"])
    folder = artifacts_dir / MODELS_DIR.name / name
    saved = read_json(folder / MODEL_JSON)["test_metrics"]
    shutil.rmtree(folder)
    evaluations = len(evaluated)
    run()
    assert len(evaluated) == evaluations
    assert read_json(folder / MODEL_JSON)["test_metrics"] == saved


def test_final_model_that_does_not_reproduce_its_row_is_not_evaluated(final_run, monkeypatch):
    run, artifacts_dir, output_dir, specs, evaluated = final_run
    original = training_module._candidate_estimator
    # Un árbol distinto del de la búsqueda: no reproduce su fila.
    monkeypatch.setattr(
        training_module, "_candidate_estimator",
        lambda name: original(name).set_params(max_depth=1) if name == "decision_tree" else original(name),
    )
    with pytest.raises(ValueError, match="decision_tree .* no reproduce su fila de la búsqueda"):
        run()
    table_path = output_dir / "test_results.csv"
    names = list(pd.read_csv(table_path)["name"]) if table_path.is_file() else []
    assert "decision_tree" not in names



def test_oob_per_type_matches_the_search_row_and_the_oob_macro_f1(final_search):
    path, train, validation, _ = final_search
    results = read_search_results(path)
    final = training_module.apply_simplicity_rule(
        results, select_candidates(results, phases=[1, 2], max_size_mb=MAX_MODEL_SIZE_MB), max_size_mb=MAX_MODEL_SIZE_MB
    )
    table = oob_per_type(results, final, train)
    summary = oob_comparison(results, final, train).set_index("task")

    assert list(table["attack_cat"]) == list(training_module.ATTACK_TYPES)
    row = results.loc[int(final.set_index("family").loc["random_forest", "classifier_row"])]
    for metric in ("precision", "recall", "f1", "support"):
        expected = [row[f"{t.lower()}_{metric}"] for t in table["attack_cat"]]
        np.testing.assert_allclose(table[f"validation_{metric}"].astype(float), np.array(expected, dtype=float), equal_nan=True)
    # El F1 macro fuera de la bolsa es el promedio de los F1 por tipo que se pueden calcular.
    assert summary.loc["attack_type", "oob"] == pytest.approx(table["oob_f1"].dropna().mean())
    # Solo cuentan los flujos con al menos un árbol fuera de la bolsa.
    assert (table["oob_support"] == table["train_flows"] - table["flows_without_oob"]).all()
    assert table["train_flows"].sum() == int((train[TARGET] == 1).sum())
    assert summary.loc["attack_type", "flows_without_oob"] == table["flows_without_oob"].sum()
    assert ((0 <= table["oob_trees_mean"]) & (table["oob_trees_mean"] <= table["trees"])).all()
    np.testing.assert_allclose(table["f1_difference"], table["oob_f1"] - table["validation_f1"])


def test_flows_without_out_of_bag_trees_are_not_measured(final_search):
    # Con class_weight, scikit-learn sortea la bolsa según el peso de cada flujo, y un flujo puede
    # quedar en la bolsa de todos los árboles; su fila de oob_decision_function_ queda en ceros.
    path, train, _, _ = final_search
    results = read_search_results(path)
    final = training_module.apply_simplicity_rule(
        results, select_candidates(results, phases=[1, 2], max_size_mb=MAX_MODEL_SIZE_MB), max_size_mb=MAX_MODEL_SIZE_MB
    )
    choice = final.set_index("family").loc["random_forest"].to_dict()
    row = results.loc[int(choice["classifier_row"])]
    results = results.copy()
    results.loc[int(choice["classifier_row"]), "params"] = json.dumps({**json.loads(row["params"]), "model__class_weight": "balanced"})
    _, _, _, oob, covered, out_of_bag = training_module._fit_oob(results, choice, "random_forest", "attack_type", train)
    assert (~covered).any(), "la prueba necesita flujos sin árboles fuera de la bolsa"
    np.testing.assert_array_equal(covered, out_of_bag > 0)
    np.testing.assert_array_equal(~covered, oob.sum(axis=1) == 0)


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


def test_model_whose_classifier_lost_categories_is_not_exported(tmp_path, tiny_models, make_model_info, sample_flows):
    # El clasificador hecho como antes: su preprocesador ajustado solo con los ataques.
    attacks = sample_flows[sample_flows[TARGET] == 1]
    classifier = Pipeline([("preprocessor", build_preprocessor("m2")), ("model", LogisticRegression(max_iter=1000))])
    model = {**tiny_models["a9"]["model"], "attack_type_classifier": classifier.fit(attacks, attacks[ATTACK_CAT])}

    with pytest.raises(ArtifactError, match="no da las mismas columnas que el del detector: le faltan proto_arp"):
        export_model(model, make_model_info("a9", name="model_x"), tmp_path)
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
