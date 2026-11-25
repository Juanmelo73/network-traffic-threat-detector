"""Pruebas de ml/evaluation.py: umbral de alerta, métricas y errores inevitables, con datos escritos a mano y resultado conocido."""

import json
import math
from fractions import Fraction

import numpy as np
import pandas as pd
import pytest

from threat_detector.artifacts import detection_rate, is_alert, predict_flows
from threat_detector.config import TARGET_RECALL
from threat_detector.dataset import ATTACK_CAT, ATTACK_TYPES, CATEGORICAL_COLS, NORMAL_CAT, TARGET
from threat_detector.ml.evaluation import (
    TOTAL_ROW,
    attack_type_metrics,
    compute_threshold,
    detection_metrics,
    false_alarms_by_category,
    flow_contributions,
    global_importance,
    ks_distance,
    logistic_coefficients,
    numeric_differences,
    label_mixed_groups,
    stratified_samples,
    threshold_rule,
    unavoidable_type_errors,
)
from threat_detector.ml.preprocessing import build_preprocessor, flow_pattern_ids
from threat_detector.ml.training import feature_groups
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

# 20 ataques con probabilidades 0,05 a 1,00 (redondeadas a 2 decimales, para que el punto flotante
# no cambie los valores esperados) y 10 normales: 6 con probabilidad ≥ 0,1 y 4 por debajo.
ATTACK_PROBS = np.round(np.arange(1, 21) * 0.05, 2)
NORMAL_PROBS = np.array([0.02, 0.05, 0.08, 0.09, 0.15, 0.2, 0.3, 0.5, 0.7, 0.9])
Y_TRUE = np.array([1] * 20 + [0] * 10)
PROBS = np.concatenate([ATTACK_PROBS, NORMAL_PROBS])

# Caso a mano de detection_metrics: con umbral 0,5 hay tp=4, fp=1, tn=4 y fn=1.
LABELS = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0]
SCORES = [0.90, 0.80, 0.70, 0.60, 0.20, 0.65, 0.30, 0.20, 0.10, 0.05]


def round_trips_json(value):
    """True si el valor se escribe en JSON y se lee de vuelta sin cambios (sin tipos de numpy)."""
    return json.loads(json.dumps(value)) == value


# compute_threshold


def test_threshold_is_the_highest_that_keeps_target_recall():
    # 95 % de 20 ataques = 19: el umbral es la probabilidad del ataque n.º 19 de mayor a menor, 0,1.
    threshold = compute_threshold(Y_TRUE, PROBS)
    assert threshold == 0.1
    assert detection_rate(Y_TRUE, is_alert(PROBS, threshold)) == 0.95
    # Un umbral apenas más alto ya deja menos del 95 %.
    assert detection_rate(Y_TRUE, is_alert(PROBS, threshold + 1e-4)) == 0.9


def test_normal_flows_do_not_change_the_threshold():
    low_normals = np.full(10, 0.01)
    high_normals = np.full(10, 0.99)
    for normals in (low_normals, high_normals):
        assert compute_threshold(Y_TRUE, np.concatenate([ATTACK_PROBS, normals])) == 0.1


def test_needed_attacks_are_computed_exactly():
    # ceil(TARGET_RECALL × ataques) con punto flotante da lo mismo que con fracciones exactas.
    # Si cambia TARGET_RECALL, esta prueba vuelve a comprobarlo.
    exact = Fraction(str(TARGET_RECALL))
    assert all(math.ceil(TARGET_RECALL * n) == math.ceil(exact * n) for n in range(1, 50_001))


def test_threshold_keeps_exactly_the_needed_attacks():
    # De 1 a 200 ataques con probabilidades distintas: quedan como alerta exactamente los necesarios.
    for attacks in range(1, 201):
        probabilities = np.arange(1, attacks + 1) / (attacks + 1)
        y_true = np.array([1] * attacks + [0])
        threshold = compute_threshold(y_true, np.append(probabilities, 0.0))
        needed = math.ceil(Fraction(str(TARGET_RECALL)) * attacks)
        assert int(is_alert(probabilities, threshold).sum()) == needed, f"{attacks} ataques"


def test_threshold_errors():
    with pytest.raises(ValueError, match="deben traer los mismos flujos"):
        compute_threshold([1, 0, 1], [0.5, 0.2])
    with pytest.raises(ValueError, match="solo tienen una clase"):
        compute_threshold([1, 1, 1], [0.5, 0.2, 0.9])


# threshold_rule


def test_threshold_rule_reports_what_the_threshold_achieved():
    rule = threshold_rule(Y_TRUE, PROBS, 0.1)
    assert rule == {
        "target_recall": TARGET_RECALL,
        "computed_on": "validation",
        "validation_flows": 30,
        "validation_detection_rate": 0.95,
        "validation_false_alarm_rate": 0.6,
    }
    assert round_trips_json(rule)


def test_threshold_rule_errors():
    with pytest.raises(ValueError, match="deben traer los mismos flujos"):
        threshold_rule([1, 0], [0.5], 0.5)
    with pytest.raises(ValueError, match="solo tienen una clase"):
        threshold_rule([0, 0], [0.5, 0.1], 0.5)


# detection_metrics


def test_detection_metrics_hand_case():
    metrics = detection_metrics(LABELS, SCORES, 0.5)
    assert metrics["confusion"] == {"tp": 4, "fp": 1, "tn": 4, "fn": 1}
    assert metrics["detection_rate"] == pytest.approx(0.8)
    assert metrics["false_alarm_rate"] == pytest.approx(0.2)
    assert metrics["precision"] == pytest.approx(0.8)
    assert metrics["f1"] == pytest.approx(0.8)
    assert metrics["accuracy"] == pytest.approx(0.8)
    # pr_auc: 0,2·1 + 0,2·1 + 0,2·1 + 0,2·0,8 + 0,2·0,625; roc_auc: 21,5 de 25 pares ataque-normal bien ordenados.
    assert metrics["pr_auc"] == pytest.approx(0.885)
    assert metrics["roc_auc"] == pytest.approx(0.86)
    assert list(metrics) == ["detection_rate", "false_alarm_rate", "precision", "f1", "pr_auc",
                             "roc_auc", "accuracy", "confusion"]
    assert round_trips_json(metrics)


def test_detection_metrics_perfect_separation():
    metrics = detection_metrics([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1], 0.5)
    assert metrics["pr_auc"] == 1.0 and metrics["roc_auc"] == 1.0 and metrics["f1"] == 1.0


def test_detection_metrics_without_alerts():
    metrics = detection_metrics(LABELS, SCORES, 0.95)
    assert metrics["precision"] is None
    assert metrics["f1"] == 0
    assert metrics["detection_rate"] == 0


def test_detection_metrics_errors():
    with pytest.raises(ValueError, match="deben traer los mismos flujos"):
        detection_metrics([1, 0], [0.5], 0.5)
    with pytest.raises(ValueError, match="solo tienen una clase"):
        detection_metrics([1, 1], [0.5, 0.6], 0.5)


# attack_type_metrics


def hand_attack_types():
    """Tipos reales, tipos predichos y alertas escritos a mano (como en el notebook 04, sección 7)."""
    rows = (
        [("Generic", "Generic", True)] * 3 + [("Generic", "Exploits", True)]
        + [("Exploits", "Exploits", True)] * 2 + [("Exploits", "Generic", True)]
        + [("DoS", "Exploits", True), ("Fuzzers", None, False), ("Normal", "Generic", True)]
    )
    return (list(column) for column in zip(*rows))


def test_attack_type_metrics_hand_case():
    true_cats, predicted_cats, alerts = hand_attack_types()
    metrics = attack_type_metrics(true_cats, predicted_cats, alerts)

    # Solo cuentan los ataques reales con alerta: ni el Fuzzers sin alerta ni el Normal con alerta.
    assert metrics["evaluated_flows"] == 8
    by_type = {c["attack_cat"]: c for c in metrics["per_class"]}
    assert [c["attack_cat"] for c in metrics["per_class"]] == ATTACK_TYPES
    assert by_type["Generic"] == {"attack_cat": "Generic", "precision": 0.75, "recall": 0.75, "f1": 0.75, "support": 4}
    assert by_type["Exploits"]["precision"] == 0.5
    assert by_type["Exploits"]["recall"] == pytest.approx(2 / 3)
    assert by_type["Exploits"]["f1"] == pytest.approx(4 / 7)
    # DoS tiene flujos pero nunca se predijo: precisión None, recall y f1 en 0.
    assert by_type["DoS"] == {"attack_cat": "DoS", "precision": None, "recall": 0.0, "f1": 0.0, "support": 1}
    # Los tipos sin flujos ni predicciones no cuentan en macro_f1.
    for attack_cat in set(ATTACK_TYPES) - {"Generic", "Exploits", "DoS"}:
        assert by_type[attack_cat] == {"attack_cat": attack_cat, "precision": None, "recall": None,
                                       "f1": None, "support": 0}
    assert metrics["macro_f1"] == pytest.approx((0.75 + 4 / 7 + 0) / 3)

    matrix = np.array(metrics["confusion"]["matrix"])
    assert metrics["confusion"]["labels"] == ATTACK_TYPES and matrix.shape == (9, 9)
    generic, exploits, dos = (ATTACK_TYPES.index(t) for t in ("Generic", "Exploits", "DoS"))
    expected = np.zeros((9, 9), dtype=int)
    expected[generic, generic], expected[generic, exploits] = 3, 1
    expected[exploits, exploits], expected[exploits, generic] = 2, 1
    expected[dos, exploits] = 1
    np.testing.assert_array_equal(matrix, expected)
    assert round_trips_json(metrics)


def test_evaluated_flows_equal_detection_tp():
    true_cats, predicted_cats, alerts = hand_attack_types()
    labels = [int(cat != "Normal") for cat in true_cats]
    detection = detection_metrics(labels, [0.9 if alert else 0.1 for alert in alerts], 0.5)
    assert attack_type_metrics(true_cats, predicted_cats, alerts)["evaluated_flows"] == detection["confusion"]["tp"]


def test_attack_type_metrics_without_evaluated_flows():
    metrics = attack_type_metrics(["Generic", "Normal"], [None, None], [False, False])
    assert metrics["evaluated_flows"] == 0
    assert metrics["macro_f1"] is None
    assert metrics["confusion"]["matrix"] == [[0] * 9 for _ in range(9)]


@pytest.mark.parametrize(
    "true_cats, predicted_cats, alerts, message",
    [
        (["Generic", "worms"], ["Generic", "Worms"], [True, True], "ataques reales con un tipo.*worms"),
        (["Generic", "DoS"], ["Generic", "Normal"], [True, True], "alertas con un tipo probable.*Normal"),
        (["Generic", "DoS"], ["Generic"], [True, True], "deben traer los mismos flujos"),
    ],
    ids=["invalid_true_type", "normal_as_predicted_type", "different_lengths"],
)
def test_attack_type_metrics_errors(true_cats, predicted_cats, alerts, message):
    with pytest.raises(ValueError, match=message):
        attack_type_metrics(true_cats, predicted_cats, alerts)


# Errores inevitables

# Grupos de flujos idénticos escritos a mano: cada grupo copia las variables de una fila distinta
# de sample_flows.csv y le pone estas etiquetas.
GROUPS = [
    ["DoS", "DoS", "DoS", "Exploits"],            # 1 error seguro de Exploits
    ["Analysis", "Analysis", "Backdoor", "Backdoor"],  # empate: 4 flujos empatados, 2 errores mínimos
    ["Generic", "Generic"],                       # un solo tipo: no es un grupo mezclado
    [NORMAL_CAT, NORMAL_CAT, "Fuzzers"],          # mezcla normales y un ataque
    ["Shellcode"],                                # flujo que no se repite
]


@pytest.fixture
def grouped_flows(sample_flows):
    rows = []
    for position, labels in enumerate(GROUPS):
        for attack_cat in labels:
            row = sample_flows.iloc[position].copy()
            row[ATTACK_CAT] = attack_cat
            row[TARGET] = int(attack_cat != NORMAL_CAT)
            rows.append(row)
    flows = pd.DataFrame(rows).reset_index(drop=True)
    # Cada grupo debe ser un patrón distinto.
    assert flow_pattern_ids(flows).nunique() == len(GROUPS)
    return flows


def test_unavoidable_type_errors_with_known_groups(grouped_flows):
    table = unavoidable_type_errors(grouped_flows).set_index("attack_cat")

    assert list(table.index) == [*ATTACK_TYPES, TOTAL_ROW]
    expected = {
        # tipo: (flows, mixed_group_flows, certain_errors, tied_flows)
        "DoS": (3, 3, 0, 0),
        "Exploits": (1, 1, 1, 0),
        "Analysis": (2, 2, 0, 2),
        "Backdoor": (2, 2, 0, 2),
        "Generic": (2, 0, 0, 0),
        "Fuzzers": (1, 0, 0, 0),
        "Shellcode": (1, 0, 0, 0),
        "Reconnaissance": (0, 0, 0, 0),
        "Worms": (0, 0, 0, 0),
        TOTAL_ROW: (12, 8, 1, 4),
    }
    for attack_cat, values in expected.items():
        assert tuple(table.loc[attack_cat, ["flows", "mixed_group_flows", "certain_errors", "tied_flows"]]) == values
    assert table.loc["Exploits", "certain_error_rate"] == 1.0
    assert pd.isna(table.loc["Worms", "certain_error_rate"])
    # Mínimo exacto: 1 Exploits en el primer grupo y 2 en el empate.
    assert table.loc[TOTAL_ROW, "min_errors"] == 3
    assert table.loc[ATTACK_TYPES, "min_errors"].isna().all()


def test_label_mixed_groups_with_known_groups(grouped_flows):
    table = label_mixed_groups(grouped_flows)
    assert table.to_dict("records") == [
        {"groups": 1, "flows": 3, "min_errors": 1, "share_of_flows": 3 / len(grouped_flows)}
    ]


def test_without_mixed_groups_everything_is_zero(sample_flows):
    flows = sample_flows.drop_duplicates(subset=sample_flows.columns.drop(["id", TARGET, ATTACK_CAT]))
    assert label_mixed_groups(flows).loc[0, ["groups", "flows", "min_errors"]].tolist() == [0, 0, 0]
    total = unavoidable_type_errors(flows).set_index("attack_cat").loc[TOTAL_ROW]
    assert (total["mixed_group_flows"], total["certain_errors"], total["tied_flows"], total["min_errors"]) == (0, 0, 0, 0)


# Falsas alarmas por categoría


@pytest.fixture
def category_table(tiny_models, sample_flows):
    """Tabla de false_alarms_by_category del modelo de prueba a9, con una categoría nueva en "test"."""
    tiny = tiny_models["a9"]
    info = {"detector_type": tiny["detector_type"], "threshold": tiny["threshold"]}
    test = sample_flows.copy()
    test.loc[test.index[test[TARGET] == 0][:3], "service"] = "zzz_nueva"
    parts = {"train": sample_flows, "validation": sample_flows, "test": test}
    return false_alarms_by_category(tiny["model"], info, parts), tiny, info, parts


def test_categories_add_up_to_the_normals_and_the_false_alarms(category_table):
    table, tiny, info, parts = category_table
    assert list(table["column"].unique()) == sorted(CATEGORICAL_COLS)
    for name, flows in parts.items():
        normals = flows[TARGET] == 0
        _, alerts, _ = predict_flows(tiny["model"], info, flows)
        false_alarms = int((alerts & normals.to_numpy()).sum())
        for column, rows in table.groupby("column"):
            assert rows[f"{name}_normals"].sum() == normals.sum()
            assert rows[f"{name}_false_alarms"].sum() == false_alarms
            assert rows[f"{name}_share"].sum() == pytest.approx(1)
    if table["test_false_alarms"].sum():
        for _, rows in table.groupby("column"):
            assert rows["share_of_test_false_alarms"].sum() == pytest.approx(1)


def test_categories_say_how_the_model_sees_them(category_table):
    table, tiny, _, _ = category_table
    new = table[(table["column"] == "service") & (table["category"] == "zzz_nueva")].iloc[0]
    assert new["in_training"] == "nueva" and new["train_normals"] == 0 and new["test_normals"] == 3
    assert pd.isna(new["train_false_alarm_rate"])
    encoder = tiny["model"]["detector"]["preprocessor"].named_transformers_["categorical"]
    for position, column in enumerate(encoder.feature_names_in_):
        rows = table[table["column"] == column].set_index("category")
        grouped = encoder.infrequent_categories_[position]
        infrequent = set() if grouped is None else set(grouped)
        for category in set(rows.index) & set(encoder.categories_[position]):
            assert rows.loc[category, "in_training"] == ("agrupada" if category in infrequent else "propia")


def test_table_is_sorted_by_test_false_alarms(category_table):
    table = category_table[0]
    for _, rows in table.groupby("column"):
        assert list(rows["test_false_alarms"]) == sorted(rows["test_false_alarms"], reverse=True)


# Diferencias en las variables numéricas


@pytest.mark.parametrize(
    "first, second, expected",
    [
        ([1, 2, 3], [1, 2, 3], 0.0),          # iguales
        ([1, 2, 3], [10, 20], 1.0),           # sin solapamiento
        ([1, 2, 3], [2, 3, 4], 1 / 3),        # en 1, una acumula 1/3 y la otra 0
        ([0, 0, 0, 5], [0, 5, 5, 5], 0.5),    # con valores repetidos: en 0, 3/4 contra 1/4
    ],
)
def test_ks_distance_known_values(first, second, expected):
    assert ks_distance(first, second) == pytest.approx(expected)
    assert ks_distance(second, first) == pytest.approx(expected)


def test_ks_distance_does_not_depend_on_the_scale():
    first, second = [1, 5, 9, 200], [2, 3, 50, 70, 1000]
    assert ks_distance(np.log1p(first), np.log1p(second)) == pytest.approx(ks_distance(first, second))


def test_ks_distance_needs_values():
    with pytest.raises(ValueError, match="al menos un valor"):
        ks_distance([], [1])


def test_numeric_differences_table():
    first = pd.DataFrame({"dur": [1.0, 2.0, 3.0, 4.0], "sbytes": [10, 10, 10, 10]})
    second = pd.DataFrame({"dur": [3.0, 4.0, 5.0, 6.0, 7.0], "sbytes": [10, 10, 10, 10, 10]})
    table = numeric_differences(first, second, ["dur", "sbytes"]).set_index("variable")
    assert table.loc["dur", "first_median"] == 2.5 and table.loc["dur", "second_median"] == 5.0
    assert (table.loc["dur", "first_flows"], table.loc["dur", "second_flows"]) == (4, 5)
    assert table.loc["dur", "ks_d"] == pytest.approx(ks_distance(first["dur"], second["dur"]))
    assert table.loc["sbytes", "ks_d"] == 0.0


# Importancia global de las variables

# Detectores de prueba diminutos, entrenados con sample_flows.csv: no son los modelos del proyecto.
IMPORTANCE_MODELS = {
    "hgb": ("m1", lambda: HistGradientBoostingClassifier(max_iter=20, random_state=42), "shap_tree"),
    "rf": ("m2", lambda: RandomForestClassifier(n_estimators=5, max_depth=4, random_state=42), "shap_tree"),
    "lr": ("m2", lambda: LogisticRegression(max_iter=1000), "linear_logit"),
}


def importance_model(kind, flows):
    """(model, info) de un detector de prueba, con lo que leen las funciones de importancia."""
    method, estimator, explanation = IMPORTANCE_MODELS[kind]
    detector = Pipeline([("preprocessor", build_preprocessor(method)), ("model", estimator())]).fit(flows, flows[TARGET])
    info = {"name": kind, "explanation_method": explanation, "feature_groups": feature_groups(detector["preprocessor"])}
    return {"detector": detector, "attack_type_classifier": detector}, info


def test_stratified_samples_are_disjoint_and_keep_the_proportions(sample_flows):
    first, second = stratified_samples(sample_flows, 100, 2, random_state=42)
    assert len(first) == len(second) == 100
    assert first.index.intersection(second.index).empty
    expected = sample_flows[ATTACK_CAT].value_counts(normalize=True) * 100
    for sample in (first, second):
        counts = sample[ATTACK_CAT].value_counts().reindex(expected.index, fill_value=0)
        assert (counts - expected).abs().max() <= 1
    # Con la misma semilla salen las mismas muestras.
    again = stratified_samples(sample_flows, 100, 2, random_state=42)
    assert first.index.equals(again[0].index) and second.index.equals(again[1].index)


@pytest.mark.parametrize("kind", list(IMPORTANCE_MODELS))
def test_flow_contributions_add_up_to_the_model_output(kind, sample_flows):
    # Suma de las contribuciones + valor base = salida del modelo para la clase de ataque: log-odds
    # en HistGradientBoosting y regresión logística, probabilidad en Random Forest.
    model, info = importance_model(kind, sample_flows)
    flows = sample_flows.iloc[::50]
    contributions = flow_contributions(model, info, flows)
    assert list(contributions.columns) == list(info["feature_groups"]) and contributions.index.equals(flows.index)
    estimator = model["detector"]["model"]
    probability = model["detector"].predict_proba(flows)[:, list(estimator.classes_).index(1)]
    if kind == "lr":
        base, output = estimator.intercept_[0], np.log(probability / (1 - probability))
    else:
        import shap

        expected = np.atleast_1d(shap.TreeExplainer(estimator).expected_value)
        base = expected[-1] if kind == "rf" else expected[0]
        output = probability if kind == "rf" else np.log(probability / (1 - probability))
    np.testing.assert_allclose(contributions.sum(axis=1) + base, output, atol=1e-6)


def test_global_importance_ranks_the_mean_absolute_contribution(sample_flows):
    model, info = importance_model("hgb", sample_flows)
    table = global_importance(model, info, sample_flows)
    expected = flow_contributions(model, info, sample_flows).abs().mean().sort_values(ascending=False, kind="stable")
    assert table["feature"].tolist() == expected.index.tolist()
    np.testing.assert_allclose(table["mean_abs_contribution"], expected.to_numpy())
    assert table["rank"].tolist() == list(range(1, len(expected) + 1))
    assert table["share"].sum() == pytest.approx(1)


def test_logistic_coefficients_follow_the_prepared_columns(sample_flows):
    model, info = importance_model("lr", sample_flows)
    table = logistic_coefficients(model, info)
    estimator = model["detector"]["model"]
    assert table["column"].tolist() == list(model["detector"]["preprocessor"].get_feature_names_out())
    np.testing.assert_array_equal(table["coefficient"], estimator.coef_[0])
    # Las columnas de cada variable son las de feature_groups.
    assert table.groupby("feature", sort=False)["column"].apply(list).to_dict() == info["feature_groups"]


def test_importance_needs_an_explanation_method(sample_flows):
    model, info = importance_model("lr", sample_flows)
    with pytest.raises(ValueError, match="no tiene un método de explicación"):
        flow_contributions(model, {**info, "explanation_method": None}, sample_flows)

