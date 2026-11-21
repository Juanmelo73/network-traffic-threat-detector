"""Umbral de alerta y métricas de evaluación de un modelo (contrato, secciones 7 y 11)."""

import math

import numpy as np
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score

from threat_detector.artifacts import detection_rate, false_alarm_rate, is_alert
from threat_detector.config import TARGET_RECALL
from threat_detector.dataset import ATTACK_TYPES, NORMAL_CAT


def _check_inputs(y_true, attack_probability):
    """Lanza ValueError si etiquetas y probabilidades no tienen los mismos flujos o falta una clase."""
    if len(y_true) != len(attack_probability):
        raise ValueError(
            f"Las etiquetas traen {len(y_true)} flujos y las probabilidades {len(attack_probability)}; "
            "deben traer los mismos flujos."
        )
    if set(np.unique(y_true).tolist()) != {0, 1}:
        raise ValueError(
            "Estas métricas necesitan flujos normales y ataques reales; "
            "los datos recibidos solo tienen una clase."
        )


def compute_threshold(y_true, attack_probability):
    """Umbral más alto que deja al menos TARGET_RECALL de los ataques reales como alerta.

    Se calcula con las predicciones de validación, nunca con la prueba. Un flujo es alerta si su
    probabilidad es mayor o igual que el umbral (is_alert en artifacts.py). Los flujos normales no
    cambian el umbral, pero se exigen, igual que en threshold_rule, que se calcula con los mismos datos.
    """
    y_true = np.asarray(y_true)
    attack_probability = np.asarray(attack_probability, dtype=float)
    _check_inputs(y_true, attack_probability)
    attack_probabilities = np.sort(attack_probability[y_true == 1])[::-1]

    # Cuántos ataques deben quedar como alerta: TARGET_RECALL de los ataques, redondeado hacia arriba.
    needed = math.ceil(TARGET_RECALL * len(attack_probabilities))
    return float(attack_probabilities[needed - 1])


def threshold_rule(y_true, attack_probability, threshold):
    """Objeto threshold_rule de model.json: la regla del umbral y lo que logró en validación.

    Recibe las etiquetas y probabilidades de validación (computed_on siempre es "validation").
    """
    y_true = np.asarray(y_true)
    attack_probability = np.asarray(attack_probability, dtype=float)
    _check_inputs(y_true, attack_probability)
    alerts = is_alert(attack_probability, threshold)
    return {
        "target_recall": TARGET_RECALL,
        "computed_on": "validation",
        "validation_flows": len(y_true),
        "validation_detection_rate": detection_rate(y_true, alerts),
        "validation_false_alarm_rate": false_alarm_rate(y_true, alerts),
    }


def detection_metrics(y_true, attack_probability, threshold):
    """Objeto detection de test_metrics (contrato, sección 7): la detección con el umbral del modelo."""
    y_true = np.asarray(y_true)
    attack_probability = np.asarray(attack_probability, dtype=float)
    _check_inputs(y_true, attack_probability)

    alerts = is_alert(attack_probability, threshold)
    attacks = y_true == 1
    tp = int((alerts & attacks).sum())
    fp = int((alerts & ~attacks).sum())
    tn = int((~alerts & ~attacks).sum())
    fn = int((~alerts & attacks).sum())

    return {
        "detection_rate": detection_rate(y_true, alerts),
        "false_alarm_rate": false_alarm_rate(y_true, alerts),
        # Sin ninguna alerta la precisión no se puede calcular (contrato, sección 7).
        "precision": tp / (tp + fp) if tp + fp else None,
        "f1": 2 * tp / (2 * tp + fp + fn),
        "pr_auc": float(average_precision_score(y_true, attack_probability)),
        "roc_auc": float(roc_auc_score(y_true, attack_probability)),
        "accuracy": (tp + tn) / len(y_true),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def attack_type_metrics(true_attack_cat, predicted_attack_cat, alerts):
    """Objeto attack_type de test_metrics (contrato, sección 7): el tipo probable de los ataques.

    Solo evalúa los ataques reales que dieron alerta, porque el tipo probable solo existe en las
    alertas; así evaluated_flows es igual a tp de detection_metrics. `alerts` trae un valor por
    flujo, como el que devuelve is_alert con muchos flujos.
    """
    true_attack_cat = np.asarray(true_attack_cat, dtype=object)
    predicted_attack_cat = np.asarray(predicted_attack_cat, dtype=object)
    alerts = np.asarray(alerts, dtype=bool)
    if not len(true_attack_cat) == len(predicted_attack_cat) == len(alerts):
        raise ValueError(
            f"Los tipos reales traen {len(true_attack_cat)} flujos, los predichos "
            f"{len(predicted_attack_cat)} y las alertas {len(alerts)}; deben traer los mismos flujos."
        )

    evaluated = (true_attack_cat != NORMAL_CAT) & alerts
    y_true = true_attack_cat[evaluated]
    y_pred = predicted_attack_cat[evaluated]
    # confusion_matrix descartaría sin avisar los valores que no están en ATTACK_TYPES.
    for description, values in (("ataques reales con un tipo", y_true), ("alertas con un tipo probable", y_pred)):
        invalid = sorted({str(value) for value in values if value not in ATTACK_TYPES})
        if invalid:
            raise ValueError(
                f"Hay {description} que no es uno de los 9 tipos de ataque: {', '.join(invalid)}."
            )

    # Fila = tipo real, columna = tipo predicho, en el orden de ATTACK_TYPES. confusion_matrix no
    # acepta datos vacíos: sin flujos evaluados la matriz es de ceros.
    if len(y_true):
        matrix = confusion_matrix(y_true, y_pred, labels=ATTACK_TYPES)
    else:
        matrix = np.zeros((len(ATTACK_TYPES), len(ATTACK_TYPES)), dtype=int)
    per_class = []
    for i, attack_cat in enumerate(ATTACK_TYPES):
        tp = int(matrix[i, i])
        support = int(matrix[i, :].sum())
        predicted = int(matrix[:, i].sum())
        denominator = support + predicted  # = 2·tp + fp + fn
        per_class.append({
            "attack_cat": attack_cat,
            "precision": tp / predicted if predicted else None,
            "recall": tp / support if support else None,
            "f1": 2 * tp / denominator if denominator else None,
            "support": support,
        })

    # macro_f1: promedio de los f1 que se pueden calcular; un tipo ausente no cuenta como 0.
    # Sin ningún flujo evaluado no hay ningún f1, y macro_f1 es None (contrato, sección 7).
    f1_values = [c["f1"] for c in per_class if c["f1"] is not None]
    return {
        "evaluated_flows": int(evaluated.sum()),
        "macro_f1": sum(f1_values) / len(f1_values) if f1_values else None,
        "per_class": per_class,
        "confusion": {"labels": list(ATTACK_TYPES), "matrix": matrix.tolist()},
    }
