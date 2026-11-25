"""Umbral de alerta, métricas de evaluación de un modelo (contrato, secciones 7 y 11) y errores inevitables."""

import math

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score

from threat_detector.artifacts import detection_rate, false_alarm_rate, is_alert
from threat_detector.config import TARGET_RECALL
from threat_detector.dataset import ATTACK_CAT, ATTACK_TYPES, NORMAL_CAT, TARGET
from threat_detector.ml.preprocessing import flow_pattern_ids


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


# Errores inevitables: flujos idénticos (mismo flow_pattern_ids) con etiquetas distintas. Ningún
# modelo puede separarlos, porque recibe exactamente los mismos valores.

# Nombre de la fila con los totales en unavoidable_type_errors.
TOTAL_ROW = "Total"


def _pattern_counts(flows, column):
    """Cuántos flujos de cada valor de column tiene cada grupo de flujos idénticos (una fila por grupo)."""
    return pd.crosstab(flow_pattern_ids(flows).to_numpy(), flows[column].to_numpy())


def _min_errors(counts):
    """Errores mínimos aun memorizando: en cada grupo, todos los flujos que no son del valor más frecuente."""
    return int((counts.sum(axis=1) - counts.max(axis=1)).sum())


def unavoidable_type_errors(flows):
    """Tabla de los errores de tipo que ningún modelo puede evitar, entre los ataques de flows.

    Una fila por tipo de ataque, en el orden de ATTACK_TYPES:
    - flows: ataques de ese tipo;
    - mixed_group_flows: los que están en un grupo de flujos idénticos con otros tipos;
    - certain_errors: los que no son del tipo más frecuente de su grupo, y por eso se equivocan
      aunque el modelo memorice; certain_error_rate es certain_errors / flows;
    - tied_flows: los que empatan como tipo más frecuente de su grupo con otro tipo; su error
      depende de cuál elija el modelo.
    La última fila, TOTAL_ROW, suma las columnas y trae en min_errors el mínimo exacto de errores:
    en cada grupo, todos los flujos menos los del tipo más frecuente. min_errors va vacío en los tipos.
    """
    attacks = flows[flows[TARGET] == 1]
    counts = _pattern_counts(attacks, ATTACK_CAT).reindex(columns=ATTACK_TYPES, fill_value=0)
    present = counts > 0
    mixed = present.sum(axis=1) > 1
    most_frequent = counts.eq(counts.max(axis=1), axis=0) & present
    tied = most_frequent & (most_frequent.sum(axis=1) > 1).to_numpy()[:, None]

    table = pd.DataFrame({
        "attack_cat": ATTACK_TYPES,
        "flows": counts.sum().to_numpy(),
        "mixed_group_flows": counts[mixed].sum().to_numpy(),
        "certain_errors": counts.where(~most_frequent, 0).sum().to_numpy(),
        "tied_flows": counts.where(tied, 0).sum().to_numpy(),
    })
    total = {"attack_cat": TOTAL_ROW, **table.drop(columns="attack_cat").sum().to_dict()}
    table = pd.concat([table, pd.DataFrame([total])], ignore_index=True)
    table["certain_error_rate"] = table["certain_errors"] / table["flows"].where(table["flows"] > 0)
    table["min_errors"] = pd.array([pd.NA] * len(ATTACK_TYPES) + [_min_errors(counts)], dtype="Int64")
    return table[[
        "attack_cat", "flows", "mixed_group_flows", "certain_errors", "certain_error_rate",
        "tied_flows", "min_errors",
    ]]


def label_mixed_groups(flows):
    """Grupos de flujos idénticos que mezclan flujos normales y ataques, en una tabla de una fila.

    groups: cantidad de esos grupos; flows: flujos que tienen; min_errors: errores mínimos del
    detector aun memorizando (en cada grupo, los flujos que no son de la etiqueta más frecuente);
    share_of_flows: flows / todos los flujos recibidos.
    """
    counts = _pattern_counts(flows, TARGET)
    mixed = counts[(counts > 0).sum(axis=1) > 1]
    mixed_flows = int(mixed.to_numpy().sum())
    return pd.DataFrame([{
        "groups": len(mixed),
        "flows": mixed_flows,
        "min_errors": _min_errors(mixed),
        "share_of_flows": mixed_flows / len(flows),
    }])
