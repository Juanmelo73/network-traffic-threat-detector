"""Modelo simulado: resultados inventados pero repetibles, en el formato del contrato (sección 13)."""

import numpy as np
import pandas as pd

from threat_detector.app.analyses import python_value
from threat_detector.artifacts import is_alert
from threat_detector.dataset import ATTACK_TYPES

# La probabilidad sale del número de cada flujo en pasos de 1 / PROBABILITY_STEPS: de 0 a 0,999999.
PROBABILITY_STEPS = 1_000_000
# Cada contribución sale en pasos de 1 / CONTRIBUTION_STEPS: de -1 a 1.
CONTRIBUTION_STEPS = 1_000_000


def _flow_numbers(flows, info):
    """Un número entero por flujo, que depende solo de las variables que usa el modelo.

    No mira id, label ni attack_cat. Las numéricas se pasan a decimal, así que 1 y 1.0 dan lo
    mismo; las categóricas se pasan a texto, con las vacías como texto vacío. Se usa la misma
    función que flow_pattern_ids: con index=False, el número no depende de la posición del flujo.
    """
    numeric = flows[info["numeric_cols"]].astype(float)
    categorical = flows[info["categorical_cols"]].fillna("").astype(str)
    return pd.util.hash_pandas_object(pd.concat([numeric, categorical], axis=1), index=False).to_numpy()


class MockPredictor:
    """Predictor del modelo simulado: no tiene model.joblib y calcula todo con su model.json."""

    def __init__(self, info):
        self.info = info

    def predict(self, flows):
        """(attack_probability, alerts, predicted_attack_cat) de los flujos, en el formato de predict_flows."""
        numbers = _flow_numbers(flows, self.info)
        attack_probability = (numbers % PROBABILITY_STEPS) / PROBABILITY_STEPS
        alerts = is_alert(attack_probability, self.info["threshold"])
        # El tipo probable solo se da en las alertas; en los demás flujos es None (contrato, sección 3).
        predicted_attack_cat = np.full(len(numbers), None, dtype=object)
        type_positions = (numbers[alerts] // PROBABILITY_STEPS) % len(ATTACK_TYPES)
        predicted_attack_cat[alerts] = np.array(ATTACK_TYPES, dtype=object)[type_positions]
        return attack_probability, alerts, predicted_attack_cat

    def explain(self, flow):
        """Contribuciones inventadas de un flujo (una fila de la tabla), en el formato de la sección 5.

        Da una entrada {feature, value, contribution} por cada variable de feature_groups, con el
        valor del archivo, ordenadas por el valor absoluto de contribution, de mayor a menor. Si
        la suma de las contribuciones no tiene el signo del flujo (positiva si es alerta, negativa
        si no), se les cambia el signo a todas, para que la explicación no contradiga la severidad.
        """
        number = _flow_numbers(flow.to_frame().T, self.info)[0]
        features = list(self.info["feature_groups"])
        # Cada contribución combina el número del flujo con el nombre de la variable. Se calcula en
        # enteros, para que la suma sea exacta.
        keys = np.array([f"{number}:{feature}" for feature in features], dtype=object)
        steps = (pd.util.hash_array(keys) % (2 * CONTRIBUTION_STEPS + 1)).astype(np.int64) - CONTRIBUTION_STEPS

        alert = is_alert((number % PROBABILITY_STEPS) / PROBABILITY_STEPS, self.info["threshold"])
        if (steps.sum() > 0) != alert:
            steps = -steps

        contributions = [
            {"feature": feature, "value": python_value(flow[feature]), "contribution": int(step) / CONTRIBUTION_STEPS}
            for feature, step in zip(features, steps)
        ]
        return sorted(contributions, key=lambda entry: abs(entry["contribution"]), reverse=True)
