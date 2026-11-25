"""Interfaz común de los modelos de la app: los reales (model.joblib) y el simulado."""

from typing import Protocol

import numpy as np

from threat_detector.app.analyses import python_value
from threat_detector.app.mock import MockPredictor
from threat_detector.artifacts import predict_flows
from threat_detector.config import PREDICTION_BATCH_ROWS

# Métodos de explicación de los modelos entrenados (contrato, sección 11).
SHAP_TREE = "shap_tree"        # SHAP TreeExplainer: log-odds en HistGradientBoosting, probabilidad en Random Forest
LINEAR_LOGIT = "linear_logit"  # coeficiente × valor preparado, en log-odds
# Clase del detector binario hacia la que empuja una contribución positiva ("ataque").
ATTACK_CLASS = 1


class Predictor(Protocol):
    """Lo que la app necesita de un modelo, sea real o simulado."""

    # Su model.json.
    info: dict

    def predict(self, flows):
        """(attack_probability, alerts, predicted_attack_cat) de flujos ya validados."""

    def explain(self, flow):
        """Contribuciones de un flujo (contrato, sección 5), o None si el modelo no puede explicar."""


def _attack_column(classes):
    """Posición de la clase de ataque en classes_; se busca por nombre, nunca por posición (contrato, sección 10)."""
    return list(classes).index(ATTACK_CLASS)


def _tree_contributions(explainer, estimator, features):
    """Contribución de cada columna preparada hacia la clase de ataque, con SHAP TreeExplainer.

    Con dos clases, HistGradientBoosting da una sola columna de valores, la de classes_[1], en
    log-odds; Random Forest da una por clase, en probabilidad. La suma de las contribuciones más el
    valor base del explicador es la salida del modelo para la clase de ataque.
    """
    values = np.asarray(explainer.shap_values(features))
    column = _attack_column(estimator.classes_)
    if values.ndim == 3:
        return values[0, :, column]
    # Una sola columna: es la de classes_[1]. Si el ataque fuera classes_[0], el signo se invierte.
    return values[0] if column == 1 else -values[0]


def _linear_contributions(estimator, features):
    """Contribución exacta de cada columna en log-odds: coeficiente × valor preparado.

    En una regresión logística binaria, coef_ corresponde a classes_[1]. La suma de las
    contribuciones más el intercepto es el log-odds de la clase de ataque.
    """
    contributions = features.to_numpy(dtype=float)[0] * estimator.coef_[0]
    return contributions if _attack_column(estimator.classes_) == 1 else -contributions


class PipelinePredictor:
    """Predictor de un modelo entrenado: los Pipeline de su model.joblib."""

    def __init__(self, info, model):
        self.info = info
        self.model = model
        # El explicador SHAP se construye la primera vez que se pide una explicación y se guarda.
        self._explainer = None

    def predict(self, flows):
        """Predice por bloques de PREDICTION_BATCH_ROWS flujos y une los resultados en el orden del archivo."""
        parts = [
            predict_flows(self.model, self.info, flows.iloc[start:start + PREDICTION_BATCH_ROWS])
            for start in range(0, len(flows), PREDICTION_BATCH_ROWS)
        ]
        return tuple(np.concatenate(values) for values in zip(*parts))

    def _tree_explainer(self, estimator):
        if self._explainer is None:
            # shap se importa solo cuando se pide la primera explicación: así no pesa al arrancar.
            import shap

            # Sin datos de referencia usa el modo tree_path_dependent, que solo necesita los
            # árboles: la app no tiene los datos de entrenamiento.
            self._explainer = shap.TreeExplainer(estimator)
        return self._explainer

    def explain(self, flow):
        """Contribuciones de un flujo en el formato de la sección 5 del contrato, o None si el modelo no explica.

        flow es una fila del archivo (las columnas originales). Explica la probabilidad de ataque del
        detector. Da una entrada {feature, value, contribution} por cada variable de feature_groups:
        las columnas preparadas de una variable (por ejemplo, las one-hot de proto) se suman. value es
        el valor del archivo y las entradas van ordenadas por el valor absoluto de contribution, de
        mayor a menor. Positivo empuja hacia "ataque". La escala depende del método (sección 11).
        """
        if not self.info["can_explain"]:
            return None
        detector = self.model["detector"]
        features = detector["preprocessor"].transform(flow.to_frame().T.infer_objects())
        estimator = detector["model"]
        method = self.info["explanation_method"]
        if method == SHAP_TREE:
            values = _tree_contributions(self._tree_explainer(estimator), estimator, features)
        elif method == LINEAR_LOGIT:
            values = _linear_contributions(estimator, features)
        else:
            raise ValueError(f"Método de explicación desconocido: {method}.")

        by_column = dict(zip(features.columns, values))
        contributions = [
            {
                "feature": feature,
                "value": python_value(flow[feature]),
                "contribution": float(sum(by_column[column] for column in columns)),
            }
            for feature, columns in self.info["feature_groups"].items()
        ]
        return sorted(contributions, key=lambda entry: abs(entry["contribution"]), reverse=True)


def build_predictors(models):
    """Un predictor por modelo, a partir de lo que devuelve load_artifacts: {name: predictor}, en el mismo orden."""
    return {
        name: MockPredictor(entry["info"]) if entry["info"]["is_mock"] else PipelinePredictor(entry["info"], entry["model"])
        for name, entry in models.items()
    }
