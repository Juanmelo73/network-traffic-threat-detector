"""Interfaz común de los modelos de la app: los reales (model.joblib) y el simulado."""

from typing import Protocol

from threat_detector.app.mock import MockPredictor
from threat_detector.artifacts import predict_flows


class Predictor(Protocol):
    """Lo que la app necesita de un modelo, sea real o simulado."""

    # Su model.json.
    info: dict

    def predict(self, flows):
        """(attack_probability, alerts, predicted_attack_cat) de flujos ya validados."""

    def explain(self, flow):
        """Contribuciones de un flujo (contrato, sección 5), o None si el modelo no puede explicar."""


class PipelinePredictor:
    """Predictor de un modelo entrenado: los Pipeline de su model.joblib."""

    def __init__(self, info, model):
        self.info = info
        self.model = model

    def predict(self, flows):
        return predict_flows(self.model, self.info, flows)

    def explain(self, flow):
        if not self.info["can_explain"]:
            return None
        raise NotImplementedError("Los métodos de explicación de los modelos entrenados todavía no están definidos.")


def build_predictors(models):
    """Un predictor por modelo, a partir de lo que devuelve load_artifacts: {name: predictor}, en el mismo orden."""
    return {
        name: MockPredictor(entry["info"]) if entry["info"]["is_mock"] else PipelinePredictor(entry["info"], entry["model"])
        for name, entry in models.items()
    }
