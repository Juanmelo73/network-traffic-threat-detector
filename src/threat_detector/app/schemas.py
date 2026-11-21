"""Formato de las respuestas de la API (contrato, secciones 3 a 7) y de sus errores (sección 9)."""

from typing import Literal

from pydantic import BaseModel

from threat_detector.config import MAX_UPLOAD_MB, SIMULATION_SPEEDS

Severity = Literal["critical", "high", "medium", "low", "normal"]


# Sección 3: el flujo predicho.
class PredictedFlow(BaseModel):
    id: int
    proto: str | None
    service: str | None
    state: str | None
    attack_probability: float
    is_alert: bool
    severity: Severity
    predicted_attack_cat: str | None
    true_label: int | None
    true_attack_cat: str | None


# Sección 4: POST /api/predict y GET /api/analysis/{analysis_id}.
class AnalysisModel(BaseModel):
    name: str
    display_name: str
    threshold: float


class AlertsBySeverity(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class Summary(BaseModel):
    total_flows: int
    alerts: int
    alerts_by_severity: AlertsBySeverity
    detection_rate: float | None
    false_alarm_rate: float | None


class AnalysisResponse(BaseModel):
    analysis_id: str
    model: AnalysisModel
    has_labels: bool
    summary: Summary
    flows: list[PredictedFlow]


# Sección 5: GET /api/explain/{id}.
class Contribution(BaseModel):
    feature: str
    value: int | float | str | None
    contribution: float


class ExplainResponse(BaseModel):
    analysis_id: str
    flow: PredictedFlow
    can_explain: bool
    contributions: list[Contribution] | None


# Sección 6: GET /api/models.
class ModelSummary(BaseModel):
    name: str
    display_name: str
    is_mock: bool
    can_explain: bool
    use_ttl: bool
    threshold: float


class ModelsResponse(BaseModel):
    default_model: str
    models: list[ModelSummary]


# Sección 7: GET /api/metrics.
class DetectionConfusion(BaseModel):
    tp: int
    fp: int
    tn: int
    fn: int


class DetectionMetrics(BaseModel):
    detection_rate: float
    false_alarm_rate: float
    precision: float | None
    f1: float
    pr_auc: float
    roc_auc: float
    accuracy: float
    confusion: DetectionConfusion


class ClassMetrics(BaseModel):
    attack_cat: str
    precision: float | None
    recall: float | None
    f1: float | None
    support: int


class TypeConfusion(BaseModel):
    labels: list[str]
    matrix: list[list[int]]


class AttackTypeMetrics(BaseModel):
    evaluated_flows: int
    macro_f1: float | None
    per_class: list[ClassMetrics]
    confusion: TypeConfusion


class Complexity(BaseModel):
    training_seconds: float
    training_flows: int
    prediction_ms_per_1000_flows: float
    model_size_mb: float
    hardware: str


class ModelMetrics(BaseModel):
    name: str
    display_name: str
    is_mock: bool
    test_flows: int
    detection: DetectionMetrics
    attack_type: AttackTypeMetrics
    complexity: Complexity | None


class MetricsResponse(BaseModel):
    models: list[ModelMetrics]


# Sección 9: errores. Estado HTTP de cada código; los de validación del archivo traen su propio
# mensaje. Los de la simulación no tienen estado HTTP, porque llegan como mensaje "error".
ERROR_STATUS = {
    "no_file": 400,
    "file_and_sample": 400,
    "file_too_large": 413,
    "unreadable_file": 400,
    "empty_file": 400,
    "unknown_model": 400,
    "missing_columns": 400,
    "missing_label_column": 400,
    "invalid_ids": 400,
    "invalid_values": 400,
    "invalid_labels": 400,
    "missing_analysis_id": 400,
    "analysis_not_found": 404,
    "flow_not_found": 404,
    "invalid_request": 400,
    "not_found": 404,
    "method_not_allowed": 405,
    "internal_error": 500,
    "invalid_message": None,
    "invalid_speed": None,
}

# Las velocidades escritas como en los botones: "1×, 2× o 4×".
_SPEED_LABELS = [f"{speed}×" for speed in SIMULATION_SPEEDS]

# Mensajes fijos; {nombre} se reemplaza con el valor que se pasa a ApiError.
ERROR_MESSAGES = {
    "no_file": "No se recibió ningún archivo. Selecciona un archivo CSV para analizar.",
    "file_and_sample": "Envía un archivo o pide la muestra de demostración, pero no los dos a la vez.",
    "file_too_large": f"El archivo pesa más de {MAX_UPLOAD_MB} MB, que es el máximo permitido.",
    "unknown_model": "El modelo «{model}» no está disponible. Elige otro en la pantalla Modelos.",
    "missing_analysis_id": "Falta indicar a qué análisis pertenece el flujo.",
    "analysis_not_found": "Este análisis ya no está disponible. Vuelve a cargar el archivo para analizarlo de nuevo.",
    "flow_not_found": "El flujo {id} no está en este análisis.",
    "invalid_request": "El pedido no es válido: revisa el campo {field}.",
    "not_found": "La dirección pedida no existe.",
    "method_not_allowed": "La dirección pedida no acepta este tipo de pedido.",
    "internal_error": "Ocurrió un error inesperado en el servidor. Intenta de nuevo; si se repite, avisa al equipo.",
    "invalid_message": "La simulación recibió un mensaje que no entiende. Reinicia la simulación.",
    "invalid_speed": f"La velocidad debe ser {', '.join(_SPEED_LABELS[:-1])} o {_SPEED_LABELS[-1]}.",
}

# invalid_request cuando el problema no es de un campo, como un formulario dañado.
INVALID_REQUEST_WITHOUT_FIELD = "El pedido no es válido."


class ApiError(Exception):
    """Error de la API con el formato de la sección 9: code, message en español y details."""

    def __init__(self, code, details=None, message=None):
        if message is None:
            message = ERROR_MESSAGES[code].format(**(details or {}))
        super().__init__(message)
        self.code = code
        self.status_code = ERROR_STATUS[code]
        self.message = message
        self.details = details

    def content(self):
        """El cuerpo JSON de la respuesta."""
        return {"error": {"code": self.code, "message": self.message, "details": self.details}}
