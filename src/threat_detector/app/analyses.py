"""Análisis de archivos de flujos: lectura, validación, predicción y guardado en memoria (contrato, secciones 2 a 5)."""

import io
import secrets
import threading
from collections import OrderedDict

import numpy as np
import pandas as pd

from threat_detector.artifacts import detection_rate, false_alarm_rate, severity
from threat_detector.config import DEMO_SAMPLE_CSV, MAX_STORED_ANALYSES
from threat_detector.dataset import (
    ATTACK_CAT,
    CATEGORICAL_COLS,
    ID_COL,
    TARGET,
    TARGET_COLS,
    FlowValidationError,
    check_columns,
    check_not_empty,
    check_values,
    validate_ids,
    validate_labels,
)

# Severidades que cuentan como alerta, en el orden de summary.alerts_by_severity (contrato, sección 4).
ALERT_SEVERITIES = ("critical", "high", "medium", "low")

SAMPLE_PREFIX = "sample-"
UNLABELED_SUFFIX = "-unlabeled"


def python_value(value):
    """Un valor de la tabla como tipo de Python, para escribirlo en JSON; None si la celda está vacía."""
    if pd.isna(value):
        return None
    return value.item() if isinstance(value, np.generic) else value


def _text_values(column):
    """Una columna de texto como lista de Python, con None en las celdas vacías."""
    return column.astype(object).where(column.notna(), None).tolist()


INT32 = np.iinfo(np.int32)
INT64 = np.iinfo(np.int64)


def compact_flows(flows):
    """Copia de los flujos que ocupa menos memoria y conserva los mismos valores.

    El texto (proto, service, state y attack_cat) pasa a category y las columnas enteras a int32
    cuando todos sus valores caben; las demás quedan igual. Es una tabla nueva: no comparte memoria
    con la recibida, que se puede liberar. Con un archivo de 25 MB baja de unos 62 MB a unos 23 MB.
    """
    columns = {}
    for column in flows.columns:
        values = flows[column]
        if column in (*CATEGORICAL_COLS, ATTACK_CAT):
            values = values.astype("category")
        elif values.dtype == np.int64 and values.min() >= INT32.min and values.max() <= INT32.max:
            values = values.astype(np.int32)
        columns[column] = values
    # DataFrame a partir de un diccionario copia los datos.
    return pd.DataFrame(columns, copy=True)


def read_flows(content):
    """Lee los bytes de un CSV de flujos; lanza FlowValidationError (unreadable_file o empty_file) si no se puede.

    Se lee en UTF-8, aceptando la marca BOM con que Excel puede empezar el archivo. Las categóricas
    y attack_cat se leen como texto, para que lleguen tal como vienen (por ejemplo, "-").
    """
    # Un encabezado con punto y coma y sin comas se informa con su propio mensaje. Se revisa antes de
    # leer el resto, porque esos archivos suelen traer también los decimales con coma.
    header = content.split(b"\n", 1)[0]
    if b";" in header and b"," not in header:
        raise FlowValidationError(
            "unreadable_file",
            "El archivo está separado por punto y coma (;), pero debe estar separado por comas, como los CSV de UNSW-NB15. Guárdalo de nuevo con comas y vuelve a cargarlo.",
        )
    unreadable = FlowValidationError(
        "unreadable_file",
        "No se pudo leer el archivo. Revisa que sea un CSV separado por comas, con una fila de encabezado.",
    )
    try:
        flows = pd.read_csv(
            io.BytesIO(content),
            encoding="utf-8-sig",
            dtype={column: str for column in [*CATEGORICAL_COLS, ATTACK_CAT]},
        )
    except pd.errors.EmptyDataError:
        # Sin ningún contenido, ni siquiera el encabezado.
        raise FlowValidationError("empty_file", "El archivo no tiene flujos para analizar.") from None
    except (pd.errors.ParserError, UnicodeDecodeError) as error:
        raise unreadable from error
    # Si todas las filas traen un campo más que el encabezado, pandas usa la primera columna como
    # índice en vez de dar un error: las columnas quedarían corridas. Sin eso, el índice es 0, 1, 2...
    # Si la primera columna valiera justo 0, 1, 2..., no se notaría aquí.
    if not flows.index.equals(pd.RangeIndex(len(flows))):
        raise unreadable
    check_not_empty(flows)
    return flows


def validate_upload(flows, info, use_labels):
    """Valida un archivo para el modelo de info, en el orden de la sección 9; devuelve has_labels.

    Lanza FlowValidationError con el primer problema: missing_columns, missing_label_column,
    invalid_ids, invalid_values o invalid_labels. El archivo trae etiquetas si use_labels es
    verdadero y tiene label y attack_cat; con use_labels falso, las etiquetas no se revisan.
    """
    numeric_cols = info["numeric_cols"]
    check_columns(flows, [ID_COL, *info["categorical_cols"], *numeric_cols])

    present = [column for column in TARGET_COLS if column in flows.columns]
    if use_labels and len(present) == 1:
        missing = next(column for column in TARGET_COLS if column not in present)
        raise FlowValidationError(
            "missing_label_column",
            f"El archivo trae la columna {present[0]} pero no la columna {missing}. "
            "Agrega la columna que falta o analízalo sin etiquetas.",
            {"missing_column": missing},
        )

    validate_ids(flows)
    check_values(flows, numeric_cols)
    has_labels = use_labels and len(present) == len(TARGET_COLS)
    if has_labels:
        validate_labels(flows)
    return has_labels


class Analysis:
    """Un archivo ya predicho con un modelo; arma sus respuestas (secciones 3 a 5) cada vez que se piden."""

    def __init__(self, analysis_id, flows, predictor, has_labels):
        self.analysis_id = analysis_id
        self.predictor = predictor
        self.has_labels = has_labels
        info = predictor.info
        # Solo las columnas que se usan después: id, las del modelo y las etiquetas.
        columns = [ID_COL, *info["categorical_cols"], *info["numeric_cols"], *(TARGET_COLS if has_labels else [])]
        flows = flows[columns].reset_index(drop=True)

        # Se predice con los flujos tal como se leyeron; después se guarda una copia compacta.
        self.attack_probability, self.alerts, self.predicted_attack_cat = predictor.predict(flows)
        self.severities = pd.Categorical([severity(p, info["threshold"]) for p in self.attack_probability.tolist()])
        # Los id ya están validados: son enteros sin repetir, aunque vengan escritos como decimales.
        self.ids = pd.to_numeric(flows[ID_COL]).astype(np.int64).to_numpy()
        # Para buscar un flujo por id: los id ordenados y la posición de cada uno en el archivo.
        self._order = np.argsort(self.ids, kind="stable")
        self._sorted_ids = self.ids[self._order]
        self.true_label = pd.to_numeric(flows[TARGET]).astype(np.int64).to_numpy() if has_labels else None
        self.flows = compact_flows(flows)

    def position(self, flow_id):
        """Posición en el archivo del flujo con ese id, o None si no está en el análisis."""
        if not INT64.min <= flow_id <= INT64.max:
            return None
        index = int(np.searchsorted(self._sorted_ids, flow_id))
        if index < len(self._sorted_ids) and self._sorted_ids[index] == flow_id:
            return int(self._order[index])
        return None

    def flow_responses(self, positions=None):
        """Los flujos predichos de la sección 3, en el orden del archivo; positions elige solo algunos."""
        rows = slice(None) if positions is None else list(positions)
        flows = self.flows.iloc[rows]
        count = len(flows)
        if self.has_labels:
            true_label = self.true_label[rows].tolist()
            true_attack_cat = _text_values(flows[ATTACK_CAT])
        else:
            true_label = true_attack_cat = [None] * count
        fields = {
            "id": self.ids[rows].tolist(),
            "proto": _text_values(flows["proto"]),
            "service": _text_values(flows["service"]),
            "state": _text_values(flows["state"]),
            "attack_probability": self.attack_probability[rows].tolist(),
            "is_alert": self.alerts[rows].tolist(),
            "severity": self.severities[rows].tolist(),
            "predicted_attack_cat": self.predicted_attack_cat[rows].tolist(),
            "true_label": true_label,
            "true_attack_cat": true_attack_cat,
        }
        return [dict(zip(fields, values)) for values in zip(*fields.values())]

    def summary(self):
        """Los indicadores de la consola (sección 4); detección y falsas alarmas son None sin etiquetas."""
        counts = pd.Series(self.severities).value_counts()
        return {
            "total_flows": len(self.flows),
            "alerts": int(self.alerts.sum()),
            "alerts_by_severity": {level: int(counts.get(level, 0)) for level in ALERT_SEVERITIES},
            "detection_rate": detection_rate(self.true_label, self.alerts) if self.has_labels else None,
            "false_alarm_rate": false_alarm_rate(self.true_label, self.alerts) if self.has_labels else None,
        }

    def model_response(self):
        """El modelo del análisis: name, display_name y threshold (secciones 4 y 8)."""
        info = self.predictor.info
        return {"name": info["name"], "display_name": info["display_name"], "threshold": info["threshold"]}

    def response(self):
        """La respuesta de POST /api/predict y de GET /api/analysis/{analysis_id} (sección 4)."""
        return {
            "analysis_id": self.analysis_id,
            "model": self.model_response(),
            "has_labels": self.has_labels,
            "summary": self.summary(),
            "flows": self.flow_responses(),
        }

    def explain(self, flow_id):
        """(flujo predicho, contribuciones) del flujo con ese id (sección 5), o None si no está en el análisis."""
        position = self.position(flow_id)
        if position is None:
            return None
        return self.flow_responses([position])[0], self.predictor.explain(self.flows.iloc[position])


def run_analysis(analysis_id, flows, predictor, has_labels):
    """Predice flujos ya validados con validate_upload y devuelve su Analysis."""
    return Analysis(analysis_id, flows, predictor, has_labels)


def sample_id(model_name, use_labels):
    """analysis_id fijo de la muestra de demostración: sample-<modelo> o sample-<modelo>-unlabeled (sección 2)."""
    return f"{SAMPLE_PREFIX}{model_name}{'' if use_labels else UNLABELED_SUFFIX}"


def parse_sample_id(analysis_id):
    """(model_name, use_labels) de un analysis_id de la muestra, o None si no es de la muestra.

    Los nombres de modelo van en snake_case, sin guiones, así que el sufijo no se confunde con el nombre.
    """
    if not analysis_id.startswith(SAMPLE_PREFIX):
        return None
    name = analysis_id.removeprefix(SAMPLE_PREFIX)
    if name.endswith(UNLABELED_SUFFIX):
        return name.removesuffix(UNLABELED_SUFFIX), False
    return name, True


class AnalysisStore:
    """Análisis guardados en memoria (sección 2).

    Guarda los max_uploaded análisis de archivos subidos más recientes y borra el más antiguo por
    orden de creación; consultar uno no lo renueva. Los de la muestra se guardan aparte, no cuentan
    para ese límite y se regeneran si no están. Un lock protege los diccionarios, porque las rutas
    pueden atenderse en paralelo.
    """

    def __init__(self, max_uploaded=MAX_STORED_ANALYSES):
        self.max_uploaded = max_uploaded
        self._uploaded = OrderedDict()
        self._samples = {}
        self._lock = threading.Lock()

    def new_id(self):
        """analysis_id aleatorio para un archivo subido: 12 caracteres hexadecimales que no estén en uso."""
        with self._lock:
            while True:
                analysis_id = secrets.token_hex(6)
                if analysis_id not in self._uploaded:
                    return analysis_id

    def add(self, analysis):
        """Guarda el análisis de un archivo subido y borra los más antiguos si se pasa del límite."""
        with self._lock:
            self._uploaded[analysis.analysis_id] = analysis
            while len(self._uploaded) > self.max_uploaded:
                self._uploaded.popitem(last=False)

    def get(self, analysis_id):
        """El análisis guardado con ese analysis_id, o None; no regenera la muestra."""
        with self._lock:
            return self._uploaded.get(analysis_id) or self._samples.get(analysis_id)

    def sample(self, predictor, use_labels):
        """El análisis de sample_flows.csv con ese modelo y modo; si no está guardado, lo genera y lo guarda.

        Se genera con las mismas funciones que un archivo subido. Si dos pedidos lo generan a la vez,
        los dos resultados son iguales, porque los modelos son deterministas.
        """
        analysis_id = sample_id(predictor.info["name"], use_labels)
        analysis = self.get(analysis_id)
        if analysis is None:
            flows = read_flows(DEMO_SAMPLE_CSV.read_bytes())
            has_labels = validate_upload(flows, predictor.info, use_labels)
            analysis = run_analysis(analysis_id, flows, predictor, has_labels)
            with self._lock:
                self._samples[analysis_id] = analysis
        return analysis

    def find(self, analysis_id, predictors):
        """El análisis con ese analysis_id; regenera la muestra de un modelo cargado. None si no existe."""
        analysis = self.get(analysis_id)
        if analysis is not None:
            return analysis
        parsed = parse_sample_id(analysis_id)
        if parsed is None or parsed[0] not in predictors:
            return None
        model_name, use_labels = parsed
        return self.sample(predictors[model_name], use_labels)
