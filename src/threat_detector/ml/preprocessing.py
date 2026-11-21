"""Preparación de los flujos antes de entrenar."""

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler

from threat_detector.config import MIN_CATEGORY_FRACTION, RANDOM_STATE, VALIDATION_SIZE
from threat_detector.dataset import ATTACK_CAT, CATEGORICAL_COLS, INPUT_COLS

# Columnas que no son variables de entrada, además de id y las etiquetas (que INPUT_COLS ya excluye).
DROPPED_COLS = [
    "is_ftp_login",     # decisión 4: idéntica a ct_ftp_cmd
    "stcpb", "dtcpb",   # decisión 10: números de secuencia TCP, aleatorios por diseño
    "swin", "dwin",     # decisión 11: la misma información que proto y dpkts
    "tcprtt",           # decisión 12: synack + ackdat
    "is_sm_ips_ports",  # decisión 15: la misma información que proto = arp
]

# Decisión 14: atajo conocido del dataset; el método M3 entrena sin estas columnas.
TTL_COLS = ["sttl", "dttl", "ct_state_ttl"]

# Decisiones 7 y 10: variables asimétricas a las que se aplica log1p, en el orden del archivo.
LOG_COLS = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sload", "dload", "sloss", "dloss",
    "sinpkt", "dinpkt", "sjit", "djit", "dmean", "response_body_len", "ct_srv_src",
    "ct_dst_ltm", "ct_dst_src_ltm", "ct_src_ltm", "ct_srv_dst",
]

# Métodos de preprocesamiento que se comparan con cada modelo; la clave es preprocessing_method
# de model.json.
PREPROCESSING_METHODS = {
    "m1": {"scale": False, "use_ttl": True},  # las decisiones del EDA, sin escalar
    "m2": {"scale": True, "use_ttl": True},   # M1 más estandarización de las numéricas
    "m3": {"scale": True, "use_ttl": False},  # M2 sin las variables de TTL
}


def numeric_input_cols(use_ttl=True):
    """Variables numéricas que recibe el modelo, en el orden del archivo: 32 con TTL y 29 sin TTL."""
    excluded = set(CATEGORICAL_COLS) | set(DROPPED_COLS)
    if not use_ttl:
        excluded |= set(TTL_COLS)
    return [c for c in INPUT_COLS if c not in excluded]


def build_preprocessor(method):
    """Devuelve, sin ajustar, el preprocesador de un método de PREPROCESSING_METHODS.

    Está hecho solo con piezas de scikit-learn, así que se puede guardar con joblib y cargar sin
    importar threat_detector. Recibe los flujos con sus columnas originales, ya validados con
    validate_flows, y devuelve una tabla con las variables listas para el modelo.
    """
    if method not in PREPROCESSING_METHODS:
        raise ValueError(
            f"Método de preprocesamiento desconocido: {method}. "
            f"Usa uno de: {', '.join(PREPROCESSING_METHODS)}."
        )
    settings = PREPROCESSING_METHODS[method]
    numeric_cols = numeric_input_cols(settings["use_ttl"])
    log_cols = [c for c in numeric_cols if c in LOG_COLS]
    plain_cols = [c for c in numeric_cols if c not in LOG_COLS]

    # log1p no aprende nada; el escalado (M2 y M3) va después y aprende media y desviación.
    log_steps = [FunctionTransformer(np.log1p, feature_names_out="one-to-one")]
    plain_step = "passthrough"
    if settings["scale"]:
        log_steps.append(StandardScaler())
        plain_step = StandardScaler()

    categories = OneHotEncoder(
        min_frequency=MIN_CATEGORY_FRACTION,
        handle_unknown="infrequent_if_exist",
        sparse_output=False,
    )
    return ColumnTransformer(
        [
            ("log", make_pipeline(*log_steps), log_cols),
            ("plain", plain_step, plain_cols),
            ("categorical", categories, CATEGORICAL_COLS),
        ],
        remainder="drop",
        verbose_feature_names_out=False,
    ).set_output(transform="pandas")


def flow_pattern_ids(flows):
    """Devuelve un id por flujo; los flujos con los mismos valores en INPUT_COLS comparten el id."""
    # hash_pandas_object resume cada fila en un número de 64 bits. Con index=False el id depende
    # solo de los valores del flujo, no de su posición ni de su id; las etiquetas tampoco cuentan.
    return pd.util.hash_pandas_object(flows[INPUT_COLS], index=False)


def split_train_validation(flows):
    """Separa los flujos en entrenamiento y validación, estratificando por attack_cat.

    Cada grupo de flujos idénticos va completo a una sola de las dos partes. Con la semilla fija
    el resultado es siempre el mismo. Devuelve (train_flows, validation_flows) con todas las
    columnas y el índice original.
    """
    # Se arman 1 / VALIDATION_SIZE partes de tamaño parecido (5 con 0.20); la primera es la validación.
    n_splits = round(1 / VALIDATION_SIZE)
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE)
    train_rows, validation_rows = next(
        splitter.split(flows, flows[ATTACK_CAT], groups=flow_pattern_ids(flows))
    )
    return flows.iloc[train_rows], flows.iloc[validation_rows]
