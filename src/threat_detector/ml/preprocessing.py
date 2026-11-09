"""Preparación de los flujos antes de entrenar."""

import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from threat_detector.config import RANDOM_STATE, VALIDATION_SIZE
from threat_detector.dataset import ATTACK_CAT, INPUT_COLS


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
