"""Definición de las columnas de UNSW-NB15 y carga de sus archivos CSV."""

import numpy as np
import pandas as pd

from threat_detector.config import (
    DEMO_MIN_PER_ATTACK,
    DEMO_SAMPLE_CSV,
    DEMO_SAMPLE_SIZE,
    FEATURES_CSV,
    MAX_ERROR_ROWS,
    RANDOM_STATE,
    TEST_CSV,
    TEST_ROWS,
    TRAIN_CSV,
    TRAIN_ROWS,
)

ID_COL = "id"
TARGET = "label"
ATTACK_CAT = "attack_cat"
TARGET_COLS = [TARGET, ATTACK_CAT]

# Valores de attack_cat: el tráfico normal y los 9 tipos de ataque, en el orden del contrato (sección 2).
NORMAL_CAT = "Normal"
ATTACK_TYPES = [
    "Generic", "Exploits", "Fuzzers", "DoS", "Reconnaissance",
    "Analysis", "Backdoor", "Shellcode", "Worms",
]

CATEGORICAL_COLS = ["proto", "service", "state"]

# Las 45 columnas de las particiones, en el orden en que vienen en los archivos.
RAW_COLUMNS = [
    "id", "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes",
    "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt",
    "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat",
    "smean", "dmean", "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl",
    "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst",
    "is_sm_ips_ports", "attack_cat", "label",
]

# Las 42 variables de entrada tal como vienen en el archivo: todas menos el identificador y las
# etiquetas. Todavía incluye las que descarta el preprocesamiento.
INPUT_COLS = [c for c in RAW_COLUMNS if c != ID_COL and c not in TARGET_COLS]

# Nombre en NUSW-NB15_features.csv (en minúsculas) -> nombre en las particiones.
DESCRIPTION_RENAMES = {
    "smeansz": "smean",
    "dmeansz": "dmean",
    "sintpkt": "sinpkt",
    "dintpkt": "dinpkt",
    "res_bdy_len": "response_body_len",
    "ct_src_ ltm": "ct_src_ltm",
}


def load_flows(path, expected_rows):
    """Lee un CSV de flujos y verifica sus columnas y filas; lanza un error claro si no coinciden."""
    if not path.is_file():
        raise FileNotFoundError(
            f"No se encontró el archivo {path.name}. Revisa data/README.md para saber cómo descargarlo."
        )

    flows = pd.read_csv(path)

    missing = [c for c in RAW_COLUMNS if c not in flows.columns]
    extra = [c for c in flows.columns if c not in RAW_COLUMNS]
    if missing or extra:
        raise ValueError(f"{path.name} no tiene las columnas esperadas. Faltan: {missing}. Sobran: {extra}.")

    if len(flows) != expected_rows:
        raise ValueError(
            f"{path.name} tiene {len(flows):,} filas y se esperaban {expected_rows:,}. "
            "La descarga puede estar incompleta o ser otra versión del dataset."
        )
    return flows


class FlowValidationError(ValueError):
    """Un archivo de flujos no se puede analizar; code y details siguen la sección 9 del contrato."""

    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code = code
        self.details = details


def _bad_rows(bad):
    """Primeras líneas del archivo con problemas (como máximo MAX_ERROR_ROWS) y total de filas con problemas.

    bad trae un valor por flujo, en el orden del archivo. Se cuenta por posición, no por el índice
    de pandas: posición + 2 = línea del archivo (el encabezado es la línea 1).
    """
    bad = np.asarray(bad, dtype=bool)
    lines = (np.flatnonzero(bad)[:MAX_ERROR_ROWS] + 2).tolist()
    return lines, int(bad.sum())


def _numbers(values):
    """Convierte una columna a números; lo que no es un número queda vacío (la columna recibida no cambia)."""
    return pd.to_numeric(values, errors="coerce")


def check_not_empty(flows):
    """Lanza FlowValidationError (empty_file) si no hay ningún flujo."""
    if len(flows) == 0:
        raise FlowValidationError("empty_file", "El archivo no tiene flujos para analizar.")


def check_columns(flows, required):
    """Lanza FlowValidationError (missing_columns) con todas las columnas de required que faltan."""
    missing = [c for c in required if c not in flows.columns]
    if missing:
        raise FlowValidationError(
            "missing_columns",
            f"Al archivo le faltan columnas obligatorias: {', '.join(missing)}.",
            {"missing_columns": missing},
        )


def check_values(flows, numeric_cols):
    """Lanza FlowValidationError (invalid_values) si una variable numérica está vacía, no es un número o es negativa.

    Primero revisa los vacíos y los que no son números; solo si no hay, los negativos. Los
    infinitos también cuentan como "no numéricos", porque no son una medida posible.
    """
    numbers = flows[numeric_cols].apply(_numbers)
    problems = (
        ("empty_or_not_numeric", "vacíos o no numéricos", ~np.isfinite(numbers)),
        ("negative", "negativos", numbers < 0),
    )
    for reason, text, mask in problems:
        lines, total = _bad_rows(mask.any(axis=1))
        if total:
            columns = mask.columns[mask.any()].tolist()
            raise FlowValidationError(
                "invalid_values",
                f"Hay {total} flujo(s) con valores {text} en las columnas {', '.join(columns)}. "
                f"Primeras filas afectadas: {', '.join(map(str, lines))}.",
                {"reason": reason, "columns": columns, "rows": lines, "total_rows": total},
            )


def validate_flows(flows, numeric_cols, categorical_cols):
    """Comprueba que los flujos se pueden preparar; si no, lanza FlowValidationError con un mensaje en español.

    Revisa, en este orden: que haya al menos un flujo, que estén todas las columnas que usa el
    modelo, que las numéricas no tengan valores vacíos o que no son números, y que no sean
    negativas. Las filas se numeran como líneas del archivo (encabezado = línea 1), suponiendo
    que los flujos están en el orden del archivo. FlowValidationError es un ValueError.
    """
    check_not_empty(flows)
    check_columns(flows, [*numeric_cols, *categorical_cols])
    check_values(flows, numeric_cols)


def validate_ids(flows):
    """Lanza FlowValidationError (invalid_ids) si algún id está vacío, no es un número entero o se repite.

    Se comparan como números: 3.0 es el id 3, y 1 y 1.0 son el mismo id. Si un id se repite, se
    marcan todas sus filas, para que se vean juntas.
    """
    ids = _numbers(flows[ID_COL])
    not_integer = ~np.isfinite(ids) | (ids != np.floor(ids))
    repeated = ids.duplicated(keep=False) & ~not_integer
    lines, total = _bad_rows(not_integer | repeated)
    if total:
        raise FlowValidationError(
            "invalid_ids",
            f"Hay {total} flujo(s) con un id vacío, que no es un número entero o que está repetido. "
            f"Primeras filas afectadas: {', '.join(map(str, lines))}.",
            {"rows": lines, "total_rows": total},
        )


def validate_labels(flows):
    """Lanza FlowValidationError (invalid_labels) si label no es 0 o 1, o attack_cat no es uno de los 10 valores.

    label se compara como número: 0.0 y 1.0 valen, porque pandas lee la columna como decimal cuando
    tiene una celda vacía. Una celda vacía no vale. Se revisa primero label y después attack_cat, y
    el error trae solo la primera columna que falla.
    """
    checks = (
        (TARGET, ~_numbers(flows[TARGET]).isin([0, 1])),
        (ATTACK_CAT, ~flows[ATTACK_CAT].isin([NORMAL_CAT, *ATTACK_TYPES])),
    )
    for column, bad in checks:
        lines, total = _bad_rows(bad)
        if total:
            raise FlowValidationError(
                "invalid_labels",
                f"Hay {total} flujo(s) con etiquetas no válidas en la columna {column}. "
                f"Primeras filas afectadas: {', '.join(map(str, lines))}.",
                {"column": column, "rows": lines, "total_rows": total},
            )


def load_train():
    """Carga la partición oficial de entrenamiento; de aquí salen entrenamiento y validación."""
    return load_flows(TRAIN_CSV, TRAIN_ROWS)


def load_test():
    """Carga la partición oficial de prueba, que se usa para evaluar una sola vez, al final."""
    return load_flows(TEST_CSV, TEST_ROWS)


def load_feature_descriptions():
    """Carga la descripción de las variables, con los nombres escritos como en las particiones."""
    if not FEATURES_CSV.is_file():
        raise FileNotFoundError(
            f"No se encontró el archivo {FEATURES_CSV.name}. Revisa data/README.md para saber cómo descargarlo."
        )

    # cp1252: el archivo trae el apóstrofo como el byte 0x92, que no es válido en UTF-8.
    descriptions = pd.read_csv(FEATURES_CSV, encoding="cp1252")
    descriptions.columns = descriptions.columns.str.strip().str.lower()
    descriptions["name"] = descriptions["name"].str.strip().str.lower().replace(DESCRIPTION_RENAMES)
    return descriptions


def make_demo_sample(test_flows):
    """Elige los flujos de la muestra de demostración a partir del conjunto de prueba, sin guardar nada.

    Toma DEMO_MIN_PER_ATTACK flujos de cada tipo de ataque y completa DEMO_SAMPLE_SIZE con flujos
    al azar, repartidos entre las clases de attack_cat en la misma proporción que en la prueba.
    Devuelve las filas barajadas, con las 45 columnas originales; con la semilla fija sale siempre igual.
    """
    # 1. El mínimo de cada tipo de ataque (label = 1), para que todos aparezcan en la muestra.
    attacks = test_flows[test_flows[TARGET] == 1]
    minimum = attacks.groupby(ATTACK_CAT).sample(n=DEMO_MIN_PER_ATTACK, random_state=RANDOM_STATE)

    # 2. Cuántos flujos más le tocan a cada clase según su proporción en la prueba. Se redondea
    # hacia abajo y los que faltan van a las clases con la mayor parte decimal (mayor resto),
    # para que la suma dé exactamente DEMO_SAMPLE_SIZE.
    remaining = DEMO_SAMPLE_SIZE - len(minimum)
    shares = test_flows[ATTACK_CAT].value_counts(normalize=True) * remaining
    quotas = shares.astype(int)
    leftover = remaining - quotas.sum()
    quotas[(shares - quotas).nlargest(leftover).index] += 1

    # 3. Esos flujos se eligen al azar entre los que no quedaron en el mínimo.
    rest = test_flows.drop(minimum.index)
    extra = [
        rest[rest[ATTACK_CAT] == attack_cat].sample(n=quota, random_state=RANDOM_STATE)
        for attack_cat, quota in quotas.items()
        if quota > 0
    ]

    # 4. Se barajan: la prueba trae muchos flujos de la misma clase seguidos, y la simulación los
    # reproduce en el orden del archivo.
    sample = pd.concat([minimum, *extra]).sample(frac=1, random_state=RANDOM_STATE)
    return sample[RAW_COLUMNS].reset_index(drop=True)


def write_demo_sample():
    """Genera sample_flows.csv, la muestra de demostración de la app, a partir del conjunto de prueba.

    Se ejecuta desde la terminal con el comando que documenta data/README.md.
    """
    sample = make_demo_sample(load_test())
    # Sin el índice de pandas, para que el archivo tenga las mismas 45 columnas que uno que suba el usuario.
    sample.to_csv(DEMO_SAMPLE_CSV, index=False)
    print(f"Muestra guardada en {DEMO_SAMPLE_CSV.name}: {len(sample)} flujos.")
