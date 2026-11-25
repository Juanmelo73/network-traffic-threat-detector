"""Búsqueda de modelos y exportación de los modelos entrenados a artifacts/ (contrato, secciones 10 a 12)."""

import csv
import json
import math
import os
import platform
import re
import warnings
from copy import deepcopy
from datetime import datetime, timezone
from io import BytesIO, StringIO
from pathlib import Path
from time import perf_counter

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import ParameterGrid
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.class_weight import compute_sample_weight

from threat_detector.artifacts import (
    DETECTOR_TYPES,
    PIPELINE_STEPS,
    attack_cat_from_proba,
    attack_probability_from_proba,
    check_model,
    check_model_info,
    load_model,
    predict_flows,
    read_model_info,
    read_registry,
)
from threat_detector.config import (
    ARTIFACTS_DIR,
    BYTES_PER_MB,
    MAX_MODEL_SIZE_MB,
    MODEL_JOBLIB,
    MODEL_SEARCH_CSV,
    MODEL_SEARCH_DIR,
    OOB_CSV,
    MODEL_JSON,
    MODELS_DIR,
    RANDOM_STATE,
    REGISTRY_PATH,
    SCORE_TIE_TOLERANCE,
    TEST_PER_TYPE_CSV,
    TEST_RESULTS_CSV,
)
from threat_detector.dataset import (
    ATTACK_CAT,
    ATTACK_TYPES,
    CATEGORICAL_COLS,
    INPUT_COLS,
    TARGET,
    load_test,
    load_train,
    validate_flows,
    validate_labels,
)
from threat_detector.ml.evaluation import (
    attack_type_metrics,
    compute_threshold,
    detection_metrics,
    threshold_rule,
)
from threat_detector.ml.preprocessing import (
    LOG_COLS,
    PREPROCESSING_METHODS,
    build_preprocessor,
    numeric_input_cols,
    split_train_validation,
)

# Familias de modelos de la búsqueda, todas de scikit-learn. Este orden también desempata al
# final, cuando dos combinaciones quedan iguales en todos los criterios.
MODEL_FAMILIES = (
    "dummy",
    "logistic_regression",
    "decision_tree",
    "random_forest",
    "extra_trees",
    "hist_gradient_boosting",
    "gaussian_nb",
    "mlp",
)

# Ensambles: crecen por bloques hasta el tope, se mide en validación la métrica con la que se elige
# su tarea (PR-AUC o F1 macro) en cada bloque y se guarda el tamaño con la mejor (best_iteration).
# No se corta antes: así ninguna familia queda en desventaja por una parada prematura.
TREE_COUNT_STEP = 25
BOOSTING_ITERATION_STEP = 10
# Topes: los valores por defecto de scikit-learn (n_estimators=100 y max_iter=100).
MAX_TREE_COUNT = 100
MAX_BOOSTING_ITERATIONS = 100
# El valor por defecto de MLPClassifier.
MLP_MAX_ITER = 200

# Versión de la búsqueda; se guarda en cada fila. Se sube cada vez que cambia algo que afecta los
# resultados (fit_candidate, las métricas o los datos), para que run_search no mezcle filas de
# versiones distintas en el mismo archivo.
SEARCH_VERSION = 3

# Tareas de la búsqueda. Cada una tiene su propio pipeline, sus hiperparámetros y su fila de
# resultados: "detector" (label, todos los flujos) y "attack_type" (attack_cat, solo ataques).
TASKS = ("detector", "attack_type")
# Los hiperparámetros se nombran como en el grid de un Pipeline con el paso "model".
PARAM_PREFIX = "model__"
# Única clave de params sin el prefijo: pesos por flujo que se pasan a fit, para las familias sin
# class_weight (MLP). Sus valores: None (sin pesos) o "balanced" (compute_sample_weight).
SAMPLE_WEIGHT_PARAM = "sample_weight"
SAMPLE_WEIGHT_VALUES = (None, "balanced")
# Parámetros que no cambian lo que aprende el modelo, o que maneja la búsqueda: no se anotan en
# fixed_params como excepciones a los valores por defecto.
MECHANICAL_PARAMS = {"random_state", "n_jobs", "warm_start", "verbose"}
# Comienzo del aviso de scikit-learn sobre class_weight "balanced" con warm_start (ver _fit_task).
WARM_START_WEIGHTS_WARNING = 'class_weight presets "balanced" or "balanced_subsample"'
# Métricas de cada tipo de ataque en la fila del clasificador.
TYPE_METRICS = ("precision", "recall", "f1", "support")

# Columnas de una fila de resultados, en este orden. Las de la otra tarea quedan vacías.
RESULT_COLUMNS = [
    # Identificación
    "run_at", "search_version", "phase", "task", "family", "requested_method", "method", "params", "fixed_params",
    "sklearn_version", "train_flows", "validation_flows",
    # Diagnóstico
    "best_iteration", "converged", "convergence_warnings", "mlp_scaled_fallback",
    # Costo
    "search_seconds", "predict_ms_per_1000_flows", "model_size_mb",
    # Detector
    "pr_auc", "roc_auc", "threshold", "detection_rate", "false_alarm_rate", "precision", "f1",
    "tp", "fp", "tn", "fn", "train_pr_auc", "train_false_alarm_rate",
    # Clasificador de tipos
    "macro_f1", "min_type_f1", "train_macro_f1",
    *[f"{attack_cat.lower()}_{metric}" for attack_cat in ATTACK_TYPES for metric in TYPE_METRICS],
    "type_confusion",
]

# Campos de complexity que se miden al entrenar; model_size_mb lo agrega export_model al guardar.
COMPLEXITY_INPUTS = {
    "training_seconds",
    "training_flows",
    "prediction_ms_per_1000_flows",
    "hardware",
}

# name de un modelo: minúsculas y snake_case, porque también es el nombre de su carpeta (contrato, sección 2).
MODEL_NAME_PATTERN = r"[a-z][a-z0-9_]*"
# Nombre del modelo simulado, que se escribe a mano: ml/ nunca lo exporta ni lo sobrescribe.
MOCK_MODEL_NAME = "mock"

# Sufijo del archivo temporal con que se escribe registry.json antes de reemplazarlo.
TEMP_SUFFIX = ".tmp"


def _candidate_estimator(name):
    """Crea el estimador de una familia, con su semilla y los valores fijos de la búsqueda."""
    if name == "dummy":
        return DummyClassifier(random_state=RANDOM_STATE)
    if name == "logistic_regression":
        # Excepción a los valores por defecto (max_iter=100): con 100 iteraciones no converge; con
        # M2, el clasificador de tipos necesitó 477 (columna best_iteration de search_results.csv).
        # Queda anotada en fixed_params de cada fila.
        return LogisticRegression(max_iter=1000, random_state=RANDOM_STATE)
    if name == "decision_tree":
        return DecisionTreeClassifier(random_state=RANDOM_STATE)
    if name == "random_forest":
        return RandomForestClassifier(
            n_estimators=TREE_COUNT_STEP,
            n_jobs=-1,
            random_state=RANDOM_STATE,
            warm_start=True,
        )
    if name == "extra_trees":
        return ExtraTreesClassifier(
            n_estimators=TREE_COUNT_STEP,
            n_jobs=-1,
            random_state=RANDOM_STATE,
            warm_start=True,
        )
    if name == "hist_gradient_boosting":
        # Con el valor por defecto ("auto") y más de 10.000 flujos, scikit-learn activa su propio
        # early stopping. Se apaga, porque aquí la parada la decide la validación agrupada.
        return HistGradientBoostingClassifier(
            max_iter=BOOSTING_ITERATION_STEP,
            random_state=RANDOM_STATE,
            warm_start=True,
            early_stopping=False,
        )
    if name == "gaussian_nb":
        return GaussianNB()
    if name == "mlp":
        # early_stopping=True (decidido): aparta validation_fraction (10 %) del entrenamiento,
        # estratificado pero sin agrupar flujos idénticos. Las métricas de la fila salen de la
        # validación agrupada.
        return MLPClassifier(
            max_iter=MLP_MAX_ITER,
            early_stopping=True,
            random_state=RANDOM_STATE,
        )
    raise ValueError(
        f"Modelo desconocido: {name}. Usa uno de: {', '.join(MODEL_FAMILIES)}."
    )


def _growth(family, params=None):
    """(parámetro, paso, tope) de un ensamble que crece por bloques, o None si se ajusta de una vez.

    Si params trae el parámetro que crece (model__n_estimators o model__max_iter), ese valor es el
    tope; debe ser un múltiplo del paso. Si no, el tope es el valor por defecto de scikit-learn.
    """
    if family in ("random_forest", "extra_trees"):
        parameter, step, limit = "n_estimators", TREE_COUNT_STEP, MAX_TREE_COUNT
    elif family == "hist_gradient_boosting":
        parameter, step, limit = "max_iter", BOOSTING_ITERATION_STEP, MAX_BOOSTING_ITERATIONS
    else:
        return None
    limit = (params or {}).get(PARAM_PREFIX + parameter, limit)
    if not isinstance(limit, int) or limit < step or limit % step:
        raise ValueError(
            f"El tope de {PARAM_PREFIX}{parameter} debe ser un múltiplo de {step} (se crece de "
            f"{step} en {step}); se recibió {limit}."
        )
    return parameter, step, limit


def _model_params(params):
    """Los hiperparámetros del estimador, sin el prefijo model__ y sin sample_weight, que va a fit."""
    wrong = [name for name in params if name != SAMPLE_WEIGHT_PARAM and not name.startswith(PARAM_PREFIX)]
    if wrong:
        raise ValueError(
            f"Los hiperparámetros deben empezar con {PARAM_PREFIX} (por ejemplo, model__C), salvo "
            f"{SAMPLE_WEIGHT_PARAM}: {', '.join(wrong)}."
        )
    if params.get(SAMPLE_WEIGHT_PARAM) not in SAMPLE_WEIGHT_VALUES:
        raise ValueError(
            f"{SAMPLE_WEIGHT_PARAM} debe ser None o \"balanced\"; se recibió {params[SAMPLE_WEIGHT_PARAM]}."
        )
    return {
        name.removeprefix(PARAM_PREFIX): value
        for name, value in params.items()
        if name != SAMPLE_WEIGHT_PARAM
    }


def fixed_params(family, params):
    """Valores fijos de la búsqueda que no son los de scikit-learn, como {"max_iter": 1000}.

    No cuenta los hiperparámetros buscados, los de MECHANICAL_PARAMS ni el que crece por bloques.
    """
    estimator = _candidate_estimator(family)
    defaults = type(estimator)().get_params()
    growth = _growth(family, params)
    skipped = MECHANICAL_PARAMS | set(_model_params(params)) | ({growth[0]} if growth else set())
    return {
        name: value
        for name, value in sorted(estimator.get_params().items())
        if name not in skipped and value != defaults[name]
    }


def _task_data(task, flows):
    """(variables, objetivo) de una tarea: el detector usa todos los flujos y label; el clasificador, solo los ataques y attack_cat."""
    if task == "detector":
        return flows[INPUT_COLS], flows[TARGET].to_numpy()
    attacks = flows[flows[TARGET] == 1]
    return attacks[INPUT_COLS], attacks[ATTACK_CAT].to_numpy()


def _task_metrics(task, estimator, features, target):
    """Métricas de validación de una tarea y su puntaje de selección: PR-AUC o F1 macro.

    features ya pasó por el preprocesador. El detector usa el umbral de compute_threshold y
    detection_metrics; el clasificador, attack_type_metrics sobre todos los ataques recibidos.
    """
    proba = estimator.predict_proba(features)
    if task == "detector":
        attack_probability = attack_probability_from_proba(proba, estimator.classes_, "binary")
        threshold = compute_threshold(target, attack_probability)
        detection = detection_metrics(target, attack_probability, threshold)
        metrics = {
            "threshold": threshold,
            **{name: detection[name] for name in (
                "pr_auc", "roc_auc", "detection_rate", "false_alarm_rate", "precision", "f1",
            )},
            **detection["confusion"],
        }
        return metrics, detection["pr_auc"]

    predicted = attack_cat_from_proba(proba, estimator.classes_)
    types = attack_type_metrics(target, predicted, np.ones(len(target), dtype=bool))
    f1_values = [c["f1"] for c in types["per_class"] if c["f1"] is not None]
    metrics = {
        "macro_f1": types["macro_f1"],
        "min_type_f1": min(f1_values) if f1_values else None,
        "type_confusion": json.dumps(types["confusion"]["matrix"]),
    }
    for c in types["per_class"]:
        for metric in TYPE_METRICS:
            metrics[f"{c['attack_cat'].lower()}_{metric}"] = c[metric]
    return metrics, types["macro_f1"]


def _train_metrics(task, estimator, features, target, validation_metrics):
    """Métricas en la parte de entrenamiento, para compararlas con las de validación.

    Detector: PR-AUC y tasa de falsas alarmas con el umbral calculado en validación, el que usaría
    la app. Clasificador: F1 macro sobre los ataques de entrenamiento.
    """
    proba = estimator.predict_proba(features)
    if task == "detector":
        attack_probability = attack_probability_from_proba(proba, estimator.classes_, "binary")
        detection = detection_metrics(target, attack_probability, validation_metrics["threshold"])
        return {"train_pr_auc": detection["pr_auc"], "train_false_alarm_rate": detection["false_alarm_rate"]}
    predicted = attack_cat_from_proba(proba, estimator.classes_)
    types = attack_type_metrics(target, predicted, np.ones(len(target), dtype=bool))
    return {"train_macro_f1": types["macro_f1"]}


def _iterations(estimator):
    """Iteraciones que usó un estimador iterativo (n_iter_), o None si no tiene."""
    n_iter = getattr(estimator, "n_iter_", None)
    return None if n_iter is None else int(np.max(n_iter))


def _fit_task(task, family, method, params, train_flows, validation_flows):
    """Ajusta el pipeline de una tarea con un método. Devuelve (pipeline, diagnóstico, métricas)."""
    train_inputs, train_target = _task_data(task, train_flows)
    validation_inputs, validation_target = _task_data(task, validation_flows)

    # El preprocesador se ajusta con todos los flujos de entrenamiento, también en el
    # clasificador, que después aprende solo con los ataques. Así los dos pipelines conservan las
    # mismas categorías (ajustado solo con ataques perdería, por ejemplo, proto_arp y service_ssh).
    preprocessor = build_preprocessor(method).fit(train_flows[INPUT_COLS])
    train_features = preprocessor.transform(train_inputs)
    validation_features = preprocessor.transform(validation_inputs)

    estimator = _candidate_estimator(family)
    estimator.set_params(**_model_params(params))
    growth = _growth(family, params)
    # Pesos por flujo para las familias sin class_weight: cada clase pesa lo mismo en total.
    fit_params = {}
    if params.get(SAMPLE_WEIGHT_PARAM) == "balanced":
        fit_params["sample_weight"] = compute_sample_weight("balanced", train_target)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ConvergenceWarning)
        if growth is None:
            estimator.fit(train_features, train_target, **fit_params)
            metrics, _ = _task_metrics(task, estimator, validation_features, validation_target)
            best, best_iteration = estimator, _iterations(estimator)
        else:
            # Se mide cada bloque hasta el tope y se guarda el de mejor puntaje de validación; si
            # dos tamaños empatan, el menor. Crecer por bloques da los mismos árboles que entrenar
            # de una vez con ese tamaño.
            parameter, step, limit = growth
            best, best_iteration, best_score = None, None, -np.inf
            for size in range(step, limit + 1, step):
                estimator.set_params(**{parameter: size}).fit(train_features, train_target, **fit_params)
                size_metrics, score = _task_metrics(
                    task, estimator, validation_features, validation_target
                )
                if score > best_score:
                    best, best_iteration, best_score = deepcopy(estimator), size, score
                    metrics = size_metrics
            # El modelo guardado se comporta como uno entrenado de una vez.
            best.set_params(warm_start=False)

    # record=True captura todos los avisos: los de convergencia se anotan en la fila y los demás
    # se vuelven a emitir, para no esconderlos. La excepción es el aviso de scikit-learn sobre
    # class_weight "balanced" con warm_start, que solo aplica si los datos cambian entre ajustes;
    # aquí cada bloque usa los mismos datos (tests/test_training.py lo comprueba).
    convergence_warnings = []
    for item in caught:
        if issubclass(item.category, ConvergenceWarning):
            convergence_warnings.append(str(item.message))
        elif not str(item.message).startswith(WARM_START_WEIGHTS_WARNING):
            warnings.warn_explicit(item.message, item.category, item.filename, item.lineno)

    metrics.update(_train_metrics(task, best, train_features, train_target, metrics))
    pipeline = Pipeline([("preprocessor", preprocessor), ("model", best)])
    diagnosis = {
        "best_iteration": best_iteration,
        "convergence_warnings": convergence_warnings,
    }
    return pipeline, diagnosis, metrics


def fit_candidate(phase, task, family, method, params, train_flows, validation_flows):
    """Entrena una combinación para una tarea y la mide en validación. Devuelve (pipeline, fila).

    task es "detector" o "attack_type"; params, los hiperparámetros con el prefijo model__. La
    fila trae exactamente RESULT_COLUMNS; las columnas de la otra tarea quedan en None. Si MLP no
    converge con M1, se vuelve a entrenar con M2 (decidido): method dice el método final y
    convergence_warnings trae los avisos de los dos intentos. converged es True si el ajuste final
    no dio avisos de convergencia; en los modelos que no iteran siempre es True.
    """
    if task not in TASKS:
        raise ValueError(f"Tarea desconocida: {task}. Usa una de: {', '.join(TASKS)}.")
    started = perf_counter()
    pipeline, diagnosis, metrics = _fit_task(
        task, family, method, params, train_flows, validation_flows
    )
    all_warnings = list(diagnosis["convergence_warnings"])
    actual_method, fallback = method, False
    if family == "mlp" and method == "m1" and diagnosis["convergence_warnings"]:
        actual_method, fallback = "m2", True
        pipeline, diagnosis, metrics = _fit_task(
            task, family, actual_method, params, train_flows, validation_flows
        )
        all_warnings += diagnosis["convergence_warnings"]
    search_seconds = perf_counter() - started

    # Costo del pipeline elegido: una pasada de predicción sobre la validación de su tarea, con
    # la preparación incluida, y su tamaño serializado sin compresión, como lo guarda export_model.
    validation_inputs, _ = _task_data(task, validation_flows)
    predict_started = perf_counter()
    pipeline.predict_proba(validation_inputs)
    predict_ms = (perf_counter() - predict_started) * 1000
    serialized = BytesIO()
    joblib.dump(pipeline, serialized)

    row = dict.fromkeys(RESULT_COLUMNS)
    row.update({
        "run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "search_version": SEARCH_VERSION,
        "phase": phase,
        "task": task,
        "family": family,
        "requested_method": method,
        "method": actual_method,
        "params": json.dumps(params, sort_keys=True),
        "fixed_params": json.dumps(fixed_params(family, params), sort_keys=True),
        "sklearn_version": sklearn.__version__,
        "train_flows": len(_task_data(task, train_flows)[0]),
        "validation_flows": len(validation_inputs),
        "best_iteration": diagnosis["best_iteration"],
        "converged": not diagnosis["convergence_warnings"],
        "convergence_warnings": " | ".join(all_warnings) or None,
        "mlp_scaled_fallback": fallback,
        "search_seconds": search_seconds,
        "predict_ms_per_1000_flows": predict_ms / len(validation_inputs) * 1000,
        "model_size_mb": serialized.tell() / BYTES_PER_MB,
        **metrics,
    })
    return pipeline, row


# Columnas que deben coincidir entre las filas guardadas y la corrida actual para poder reanudar.
RESUME_COLUMNS = ("search_version", "sklearn_version", "train_flows", "validation_flows")


def check_search_data(train_flows, validation_flows):
    """Comprueba una sola vez los datos de la búsqueda; si algo falla, lanza ValueError en español.

    Las dos partes deben ser flujos válidos con etiquetas válidas y tener flujos normales y
    ataques, y el entrenamiento debe traer los 9 tipos de ataque.
    """
    for flows in (train_flows, validation_flows):
        validate_flows(flows, numeric_input_cols(), CATEGORICAL_COLS)
        validate_labels(flows)
    for name, flows in (("El entrenamiento", train_flows), ("La validación", validation_flows)):
        if set(flows[TARGET].astype(int)) != {0, 1}:
            raise ValueError(f"{name} debe tener flujos normales y ataques.")
    present = set(train_flows.loc[train_flows[TARGET] == 1, ATTACK_CAT])
    missing = [attack_cat for attack_cat in ATTACK_TYPES if attack_cat not in present]
    if missing:
        raise ValueError(
            f"El entrenamiento no contiene estos tipos de ataque: {', '.join(missing)}."
        )


def _candidate_key(phase, task, family, method, params):
    """Clave de un candidato en el archivo de resultados; params se escribe como en la fila."""
    return (str(phase), task, family, method, json.dumps(params, sort_keys=True))


def _read_saved_rows(results_path):
    """Filas ya guardadas, como diccionarios de textos. Lanza ValueError si el archivo no es confiable."""
    if not results_path.is_file() or results_path.stat().st_size == 0:
        return []
    text = results_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    # Cada fila se escribe completa, con su salto de línea al final. Si falta, la búsqueda se
    # cortó mientras escribía y esa fila no se puede usar.
    if not text.endswith("\n"):
        raise ValueError(
            f"La última línea de {results_path} (la {len(lines)}) está incompleta: la búsqueda se "
            "interrumpió mientras la escribía. Borra esa línea y vuelve a ejecutar la búsqueda."
        )
    reader = csv.reader(StringIO(text))
    header = next(reader)
    if header != RESULT_COLUMNS:
        raise ValueError(
            f"{results_path} tiene otras columnas que las de esta búsqueda (quizá es de un formato "
            "anterior). Usa otro archivo de resultados para no mezclarlos."
        )
    rows = []
    for line_number, values in enumerate(reader, start=2):
        if len(values) != len(RESULT_COLUMNS):
            raise ValueError(
                f"La línea {line_number} de {results_path} tiene {len(values)} valores y deberían "
                f"ser {len(RESULT_COLUMNS)}. Revisa esa línea antes de seguir."
            )
        rows.append(dict(zip(RESULT_COLUMNS, values)))
    return rows


def _check_same_run(saved_rows, train_flows, validation_flows, results_path):
    """Lanza ValueError si las filas guardadas no son de la misma versión, scikit-learn y datos."""
    expected = {
        task: {
            "search_version": str(SEARCH_VERSION),
            "sklearn_version": sklearn.__version__,
            "train_flows": str(len(_task_data(task, train_flows)[0])),
            "validation_flows": str(len(_task_data(task, validation_flows)[0])),
        }
        for task in TASKS
    }
    for row in saved_rows:
        for column in RESUME_COLUMNS:
            current = expected[row["task"]][column]
            if row[column] != current:
                raise ValueError(
                    f"No se mezclan resultados: las filas de {results_path} tienen {column} = "
                    f"{row[column]} ({row['task']}) y esta corrida tiene {current}. Usa otro "
                    "archivo de resultados o vuelve a la versión, los datos o la versión de "
                    "scikit-learn con que se calcularon."
                )


def _append_row(results_path, row, with_header):
    """Agrega una fila completa al CSV en una sola escritura y la fuerza al disco."""
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=RESULT_COLUMNS, lineterminator="\n")
    if with_header:
        writer.writeheader()
    writer.writerow(row)
    with results_path.open("a", encoding="utf-8", newline="") as file:
        file.write(buffer.getvalue())
        file.flush()
        os.fsync(file.fileno())


def run_search(candidates, train_flows, validation_flows, results_path=MODEL_SEARCH_CSV, verbose=False):
    """Entrena y mide en validación cada candidato, guardando cada fila apenas termina.

    candidates es una lista de (phase, task, family, method, params), como los recibe
    fit_candidate. Si results_path ya tiene filas, se saltan los candidatos que ya están, así que
    una búsqueda interrumpida sigue donde quedó; antes se comprueba que esas filas son de la misma
    SEARCH_VERSION, versión de scikit-learn y cantidad de flujos. Los modelos no se guardan: el
    entrenamiento final los vuelve a entrenar desde su fila. Devuelve todas las filas del archivo
    como DataFrame.
    """
    check_search_data(train_flows, validation_flows)
    saved_rows = _read_saved_rows(results_path)
    _check_same_run(saved_rows, train_flows, validation_flows, results_path)

    done = {
        (row["phase"], row["task"], row["family"], row["requested_method"], row["params"])
        for row in saved_rows
    }
    pending = []
    for candidate in candidates:
        key = _candidate_key(*candidate)
        if key not in done:
            done.add(key)
            pending.append(candidate)
    if verbose:
        print(f"Candidatos: {len(candidates)}; ya guardados: {len(candidates) - len(pending)}; por entrenar: {len(pending)}.")

    results_path.parent.mkdir(parents=True, exist_ok=True)
    with_header = not saved_rows and not (results_path.is_file() and results_path.stat().st_size)
    for number, (phase, task, family, method, params) in enumerate(pending, start=1):
        _, row = fit_candidate(phase, task, family, method, params, train_flows, validation_flows)
        _append_row(results_path, row, with_header)
        with_header = False
        if verbose:
            score = f"PR-AUC {row['pr_auc']:.4f}" if task == "detector" else f"F1 macro {row['macro_f1']:.4f}"
            print(
                f"[{number}/{len(pending)}] {task}, {family}, {row['method']}, {row['params']}: "
                f"{score}; {row['search_seconds']:.1f} s; {row['model_size_mb']:.2f} MB",
                flush=True,
            )
    return read_search_results(results_path)


def read_search_results(results_path=MODEL_SEARCH_CSV):
    """La tabla de resultados como DataFrame; vacía, con RESULT_COLUMNS, si el archivo no existe.

    phase se lee como número (1 o 2) o como texto (CURVE_PHASE), para poder filtrar con phase == 1.
    """
    if not results_path.is_file():
        return pd.DataFrame(columns=RESULT_COLUMNS)
    return pd.read_csv(results_path, converters={"phase": lambda value: int(value) if value.isdigit() else value})


def phase1_candidates():
    """Candidatos de la fase 1: cada familia con sus valores por defecto, con los 3 métodos y las 2 tareas.

    params va vacío; lo que no es por defecto queda anotado en fixed_params de cada fila.
    """
    return [
        (1, task, family, method, {})
        for family in MODEL_FAMILIES
        for method in PREPROCESSING_METHODS
        for task in TASKS
    ]


# Búsqueda de hiperparámetros: una malla por familia y tarea. Los valores y su justificación están
# en el notebook 05. Random Forest y Extra Trees incluyen parámetros que limitan el tamaño
# (min_samples_leaf, max_depth y el tope de árboles); n_estimators y max_iter son topes del
# crecimiento por bloques. En Extra Trees no va "balanced_subsample": sin bootstrap (su valor por
# defecto), scikit-learn lo trata igual que "balanced".
_FOREST_GRID = {
    "model__min_samples_leaf": [1, 5, 10, 20],
    "model__max_depth": [None, 20],
    "model__n_estimators": [50, 100],
}
_HGB_GRID = {
    "model__learning_rate": [0.05, 0.1],
    "model__max_leaf_nodes": [15, 31, 63],
    "model__min_samples_leaf": [20, 100],
    "model__max_iter": [200],
    "model__class_weight": [None, "balanced"],
}
_MLP_GRID = {
    "model__hidden_layer_sizes": [(64,), (100,), (100, 50)],
    "model__alpha": [0.0001, 0.001, 0.01],
    SAMPLE_WEIGHT_PARAM: [None, "balanced"],
}
PHASE2_GRIDS = {
    "random_forest": {
        "detector": {**_FOREST_GRID, "model__class_weight": [None, "balanced"]},
        "attack_type": {**_FOREST_GRID, "model__class_weight": [None, "balanced", "balanced_subsample"]},
    },
    "extra_trees": {
        "detector": {**_FOREST_GRID, "model__class_weight": [None, "balanced"]},
        "attack_type": {**_FOREST_GRID, "model__class_weight": [None, "balanced"]},
    },
    "hist_gradient_boosting": {"detector": _HGB_GRID, "attack_type": _HGB_GRID},
    "mlp": {"detector": _MLP_GRID, "attack_type": _MLP_GRID},
}

# Curvas de validación: se varía un parámetro a la vez desde la combinación elegida de cada familia
# y tarea. Sus filas llevan phase = CURVE_PHASE y no cuentan para elegir modelos.
CURVE_PHASE = "curve"
CURVE_PARAMS = {
    "random_forest": {
        "model__max_depth": [5, 10, 15, 20, 25, 30, None],
        "model__min_samples_leaf": [1, 2, 5, 10, 20, 50, 100],
    },
    "extra_trees": {
        "model__max_depth": [5, 10, 15, 20, 25, 30, None],
        "model__min_samples_leaf": [1, 2, 5, 10, 20, 50, 100],
    },
    "hist_gradient_boosting": {"model__max_leaf_nodes": [7, 15, 31, 63, 127, 255]},
}


def phase2_candidates(methods):
    """Candidatos de la búsqueda de hiperparámetros: la malla de PHASE2_GRIDS, en las dos tareas.

    methods es {familia: método}, el que eligió el barrido con valores por defecto para cada una
    de las familias de PHASE2_GRIDS.
    """
    missing = [family for family in PHASE2_GRIDS if family not in methods]
    if missing:
        raise ValueError(f"Falta el método de: {', '.join(missing)}.")
    return [
        (2, task, family, methods[family], dict(params))
        for family, grids in PHASE2_GRIDS.items()
        for task in TASKS
        for params in ParameterGrid(grids[task])
    ]


def curve_candidates(results, selection):
    """Candidatos de las curvas de validación, desde las combinaciones elegidas en selection.

    selection es una tabla de select_candidates; para cada familia de CURVE_PARAMS que tenga
    método, se parte de los params de su detector y de su clasificador (detector_row y
    classifier_row en results) y se varía un parámetro a la vez.
    """
    candidates = []
    for choice in selection.dropna(subset=["method"]).itertuples():
        if choice.family not in CURVE_PARAMS:
            continue
        for task, row in (("detector", choice.detector_row), ("attack_type", choice.classifier_row)):
            base = json.loads(results.loc[row, "params"])
            for name, values in CURVE_PARAMS[choice.family].items():
                candidates += [
                    (CURVE_PHASE, task, choice.family, choice.method, {**base, name: value})
                    for value in values
                ]
    return candidates


# Criterios de selección, en orden: (columna, mayor es mejor, tolerancia de empate). Cada criterio
# deja las filas que empatan con la mejor (diferencia menor que la tolerancia); el siguiente
# decide entre ellas. Con tolerancia 0 solo empatan valores iguales. El empate se mide siempre
# contra la mejor, no en cadena.
# Decimales con que se compara la diferencia entre dos puntajes (ver _best).
DIFFERENCE_DECIMALS = 12
DETECTOR_CRITERIA = [("pr_auc", True, SCORE_TIE_TOLERANCE), ("false_alarm_rate", False, 0)]
CLASSIFIER_CRITERIA = [("macro_f1", True, SCORE_TIE_TOLERANCE), ("min_type_f1", True, 0)]
# Para elegir el método de una familia y ordenar las familias: el detector manda si hay una
# diferencia real; si no, decide el clasificador, y después la menor tasa de falsas alarmas.
COMBINED_CRITERIA = [
    ("pr_auc", True, SCORE_TIE_TOLERANCE),
    ("macro_f1", True, SCORE_TIE_TOLERANCE),
    ("false_alarm_rate", False, 0),
]


def _best(rows, criteria):
    """La mejor fila de una lista de diccionarios según criteria. Un valor vacío cuenta como el peor.

    Si quedan empatadas en todos los criterios, gana la primera de la lista.
    """
    for column, higher_is_better, tolerance in criteria:
        worst = -np.inf if higher_is_better else np.inf
        values = [worst if pd.isna(row[column]) else row[column] for row in rows]
        best = max(values) if higher_is_better else min(values)
        # La diferencia se redondea: en binario, 0.0021 - 0.0011 da 0.000999…, y una diferencia
        # de exactamente 0,001 no es un empate.
        rows = [
            row for row, value in zip(rows, values)
            if value == best or round(abs(best - value), DIFFERENCE_DECIMALS) < tolerance
        ]
    return rows[0]


def _rank(rows, criteria):
    """Las filas ordenadas aplicando _best una y otra vez a las que quedan."""
    rows, ranked = list(rows), []
    while rows:
        best = _best(rows, criteria)
        ranked.append(best)
        rows.remove(best)
    return ranked


# Para elegir el par detector + clasificador de un método dentro de un tamaño máximo: la regla
# combinada y, al final, el peor tipo.
PAIR_CRITERIA = [*COMBINED_CRITERIA, ("min_type_f1", True, 0)]


def _choice(family, method, detector, classifier):
    """Fila de select_candidates para un par detector + clasificador (filas de results con su índice)."""
    return {
        "family": family,
        "method": method,
        "pr_auc": detector["pr_auc"],
        "false_alarm_rate": detector["false_alarm_rate"],
        "macro_f1": classifier["macro_f1"],
        "min_type_f1": classifier["min_type_f1"],
        "detector_params": detector["params"],
        "classifier_params": classifier["params"],
        "detector_row": detector["index"],
        "classifier_row": classifier["index"],
        "model_size_mb": detector["model_size_mb"] + classifier["model_size_mb"],
    }


def select_candidates(results, phases=None, max_size_mb=None):
    """Elige la mejor combinación de cada familia y ordena las familias (decisión b).

    results es la tabla de run_search; phases limita las filas a esas fases (todas si es None).
    Solo cuentan las filas con converged = True. Por familia y método se elige el mejor detector
    (PR-AUC; empate: menor tasa de falsas alarmas) y el mejor clasificador (F1 macro; empate: mayor
    F1 del peor tipo). Luego se elige el método con COMBINED_CRITERIA: el detector y el clasificador
    usan el mismo (contrato, sección 10). Las familias se ordenan con la misma regla.

    Con max_size_mb, en cada método se elige el par detector + clasificador entre los pares que
    suman menos de max_size_mb, con PAIR_CRITERIA (PR-AUC → F1 macro → falsas alarmas → peor tipo);
    una familia sin ningún par que quepa queda sin método ni puesto.

    Devuelve una fila por familia. rank ordena todas las familias; app_rank solo las que pesan
    menos de MAX_MODEL_SIZE_MB entre detector y clasificador (fits_app). Una familia sin ningún
    método con filas convergidas de las dos tareas queda sin método ni puesto. Lanza ValueError si
    a una familia le faltan filas de alguna tarea.
    """
    rows = results if phases is None else results[results["phase"].isin(phases)]
    unknown = sorted(set(rows["family"]) - set(MODEL_FAMILIES))
    if unknown:
        raise ValueError(f"Familias desconocidas en los resultados: {', '.join(unknown)}.")

    choices = []
    for family in [f for f in MODEL_FAMILIES if f in set(rows["family"])]:
        family_rows = rows[rows["family"] == family]
        missing = [task for task in TASKS if task not in set(family_rows["task"])]
        if missing:
            raise ValueError(
                f"A {family} le faltan filas de: {', '.join(missing)}. Completa la búsqueda antes de elegir."
            )
        usable = family_rows[family_rows["converged"].astype(bool)]
        by_method = []
        for method in PREPROCESSING_METHODS:
            detectors = usable[(usable["task"] == "detector") & (usable["method"] == method)]
            classifiers = usable[(usable["task"] == "attack_type") & (usable["method"] == method)]
            if detectors.empty or classifiers.empty:
                continue
            detector_records = detectors.reset_index().to_dict("records")
            classifier_records = classifiers.reset_index().to_dict("records")
            if max_size_mb is None:
                detector = _best(detector_records, DETECTOR_CRITERIA)
                classifier = _best(classifier_records, CLASSIFIER_CRITERIA)
                by_method.append(_choice(family, method, detector, classifier))
                continue
            pairs = [
                _choice(family, method, detector, classifier)
                for detector in detector_records
                for classifier in classifier_records
                if detector["model_size_mb"] + classifier["model_size_mb"] < max_size_mb
            ]
            if pairs:
                by_method.append(_best(pairs, PAIR_CRITERIA))
        choices.append(_best(by_method, COMBINED_CRITERIA) if by_method else {"family": family})

    ranked = _rank([c for c in choices if "method" in c], COMBINED_CRITERIA)
    app_rank = 0
    for rank, choice in enumerate(ranked, start=1):
        choice["rank"] = rank
        choice["fits_app"] = choice["model_size_mb"] < MAX_MODEL_SIZE_MB
        if choice["fits_app"]:
            app_rank += 1
            choice["app_rank"] = app_rank
    columns = [
        "rank", "app_rank", "family", "method", "pr_auc", "false_alarm_rate", "macro_f1",
        "min_type_f1", "model_size_mb", "fits_app", "detector_params", "classifier_params",
        "detector_row", "classifier_row",
    ]
    unranked = [c for c in choices if "method" not in c]
    table = pd.DataFrame([*ranked, *unranked], columns=columns)
    return table.astype({"rank": "Int64", "app_rank": "Int64", "detector_row": "Int64", "classifier_row": "Int64"})


# Regla de simplicidad (sobreentrenamiento), después de select_candidates: dentro de la misma
# familia, método y tarea, si una combinación más simple empata con la elegida, se usa la más
# simple. Cuentan las filas del barrido, de la búsqueda y de las curvas: la regla solo puede elegir
# algo más simple que empata, nunca algo con mejor puntaje.
SIMPLICITY_PHASES = (1, 2, CURVE_PHASE)


def complexity(family, row):
    """Dimensiones de complejidad de una fila de resultados; en todas, menor es más simple.

    Random Forest y Extra Trees: max_depth (sin límite = infinito), min_samples_leaf (con signo
    negativo: más flujos por hoja es más simple) y árboles usados (best_iteration).
    HistGradientBoosting: max_leaf_nodes, min_samples_leaf (negativo) e iteraciones usadas. MLP:
    neuronas, capas y alpha (negativo). Las demás familias no tienen dimensiones: {}.
    """
    params = json.loads(row["params"])
    if family in ("random_forest", "extra_trees"):
        depth = params.get("model__max_depth")
        return {
            "max_depth": math.inf if depth is None else depth,
            "min_samples_leaf": -params.get("model__min_samples_leaf", 1),
            "iterations": row["best_iteration"],
        }
    if family == "hist_gradient_boosting":
        return {
            "max_leaf_nodes": params.get("model__max_leaf_nodes", 31),
            "min_samples_leaf": -params.get("model__min_samples_leaf", 20),
            "iterations": row["best_iteration"],
        }
    if family == "mlp":
        layers = list(params.get("model__hidden_layer_sizes", [100]))
        return {"neurons": sum(layers), "layers": len(layers), "alpha": -params.get("model__alpha", 0.0001)}
    return {}


def _is_simpler(candidate, chosen):
    """candidate no es más complejo en ninguna dimensión y es más simple en al menos una."""
    return bool(chosen) and all(candidate[k] <= chosen[k] for k in chosen) and any(
        candidate[k] < chosen[k] for k in chosen
    )


def _ties(task, candidate, chosen):
    """Empate de la regla: PR-AUC a menos de SCORE_TIE_TOLERANCE y falsas alarmas no peores, o F1 macro."""
    if task == "detector":
        return (
            round(abs(candidate["pr_auc"] - chosen["pr_auc"]), DIFFERENCE_DECIMALS) < SCORE_TIE_TOLERANCE
            and candidate["false_alarm_rate"] <= chosen["false_alarm_rate"]
        )
    return round(abs(candidate["macro_f1"] - chosen["macro_f1"]), DIFFERENCE_DECIMALS) < SCORE_TIE_TOLERANCE


def apply_simplicity_rule(results, selection, max_size_mb=None):
    """Aplica la regla de simplicidad a una tabla de select_candidates y devuelve una copia.

    Para cada familia con método, y para su detector y su clasificador, busca en results las filas
    convergidas de la misma familia, método y tarea (fases de SIMPLICITY_PHASES) que sean más
    simples (complexity) y empaten con la elegida. Si hay varias, gana la de menor model_size_mb;
    con max_size_mb, solo cuentan las que dejan el par por debajo de ese tamaño. Actualiza la fila,
    los params, las métricas y el tamaño, y marca detector_simplified y classifier_simplified. El
    orden de las familias no cambia.
    """
    table = selection.copy()
    table["detector_simplified"] = False
    table["classifier_simplified"] = False
    usable = results[results["phase"].isin(SIMPLICITY_PHASES) & results["converged"].astype(bool)]
    for position, choice in table.iterrows():
        if pd.isna(choice["method"]):
            continue
        family = choice["family"]
        for task, row_column, params_column, flag in (
            ("detector", "detector_row", "detector_params", "detector_simplified"),
            ("attack_type", "classifier_row", "classifier_params", "classifier_simplified"),
        ):
            chosen = results.loc[table.at[position, row_column]]
            other_row = table.at[position, "classifier_row" if task == "detector" else "detector_row"]
            other_size = results.loc[other_row, "model_size_mb"]
            chosen_complexity = complexity(family, chosen)
            pool = usable[
                (usable["family"] == family) & (usable["method"] == choice["method"]) & (usable["task"] == task)
            ]
            simpler = [
                (index, row) for index, row in pool.iterrows()
                if index != chosen.name
                and _is_simpler(complexity(family, row), chosen_complexity)
                and _ties(task, row, chosen)
                and (max_size_mb is None or row["model_size_mb"] + other_size < max_size_mb)
            ]
            if not simpler:
                continue
            index, row = min(simpler, key=lambda item: (item[1]["model_size_mb"], item[0]))
            table.at[position, row_column] = index
            table.at[position, params_column] = row["params"]
            table.at[position, flag] = True
            metrics = ("pr_auc", "false_alarm_rate") if task == "detector" else ("macro_f1", "min_type_f1")
            for metric in metrics:
                table.at[position, metric] = row[metric]
            table.at[position, "model_size_mb"] = row["model_size_mb"] + other_size
    return table


def _piece_names(transformer):
    """Nombres de las piezas de una parte del ColumnTransformer, por ejemplo ["FunctionTransformer", "StandardScaler"]."""
    if isinstance(transformer, str):
        return [transformer]
    if isinstance(transformer, Pipeline):
        return [type(step).__name__ for _, step in transformer.steps]
    return [type(transformer).__name__]


def _preprocessor_structure(preprocessor):
    """Estructura de un preprocesador: cada parte con sus piezas y sus columnas."""
    if not isinstance(preprocessor, ColumnTransformer):
        return None
    return [
        (name, _piece_names(transformer), list(cols))
        for name, transformer, cols in preprocessor.transformers
    ]


def feature_groups(preprocessor):
    """Para cada variable original, las columnas que salen del preprocesador ya ajustado.

    Las claves van en el orden del contrato: primero las numéricas, en el orden del archivo, y
    después CATEGORICAL_COLS. Una numérica tiene una sola columna, con su mismo nombre; una
    categórica, una por categoría más la columna "infrecuente".
    """
    columns = {name: list(cols) for name, _, cols in preprocessor.transformers_}
    numeric = set(columns["log"]) | set(columns["plain"])
    groups = {c: [c] for c in INPUT_COLS if c in numeric}

    # Las columnas one-hot se reparten por su prefijo <variable>_. Solo se buscan entre las de la
    # parte categórica, así que una numérica como ct_state_ttl no se confunde con state.
    encoded = list(
        preprocessor.named_transformers_["categorical"].get_feature_names_out()
    )
    for col in columns["categorical"]:
        groups[col] = [name for name in encoded if name.startswith(f"{col}_")]

    # Cada columna de salida debe quedar en exactamente un grupo.
    grouped = [name for names in groups.values() for name in names]
    if sorted(grouped) != sorted(preprocessor.get_feature_names_out()):
        raise ValueError(
            "Las columnas del preprocesador no se pudieron repartir entre las variables originales."
        )
    return groups


def build_model_info(
    name,
    display_name,
    model,
    detector_type,
    preprocessing_method,
    threshold,
    threshold_rule,
    can_explain,
    explanation_method,
    test_metrics,
    complexity,
    trained_at,
):
    """Arma model.json como diccionario, con los campos en el orden del contrato (sección 11).

    model es el diccionario de model.joblib, ya entrenado. trained_at es un datetime con zona
    horaria y se escribe en UTC. complexity trae los campos medidos al entrenar; model_size_mb
    queda en None hasta que export_model guarda el modelo. Lanza ValueError si el modelo no está
    hecho como pide el contrato (sección 10).
    """
    if detector_type not in DETECTOR_TYPES:
        raise ValueError(
            f"Tipo de detector desconocido: {detector_type}. Usa uno de: {', '.join(DETECTOR_TYPES)}."
        )
    expected_structure = _preprocessor_structure(
        build_preprocessor(preprocessing_method)
    )

    # Los dos Pipelines con los pasos de nombre fijo y el preprocesador del método declarado: así
    # el método de model.json es el verdadero y el detector y el clasificador usan el mismo.
    for key in ("detector", "attack_type_classifier"):
        pipeline = model[key]
        if (
            not isinstance(pipeline, Pipeline)
            or list(pipeline.named_steps) != PIPELINE_STEPS
        ):
            raise ValueError(
                f"{key} debe ser un Pipeline con los pasos {' y '.join(PIPELINE_STEPS)}, en ese orden."
            )
        if _preprocessor_structure(pipeline["preprocessor"]) != expected_structure:
            raise ValueError(
                f"El preprocesador de {key} no es el del método {preprocessing_method}: "
                "el detector y el clasificador deben usar el método declarado."
            )

    if trained_at.utcoffset() is None:
        raise ValueError(
            "trained_at debe traer zona horaria para poder escribirlo en UTC."
        )
    if set(complexity) != COMPLEXITY_INPUTS:
        raise ValueError(
            f"complexity debe traer exactamente: {', '.join(sorted(COMPLEXITY_INPUTS))}."
        )

    use_ttl = PREPROCESSING_METHODS[preprocessing_method]["use_ttl"]
    numeric_cols = numeric_input_cols(use_ttl)
    return {
        "name": name,
        "display_name": display_name,
        "is_mock": False,
        "trained_at": trained_at.astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "sklearn_version": sklearn.__version__,
        "detector_type": detector_type,
        "preprocessing_method": preprocessing_method,
        "use_ttl": use_ttl,
        "numeric_cols": numeric_cols,
        "categorical_cols": list(CATEGORICAL_COLS),
        "log_cols": [c for c in numeric_cols if c in LOG_COLS],
        "feature_groups": feature_groups(model["detector"]["preprocessor"]),
        "threshold": float(threshold),
        "threshold_rule": threshold_rule,
        "can_explain": can_explain,
        "explanation_method": explanation_method,
        "test_metrics": test_metrics,
        "complexity": {
            "training_seconds": complexity["training_seconds"],
            "training_flows": complexity["training_flows"],
            "prediction_ms_per_1000_flows": complexity["prediction_ms_per_1000_flows"],
            "model_size_mb": None,
            "hardware": complexity["hardware"],
        },
    }


def check_model_size(size_mb):
    """Avisa si model.joblib pesa MAX_MODEL_SIZE_MB o más. No es un error: el equipo lo revisa (contrato, sección 10)."""
    if size_mb >= MAX_MODEL_SIZE_MB:
        warnings.warn(
            f"{MODEL_JOBLIB} pesa {size_mb:.2f} MB y el límite es {MAX_MODEL_SIZE_MB} MB. "
            "El equipo debe revisarlo antes de subirlo a git.",
            stacklevel=2,
        )


def _json_text(data):
    """Texto de un JSON de artifacts/: UTF-8 legible, sangría de 2 espacios y sin NaN ni infinitos."""
    return json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def _model_json_text(info):
    """Texto de model.json; ValueError si no es un JSON válido (por ejemplo, con NaN o tipos de numpy)."""
    try:
        return _json_text(info)
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"El {MODEL_JSON} de {info['name']} no se puede escribir como JSON válido: tiene un NaN, "
            "un infinito o un valor que no es de Python (por ejemplo, un número de numpy)."
        ) from error


def export_model(model, info, artifacts_dir=ARTIFACTS_DIR):
    """Guarda un modelo en artifacts_dir/models/<name>/: model.joblib y model.json (contrato, sección 10).

    info es el model.json que arma build_model_info. Si la carpeta ya existe, sus dos archivos se
    reemplazan. No registra el modelo. Devuelve el model.json tal como quedó escrito, con
    model_size_mb; el diccionario info recibido no se modifica.
    """
    name = info["name"]
    if not re.fullmatch(MODEL_NAME_PATTERN, name):
        raise ValueError(
            f"El nombre {name} no es válido: debe ir en minúsculas y snake_case (por ejemplo, random_forest)."
        )
    if name == MOCK_MODEL_NAME:
        raise ValueError(
            f"El nombre {MOCK_MODEL_NAME} es del modelo simulado, que se escribe a mano; usa otro nombre."
        )

    # Las mismas comprobaciones que hace la app al cargar (ArtifactError si fallan), para que un
    # modelo exportado siempre se pueda cargar. test_metrics puede faltar si el modelo aún no está
    # registrado; si ya lo está, se exige, porque sin él la app no podría arrancar. Sin registry.json
    # (por ejemplo, en una carpeta de pruebas) ningún modelo está registrado.
    registered = (artifacts_dir / REGISTRY_PATH.name).is_file() and name in [
        m["name"] for m in read_registry(artifacts_dir)["models"]
    ]
    check_model_info(info, name, require_test_metrics=registered)
    if info["is_mock"]:
        raise ValueError(
            "export_model solo guarda modelos entrenados; el modelo simulado se escribe a mano."
        )
    check_model(model, info, name)

    # Antes de escribir cualquier archivo se comprueba que model.json se puede escribir. Si fallara
    # después de guardar model.joblib, la carpeta quedaría con el modelo nuevo y la descripción vieja.
    # model_size_mb, lo único que cambia después, es siempre un número válido.
    _model_json_text(info)

    model_dir = artifacts_dir / MODELS_DIR.name / name
    model_dir.mkdir(parents=True, exist_ok=True)
    joblib_path = model_dir / MODEL_JOBLIB
    joblib.dump(model, joblib_path)

    size_mb = joblib_path.stat().st_size / BYTES_PER_MB
    check_model_size(size_mb)
    written = {**info, "complexity": {**info["complexity"], "model_size_mb": size_mb}}
    (model_dir / MODEL_JSON).write_text(_model_json_text(written), encoding="utf-8")
    return written


def register_model(name, artifacts_dir=ARTIFACTS_DIR):
    """Agrega un modelo exportado a registry.json, después de su evaluación final (contrato, sección 12).

    Solo registra un modelo que la app podría cargar, con test_metrics. Si ya está registrado, no
    hace nada. Si no, lo agrega antes del modelo simulado (si está) o al final; default_model no
    cambia. Devuelve el registro. registry.json debe existir: es un archivo del proyecto.
    """
    registry = read_registry(artifacts_dir)
    load_model(name, read_model_info(name, artifacts_dir), artifacts_dir)

    names = [m["name"] for m in registry["models"]]
    if name in names:
        return registry
    position = names.index(MOCK_MODEL_NAME) if MOCK_MODEL_NAME in names else len(names)
    models = [
        *registry["models"][:position],
        {"name": name},
        *registry["models"][position:],
    ]
    registry = {**registry, "models": models}
    _write_registry(registry, artifacts_dir)
    return registry


def _write_registry(registry, artifacts_dir):
    """Escribe registry.json de una sola vez.

    Primero un archivo temporal en la misma carpeta y luego os.replace, que cambia un archivo por
    otro de una vez: si algo falla al escribir, registry.json queda como estaba, nunca a medias.
    """
    path = artifacts_dir / REGISTRY_PATH.name
    temp_path = path.with_name(path.name + TEMP_SUFFIX)
    temp_path.write_text(_json_text(registry), encoding="utf-8")
    os.replace(temp_path, path)


def set_default_model(name, artifacts_dir=ARTIFACTS_DIR):
    """Cambia default_model de registry.json (contrato, sección 12). Solo acepta un modelo registrado.

    Si ya es el modelo por defecto, no escribe nada. Devuelve el registro.
    """
    registry = read_registry(artifacts_dir)
    names = [m["name"] for m in registry["models"]]
    if name not in names:
        raise ValueError(
            f"{name} no está registrado; registra el modelo antes de hacerlo el modelo por defecto."
        )
    if registry["default_model"] == name:
        return registry
    registry = {**registry, "default_model": name}
    _write_registry(registry, artifacts_dir)
    return registry


def unregister_model(name, artifacts_dir=ARTIFACTS_DIR):
    """Saca un modelo de registry.json; su carpeta queda en artifacts/models/ (contrato, sección 12).

    No se puede quitar el modelo por defecto: primero hay que cambiarlo con set_default_model. Si
    el modelo no está registrado, no escribe nada. Devuelve el registro.
    """
    registry = read_registry(artifacts_dir)
    if registry["default_model"] == name:
        raise ValueError(
            f"{name} es el modelo por defecto; cambia el modelo por defecto con set_default_model "
            "antes de quitarlo del registro."
        )
    models = [m for m in registry["models"] if m["name"] != name]
    if len(models) == len(registry["models"]):
        return registry
    registry = {**registry, "models": models}
    _write_registry(registry, artifacts_dir)
    return registry


# Entrenamiento final: los modelos se entrenan con la parte de entrenamiento, con los
# hiperparámetros y el tamaño (best_iteration) de su fila de la búsqueda, y se evalúan en la
# prueba una sola vez (decisiones de la etapa 10 en CLAUDE.md).

# Nombre en la app de cada familia; el name del modelo es la familia.
DISPLAY_NAMES = {
    "dummy": "Referencia (dummy)",
    "logistic_regression": "Regresión logística (modelo base)",
    "decision_tree": "Árbol de decisión",
    "random_forest": "Random Forest",
    "extra_trees": "Extra Trees",
    "hist_gradient_boosting": "HistGradientBoosting",
    "gaussian_nb": "Gaussian NB",
    "mlp": "Red neuronal (MLP)",
}
# Cuántos modelos elegidos se registran, y el modelo base, que se registra además de ellos.
APP_MODELS = 3
BASE_MODEL_FAMILY = "logistic_regression"
# Método de explicación de cada familia (contrato, sección 11); las demás no explican.
EXPLANATION_METHODS = {
    "hist_gradient_boosting": "shap_tree",
    "random_forest": "shap_tree",
    "logistic_regression": "linear_logit",
}
# Método del experimento de TTL: los elegidos se entrenan también con él, mismos hiperparámetros.
TTL_METHOD = "m3"
# Diferencia máxima entre una métrica de validación del modelo final y la de su fila de la
# búsqueda. Es redondeo: con n_jobs=-1, la PR-AUC de los bosques cambió hasta 1,8e-7 entre corridas.
REPRODUCTION_TOLERANCE = 1e-6
# Veces que se mide el tiempo de predicción sobre la prueba; se toma la mediana (contrato, sección 11).
PREDICTION_TIMING_RUNS = 5
# Archivo con el nombre del procesador en Linux.
CPUINFO_PATH = Path("/proc/cpuinfo")

# Métricas del detector y del clasificador que se guardan por partición (validación y prueba).
SPLIT_METRICS = [
    "recall", "false_alarm_rate", "precision", "f1", "accuracy", "pr_auc", "roc_auc",
    "tp", "fp", "tn", "fn", "macro_f1", "type_evaluated_flows", "type_confusion",
]
FINAL_COLUMNS = [
    "name", "kind", "family", "display_name", "method", "registered",
    "detector_params", "classifier_params", "detector_iterations", "classifier_iterations", "threshold",
    *[f"{split}_{metric}" for split in ("validation", "test") for metric in SPLIT_METRICS],
    "training_seconds", "training_flows", "prediction_ms_per_1000_flows", "model_size_mb", "hardware",
    "trained_at", "sklearn_version", "search_version", "test_metrics_json",
]
PER_TYPE_COLUMNS = ["name", "kind", "family", "split", "attack_cat", "precision", "recall", "f1", "support"]


def hardware_description(cpuinfo_path=CPUINFO_PATH):
    """Procesador y núcleos lógicos del equipo, para complexity.hardware (contrato, sección 11).

    El nombre sale de "model name" en /proc/cpuinfo, porque en Linux platform.processor() puede
    dar un texto vacío (así pasa en WSL); si no está, se usa platform.machine().
    """
    name = None
    if cpuinfo_path.is_file():
        for line in cpuinfo_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("model name") and ":" in line:
                name = line.split(":", 1)[1].strip()
                break
    name = name or platform.machine() or "procesador desconocido"
    return f"{name}, {os.cpu_count()} núcleos lógicos"


def final_model_specs(final):
    """Los modelos del entrenamiento final, en orden, a partir de la tabla de apply_simplicity_rule.

    Primero los APP_MODELS elegidos (app_rank) y el modelo base, que se registran; después las
    demás familias con método, solo para el artículo; al final la versión TTL_METHOD de cada
    elegido, con los mismos hiperparámetros. Cada uno es un diccionario con name, display_name,
    kind ("elegido", "modelo base", "referencia" o "m3"), family, method, detector_row,
    classifier_row y register.
    """
    ranked = final.dropna(subset=["method"]).sort_values("rank")
    chosen = ranked[ranked["app_rank"] <= APP_MODELS]

    def spec(choice, kind, register, method=None, suffix=""):
        return {
            "name": choice["family"] + suffix,
            "display_name": DISPLAY_NAMES[choice["family"]],
            "kind": kind,
            "family": choice["family"],
            "method": method or choice["method"],
            "detector_row": int(choice["detector_row"]),
            "classifier_row": int(choice["classifier_row"]),
            "register": register,
        }

    specs = [spec(choice, "elegido", True) for _, choice in chosen.iterrows()]
    base = ranked[(ranked["family"] == BASE_MODEL_FAMILY) & ~ranked["family"].isin(chosen["family"])]
    specs += [spec(choice, "modelo base", True) for _, choice in base.iterrows()]
    taken = {s["family"] for s in specs}
    specs += [spec(choice, "referencia", False) for _, choice in ranked.iterrows() if choice["family"] not in taken]
    specs += [
        spec(choice, TTL_METHOD, False, method=TTL_METHOD, suffix=f"_{TTL_METHOD}")
        for _, choice in chosen.iterrows()
    ]
    return specs


def _fit_final_pipeline(task, family, method, row, train_flows):
    """Pipeline final de una tarea, con los params de su fila y su tamaño fijo (best_iteration)."""
    params = json.loads(row["params"])
    train_inputs, train_target = _task_data(task, train_flows)
    preprocessor = build_preprocessor(method).fit(train_flows[INPUT_COLS])
    estimator = _candidate_estimator(family).set_params(**_model_params(params))
    growth = _growth(family, params)
    if growth is not None:
        # El tamaño ya se eligió en la búsqueda: se entrena de una vez, sin crecer por bloques.
        estimator.set_params(**{growth[0]: int(row["best_iteration"]), "warm_start": False})
    fit_params = {}
    if params.get(SAMPLE_WEIGHT_PARAM) == "balanced":
        fit_params["sample_weight"] = compute_sample_weight("balanced", train_target)
    estimator.fit(preprocessor.transform(train_inputs), train_target, **fit_params)
    return Pipeline([("preprocessor", preprocessor), ("model", estimator)])


def _fit_final_model(spec, results, train_flows):
    """(model, training_seconds, trained_at): el diccionario de model.joblib entrenado."""
    started = perf_counter()
    detector = _fit_final_pipeline("detector", spec["family"], spec["method"], results.loc[spec["detector_row"]], train_flows)
    classifier = _fit_final_pipeline(
        "attack_type", spec["family"], spec["method"], results.loc[spec["classifier_row"]], train_flows
    )
    training_seconds = perf_counter() - started
    trained_at = datetime.now(timezone.utc)
    return {"detector": detector, "attack_type_classifier": classifier}, training_seconds, trained_at


def _check_reproduction(spec, results, model, validation_flows):
    """Lanza ValueError si el modelo final no da en validación lo mismo que su fila de la búsqueda.

    Se comprueba antes de tocar la prueba: así el modelo evaluado es exactamente el elegido.
    """
    for task, key, row in (
        ("detector", "detector", spec["detector_row"]),
        ("attack_type", "attack_type_classifier", spec["classifier_row"]),
    ):
        expected = results.loc[row]
        pipeline = model[key]
        inputs, target = _task_data(task, validation_flows)
        metrics, _ = _task_metrics(task, pipeline["model"], pipeline["preprocessor"].transform(inputs), target)
        names = ("pr_auc", "threshold", "false_alarm_rate") if task == "detector" else ("macro_f1",)
        for name in names:
            if not math.isclose(metrics[name], expected[name], rel_tol=0, abs_tol=REPRODUCTION_TOLERANCE):
                raise ValueError(
                    f"El modelo final {spec['name']} ({task}) no reproduce su fila de la búsqueda: "
                    f"{name} = {metrics[name]} y en la búsqueda {expected[name]}. No se evalúa en prueba."
                )


def _evaluate(model, threshold, flows):
    """(detection, attack_type) de un modelo sobre flujos con etiquetas, como lo hace la app."""
    probability, alerts, types = predict_flows(model, {"detector_type": "binary", "threshold": threshold}, flows)
    return (
        detection_metrics(flows[TARGET], probability, threshold),
        attack_type_metrics(flows[ATTACK_CAT], types, alerts),
    )


def _flat_metrics(split, detection, attack_type):
    """Las métricas de una partición con el prefijo validation_ o test_ (SPLIT_METRICS)."""
    values = {
        "recall": detection["detection_rate"],
        **{name: detection[name] for name in ("false_alarm_rate", "precision", "f1", "accuracy", "pr_auc", "roc_auc")},
        **detection["confusion"],
        "macro_f1": attack_type["macro_f1"],
        "type_evaluated_flows": attack_type["evaluated_flows"],
        "type_confusion": json.dumps(attack_type["confusion"]["matrix"]),
    }
    return {f"{split}_{name}": values[name] for name in SPLIT_METRICS}


def _prediction_ms_per_1000(model, threshold, flows):
    """Mediana de PREDICTION_TIMING_RUNS predicciones completas, en ms por cada 1.000 flujos."""
    times = []
    for _ in range(PREDICTION_TIMING_RUNS):
        started = perf_counter()
        predict_flows(model, {"detector_type": "binary", "threshold": threshold}, flows)
        times.append(perf_counter() - started)
    return float(np.median(times)) * 1000 / len(flows) * 1000


def _append_csv(path, columns, rows):
    """Agrega filas completas a un CSV en una sola escritura, con el encabezado si es nuevo."""
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
    if not path.is_file() or path.stat().st_size == 0:
        writer.writeheader()
    writer.writerows(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="") as file:
        file.write(buffer.getvalue())
        file.flush()
        os.fsync(file.fileno())


def _iterations_value(value):
    """best_iteration como entero, o None en las familias que no iteran."""
    return None if pd.isna(value) else int(value)


def _is_exported(name, artifacts_dir):
    """Si el modelo ya está exportado con su evaluación final (test_metrics)."""
    folder = artifacts_dir / MODELS_DIR.name / name
    if not (folder / MODEL_JSON).is_file() or not (folder / MODEL_JOBLIB).is_file():
        return False
    return read_model_info(name, artifacts_dir, require_test_metrics=False)["test_metrics"] is not None


def _export_final(spec, model, saved, validation_flows, artifacts_dir):
    """Exporta un modelo registrado con su model.json, usando lo guardado en test_results.csv."""
    threshold = float(saved["threshold"])
    inputs = validation_flows
    probability, _, _ = predict_flows(model, {"detector_type": "binary", "threshold": threshold}, inputs)
    explanation = EXPLANATION_METHODS.get(spec["family"])
    info = build_model_info(
        name=spec["name"],
        display_name=spec["display_name"],
        model=model,
        detector_type="binary",
        preprocessing_method=spec["method"],
        threshold=threshold,
        threshold_rule=threshold_rule(validation_flows[TARGET], probability, threshold),
        can_explain=explanation is not None,
        explanation_method=explanation,
        test_metrics=json.loads(saved["test_metrics_json"]),
        complexity={
            "training_seconds": float(saved["training_seconds"]),
            "training_flows": int(saved["training_flows"]),
            "prediction_ms_per_1000_flows": float(saved["prediction_ms_per_1000_flows"]),
            "hardware": saved["hardware"],
        },
        trained_at=datetime.strptime(saved["trained_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc),
    )
    return export_model(model, info, artifacts_dir)


def oob_comparison(results, final, train_flows, family="random_forest"):
    """PR-AUC y F1 macro fuera de la bolsa del Random Forest elegido, junto a los de validación agrupada.

    Se entrena de nuevo con oob_score=True, que no cambia los árboles. Lo fuera de la bolsa no
    respeta los grupos de flujos idénticos: la diferencia con la validación agrupada mide cuánto
    optimismo da no agruparlos. No reemplaza la validación. Los flujos sin predicción fuera de la
    bolsa (en bolsa en todos los árboles) no cuentan y se informan.
    """
    choice = final.set_index("family").loc[family]
    rows = []
    for task, row_index in (("detector", choice["detector_row"]), ("attack_type", choice["classifier_row"])):
        row = results.loc[int(row_index)]
        params = json.loads(row["params"])
        train_inputs, target = _task_data(task, train_flows)
        preprocessor = build_preprocessor(choice["method"]).fit(train_flows[INPUT_COLS])
        estimator = _candidate_estimator(family).set_params(**_model_params(params))
        estimator.set_params(n_estimators=int(row["best_iteration"]), warm_start=False, oob_score=True)
        with warnings.catch_warnings():
            # scikit-learn avisa si algún flujo quedó en bolsa en todos los árboles; se cuenta abajo.
            warnings.filterwarnings("ignore", message="Some inputs do not have OOB scores")
            estimator.fit(preprocessor.transform(train_inputs), target)
        oob = estimator.oob_decision_function_
        covered = ~np.isnan(oob).any(axis=1)
        if task == "detector":
            probability = attack_probability_from_proba(oob[covered], estimator.classes_, "binary")
            oob_value = detection_metrics(target[covered], probability, compute_threshold(target[covered], probability))["pr_auc"]
            metric, validation_value = "pr_auc", row["pr_auc"]
        else:
            predicted = attack_cat_from_proba(oob[covered], estimator.classes_)
            oob_value = attack_type_metrics(target[covered], predicted, np.ones(covered.sum(), dtype=bool))["macro_f1"]
            metric, validation_value = "macro_f1", row["macro_f1"]
        rows.append({
            "family": family, "task": task, "metric": metric, "oob": oob_value,
            "grouped_validation": validation_value, "difference": oob_value - validation_value,
            "train_flows": len(target), "flows_without_oob": int((~covered).sum()),
        })
    return pd.DataFrame(rows)


def train_final_models(
    results_path=MODEL_SEARCH_CSV,
    artifacts_dir=ARTIFACTS_DIR,
    output_dir=MODEL_SEARCH_DIR,
    train_flows=None,
    validation_flows=None,
    test_flows=None,
    verbose=True,
):
    """Entrenamiento final: entrena, evalúa en prueba una sola vez, exporta y registra.

    1. Elige con select_candidates (fases 1 y 2, dentro de MAX_MODEL_SIZE_MB) y
       apply_simplicity_rule, y arma la lista con final_model_specs.
    2. Para cada modelo: lo entrena con la parte de entrenamiento y su tamaño fijo; comprueba que
       reproduce su fila de la búsqueda (salvo las versiones M3, que no tienen fila); calcula el
       umbral en validación; lo evalúa en validación y en prueba; guarda la fila en
       test_results.csv y las métricas por tipo en test_per_type.csv; y exporta los que se registran.
    3. Registra los que se registran, en orden; fija como modelo por defecto el primero; y saca al
       simulado del registro, en ese orden.
    4. Guarda la medición fuera de la bolsa del Random Forest en oob_vs_validation.csv.

    Un modelo que ya está en test_results.csv no se vuelve a evaluar en prueba; si se registra y
    falta su exportación, se vuelve a entrenar y se exporta con lo guardado. Sin flujos, carga los
    datos del proyecto. Devuelve test_results.csv como DataFrame.
    """
    results = read_search_results(results_path)
    if train_flows is None:
        train_flows, validation_flows = split_train_validation(load_train())
    check_search_data(train_flows, validation_flows)
    selection = select_candidates(results, phases=[1, 2], max_size_mb=MAX_MODEL_SIZE_MB)
    final = apply_simplicity_rule(results, selection, max_size_mb=MAX_MODEL_SIZE_MB)
    specs = final_model_specs(final)

    test_results_path = output_dir / TEST_RESULTS_CSV.name
    per_type_path = output_dir / TEST_PER_TYPE_CSV.name
    saved = {}
    if test_results_path.is_file():
        saved = {row["name"]: row for row in pd.read_csv(test_results_path, dtype=str, keep_default_na=False).to_dict("records")}
    hardware = hardware_description()

    for spec in specs:
        name = spec["name"]
        if name in saved and (not spec["register"] or _is_exported(name, artifacts_dir)):
            if verbose:
                print(f"{name}: ya evaluado en prueba; no se repite.", flush=True)
            continue
        model, training_seconds, trained_at = _fit_final_model(spec, results, train_flows)
        if spec["kind"] != TTL_METHOD:
            _check_reproduction(spec, results, model, validation_flows)

        if name not in saved:
            if test_flows is None:
                test_flows = load_test()
                validate_flows(test_flows, numeric_input_cols(), CATEGORICAL_COLS)
                validate_labels(test_flows)
            validation_probability, _, _ = predict_flows(model, {"detector_type": "binary", "threshold": 1.0}, validation_flows)
            threshold = compute_threshold(validation_flows[TARGET], validation_probability)
            validation_detection, validation_types = _evaluate(model, threshold, validation_flows)
            test_detection, test_types = _evaluate(model, threshold, test_flows)
            serialized = BytesIO()
            joblib.dump(model, serialized)
            row = {
                "name": name, "kind": spec["kind"], "family": spec["family"], "display_name": spec["display_name"],
                "method": spec["method"], "registered": spec["register"],
                "detector_params": results.loc[spec["detector_row"], "params"],
                "classifier_params": results.loc[spec["classifier_row"], "params"],
                "detector_iterations": _iterations_value(results.loc[spec["detector_row"], "best_iteration"]),
                "classifier_iterations": _iterations_value(results.loc[spec["classifier_row"], "best_iteration"]),
                "threshold": threshold,
                **_flat_metrics("validation", validation_detection, validation_types),
                **_flat_metrics("test", test_detection, test_types),
                "training_seconds": training_seconds,
                "training_flows": len(train_flows),
                "prediction_ms_per_1000_flows": _prediction_ms_per_1000(model, threshold, test_flows),
                "model_size_mb": serialized.tell() / BYTES_PER_MB,
                "hardware": hardware,
                "trained_at": trained_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "sklearn_version": sklearn.__version__,
                "search_version": SEARCH_VERSION,
                "test_metrics_json": json.dumps(
                    {"test_flows": len(test_flows), "detection": test_detection, "attack_type": test_types},
                    allow_nan=False,
                ),
            }
            per_type = [
                {"name": name, "kind": spec["kind"], "family": spec["family"], "split": split, **c}
                for split, types in (("validation", validation_types), ("test", test_types))
                for c in types["per_class"]
            ]
            # Primero la fila de la prueba, después la exportación: si algo falla después de
            # evaluar, el resultado ya quedó guardado y la prueba no se vuelve a usar.
            _append_csv(test_results_path, FINAL_COLUMNS, [row])
            _append_csv(per_type_path, PER_TYPE_COLUMNS, per_type)
            saved[name] = {k: ("" if v is None else str(v)) for k, v in row.items()}
            if verbose:
                print(
                    f"{name}: prueba PR-AUC {test_detection['pr_auc']:.4f}, recall {test_detection['detection_rate']:.4f}, "
                    f"falsas alarmas {test_detection['false_alarm_rate']:.4f}, F1 macro {test_types['macro_f1']:.4f}",
                    flush=True,
                )
        if spec["register"]:
            _export_final(spec, model, saved[name], validation_flows, artifacts_dir)

    registered = [s["name"] for s in specs if s["register"]]
    for name in registered:
        register_model(name, artifacts_dir)
    set_default_model(registered[0], artifacts_dir)
    unregister_model(MOCK_MODEL_NAME, artifacts_dir)

    if "random_forest" in set(final.dropna(subset=["method"])["family"]):
        oob_comparison(results, final, train_flows).to_csv(output_dir / OOB_CSV.name, index=False)
    return pd.read_csv(test_results_path)
