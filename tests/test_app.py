"""Pruebas de la app: predictores, análisis en memoria, rutas de la API (con TestClient), frontend y contraste de styles.css."""

import copy
import json
import logging
import re
import socket
import threading
import time

import numpy as np
import pandas as pd
import pytest
import uvicorn
from conftest import structure, write_json
from fastapi.testclient import TestClient
from pydantic import TypeAdapter
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from starlette.websockets import WebSocketDisconnect

from threat_detector.app.analyses import (
    AnalysisStore,
    compact_flows,
    parse_sample_id,
    read_flows,
    run_analysis,
    sample_id,
    validate_upload,
)
from threat_detector.app import routes
from threat_detector.app.schemas import AnalysisResponse
from threat_detector.app.main import create_app
from threat_detector.app.mock import MockPredictor
from threat_detector.app import predictors as predictors_module
from threat_detector.app.predictors import PipelinePredictor, build_predictors
from threat_detector.app.routes import MAX_UPLOAD_BYTES
from threat_detector.artifacts import (
    ArtifactError,
    detection_rate,
    false_alarm_rate,
    load_artifacts,
    predict_flows,
    read_model_info,
    severity,
)
from threat_detector.config import (
    DEMO_SAMPLE_CSV,
    MAX_STORED_ANALYSES,
    MAX_UPLOAD_MB,
    REGISTRY_PATH,
    SIMULATION_INTERVAL_SECONDS,
    SIMULATION_SPEEDS,
    STATIC_DIR,
)
from threat_detector.dataset import (
    ATTACK_CAT,
    ATTACK_TYPES,
    ID_COL,
    NORMAL_CAT,
    TARGET,
    TARGET_COLS,
    FlowValidationError,
)
from threat_detector.ml.preprocessing import TTL_COLS, build_preprocessor
from threat_detector.ml.training import feature_groups


@pytest.fixture(scope="module")
def mock():
    """El modelo simulado del artifacts/ real."""
    return MockPredictor(read_model_info("mock"))


def assert_same_predictions(first, second):
    for a, b in zip(first, second):
        np.testing.assert_array_equal(a, b)


# MockPredictor.predict


def test_mock_predictions_follow_the_alert_and_type_rules(mock, sample_flows):
    probability, alerts, types = mock.predict(sample_flows)
    assert len(probability) == len(alerts) == len(types) == len(sample_flows)
    assert ((probability >= 0) & (probability < 1)).all()
    np.testing.assert_array_equal(alerts, probability >= mock.info["threshold"])
    assert all(t is None for t in types[~alerts])
    assert set(types[alerts]) <= set(ATTACK_TYPES)


def test_mock_predictions_are_repeatable(mock, sample_flows):
    assert_same_predictions(mock.predict(sample_flows), mock.predict(sample_flows))


def test_mock_ignores_id_labels_and_unused_columns(mock, sample_flows):
    expected = mock.predict(sample_flows)
    changed = sample_flows.copy()
    changed[ID_COL] = changed[ID_COL] + 1000
    changed[TARGET] = 1 - changed[TARGET]
    changed[ATTACK_CAT] = "Worms"
    # swin está en el archivo, pero el preprocesamiento la elimina.
    changed["swin"] = changed["swin"] + 7
    assert_same_predictions(mock.predict(changed), expected)
    assert_same_predictions(mock.predict(sample_flows.drop(columns=TARGET_COLS)), expected)


def test_mock_gives_the_same_with_decimals_and_text_as_object(mock, sample_flows):
    expected = mock.predict(sample_flows)
    changed = sample_flows.copy()
    numeric = mock.info["numeric_cols"]
    changed[numeric] = changed[numeric].astype(float)
    categorical = mock.info["categorical_cols"]
    changed[categorical] = changed[categorical].astype(object)
    assert_same_predictions(mock.predict(changed), expected)


def test_identical_flows_give_the_same_result(mock, sample_flows):
    # La fila 0 repetida al final, con otro id y otras etiquetas.
    repeated = sample_flows.iloc[[0]].assign(**{ID_COL: 99999, TARGET: 0, ATTACK_CAT: "Normal"})
    probability, alerts, types = mock.predict(pd.concat([sample_flows, repeated], ignore_index=True))
    assert (probability[0], alerts[0], types[0]) == (probability[-1], alerts[-1], types[-1])


# MockPredictor.explain


def test_mock_explanation_has_one_entry_per_variable_sorted_by_effect(mock, sample_flows):
    contributions = mock.explain(sample_flows.iloc[0])
    assert len(contributions) == 35
    assert sorted(c["feature"] for c in contributions) == sorted(mock.info["feature_groups"])
    effects = [abs(c["contribution"]) for c in contributions]
    assert effects == sorted(effects, reverse=True)
    assert all(-1 <= c["contribution"] <= 1 for c in contributions)


def test_mock_explanation_values_come_from_the_file(mock, sample_flows):
    sample_flows.loc[3, "service"] = np.nan
    flow = sample_flows.iloc[3]
    values = {c["feature"]: c["value"] for c in mock.explain(flow)}
    assert values["service"] is None
    assert values["proto"] == flow["proto"] and isinstance(values["proto"], str)
    for feature in mock.info["numeric_cols"]:
        assert values[feature] == flow[feature] and type(values[feature]) in (int, float)


def test_mock_explanation_is_repeatable_and_json_ready(mock, sample_flows):
    flow = sample_flows.iloc[7]
    contributions = mock.explain(flow)
    assert mock.explain(flow.copy()) == contributions
    assert json.loads(json.dumps(contributions, allow_nan=False)) == contributions


def test_mock_contributions_add_up_positive_exactly_on_alerts(mock, sample_flows):
    # Así el panel de explicación no contradice la severidad: suma > 0 en las alertas y < 0 en el resto.
    alerts = mock.predict(sample_flows)[1]
    totals = np.array([sum(c["contribution"] for c in mock.explain(row)) for _, row in sample_flows.iterrows()])
    np.testing.assert_array_equal(totals > 0, alerts)
    np.testing.assert_array_equal(totals < 0, ~alerts)


# build_predictors


def test_project_artifacts_give_a_pipeline_predictor_per_model():
    predictors = build_predictors(load_artifacts()[1])
    assert list(predictors) == ["hist_gradient_boosting", "random_forest", "mlp", "logistic_regression"]
    assert all(isinstance(predictor, PipelinePredictor) for predictor in predictors.values())


def test_app_tests_use_only_the_mock_predictor(mock_artifacts):
    predictors = build_predictors(load_artifacts(mock_artifacts)[1])
    assert list(predictors) == ["mock"]
    assert isinstance(predictors["mock"], MockPredictor)


def test_trained_models_get_a_pipeline_predictor(exported, sample_flows):
    registry, models = load_artifacts(exported)
    predictors = build_predictors(models)
    assert list(predictors) == [m["name"] for m in registry["models"]]
    assert isinstance(predictors["mock"], MockPredictor)
    for name in ("model_a", "model_b"):
        predictor = predictors[name]
        assert isinstance(predictor, PipelinePredictor)
        expected = predict_flows(models[name]["model"], models[name]["info"], sample_flows)
        assert_same_predictions(predictor.predict(sample_flows), expected)
        # Los modelos de prueba tienen can_explain = false.
        assert predictor.explain(sample_flows.iloc[0]) is None


# PipelinePredictor.explain

def log_odds(probability):
    """log(p / (1 − p)): la salida en log-odds de la probabilidad."""
    return np.log(probability / (1 - probability))


# Detectores de prueba diminutos, uno por método de explicación: (método de preprocesamiento, estimador, explanation_method).
EXPLAINED_MODELS = {
    "hist_gradient_boosting": ("m1", lambda: HistGradientBoostingClassifier(max_iter=20, random_state=42), "shap_tree"),
    "random_forest": ("m2", lambda: RandomForestClassifier(n_estimators=5, max_depth=4, random_state=42), "shap_tree"),
    "logistic_regression": ("m2", lambda: LogisticRegression(max_iter=1000), "linear_logit"),
    "hist_gradient_boosting_m3": ("m3", lambda: HistGradientBoostingClassifier(max_iter=20, random_state=42), "shap_tree"),
}


def explained_predictor(kind, flows):
    """PipelinePredictor con un detector de prueba entrenado con sample_flows.csv y lo que explain lee de model.json."""
    method, estimator, explanation = EXPLAINED_MODELS[kind]
    detector = Pipeline([("preprocessor", build_preprocessor(method)), ("model", estimator())]).fit(flows, flows["label"])
    info = {"can_explain": True, "explanation_method": explanation, "feature_groups": feature_groups(detector["preprocessor"])}
    return PipelinePredictor(info, {"detector": detector, "attack_type_classifier": detector})


@pytest.mark.parametrize("kind", list(EXPLAINED_MODELS))
def test_explanation_has_one_entry_per_variable_sorted_by_effect(kind, sample_flows):
    predictor = explained_predictor(kind, sample_flows)
    flow = sample_flows.iloc[3]
    contributions = predictor.explain(flow)
    assert sorted(c["feature"] for c in contributions) == sorted(predictor.info["feature_groups"])
    effects = [abs(c["contribution"]) for c in contributions]
    assert effects == sorted(effects, reverse=True)
    values = {c["feature"]: c["value"] for c in contributions}
    assert values["proto"] == flow["proto"] and values["sbytes"] == flow["sbytes"]
    assert json.loads(json.dumps(contributions)) == contributions
    # Un modelo sin TTL no devuelve sus variables.
    assert any(c in values for c in TTL_COLS) == (not kind.endswith("m3"))


@pytest.mark.parametrize("kind", list(EXPLAINED_MODELS))
def test_explanation_adds_up_to_the_model_output(kind, sample_flows):
    # Positivo empuja hacia "ataque": la suma de las contribuciones más la base da la salida del
    # modelo para la clase 1 (log-odds en HistGradientBoosting y regresión logística, probabilidad en Random Forest).
    predictor = explained_predictor(kind, sample_flows)
    detector = predictor.model["detector"]
    estimator = detector["model"]
    for position in (0, 3, 250, 499):
        flow = sample_flows.iloc[position]
        total = sum(c["contribution"] for c in predictor.explain(flow))
        probability = detector.predict_proba(flow.to_frame().T.infer_objects())[0, list(estimator.classes_).index(1)]
        if isinstance(estimator, LogisticRegression):
            expected, base = log_odds(probability), estimator.intercept_[0]
        elif isinstance(estimator, RandomForestClassifier):
            expected, base = probability, predictor._explainer.expected_value[list(estimator.classes_).index(1)]
        else:
            expected, base = log_odds(probability), np.ravel(predictor._explainer.expected_value)[0]
        assert total + base == pytest.approx(expected, abs=1e-6)


def test_explainer_is_built_once(sample_flows):
    predictor = explained_predictor("random_forest", sample_flows)
    predictor.explain(sample_flows.iloc[0])
    explainer = predictor._explainer
    predictor.explain(sample_flows.iloc[1])
    assert predictor._explainer is explainer


def test_attack_class_is_found_by_name():
    # Si el ataque fuera classes_[0], las contribuciones de un modelo binario cambian de signo.
    class Linear:
        coef_ = np.array([[2.0, -1.0]])

    features = pd.DataFrame([[1.0, 3.0]])
    Linear.classes_ = np.array([0, 1])
    np.testing.assert_allclose(predictors_module._linear_contributions(Linear, features), [2.0, -3.0])
    Linear.classes_ = np.array([1, 0])
    np.testing.assert_allclose(predictors_module._linear_contributions(Linear, features), [-2.0, 3.0])


def test_unknown_explanation_method_is_an_error(sample_flows):
    predictor = explained_predictor("logistic_regression", sample_flows)
    predictor.info["explanation_method"] = "otro"
    with pytest.raises(ValueError, match="Método de explicación desconocido: otro"):
        predictor.explain(sample_flows.iloc[0])


def test_project_models_explain_as_decided(sample_flows):
    # Los 4 modelos registrados: los que explican dan una entrada por variable; MLP responde None.
    predictors = build_predictors(load_artifacts()[1])
    for name, predictor in predictors.items():
        contributions = predictor.explain(sample_flows.iloc[0])
        if name == "mlp":
            assert contributions is None
        else:
            assert sorted(c["feature"] for c in contributions) == sorted(predictor.info["feature_groups"])


# read_flows


def csv_bytes(flows):
    """Los flujos como el contenido de un CSV subido."""
    return flows.to_csv(index=False).encode("utf-8")


def read_error(content):
    with pytest.raises(FlowValidationError) as error:
        read_flows(content)
    return error.value


def test_read_flows_reads_the_categoricals_as_text(sample_flows):
    sample_flows["proto"] = sample_flows["proto"].astype(object)
    sample_flows.loc[0, "proto"] = "123"
    flows = read_flows(csv_bytes(sample_flows))
    assert flows.loc[0, "proto"] == "123"
    assert "-" in set(flows["service"])
    assert all(isinstance(value, str) for column in ("proto", "service", "state", ATTACK_CAT) for value in flows[column])
    pd.testing.assert_frame_equal(flows.drop(columns=["proto"]), sample_flows.drop(columns=["proto"]), check_dtype=False)


def test_read_flows_accepts_the_excel_bom(sample_flows):
    flows = read_flows(b"\xef\xbb\xbf" + csv_bytes(sample_flows))
    assert flows.columns[0] == ID_COL
    assert len(flows) == len(sample_flows)


@pytest.mark.parametrize("content", [b"", b"\n\n", b"id,proto\n"], ids=["no_bytes", "blank_lines", "header_only"])
def test_files_without_flows_are_empty(content):
    error = read_error(content)
    assert (error.code, str(error), error.details) == ("empty_file", "El archivo no tiene flujos para analizar.", None)


@pytest.mark.parametrize(
    "content",
    [b"\xff\xfe\x00garbage", b"id,proto\n1,2,3\n4,5,6\n", b"id,proto\n1,2\n4,5,6,7\n", b'id,proto\n"1,tcp\n'],
    ids=["not_utf8", "one_extra_field_in_every_row", "extra_fields_in_one_row", "unclosed_quote"],
)
def test_unreadable_files_are_rejected(content):
    error = read_error(content)
    assert error.code == "unreadable_file" and error.details is None
    assert str(error) == "No se pudo leer el archivo. Revisa que sea un CSV separado por comas, con una fila de encabezado."


def test_semicolon_separated_files_get_their_own_message(sample_flows):
    # Como los guarda Excel cuando la configuración regional usa la coma para los decimales.
    semicolons = sample_flows.to_csv(index=False, sep=";", decimal=",").encode("utf-8")
    assert b"0,1" in semicolons
    for content in (semicolons, semicolons.split(b"\n", 1)[0] + b"\n"):
        error = read_error(content)
        assert (error.code, error.details) == ("unreadable_file", None)
        assert str(error) == ("El archivo está separado por punto y coma (;), pero debe estar separado por comas, "
                              "como los CSV de UNSW-NB15. Guárdalo de nuevo con comas y vuelve a cargarlo.")


# validate_upload


def upload_error(flows, info, use_labels=True):
    with pytest.raises(FlowValidationError) as error:
        validate_upload(flows, info, use_labels)
    return error.value


def test_upload_has_labels_only_with_both_columns_and_use_labels(mock, sample_flows):
    assert validate_upload(sample_flows, mock.info, True) is True
    assert validate_upload(sample_flows, mock.info, False) is False
    assert validate_upload(sample_flows.drop(columns=TARGET_COLS), mock.info, True) is False


def test_extra_columns_are_ignored(mock, sample_flows):
    assert validate_upload(sample_flows.assign(comment="x"), mock.info, True) is True


def test_missing_columns_include_id_and_follow_the_contract_order(mock, sample_flows):
    error = upload_error(sample_flows.drop(columns=["sttl", "service", ID_COL]), mock.info)
    assert (error.code, error.details) == ("missing_columns", {"missing_columns": [ID_COL, "service", "sttl"]})


@pytest.mark.parametrize("present, missing", [(TARGET, ATTACK_CAT), (ATTACK_CAT, TARGET)])
def test_a_single_label_column_is_rejected_only_with_use_labels(mock, sample_flows, present, missing):
    flows = sample_flows.drop(columns=missing)
    error = upload_error(flows, mock.info)
    assert (error.code, error.details) == ("missing_label_column", {"missing_column": missing})
    assert str(error) == (f"El archivo trae la columna {present} pero no la columna {missing}. "
                          "Agrega la columna que falta o analízalo sin etiquetas.")
    assert validate_upload(flows, mock.info, False) is False


def test_labels_are_not_checked_without_use_labels(mock, sample_flows):
    sample_flows.loc[0, TARGET] = 2
    sample_flows.loc[1, ATTACK_CAT] = "worms"
    assert validate_upload(sample_flows, mock.info, False) is False


def test_only_the_first_problem_in_the_contract_order_is_reported(mock, sample_flows):
    # Se agregan problemas de atrás hacia adelante; cada uno pasa a ser el que se informa.
    flows = sample_flows.copy()
    flows[ID_COL] = flows[ID_COL].astype(object)
    steps = [
        ("invalid_labels", lambda f: f.loc.__setitem__((0, TARGET), 2)),
        ("invalid_values", lambda f: f.loc.__setitem__((1, "sbytes"), -1)),
        ("invalid_ids", lambda f: f.loc.__setitem__((2, ID_COL), "abc")),
        ("missing_label_column", lambda f: f.drop(columns=ATTACK_CAT, inplace=True)),
        ("missing_columns", lambda f: f.drop(columns="sttl", inplace=True)),
    ]
    for code, corrupt in steps:
        corrupt(flows)
        assert upload_error(flows, mock.info).code == code


# Analysis


@pytest.fixture
def labeled(mock, sample_flows):
    return run_analysis("test-labeled", sample_flows, mock, True)


def test_response_has_the_structure_of_the_contract_examples(labeled, contract_examples):
    response = labeled.response()
    example = contract_examples["4"][0]
    assert structure({**response, "flows": response["flows"][:1]}) == structure(example)
    for flow in response["flows"]:
        assert structure(flow) == structure(contract_examples["3"][0])


def test_flows_keep_the_file_order_and_the_model_predictions(mock, labeled, sample_flows):
    flows = labeled.response()["flows"]
    probability, alerts, types = mock.predict(sample_flows)
    assert [f["id"] for f in flows] == sample_flows[ID_COL].tolist()
    assert [f["attack_probability"] for f in flows] == probability.tolist()
    assert [f["is_alert"] for f in flows] == alerts.tolist()
    assert [f["predicted_attack_cat"] for f in flows] == types.tolist()
    assert [f["severity"] for f in flows] == [severity(p, mock.info["threshold"]) for p in probability]
    assert all(f["is_alert"] == (f["severity"] != "normal") for f in flows)
    assert [f["true_label"] for f in flows] == sample_flows[TARGET].tolist()
    assert [f["true_attack_cat"] for f in flows] == sample_flows[ATTACK_CAT].tolist()


def test_summary_counts_match_the_flows(labeled, sample_flows):
    response = labeled.response()
    summary, flows = response["summary"], response["flows"]
    alerts = np.array([f["is_alert"] for f in flows])
    assert response["model"] == {"name": "mock", "display_name": "Modelo simulado", "threshold": 0.31}
    assert summary["total_flows"] == len(sample_flows) == len(flows)
    assert summary["alerts"] == alerts.sum() == sum(summary["alerts_by_severity"].values())
    assert list(summary["alerts_by_severity"]) == ["critical", "high", "medium", "low"]
    assert summary["detection_rate"] == detection_rate(sample_flows[TARGET], alerts)
    assert summary["false_alarm_rate"] == false_alarm_rate(sample_flows[TARGET], alerts)


def test_unlabeled_analysis_hides_the_labels(mock, labeled, sample_flows):
    response = run_analysis("test-unlabeled", sample_flows, mock, False).response()
    assert response["has_labels"] is False
    assert (response["summary"]["detection_rate"], response["summary"]["false_alarm_rate"]) == (None, None)
    assert all(f["true_label"] is None and f["true_attack_cat"] is None for f in response["flows"])
    # Las predicciones son las mismas que con etiquetas.
    hidden = {"true_label": None, "true_attack_cat": None}
    assert response["flows"] == [{**f, **hidden} for f in labeled.response()["flows"]]


def test_file_without_attacks_has_no_detection_rate(mock, sample_flows):
    normals = sample_flows[sample_flows[ATTACK_CAT] == NORMAL_CAT]
    summary = run_analysis("test-normals", normals, mock, True).summary()
    assert summary["detection_rate"] is None
    assert summary["false_alarm_rate"] is not None


def test_empty_categoricals_and_decimal_ids_are_written_as_json(mock, sample_flows):
    sample_flows.loc[0, "service"] = np.nan
    sample_flows[ID_COL] = sample_flows[ID_COL].astype(float)
    sample_flows[TARGET] = sample_flows[TARGET].astype(float)
    response = run_analysis("test-json", sample_flows, mock, True).response()
    first = response["flows"][0]
    assert first["service"] is None
    assert type(first["id"]) is int and type(first["true_label"]) is int
    assert json.loads(json.dumps(response, allow_nan=False)) == response


def test_explain_gives_the_flow_and_its_contributions(mock, labeled, sample_flows):
    flow_id = int(sample_flows.loc[5, ID_COL])
    flow, contributions = labeled.explain(flow_id)
    assert flow == labeled.response()["flows"][5]
    assert contributions == mock.explain(sample_flows.iloc[5])
    assert labeled.explain(-1) is None


# AnalysisStore


def small_analysis(mock, sample_flows, analysis_id):
    return run_analysis(analysis_id, sample_flows.head(3), mock, True)


def test_store_keeps_the_most_recent_uploads_by_creation_order(mock, sample_flows):
    store = AnalysisStore()
    ids = [f"upload-{n}" for n in range(MAX_STORED_ANALYSES + 1)]
    for analysis_id in ids[:-1]:
        store.add(small_analysis(mock, sample_flows, analysis_id))
    # Consultar el más antiguo no lo renueva: es el que se borra al llegar uno más.
    assert store.get(ids[0]) is not None
    store.add(small_analysis(mock, sample_flows, ids[-1]))
    assert store.get(ids[0]) is None
    assert all(store.get(analysis_id) is not None for analysis_id in ids[1:])


def test_sample_analyses_do_not_count_and_regenerate_identically(mock, sample_flows):
    store = AnalysisStore()
    predictors = {"mock": mock}
    sample = store.find("sample-mock", predictors)
    unlabeled = store.find("sample-mock-unlabeled", predictors)
    assert (sample.analysis_id, sample.has_labels) == ("sample-mock", True)
    assert (unlabeled.analysis_id, unlabeled.has_labels) == ("sample-mock-unlabeled", False)
    for n in range(MAX_STORED_ANALYSES + 1):
        store.add(small_analysis(mock, sample_flows, f"upload-{n}"))
    assert store.get("sample-mock") is sample
    assert store.sample(mock, True) is sample
    # Un servidor recién iniciado la vuelve a generar, idéntica.
    assert AnalysisStore().find("sample-mock", predictors).response() == sample.response()


def test_unknown_analyses_are_not_found(mock):
    store = AnalysisStore()
    for analysis_id in ("a3f9c2e17b4d", "sample-ghost", "sample-ghost-unlabeled"):
        assert store.find(analysis_id, {"mock": mock}) is None


def test_sample_ids_round_trip():
    for name in ("mock", "random_forest"):
        for use_labels in (True, False):
            assert parse_sample_id(sample_id(name, use_labels)) == (name, use_labels)
    assert sample_id("mock", False) == "sample-mock-unlabeled"
    assert parse_sample_id("a3f9c2e17b4d") is None


def test_new_ids_are_twelve_hex_characters_and_unique():
    store = AnalysisStore()
    ids = {store.new_id() for _ in range(200)}
    assert len(ids) == 200
    assert all(re.fullmatch(r"[0-9a-f]{12}", analysis_id) for analysis_id in ids)


# Rutas HTTP


@pytest.fixture
def client(mock_artifacts):
    """La app con solo el modelo simulado registrado; with hace que corra el lifespan."""
    with TestClient(create_app(mock_artifacts)) as test_client:
        yield test_client


@pytest.fixture
def exported_client(exported):
    """La app con la carpeta temporal de exported: model_a, model_b y mock."""
    with TestClient(create_app(exported)) as test_client:
        yield test_client


def upload(client, content, **form):
    return client.post("/api/predict", files={"file": ("flows.csv", content)}, data=form)


def error_of(response, status):
    assert response.status_code == status
    body = response.json()
    assert list(body) == ["error"] and list(body["error"]) == ["code", "message", "details"]
    return body["error"]


def test_predict_with_the_sample_follows_the_contract(client, contract_examples):
    response = client.post("/api/predict", data={"use_sample": "true"})
    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"] == "sample-mock" and body["has_labels"] is True
    assert structure({**body, "flows": body["flows"][:1]}) == structure(contract_examples["4"][0])
    unlabeled = client.post("/api/predict", data={"use_sample": "true", "use_labels": "false"}).json()
    assert (unlabeled["analysis_id"], unlabeled["has_labels"]) == ("sample-mock-unlabeled", False)


def test_uploaded_file_gives_the_same_flows_as_the_sample(client, sample_flows):
    body = upload(client, csv_bytes(sample_flows)).json()
    assert re.fullmatch(r"[0-9a-f]{12}", body["analysis_id"])
    sample = client.post("/api/predict", data={"use_sample": "true"}).json()
    assert {**body, "analysis_id": None} == {**sample, "analysis_id": None}


def test_get_analysis_returns_what_predict_returned(client, sample_flows, mock_artifacts):
    created = upload(client, csv_bytes(sample_flows), use_labels="false").json()
    assert client.get(f"/api/analysis/{created['analysis_id']}").json() == created
    sample = client.post("/api/predict", data={"use_sample": "true"}).json()
    # Un servidor recién iniciado regenera la muestra.
    with TestClient(create_app(mock_artifacts)) as fresh:
        assert fresh.get("/api/analysis/sample-mock").json() == sample


def test_predict_uses_the_chosen_or_the_default_model(exported_client, sample_flows):
    chosen = upload(exported_client, csv_bytes(sample_flows), model="model_a").json()
    assert chosen["model"]["name"] == "model_a"
    default = exported_client.post("/api/predict", data={"use_sample": "true"}).json()
    assert default["analysis_id"] == "sample-mock" and default["model"]["name"] == "mock"
    sample_a = exported_client.post("/api/predict", data={"use_sample": "true", "model": "model_a"}).json()
    assert sample_a["analysis_id"] == "sample-model_a"
    assert sample_a["flows"] == chosen["flows"]


def test_predict_request_errors(client):
    assert error_of(client.post("/api/predict"), 400)["code"] == "no_file"
    both = client.post("/api/predict", files={"file": ("flows.csv", b"id\n1\n")}, data={"use_sample": "true"})
    assert error_of(both, 400)["code"] == "file_and_sample"
    unknown = error_of(client.post("/api/predict", data={"use_sample": "true", "model": "ghost"}), 400)
    assert unknown == {"code": "unknown_model", "details": {"model": "ghost"},
                       "message": "El modelo «ghost» no está disponible. Elige otro en la pantalla Modelos."}


def test_file_size_limit(client):
    assert MAX_UPLOAD_BYTES == 25_000_000
    too_large = error_of(upload(client, b"x" * (MAX_UPLOAD_BYTES + 1)), 413)
    assert too_large == {"code": "file_too_large", "details": {"max_mb": MAX_UPLOAD_MB},
                         "message": "El archivo pesa más de 25 MB, que es el máximo permitido."}
    # Justo en el límite se acepta y se lee: una sola línea, sin flujos.
    assert error_of(upload(client, b"x" * MAX_UPLOAD_BYTES), 400)["code"] == "empty_file"


def test_file_errors_keep_the_contract_order_and_details(client, sample_flows):
    # empty_file va antes que unknown_model, y unknown_model antes que missing_columns.
    assert error_of(upload(client, b"id,proto\n", model="ghost"), 400)["code"] == "empty_file"
    missing = csv_bytes(sample_flows.drop(columns="sttl"))
    assert error_of(upload(client, missing, model="ghost"), 400)["code"] == "unknown_model"
    assert error_of(upload(client, b"\xff\xfe"), 400)["code"] == "unreadable_file"
    sample_flows.loc[[3, 7], "sbytes"] = -1
    negative = error_of(upload(client, csv_bytes(sample_flows)), 400)
    assert negative["code"] == "invalid_values"
    assert negative["details"] == {"reason": "negative", "columns": ["sbytes"], "rows": [5, 9], "total_rows": 2}


def test_failed_uploads_are_not_stored(client, sample_flows):
    upload(client, csv_bytes(sample_flows.drop(columns="sttl")))
    assert client.app.state.analyses._uploaded == {}


def test_explain_follows_the_contract(client, mock, sample_flows, contract_examples):
    flow_id = int(sample_flows.loc[5, ID_COL])
    body = client.get(f"/api/explain/{flow_id}", params={"analysis_id": "sample-mock"}).json()
    example = contract_examples["5"][0]
    first = slice(0, 1)
    assert structure({**body, "contributions": body["contributions"][first]}) == structure(
        {**example, "contributions": example["contributions"][first]})
    assert body["analysis_id"] == "sample-mock" and body["can_explain"] is True
    assert body["flow"]["id"] == flow_id
    assert body["contributions"] == mock.explain(sample_flows.iloc[5])


def test_model_without_explanation_returns_null_contributions(exported_client, sample_flows):
    flow_id = int(sample_flows.loc[0, ID_COL])
    body = exported_client.get(f"/api/explain/{flow_id}", params={"analysis_id": "sample-model_a"}).json()
    assert (body["can_explain"], body["contributions"]) == (False, None)


def test_explain_errors(client, sample_flows):
    assert error_of(client.get("/api/explain/1"), 400)["code"] == "missing_analysis_id"
    assert error_of(client.get("/api/explain/1", params={"analysis_id": ""}), 400)["code"] == "missing_analysis_id"
    gone = error_of(client.get("/api/explain/1", params={"analysis_id": "a3f9c2e17b4d"}), 404)
    assert (gone["code"], gone["details"]) == ("analysis_not_found", {"analysis_id": "a3f9c2e17b4d"})
    for flow_id, details_id in (("999999999", 999999999), ("abc", "abc"), ("1.5", "1.5")):
        error = error_of(client.get(f"/api/explain/{flow_id}", params={"analysis_id": "sample-mock"}), 404)
        assert error == {"code": "flow_not_found", "details": {"id": details_id},
                         "message": f"El flujo {flow_id} no está en este análisis."}


def test_missing_analyses_are_not_found(client):
    for analysis_id in ("a3f9c2e17b4d", "sample-ghost"):
        error = error_of(client.get(f"/api/analysis/{analysis_id}"), 404)
        assert error["message"] == "Este análisis ya no está disponible. Vuelve a cargar el archivo para analizarlo de nuevo."


def test_models_and_metrics_are_the_contract_examples(client, contract_examples):
    assert client.get("/api/models").json() == contract_examples["6"][0]
    assert client.get("/api/metrics").json() == contract_examples["7"][0]


def test_models_and_metrics_of_trained_models(exported_client, exported):
    models = exported_client.get("/api/models").json()
    assert [m["name"] for m in models["models"]] == ["model_a", "model_b", "mock"]
    metrics = exported_client.get("/api/metrics").json()["models"]
    info_a = read_model_info("model_a", exported)
    assert metrics[0] == {"name": "model_a", "display_name": info_a["display_name"], "is_mock": False,
                          **info_a["test_metrics"], "complexity": info_a["complexity"]}


def test_general_errors(client):
    assert error_of(client.get("/nowhere"), 404) == {
        "code": "not_found", "message": "La dirección pedida no existe.", "details": None}
    not_allowed = client.get("/api/predict")
    assert error_of(not_allowed, 405)["code"] == "method_not_allowed"
    assert not_allowed.headers["allow"] == "POST"
    invalid = error_of(client.post("/api/predict", data={"use_sample": "true", "use_labels": "maybe"}), 400)
    assert invalid == {"code": "invalid_request", "details": {"field": "use_labels"},
                       "message": "El pedido no es válido: revisa el campo use_labels."}


def test_static_files_are_served_after_the_api(client):
    response = client.get("/sample_flows.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert response.content == DEMO_SAMPLE_CSV.read_bytes()
    # Sin fallback: una dirección que no existe da not_found, también si la pide un navegador.
    for path in ("/missing.html", "/simulation", "/api/missing"):
        assert error_of(client.get(path, headers={"accept": "text/html"}), 404)["code"] == "not_found"
    assert client.get("/api/models").status_code == 200


def test_responses_ask_the_browser_to_revalidate(client):
    # Así una versión nueva de la interfaz llega al navegador sin recarga forzada.
    for path in ("/index.html", "/js/common.js", "/styles.css", "/assets/icons.svg", "/api/models"):
        assert client.get(path).headers["cache-control"] == "no-cache", path
    # Si el archivo no cambió, la revalidación responde 304 sin volver a enviarlo.
    etag = client.get("/js/analysis.js").headers["etag"]
    assert client.get("/js/analysis.js", headers={"If-None-Match": etag}).status_code == 304


def test_damaged_form_is_an_invalid_request(client):
    response = client.post("/api/predict", content=b"not multipart",
                           headers={"content-type": "multipart/form-data; boundary=xyz"})
    assert error_of(response, 400) == {"code": "invalid_request", "details": {"field": None},
                                       "message": "El pedido no es válido."}


def test_unexpected_errors_hide_the_python_error(sample_flows, mock_artifacts):
    def broken_predict(flows):
        raise RuntimeError("detalle interno")

    with TestClient(create_app(mock_artifacts), raise_server_exceptions=False) as test_client:
        test_client.app.state.predictors["mock"].predict = broken_predict
        response = upload(test_client, csv_bytes(sample_flows))
    error = error_of(response, 500)
    assert error["code"] == "internal_error" and "detalle interno" not in response.text


def test_app_does_not_start_with_damaged_artifacts(exported, caplog):
    (exported / REGISTRY_PATH.name).write_text("{", encoding="utf-8")
    with caplog.at_level(logging.ERROR), pytest.raises(ArtifactError, match="registry.json está dañado"):
        with TestClient(create_app(exported)):
            pass
    assert "No se pudieron cargar los modelos" in caplog.text


# Simulación (WS /ws/simulate)


@pytest.fixture
def interval(monkeypatch):
    """Devuelve una función que cambia la pausa entre flujos de la simulación, solo durante la prueba."""
    def set_interval(seconds):
        monkeypatch.setattr(routes, "SIMULATION_INTERVAL_SECONDS", seconds)
    set_interval(0)
    return set_interval


def receive_until_end(websocket):
    """Los mensajes que llegan hasta "end" o "error" (incluido), y comprueba que después se cierra la conexión."""
    messages = []
    while not messages or messages[-1]["type"] not in ("end", "error"):
        messages.append(websocket.receive_json())
    with pytest.raises(WebSocketDisconnect):
        websocket.receive_json()
    return messages


def simulate(client, *messages):
    """Abre una simulación, envía los mensajes y devuelve todo lo que llega hasta el cierre."""
    with client.websocket_connect("/ws/simulate") as websocket:
        for message in messages:
            websocket.send_text(message if isinstance(message, str) else json.dumps(message))
        return receive_until_end(websocket)


@pytest.mark.parametrize("use_labels", [True, False])
def test_simulation_replays_the_analysis(client, interval, contract_examples, use_labels):
    analysis = client.post("/api/predict", data={"use_sample": "true", "use_labels": str(use_labels).lower()}).json()
    messages = simulate(client, {"type": "start", "analysis_id": analysis["analysis_id"]})
    started, flows, end = messages[0], messages[1:-1], messages[-1]
    assert started == {"type": "started", "analysis_id": analysis["analysis_id"], "model": analysis["model"],
                       "has_labels": use_labels, "total_flows": 500, "speed": 1}
    assert [m["position"] for m in flows] == list(range(1, 501))
    assert all(m["type"] == "flow" and m["total_flows"] == 500 for m in flows)
    assert [m["flow"] for m in flows] == analysis["flows"]
    assert end == {"type": "end", "total_flows": 500}
    examples = contract_examples["8"]
    assert structure(started) == structure(examples[1]) and structure(flows[0]) == structure(examples[2])


def test_simulation_regenerates_the_sample(client, interval):
    messages = simulate(client, {"type": "start", "analysis_id": "sample-mock-unlabeled", "speed": 4})
    assert messages[0]["speed"] == 4 and messages[0]["has_labels"] is False
    assert messages[-1] == {"type": "end", "total_flows": 500}


def test_simulation_continues_if_its_analysis_is_removed(client, interval, sample_flows):
    small = sample_flows.head(20)
    created = upload(client, csv_bytes(small)).json()
    interval(0.2)
    with client.websocket_connect("/ws/simulate") as websocket:
        websocket.send_json({"type": "start", "analysis_id": created["analysis_id"]})
        assert websocket.receive_json()["type"] == "started"
        assert websocket.receive_json()["position"] == 1
        websocket.send_json({"type": "pause"})
        for _ in range(MAX_STORED_ANALYSES):
            upload(client, csv_bytes(small))
        # El análisis ya no está en memoria, pero la simulación lo sigue reproduciendo.
        assert error_of(client.get(f"/api/analysis/{created['analysis_id']}"), 404)["code"] == "analysis_not_found"
        interval(0)
        websocket.send_json({"type": "resume"})
        messages = receive_until_end(websocket)
    flows = [m for m in messages if m["type"] == "flow"]
    assert [m["position"] for m in flows] == list(range(2, 21))
    assert [m["flow"] for m in flows] == created["flows"][1:]
    assert messages[-1] == {"type": "end", "total_flows": 20}


def test_pause_stops_the_flows(client, interval):
    interval(0.2)
    with client.websocket_connect("/ws/simulate") as websocket:
        websocket.send_json({"type": "start", "analysis_id": "sample-mock"})
        websocket.receive_json()
        assert websocket.receive_json()["position"] == 1
        websocket.send_json({"type": "pause"})
        time.sleep(0.5)
        # Si la pausa no funcionara, antes del error llegarían más flujos.
        websocket.send_json({"type": "jump"})
        assert websocket.receive_json()["error"]["code"] == "invalid_message"


def test_resume_without_pause_does_nothing(client, interval, sample_flows):
    created = upload(client, csv_bytes(sample_flows.head(5))).json()
    messages = simulate(client, {"type": "start", "analysis_id": created["analysis_id"]}, {"type": "resume"})
    assert [m["position"] for m in messages[1:-1]] == [1, 2, 3, 4, 5]
    assert messages[-1] == {"type": "end", "total_flows": 5}


def test_set_speed_changes_the_pace(client, interval, sample_flows):
    created = upload(client, csv_bytes(sample_flows.head(5))).json()
    interval(0.4)
    with client.websocket_connect("/ws/simulate") as websocket:
        websocket.send_json({"type": "start", "analysis_id": created["analysis_id"]})
        websocket.receive_json()
        websocket.receive_json()
        websocket.send_json({"type": "set_speed", "speed": 4})
        begin = time.perf_counter()
        messages = receive_until_end(websocket)
        elapsed = time.perf_counter() - begin
    assert messages[-1]["type"] == "end"
    # A 1× los 4 flujos que faltan tardarían 1,6 s; a 4× tardan unos 0,4 + 3 × 0,1 = 0,7 s.
    assert elapsed < 1.2


START = {"type": "start", "analysis_id": "sample-mock"}


@pytest.mark.parametrize(
    "messages",
    [
        ["hola"],
        [{"type": "jump"}],
        [["start"]],
        [{"type": "start"}],
        [{"type": "start", "analysis_id": 5}],
        [{"type": "pause"}],
        [START, START],
        [START, {"type": "set_speed"}],
    ],
    ids=["not_json", "unknown_type", "not_an_object", "no_analysis_id", "analysis_id_not_text",
         "pause_before_start", "second_start", "set_speed_without_speed"],
)
def test_invalid_messages_end_the_simulation(client, interval, messages):
    interval(0.2)
    error = simulate(client, *messages)[-1]
    assert error == {"type": "error", "error": {
        "code": "invalid_message", "details": None,
        "message": "La simulación recibió un mensaje que no entiende. Reinicia la simulación."}}


def test_binary_message_is_invalid(client):
    with client.websocket_connect("/ws/simulate") as websocket:
        websocket.send_bytes(b"start")
        assert receive_until_end(websocket)[-1]["error"]["code"] == "invalid_message"


@pytest.mark.parametrize("speed", [3, True, "2", 2.0])
def test_invalid_speeds_end_the_simulation(client, interval, speed):
    interval(0.2)
    for messages in ([{**START, "speed": speed}], [START, {"type": "set_speed", "speed": speed}]):
        error = simulate(client, *messages)[-1]
        assert error == {"type": "error", "error": {
            "code": "invalid_speed", "details": {"speed": speed}, "message": "La velocidad debe ser 1×, 2× o 4×."}}


def test_simulation_of_a_missing_analysis(client):
    messages = simulate(client, {"type": "start", "analysis_id": "a3f9c2e17b4d"})
    assert len(messages) == 1
    assert messages[0]["error"]["code"] == "analysis_not_found"
    assert messages[0]["error"]["details"] == {"analysis_id": "a3f9c2e17b4d"}


def test_unexpected_simulation_error_hides_the_python_error(client, interval, sample_flows, caplog):
    created = upload(client, csv_bytes(sample_flows.head(3))).json()
    analysis = client.app.state.analyses.get(created["analysis_id"])

    def broken_flow_responses(positions=None):
        raise RuntimeError("detalle interno")

    analysis.flow_responses = broken_flow_responses
    with caplog.at_level(logging.ERROR):
        messages = simulate(client, {"type": "start", "analysis_id": created["analysis_id"]})
    assert messages[-1]["error"]["code"] == "internal_error"
    assert "detalle interno" not in json.dumps(messages)
    assert "detalle interno" in caplog.text


# Contraste de los colores de styles.css
#
# Fórmulas de WCAG 2.2 (https://www.w3.org/TR/WCAG22/): luminancia relativa y razón de contraste del
# glosario; mínimos de 4,5:1 para texto (criterio 1.4.3) y 3:1 para íconos, bordes y barras (1.4.11).

STYLES_CSS = STATIC_DIR / "styles.css"
THEME_BLOCKS = {
    "light": r':root,\s*\[data-theme="light"\]\s*\{(.*?)\}',
    "dark": r'\[data-theme="dark"\]\s*\{(.*?)\}',
}

# [qué se comprueba, color, fondo, mínimo]. Un fondo "a/b" es el color a (con transparencia) sobre el
# b; "heat@max" es la celda más intensa de la matriz 9×9.
CONTRAST_CHECKS = [
    ("Texto sobre el fondo", "text", "bg", 4.5),
    ("Texto sobre una tarjeta", "text", "surface", 4.5),
    ("Texto sobre una zona sombreada", "text", "surface-2", 4.5),
    ("Texto secundario sobre una tarjeta", "text-muted", "surface", 4.5),
    ("Texto secundario sobre una zona sombreada", "text-muted", "surface-2", 4.5),
    ("Texto secundario sobre el fondo", "text-muted", "bg", 4.5),
    ("Enlace sobre una tarjeta", "primary", "surface", 4.5),
    ("Texto de botón principal", "on-primary", "primary", 4.5),
    ("Texto sobre la fila seleccionada", "text", "primary-soft/surface", 4.5),
    ("Contorno de foco sobre el fondo", "focus", "bg", 3),
    ("Contorno de foco sobre una tarjeta", "focus", "surface", 3),
    ("Borde de los controles", "border-strong", "surface", 3),
    *[check for level in ("critical", "high", "medium", "low", "normal") for check in (
        (f"Severidad {level}: texto de la insignia", f"sev-{level}", f"sev-{level}-bg/surface", 4.5),
        (f"Severidad {level}: ícono y borde sobre una tarjeta", f"sev-{level}", "surface", 3),
    )],
    ("Explicación: número hacia «ataque»", "push-attack", "surface", 4.5),
    ("Explicación: número hacia «normal»", "push-normal", "surface", 4.5),
    ("Explicación: barra hacia «ataque»", "push-attack", "surface-2", 3),
    ("Explicación: barra hacia «normal»", "push-normal", "surface-2", 3),
    ("Resultado correcto", "ok", "surface", 4.5),
    ("Resultado incorrecto", "bad", "surface", 4.5),
    ("Texto del aviso", "text", "warn-bg/surface", 4.5),
    ("Título del aviso", "warn-text", "warn-bg/surface", 4.5),
    ("Aviso de modelo simulado", "warn-text", "warn-bg/surface", 4.5),
    ("Texto del recuadro informativo", "text", "info-bg/surface", 4.5),
    ("Error: texto", "text", "sev-critical-bg/surface", 4.5),
    ("Matriz: número sobre la celda más intensa", "text", "heat@max/surface", 4.5),
    ("Animación: punto sin evaluar", "text-muted", "surface", 3),
    ("Animación: carriles entre nodos", "border-strong", "surface", 3),
    ("Animación: texto del nodo Modelo", "text", "primary-soft/surface", 4.5),
    ("Animación: borde del nodo Modelo", "primary", "surface", 3),
    ("Animación: título y conteo de «Alertas»", "sev-critical", "sev-critical-bg/surface", 4.5),
    ("Animación: borde de «Alertas»", "sev-critical", "surface", 3),
    ("Animación: título y conteo de «Tráfico normal»", "sev-normal", "sev-normal-bg/surface", 4.5),
    ("Animación: borde de «Tráfico normal»", "sev-normal", "surface", 3),
]


def theme_tokens(theme):
    """Las variables (--nombre: valor) de un tema de styles.css."""
    css = STYLES_CSS.read_text(encoding="utf-8")
    block = re.search(THEME_BLOCKS[theme], css, re.DOTALL).group(1)
    return {name: value.strip() for name, value in re.findall(r"--([\w-]+)\s*:\s*([^;]+);", block)}


def parse_color(text):
    """(r, g, b, alfa) de un color #RRGGBB o rgb()/rgba()."""
    if m := re.fullmatch(r"#([0-9a-fA-F]{6})", text):
        n = int(m.group(1), 16)
        return (n >> 16) & 255, (n >> 8) & 255, n & 255, 1.0
    m = re.fullmatch(r"rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*(?:,\s*([\d.]+)\s*)?\)", text)
    assert m, f"Color no reconocido: {text}"
    return float(m.group(1)), float(m.group(2)), float(m.group(3)), float(m.group(4) or 1)


def resolve(tokens, name):
    """El color opaco de un nombre de CONTRAST_CHECKS."""
    if "/" in name:
        top, base = name.split("/")
        r, g, b, a = resolve_raw(tokens, top)
        br, bg, bb, _ = resolve(tokens, base)
        return r * a + br * (1 - a), g * a + bg * (1 - a), b * a + bb * (1 - a), 1.0
    return resolve_raw(tokens, name)


def resolve_raw(tokens, name):
    if name == "heat@max":
        r, g, b = (float(v) for v in tokens["heat"].split(","))
        return r, g, b, float(tokens["heat-max"])
    return parse_color(tokens[name])


def luminance(color):
    def linear(c8):
        c = c8 / 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b, _ = color
    return 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)


def contrast(a, b):
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def test_contrast_formula_matches_wcag_limits():
    black, white = (0, 0, 0, 1.0), (255, 255, 255, 1.0)
    assert contrast(black, white) == pytest.approx(21)
    assert contrast(white, white) == pytest.approx(1)


def test_both_themes_define_the_same_colors():
    light, dark = theme_tokens("light"), theme_tokens("dark")
    assert set(light) == set(dark)
    assert len(light) > 30


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_palette_colors_have_enough_contrast(theme):
    tokens = theme_tokens(theme)
    failures = []
    for label, fg, bg, minimum in CONTRAST_CHECKS:
        ratio = contrast(resolve(tokens, fg), resolve(tokens, bg))
        if ratio < minimum:
            failures.append(f"{label}: {ratio:.2f}:1 (mínimo {minimum}:1)")
    assert len(CONTRAST_CHECKS) == 42
    assert not failures, "\n".join(failures)


# Frontend: archivos de static/

PAGES = ["index.html", "simulation.html", "compare.html"]
CONTENT_TYPES = {".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml", ".csv": "text/csv"}
# Elementos que js/common.js busca en todas las páginas.
COMMON_IDS = ["main", "modelPill", "themeToggle", "pageStatus", "screen"]


def local_references(html):
    """Archivos propios que enlaza una página (href y src que no son externos ni anclas)."""
    refs = re.findall(r'(?:href|src)="([^"#]+)', html)
    return sorted({ref.split("?")[0] for ref in refs if not ref.startswith(("http:", "https:", "mailto:"))})


@pytest.mark.parametrize("page_name", PAGES)
def test_pages_and_their_files_are_served(client, page_name):
    response = client.get("/" + page_name)
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/html")
    for ref in local_references(response.text):
        served = client.get("/" + ref)
        assert served.status_code == 200, ref
        suffix = "." + ref.rsplit(".", 1)[-1]
        assert served.headers["content-type"].startswith(CONTENT_TYPES[suffix]), ref
    assert client.get("/").text == client.get("/index.html").text


@pytest.mark.parametrize("page_name", PAGES)
def test_pages_have_the_common_structure(page_name):
    html = (STATIC_DIR / page_name).read_text(encoding="utf-8")
    for element_id in COMMON_IDS:
        assert f'id="{element_id}"' in html, element_id
    # El modo se aplica antes de cargar los estilos, para que no parpadee.
    assert html.index("localStorage.getItem('ntd-theme')") < html.index('href="styles.css"')
    assert 'lang="es"' in html and html.count('aria-current="page"') == 1


def icon_names():
    """Los íconos de assets/icons.svg."""
    return set(re.findall(r'<symbol id="icon-([a-z-]+)"', (STATIC_DIR / "assets" / "icons.svg").read_text(encoding="utf-8")))


def test_every_icon_used_exists():
    used = set()
    for path in [*STATIC_DIR.glob("*.html"), *STATIC_DIR.glob("js/*.js")]:
        text = path.read_text(encoding="utf-8")
        used |= set(re.findall(r"#icon-([a-z-]+)", text))
        used |= set(re.findall(r"icon(?:Button)?\('([a-z-]+)'", text))
        used |= set(re.findall(r"icon: '([a-z-]+)'", text))
    assert used, "no se encontró ningún ícono usado"
    assert used <= icon_names(), used - icon_names()
    assert len(icon_names()) == 26


def js_object_keys(text, name):
    """Las claves de un objeto literal "export const NAME = { ... };" de common.js."""
    body = re.search(rf"export const {name} = \{{(.*?)\n\}};", text, re.DOTALL).group(1)
    return re.findall(r"^\s*([A-Za-z_]+):", body, re.MULTILINE)


def test_common_js_texts_cover_the_model_variables_and_attack_types(mock):
    text = (STATIC_DIR / "js" / "common.js").read_text(encoding="utf-8")
    assert sorted(js_object_keys(text, "FEATURE_LABELS")) == sorted(mock.info["feature_groups"])
    assert sorted(js_object_keys(text, "ATTACK_TYPE_DESCRIPTIONS")) == sorted(ATTACK_TYPES)
    assert sorted(js_object_keys(text, "SEVERITIES")) == sorted(["critical", "high", "medium", "low", "normal"])
    assert "arXiv:1711.02825" in text


# Frontend en un navegador real (Playwright). Se saltan solas si falta Playwright o su Chromium.


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live_server(mock_artifacts):
    """La app corriendo con Uvicorn en un puerto libre, con solo el modelo simulado registrado."""
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(create_app(mock_artifacts), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="module")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api", reason="Falta Playwright (uv add -r requirements.txt)")
    with sync_api.sync_playwright() as p:
        try:
            chromium = p.chromium.launch()
        except sync_api.Error:
            pytest.skip("Falta el Chromium de Playwright (uv run playwright install --with-deps chromium)")
        yield chromium
        chromium.close()


@pytest.fixture
def page(browser, live_server):
    context = browser.new_context(base_url=live_server)
    yield context.new_page()
    context.close()


def test_header_shows_the_chosen_model_and_the_mock_tag(page):
    page.goto("/index.html")
    pill = page.locator("#modelPill")
    pill.wait_for(state="visible")
    assert "Modelo simulado" in pill.inner_text() and "Simulado" in pill.inner_text()
    # Los íconos del sprite se dibujan: el de la navegación tiene tamaño.
    assert page.evaluate("document.querySelector('.mainnav svg use').getBBox().width") > 0


def test_theme_toggle_is_saved_and_applied_before_painting(page):
    page.goto("/index.html")
    start = page.evaluate("document.documentElement.dataset.theme")
    page.locator("#themeToggle").click()
    other = "dark" if start == "light" else "light"
    assert page.evaluate("document.documentElement.dataset.theme") == other
    # Al recargar, el modo guardado ya está puesto cuando se lee el HTML, antes de los estilos.
    page.add_init_script("document.addEventListener('readystatechange', () => { window.firstTheme ??= document.documentElement.dataset.theme; });")
    page.reload()
    assert page.evaluate("window.firstTheme") == other


def test_unknown_model_shows_its_name_without_guessing_if_it_is_mock(page):
    page.goto("/index.html")
    result = page.evaluate("""async () => {
        const c = await import('/js/common.js');
        const models = await c.fetchModels();
        const gone = c.modelName(models, { name: 'removed_model', display_name: 'Modelo retirado' });
        const mock = c.modelName(models, { name: 'mock', display_name: 'Modelo simulado' });
        return {
            goneText: gone.textContent, goneTag: !!gone.querySelector('.tag-mock'),
            goneMock: c.isMockModel(models, 'removed_model'),
            mockTag: !!mock.querySelector('.tag-mock'), mockMock: c.isMockModel(models, 'mock'),
        };
    }""")
    assert result == {"goneText": "Modelo retirado", "goneTag": False, "goneMock": None,
                      "mockTag": True, "mockMock": True}


def test_without_server_the_page_shows_network_error(page):
    page.route("**/api/models", lambda route: route.abort())
    page.goto("/index.html")
    alert = page.locator("#pageStatus [role=alert]")
    alert.wait_for()
    assert "No se pudo conectar con el servidor" in alert.inner_text()


# Consola (index.html y js/analysis.js)


def test_upload_help_and_page_size_match_the_code():
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert int(re.search(r"Máximo (\d+) MB", html).group(1)) == MAX_UPLOAD_MB
    script = (STATIC_DIR / "js" / "analysis.js").read_text(encoding="utf-8")
    page_size = int(re.search(r"const PAGE_SIZE = (\d+);", script).group(1))
    assert f"{page_size} flujos por página" in html


def percent(value):
    """Una tasa como la muestra la consola (es-CO, un decimal)."""
    return f"{value * 100:.1f}".replace(".", ",") + "%"


def load_sample(page, labeled=True):
    page.goto("/index.html")
    page.locator("#sampleLabeled" if labeled else "#sampleUnlabeled").click()
    page.locator("#results").wait_for(state="visible")


def api_json(page, path):
    return page.request.get(path).json()


def queue_ids(page):
    return [int(i) for i in page.locator("#queueTable tbody tr").evaluate_all("rows => rows.map(r => r.dataset.id)")]


def test_console_with_the_labeled_sample(page):
    load_sample(page)
    analysis = api_json(page, "/api/analysis/sample-mock")
    summary = analysis["summary"]
    assert page.url.endswith("index.html?analysis=sample-mock")
    kpis = page.locator("#kpis").inner_text()
    assert percent(summary["detection_rate"]) in kpis and percent(summary["false_alarm_rate"]) in kpis
    assert page.locator("#queueCount").inner_text() == f"Mostrando 1–25 de {summary['alerts']} alertas"
    assert "Clase real" in page.locator("#queueTable thead").inner_text()
    assert page.locator("#mockSlot [role=note]").is_visible() and page.locator("#sampleNote").is_visible()
    assert "Muestra de demostración" in page.locator("#analysisBar").inner_text()
    # Orden por probabilidad (desempate: orden del archivo) entre las alertas.
    alerts = [f for f in analysis["flows"] if f["is_alert"]]
    expected = [f["id"] for f in sorted(alerts, key=lambda f: -f["attack_probability"])][:25]
    assert queue_ids(page) == expected


def rate_tip_texts(flows):
    """Lo que debe decir la ayuda de Detección y de Falsas alarmas."""
    attacks = [f for f in flows if f["true_label"] == 1]
    normals = [f for f in flows if f["true_label"] == 0]
    detected = sum(f["is_alert"] for f in attacks)
    false_alarms = sum(f["is_alert"] for f in normals)
    return (f"{detected} de {len(attacks)} ataques reales dieron alerta.",
            f"{false_alarms} de {len(normals)} flujos normales dieron alerta.")


def test_rate_tips_say_which_flows_each_rate_uses(page):
    load_sample(page)
    detection_tip, false_alarm_tip = rate_tip_texts(api_json(page, "/api/analysis/sample-mock")["flows"])
    cards = page.locator(".kpi.has-tip")
    assert cards.count() == 2
    for card, expected in zip(cards.all(), (detection_tip, false_alarm_tip)):
        tip = card.locator(".kpi-tip")
        assert tip.is_hidden()
        card.hover()
        assert tip.is_visible() and tip.inner_text().startswith(expected)
        assert "no suman 100 %" in tip.inner_text()
        # Los lectores de pantalla la leen como descripción del indicador.
        assert card.get_attribute("aria-describedby") == tip.get_attribute("id")
    # Con el teclado también aparece.
    page.mouse.move(0, 0)
    cards.first.focus()
    assert cards.first.locator(".kpi-tip").is_visible()


def test_console_with_the_unlabeled_sample(page):
    load_sample(page, labeled=False)
    assert page.locator("#kpis").inner_text().count("Requiere etiquetas reales") == 2
    assert page.locator(".kpi.has-tip").count() == 0
    assert "Clase real" not in page.locator("#queueTable thead").inner_text()
    assert "Sin etiquetas" in page.locator("#analysisBar").inner_text()


def test_filters_order_and_pages(page):
    load_sample(page)
    summary = api_json(page, "/api/analysis/sample-mock")["summary"]
    for severity, label in (("critical", "Crítica"), ("high", "Alta"), ("medium", "Media"), ("low", "Baja")):
        page.locator(f'#filters [data-value="{severity}"]').click()
        assert page.locator("#queueCount").inner_text().endswith(f"de {summary['alerts_by_severity'][severity]} alertas")
        badges = page.locator("#queueTable tbody .sev-badge").all_inner_texts()
        assert badges and all(text.strip() == label for text in badges)
    page.locator('#filters [data-value="all"]').click()
    page.locator("#sortSelect").select_option("file")
    flows = api_json(page, "/api/analysis/sample-mock")["flows"]
    assert page.locator("#queueCount").inner_text() == f"Mostrando 1–25 de {summary['total_flows']} flujos"
    assert queue_ids(page) == [f["id"] for f in flows[:25]]
    page.locator("#nextPage").click()
    assert queue_ids(page) == [f["id"] for f in flows[25:50]]
    assert page.locator("#pageInfo").inner_text() == "Página 2 de 20"


def test_flow_panel_with_mouse_and_keyboard(page):
    load_sample(page)
    first = page.locator("#queueTable tbody tr").first
    flow_id = first.get_attribute("data-id")
    first.click()
    assert page.locator("#drawerTitle").inner_text() == f"Flujo {flow_id}"
    assert page.url.endswith(f"?analysis=sample-mock&flow={flow_id}")
    page.locator(".expl-list li").first.wait_for()
    assert page.locator(".expl-list li").count() == 10
    page.get_by_role("button", name="Ver todas (35)").click()
    assert page.locator(".expl-list li").count() == 35
    page.keyboard.press("Escape")
    assert page.locator(".drawer").count() == 0
    assert page.evaluate("document.activeElement.dataset.id") == flow_id
    assert page.url.endswith("?analysis=sample-mock")
    second = page.locator("#queueTable tbody tr").nth(1)
    second.focus()
    page.keyboard.press("Enter")
    assert page.locator("#drawerTitle").inner_text() == f"Flujo {second.get_attribute('data-id')}"


def test_direct_link_to_a_flow(page):
    flows = api_json(page, "/api/analysis/sample-mock")["flows"]
    normal = next(f for f in flows if not f["is_alert"])
    page.goto(f"/index.html?analysis=sample-mock&flow={normal['id']}")
    assert page.locator("#drawerTitle").inner_text() == f"Flujo {normal['id']}"
    assert page.locator('#filters [data-value="all"]').get_attribute("aria-checked") == "true"
    assert page.locator(f'#queueTable tbody tr[data-id="{normal["id"]}"]').get_attribute("class") == "is-selected"
    page.goto("/index.html?analysis=sample-mock&flow=999999999")
    page.locator(".drawer [role=alert]").wait_for()
    assert "El flujo 999999999 no está en este análisis." in page.locator(".drawer").inner_text()


def test_panel_says_when_the_model_does_not_explain(page):
    # Como responde /api/explain un modelo sin explicación (por ejemplo, la red neuronal): can_explain = false.
    flow = api_json(page, "/api/analysis/sample-mock")["flows"][0]
    response = {"analysis_id": "sample-mock", "flow": flow, "can_explain": False, "contributions": None}
    page.route("**/api/explain/**", lambda route: route.fulfill(json=response))
    page.goto(f"/index.html?analysis=sample-mock&flow={flow['id']}")
    page.get_by_text("Este modelo no explica sus decisiones.").wait_for()
    assert page.locator(".expl-list li").count() == 0


def test_link_to_a_missing_analysis(page):
    page.goto("/index.html?analysis=a3f9c2e17b4d")
    alert = page.locator("#uploadStatus [role=alert]")
    alert.wait_for()
    assert "Este análisis ya no está disponible" in alert.inner_text()
    assert page.locator("#results").is_hidden()


def test_uploaded_files(page):
    page.goto("/index.html")
    page.locator("#fileInput").set_input_files(str(DEMO_SAMPLE_CSV))
    page.locator("#results").wait_for(state="visible")
    assert "sample_flows.csv" in page.locator("#analysisBar").inner_text()
    assert re.search(r"\?analysis=[0-9a-f]{12}$", page.url)
    page.locator("#fileInput").set_input_files({"name": "malo.csv", "mimeType": "text/csv", "buffer": b"id,proto\n1,tcp\n"})
    alert = page.locator("#uploadStatus [role=alert]")
    alert.wait_for()
    assert "faltan columnas obligatorias" in alert.inner_text()


def test_console_remembers_its_analysis_when_coming_back(page):
    page.goto("/index.html")
    page.locator("#fileInput").set_input_files(str(DEMO_SAMPLE_CSV))
    page.locator("#results").wait_for(state="visible")
    analysis_url = page.url
    # Volver por el menú y por el logo, que abren index.html sin ?analysis=.
    for back in (page.locator(".mainnav a", has_text="Consola"), page.locator(".brand")):
        page.locator(".mainnav a", has_text="Modelos").click()
        page.wait_for_url("**/compare.html")
        back.click()
        page.locator("#results").wait_for(state="visible")
        assert page.url == analysis_url
        assert "sample_flows.csv" in page.locator("#analysisBar").inner_text()
    # Si el análisis guardado ya no existe: el mensaje del contrato, y se olvida.
    page.evaluate("sessionStorage.setItem('ntd-console-analysis', JSON.stringify({analysisId: 'a3f9c2e17b4f', fileName: 'viejo.csv'}))")
    page.goto("/index.html")
    alert = page.locator("#uploadStatus [role=alert]")
    alert.wait_for()
    assert "Este análisis ya no está disponible" in alert.inner_text()
    assert page.evaluate("sessionStorage.getItem('ntd-console-analysis')") is None
    page.goto("/index.html")
    page.wait_for_timeout(300)
    assert page.locator("#uploadStatus [role=alert]").count() == 0 and page.locator("#results").is_hidden()


def test_network_error_while_analyzing(page):
    page.route("**/api/predict", lambda route: route.abort())
    page.goto("/index.html")
    page.locator("#sampleLabeled").click()
    alert = page.locator("#uploadStatus [role=alert]")
    alert.wait_for()
    assert "No se pudo conectar con el servidor" in alert.inner_text()


# Análisis inventado con un modelo que ya no está en GET /api/models y sin alertas críticas.
RETIRED_MODEL_ANALYSIS = {
    "analysis_id": "a3f9c2e17b4e",
    "model": {"name": "removed_model", "display_name": "Modelo retirado", "threshold": 0.5},
    "has_labels": True,
    "summary": {"total_flows": 2, "alerts": 1, "alerts_by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0},
                "detection_rate": 1.0, "false_alarm_rate": 0.0},
    "flows": [
        {"id": 7, "proto": "tcp", "service": "http", "state": "FIN", "attack_probability": 0.8, "is_alert": True,
         "severity": "high", "predicted_attack_cat": "Exploits", "true_label": 1, "true_attack_cat": "Exploits"},
        {"id": 9, "proto": "udp", "service": "dns", "state": "CON", "attack_probability": 0.1, "is_alert": False,
         "severity": "normal", "predicted_attack_cat": None, "true_label": 0, "true_attack_cat": "Normal"},
    ],
}


def test_unknown_model_and_empty_severity_filter(page):
    page.route("**/api/analysis/a3f9c2e17b4e", lambda route: route.fulfill(json=RETIRED_MODEL_ANALYSIS))
    page.goto("/index.html?analysis=a3f9c2e17b4e")
    page.locator("#results").wait_for(state="visible")
    # El modelo no está en la lista: su nombre, sin "Simulado" y sin aviso.
    assert "Modelo retirado" in page.locator("#analysisBar").inner_text()
    assert page.locator("#analysisBar .tag-mock").count() == 0 and page.locator("#mockSlot").inner_text() == ""
    # El filtro con 0 está activo, el teclado no se lo salta y muestra el estado vacío.
    critical = page.locator('#filters [data-value="critical"]')
    assert critical.is_enabled() and critical.locator(".chip-n").inner_text() == "0"
    page.locator('#filters [data-value="alerts"]').focus()
    page.keyboard.press("ArrowRight")
    assert critical.get_attribute("aria-checked") == "true"
    assert "No hay alertas de severidad crítica en este análisis." in page.locator("#queueEmpty").inner_text()
    page.get_by_role("button", name="Ver todas las alertas").click()
    assert queue_ids(page) == [7]


@pytest.mark.parametrize("width", [320, 375])
def test_console_fits_small_screens(page, width):
    page.set_viewport_size({"width": width, "height": 800})
    load_sample(page)
    page.locator("#queueTable tbody tr").first.click()
    page.locator(".expl-list li").first.wait_for()
    assert page.evaluate("document.documentElement.scrollWidth") <= width



# Simulación (simulation.html y js/simulation.js)


def test_simulation_speeds_and_pace_match_the_backend():
    html = (STATIC_DIR / "simulation.html").read_text(encoding="utf-8")
    speeds = re.search(r'id="speeds">(.*?)</div>', html, re.DOTALL).group(1)
    assert tuple(int(v) for v in re.findall(r'data-value="(\d+)"', speeds)) == SIMULATION_SPEEDS
    script = (STATIC_DIR / "js" / "simulation.js").read_text(encoding="utf-8")
    assert int(re.search(r"const INTERVAL_MS = (\d+);", script).group(1)) == SIMULATION_INTERVAL_SECONDS * 1000


# Cuenta los puntos de la animación que se crean (window.dotsCreated).
COUNT_DOTS = """
window.dotsCreated = 0;
new MutationObserver((records) => {
  for (const r of records) for (const n of r.addedNodes) if (n.classList && n.classList.contains('sim-dot')) window.dotsCreated += 1;
}).observe(document, { childList: true, subtree: true });
"""


def open_simulation(page, url="/simulation.html"):
    page.goto(url)
    page.locator("#playBtn:not([disabled])").wait_for()


def wait_until_ended(page):
    """Hasta que termina la reproducción y llegan las tasas del análisis completo."""
    page.wait_for_function("document.getElementById('playBtn').textContent.includes('Reproducir de nuevo')", timeout=60000)
    page.wait_for_function("!document.getElementById('kpis').textContent.includes('Se calcula al terminar')")


def shown(page):
    return int(page.locator("#progressText").inner_text().split("/")[0].strip().replace(".", ""))


def test_full_simulation_matches_the_analysis(page, monkeypatch):
    monkeypatch.setattr(routes, "SIMULATION_INTERVAL_SECONDS", 0.002)
    page.emulate_media(reduced_motion="reduce")
    page.add_init_script(COUNT_DOTS)
    open_simulation(page)
    page.locator("#playBtn").click()
    wait_until_ended(page)
    summary = api_json(page, "/api/analysis/sample-mock")["summary"]
    stage = page.locator("#stage").inner_text()
    assert f"Alertas\n{summary['alerts']}" in stage and f"Tráfico normal\n{summary['total_flows'] - summary['alerts']}" in stage
    kpis = page.locator("#kpis").inner_text()
    assert percent(summary["detection_rate"]) in kpis and "Se calcula al terminar" not in kpis
    assert page.locator("#progressText").inner_text() == f"{summary['total_flows']} / {summary['total_flows']}"
    assert page.locator("#logList li").count() == 50
    # Con prefers-reduced-motion no se dibuja ningún punto.
    assert page.evaluate("window.dotsCreated") == 0
    page.locator("#onlyAlerts").check()
    visible = page.locator("#logList li:visible")
    assert visible.count() == page.locator("#logList li.is-alert").count() > 0
    assert "simulación terminada" in page.locator("#simLive").inner_text()
    # Al terminar, las tasas llevan la ayuda con sus cuentas.
    detection_tip, _ = rate_tip_texts(api_json(page, "/api/analysis/sample-mock")["flows"])
    page.locator(".kpi.has-tip").first.hover()
    assert page.locator(".kpi.has-tip .kpi-tip").first.inner_text().startswith(detection_tip)


def test_pause_resume_and_speed(page, monkeypatch):
    monkeypatch.setattr(routes, "SIMULATION_INTERVAL_SECONDS", 0.15)
    sent = []
    page.on("websocket", lambda ws: ws.on("framesent", lambda payload: sent.append(json.loads(payload))))
    open_simulation(page)
    page.locator("#playBtn").click()
    page.wait_for_function("parseInt(document.getElementById('progressText').textContent) >= 2")
    page.locator("#playBtn").click()
    assert page.locator("#playBtn").inner_text().strip() == "Reanudar"
    page.wait_for_timeout(400)
    paused_at = shown(page)
    page.wait_for_timeout(600)
    assert shown(page) == paused_at
    page.locator("#playBtn").click()
    page.wait_for_function(f"parseInt(document.getElementById('progressText').textContent) > {paused_at}")
    page.locator('#speeds [data-value="4"]').click()
    page.wait_for_timeout(200)
    assert {"type": "set_speed", "speed": 4} in sent
    assert page.locator("#speedHelp").inner_text() == "4 flujos por segundo"
    assert [m["type"] for m in sent[:3]] == ["start", "pause", "resume"]


def test_clicking_a_flow_pauses_and_closing_resumes(page, monkeypatch):
    monkeypatch.setattr(routes, "SIMULATION_INTERVAL_SECONDS", 0.15)
    open_simulation(page)
    page.locator("#playBtn").click()
    item = page.locator("#logList .tl-btn").first
    item.wait_for()
    flow_id = item.locator(".tl-id").inner_text().split()[-1]
    item.click()
    assert page.locator("#drawerTitle").inner_text() == f"Flujo {flow_id}"
    assert page.locator("#playBtn").inner_text().strip() == "Reanudar"
    link = page.get_by_role("link", name="Abrir en la cola de alertas")
    assert link.get_attribute("href") == f"index.html?analysis=sample-mock&flow={flow_id}"
    page.keyboard.press("Escape")
    assert page.locator("#playBtn").inner_text().strip() == "Pausar"


def test_hidden_tab_applies_flows_without_animating(page, monkeypatch):
    monkeypatch.setattr(routes, "SIMULATION_INTERVAL_SECONDS", 0.1)
    page.add_init_script(COUNT_DOTS)
    open_simulation(page)
    page.locator('#speeds [data-value="4"]').click()
    page.locator("#playBtn").click()
    page.locator(".sim-dot").first.wait_for(state="attached")
    set_visibility = """(state) => {
        Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state });
        document.dispatchEvent(new Event('visibilitychange'));
    }"""
    page.evaluate(set_visibility, "hidden")
    # Los puntos en camino llegan de inmediato; mientras esté oculta, no se crea ninguno.
    assert page.locator(".sim-dot").count() == 0
    before_dots, before_shown = page.evaluate("window.dotsCreated"), shown(page)
    page.wait_for_timeout(800)
    assert page.evaluate("window.dotsCreated") == before_dots
    assert shown(page) > before_shown
    # Progreso e indicador de flujos recibidos, leídos en el mismo instante: coinciden.
    progress, received = page.evaluate("""() => [
        parseInt(document.getElementById('progressText').textContent),
        parseInt(document.querySelector('#kpis .kpi-value').textContent)]""")
    assert progress == received
    # Al volver a la pestaña, la animación sigue con los flujos nuevos.
    page.evaluate(set_visibility, "visible")
    page.wait_for_function(f"window.dotsCreated > {before_dots}")


def test_unlabeled_sample_and_linked_analysis(page, monkeypatch):
    monkeypatch.setattr(routes, "SIMULATION_INTERVAL_SECONDS", 0.002)
    page.emulate_media(reduced_motion="reduce")
    open_simulation(page)
    page.locator('#labelsMode [data-value="unlabeled"]').click()
    page.wait_for_function("document.getElementById('analysisBar').textContent.includes('Sin etiquetas')")
    page.locator("#playBtn").click()
    wait_until_ended(page)
    assert page.locator("#kpis").inner_text().count("Requiere etiquetas reales") == 2
    # Desde la consola: se reproduce ese análisis y no hay selector de etiquetas.
    open_simulation(page, "/simulation.html?analysis=sample-mock")
    assert page.locator("#labelsMode").is_hidden()
    assert "Con etiquetas" in page.locator("#analysisBar").inner_text()


def test_simulation_errors(page):
    page.goto("/simulation.html?analysis=a3f9c2e17b4d")
    alert = page.locator("#simStatus [role=alert]")
    alert.wait_for()
    assert "Este análisis ya no está disponible" in alert.inner_text()
    assert page.locator("#playBtn").is_disabled()
    # El WebSocket se cierra sin "end" ni "error": network_error.
    page.route_web_socket("**/ws/simulate", lambda ws: ws.close())
    open_simulation(page)
    page.locator("#playBtn").click()
    page.locator("#simStatus [role=alert]").wait_for()
    assert "No se pudo conectar con el servidor" in page.locator("#simStatus").inner_text()


@pytest.mark.parametrize("width", [320, 375])
def test_simulation_fits_small_screens(page, monkeypatch, width):
    monkeypatch.setattr(routes, "SIMULATION_INTERVAL_SECONDS", 0.05)
    page.set_viewport_size({"width": width, "height": 800})
    open_simulation(page)
    page.locator("#playBtn").click()
    page.locator("#logList .tl-btn").first.wait_for()
    assert page.evaluate("document.documentElement.scrollWidth") <= width



# Modelos (compare.html y js/compare.js)


def score(value):
    """Un puntaje como lo muestra la pantalla (3 decimales, coma)."""
    return f"{value:.3f}".replace(".", ",")


def thousands(n):
    return f"{n:,}".replace(",", ".")


def open_models(page):
    page.goto("/compare.html")
    page.locator("#modelsContent").wait_for(state="visible")


def compare_row(page, row_label):
    """La fila de la comparación cuya etiqueta es exactamente row_label."""
    label = page.locator("td:first-child", has_text=re.compile("^" + re.escape(row_label) + "$"))
    return page.locator("#compareTable tbody tr", has=label)


def compare_cells(page, row_label):
    """Los valores de una fila de la comparación, uno por modelo."""
    return compare_row(page, row_label).locator("td").all_inner_texts()[1:]


def test_models_page_with_the_mock_model(page):
    open_models(page)
    metrics = api_json(page, "/api/metrics")["models"][0]
    d = metrics["detection"]
    assert page.locator(".model-card").count() == 1
    card = page.locator(".model-card")
    assert "Simulado" in card.inner_text() and "Métricas inventadas." in card.inner_text()
    assert "En uso en la consola y la simulación" in card.inner_text()
    assert compare_cells(page, "Detección (recall)") == [percent(d["detection_rate"])]
    assert compare_cells(page, "PR-AUC") == [score(d["pr_auc"])]
    assert compare_cells(page, "F1 macro (9 tipos)") == [score(metrics["attack_type"]["macro_f1"])]
    assert compare_cells(page, "Tiempo de entrenamiento") == ["No aplica"]
    assert page.locator("#compareTable .best").count() == 0
    assert "al menos dos modelos entrenados" in page.locator("#bestNote").inner_text()
    assert "(82.332 flujos)" in page.locator("#testFlows").inner_text()
    matrix = metrics["attack_type"]["confusion"]["matrix"]
    cells = page.locator(".cm9 tbody td").all_inner_texts()
    assert cells == [thousands(v) for row in matrix for v in row]
    assert page.locator(".cm9 td.diag").count() == 9
    assert "detectar al menos el 95 % de los ataques" in page.locator("#tabPanel").inner_text()
    assert "No aplica: el modelo simulado no se entrena." in page.locator("#tabPanel").inner_text()


def fake_models_and_metrics(page):
    """El simulado más dos modelos entrenados inventados, a partir de las respuestas reales."""
    models = api_json(page, "/api/models")
    mock_metrics = api_json(page, "/api/metrics")["models"][0]
    complexity = {"training_seconds": 134.2, "training_flows": 140273, "prediction_ms_per_1000_flows": 4.1,
                  "model_size_mb": 3.8, "hardware": "Equipo de prueba"}
    entries = [("model_a", "Modelo A", 0.96, 0.10, None), ("model_b", "Modelo B", 0.95, 0.10, 0.9)]
    for name, display, detection, false_alarm, precision in entries:
        models["models"].append({**models["models"][0], "name": name, "display_name": display, "is_mock": False,
                                 "use_ttl": name == "model_a"})
    metrics = {"models": []}
    for model in models["models"]:
        entry = copy.deepcopy(mock_metrics)
        entry.update(name=model["name"], display_name=model["display_name"], is_mock=model["is_mock"])
        if not model["is_mock"]:
            _, _, detection, false_alarm, precision = next(e for e in entries if e[0] == model["name"])
            entry["detection"].update(detection_rate=detection, false_alarm_rate=false_alarm, precision=precision)
            entry["complexity"] = complexity
        else:
            # El simulado tiene el valor más alto, pero nunca se marca como mejor.
            entry["detection"]["detection_rate"] = 0.99
        metrics["models"].append(entry)
    page.route("**/api/models", lambda route: route.fulfill(json=models))
    page.route("**/api/metrics", lambda route: route.fulfill(json=metrics))


def test_best_values_and_choosing_a_model(page):
    page.goto("/compare.html")
    fake_models_and_metrics(page)
    open_models(page)
    columns = ["mock", "model_a", "model_b"]
    best = lambda label: [columns[i] for i, td in enumerate(compare_row(page, label).locator("td").all()[1:])
                          if "best" in (td.get_attribute("class") or "")]
    assert best("Detección (recall)") == ["model_a"]
    assert best("Falsas alarmas") == ["model_a", "model_b"]
    assert best("Precisión") == ["model_b"]
    assert compare_cells(page, "Precisión")[1] == "—"
    assert "La estrella marca el mejor valor" in page.locator("#bestNote").inner_text()
    # Elegir el modelo B: se guarda, cambia la cabecera y la tarjeta, y sigue elegido al recargar.
    card_b = page.locator(".model-card", has_text="Modelo B")
    card_b.get_by_role("button", name="Usar este modelo").click()
    assert page.evaluate("localStorage.getItem('ntd-model')") == "model_b"
    assert "Modelo B" in page.locator("#modelPill").inner_text()
    assert "is-active" in card_b.get_attribute("class")
    assert "Ahora la consola y la simulación usan «Modelo B»" in page.locator("#toast").inner_text()
    page.reload()
    page.locator("#modelsContent").wait_for(state="visible")
    assert "is-active" in page.locator(".model-card", has_text="Modelo B").get_attribute("class")
    # Pestañas con el teclado: empieza en el modelo en uso.
    assert page.locator("#tab-model_b").get_attribute("aria-selected") == "true"
    page.locator("#tab-model_b").focus()
    page.keyboard.press("ArrowLeft")
    assert page.locator("#tab-model_a").get_attribute("aria-selected") == "true"
    assert page.locator("#tabPanel").get_attribute("aria-labelledby") == "tab-model_a"
    assert "2 min 14 s" in page.locator("#tabPanel").inner_text()


def test_models_page_error(page):
    page.route("**/api/metrics", lambda route: route.fulfill(status=500, json={"error": {
        "code": "internal_error", "message": "Ocurrió un error inesperado en el servidor. Intenta de nuevo; si se repite, avisa al equipo.",
        "details": None}}))
    page.goto("/compare.html")
    alert = page.locator("#modelsStatus [role=alert]")
    alert.wait_for()
    assert "Ocurrió un error inesperado" in alert.inner_text()
    assert page.get_by_role("button", name="Reintentar").is_visible()


@pytest.mark.parametrize("width", [320, 375])
def test_models_page_fits_small_screens(page, width):
    page.set_viewport_size({"width": width, "height": 800})
    open_models(page)
    assert page.evaluate("document.documentElement.scrollWidth") <= width



# Valores que la interfaz muestra con otro texto ("unas" de proto se muestra "unassigned")

UNAS_TITLE = "Valor en el archivo: unas"


def upload_unas_flows(page, sample_flows):
    """Sube un flujo tcp y 8 con proto "unas" de la muestra; devuelve el analysis_id."""
    flows = pd.concat([sample_flows[sample_flows["proto"] == "tcp"].head(1),
                       sample_flows[sample_flows["proto"] == "unas"].head(8)])
    page.goto("/index.html")
    page.locator("#fileInput").set_input_files({"name": "unas.csv", "mimeType": "text/csv", "buffer": csv_bytes(flows)})
    page.locator("#results").wait_for(state="visible")
    return re.search(r"\?analysis=([0-9a-f]{12})$", page.url).group(1)


def test_unas_is_shown_as_unassigned_in_the_console(page, sample_flows):
    analysis_id = upload_unas_flows(page, sample_flows)
    # La API sigue devolviendo el valor original: el cambio es solo de presentación.
    flows = api_json(page, f"/api/analysis/{analysis_id}")["flows"]
    assert sorted(f["proto"] for f in flows) == ["tcp"] + ["unas"] * 8

    page.locator('#filters [data-value="all"]').click()
    cells = page.locator("#queueTable tbody tr td.cat:nth-child(5)")
    assert sorted(cells.all_inner_texts()) == ["tcp"] + ["unassigned"] * 8
    assert page.locator("#queueTable td.cat[title]").evaluate_all("tds => tds.map(td => td.title)") == [UNAS_TITLE] * 8

    unas_id = next(f["id"] for f in flows if f["proto"] == "unas")
    page.locator(f'#queueTable tbody tr[data-id="{unas_id}"]').click()
    drawer = page.locator(".drawer")
    page.locator(".expl-list li").first.wait_for()
    proto_value = page.locator(".kv dd").nth(1)
    assert proto_value.inner_text() == "unassigned" and proto_value.get_attribute("title") == UNAS_TITLE
    page.get_by_role("button", name=re.compile(r"^Ver todas")).click()
    explained = page.locator('.expl-item:has([data-tech="proto"]) .val')
    assert explained.inner_text() == "unassigned" and explained.get_attribute("title") == UNAS_TITLE
    # "unas" no se ve en ninguna parte: solo queda en el texto al pasar el mouse.
    assert not re.search(r"\bunas\b", drawer.inner_text() + page.locator("#queueTable").inner_text())


def test_unas_is_shown_as_unassigned_in_the_simulation(page, monkeypatch, sample_flows):
    monkeypatch.setattr(routes, "SIMULATION_INTERVAL_SECONDS", 0.002)
    page.emulate_media(reduced_motion="reduce")
    analysis_id = upload_unas_flows(page, sample_flows)
    flows = api_json(page, f"/api/analysis/{analysis_id}")["flows"]
    open_simulation(page, f"/simulation.html?analysis={analysis_id}")
    page.locator("#playBtn").click()
    wait_until_ended(page)

    meta = page.locator("#logList .tl-meta")
    assert sorted(m.split(" · ")[0] for m in meta.all_inner_texts()) == ["tcp"] + ["unassigned"] * 8
    assert meta.evaluate_all("ms => ms.filter(m => m.title).length") == 8
    # La última alerta es la última del archivo que dio alerta; si es de "unas", también se muestra cambiada.
    last_alert = [f for f in flows if f["is_alert"]][-1]
    shown_proto = "unassigned" if last_alert["proto"] == "unas" else last_alert["proto"]
    assert page.locator("#lastAlert .help").inner_text().startswith(shown_proto + " · ")
    assert not re.search(r"\bunas\b", page.locator("#logList").inner_text() + page.locator("#lastAlert").inner_text())

# Los modelos entrenados del artifacts/ real (solo leen)

EXPLAINING_MODELS = ["hist_gradient_boosting", "random_forest", "logistic_regression"]
MODEL_NAMES = {
    "hist_gradient_boosting": "HistGradientBoosting", "random_forest": "Random Forest",
    "mlp": "Red neuronal (MLP)", "logistic_regression": "Regresión logística (modelo base)",
}


@pytest.fixture(scope="module")
def real_client():
    """La app con el artifacts/ real: los 4 modelos entrenados."""
    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.mark.parametrize("name", [*EXPLAINING_MODELS, "mlp"])
def test_project_models_explain_flows_without_labels(name, real_client, sample_flows):
    # La muestra sin etiquetas y un archivo subido sin label ni attack_cat.
    unlabeled = sample_flows.drop(columns=TARGET_COLS)
    analyses = [
        real_client.post("/api/predict", data={"use_sample": "true", "use_labels": "false", "model": name}).json(),
        upload(real_client, csv_bytes(unlabeled), model=name).json(),
    ]
    for analysis in analyses:
        assert analysis["has_labels"] is False and analysis["model"]["name"] == name
        flow_id = analysis["flows"][0]["id"]
        body = real_client.get(f"/api/explain/{flow_id}", params={"analysis_id": analysis["analysis_id"]}).json()
        if name == "mlp":
            assert (body["can_explain"], body["contributions"]) == (False, None)
        else:
            assert body["can_explain"] is True
            assert len(body["contributions"]) == 35


@pytest.fixture(scope="module")
def real_live_server():
    """La app con el artifacts/ real corriendo con Uvicorn en un puerto libre."""
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture
def real_page(browser, real_live_server):
    context = browser.new_context(base_url=real_live_server)
    yield context.new_page()
    context.close()


def choose_in_browser(page, name):
    """Guarda el modelo elegido en el navegador, como lo hace la pantalla Modelos."""
    page.goto("/index.html")
    page.evaluate(f"localStorage.setItem('ntd-model', '{name}')")


def test_header_pill_of_a_trained_model_has_no_extra_text(real_page):
    real_page.goto("/index.html")
    pill = real_page.locator("#modelPill")
    pill.wait_for(state="visible")
    assert pill.inner_text().split() == "Modelo en uso: HistGradientBoosting".split()


@pytest.mark.parametrize("name", EXPLAINING_MODELS)
def test_panel_without_labels_shows_the_variables(name, real_page):
    choose_in_browser(real_page, name)
    load_sample(real_page, labeled=False)
    assert "Sin etiquetas" in real_page.locator("#analysisBar").inner_text()
    real_page.locator("#queueTable tbody tr").first.click()
    real_page.locator(".expl-list li").first.wait_for()
    assert real_page.locator(".expl-list li").count() == 10
    assert real_page.get_by_role("button", name="Ver todas (35)").is_visible()


def wait_for_model(page, display_name):
    """Hasta que la barra del análisis muestra ese modelo."""
    page.wait_for_function(
        "name => document.getElementById('analysisBar').textContent.includes('Modelo: ' + name)", arg=display_name)


def choose_in_models_screen(page, display_name):
    page.goto("/compare.html")
    page.locator(".model-card", has_text=display_name).get_by_role("button", name="Usar este modelo").click()


def rate_tips_shown(page):
    return [tip.text_content() for tip in page.locator(".kpi.has-tip .kpi-tip").all()]


@pytest.mark.parametrize("way_back", ["menu", "back"])
def test_sample_follows_the_chosen_model(real_page, way_back):
    # La muestra con etiquetas y la red neuronal; después se eligen otros modelos en Modelos y se vuelve
    # a la consola por el menú o con «Atrás». Siempre se ve la muestra del modelo elegido.
    choose_in_browser(real_page, "mlp")
    load_sample(real_page)
    wait_for_model(real_page, "Red neuronal (MLP)")
    shown_tips = {tuple(rate_tips_shown(real_page))}
    for name, display_name in [("random_forest", "Random Forest"), ("logistic_regression", "Regresión logística (modelo base)")]:
        choose_in_models_screen(real_page, display_name)
        if way_back == "menu":
            real_page.get_by_role("link", name="Consola").first.click()
        else:
            real_page.go_back()
        wait_for_model(real_page, display_name)
        assert real_page.url.endswith(f"index.html?analysis=sample-{name}")
        assert "Con etiquetas" in real_page.locator("#analysisBar").inner_text()
        assert real_page.locator("#modelSlot").inner_text() == ""
        assert real_page.locator("#h-summary").text_content() == "Resumen del análisis"
        # Las ayudas de Detección y Falsas alarmas son las del modelo elegido.
        flows = api_json(real_page, f"/api/analysis/sample-{name}")["flows"]
        tips = rate_tips_shown(real_page)
        assert [tip.split(" Se calcula")[0] for tip in tips] == list(rate_tip_texts(flows))
        shown_tips.add(tuple(tips))
    # Las ayudas cambiaron con cada modelo.
    assert len(shown_tips) == 3


def test_page_restored_from_the_back_forward_cache_follows_the_chosen_model(real_page):
    # Chromium con Playwright recarga al ir «Atrás»; un navegador puede restaurar la página guardada
    # (bfcache) sin ejecutarla. Se simula esa restauración con el mismo evento que lanza el navegador.
    choose_in_browser(real_page, "mlp")
    load_sample(real_page)
    wait_for_model(real_page, "Red neuronal (MLP)")
    real_page.evaluate("window.notReloaded = true; localStorage.setItem('ntd-model', 'random_forest')")
    real_page.evaluate("window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }))")
    wait_for_model(real_page, "Random Forest")
    assert real_page.evaluate("window.notReloaded") is None
    assert "Modelo en uso: Random Forest" in " ".join(real_page.locator("#modelPill").inner_text().split())


def test_sample_keeps_its_labels_mode_and_flow_link(real_page, sample_flows):
    # Un enlace a un flujo de la muestra sin etiquetas de la red neuronal, con HistGradientBoosting elegido.
    flow_id = int(sample_flows["id"].iloc[0])
    choose_in_browser(real_page, "hist_gradient_boosting")
    real_page.goto(f"/index.html?analysis=sample-mlp-unlabeled&flow={flow_id}")
    wait_for_model(real_page, "HistGradientBoosting")
    assert "Sin etiquetas" in real_page.locator("#analysisBar").inner_text()
    assert "analysis=sample-hist_gradient_boosting-unlabeled" in real_page.url
    # Se abre el mismo flujo, ahora con la explicación de HistGradientBoosting.
    assert f"flow={flow_id}" in real_page.url
    real_page.locator(".expl-list li").first.wait_for()
    assert real_page.locator(".expl-list li").count() == 10


def test_notice_for_an_uploaded_file_asks_to_upload_it_again(real_page):
    choose_in_browser(real_page, "mlp")
    real_page.goto("/index.html")
    real_page.locator("#fileInput").set_input_files(str(DEMO_SAMPLE_CSV))
    real_page.locator("#results").wait_for(state="visible")
    real_page.evaluate("localStorage.setItem('ntd-model', 'random_forest')")
    real_page.goto("/index.html")
    real_page.locator("#results").wait_for(state="visible")
    text = real_page.locator("#modelSlot").inner_text()
    assert "Este análisis se hizo con Red neuronal (MLP). El modelo elegido ahora es Random Forest" in text
    assert "Para analizarlo con Random Forest, vuelve a cargar el archivo." in text
    assert real_page.locator("#modelSlot button").count() == 0
    # Los indicadores dicen de qué modelo son; el archivo sigue siendo el de la red neuronal.
    assert real_page.locator("#h-summary").text_content() == "Resumen del análisis con Red neuronal (MLP)"
    assert "Modelo: Red neuronal (MLP)" in real_page.locator("#analysisBar").inner_text()
    # Al volver a cargarlo, se analiza con el elegido y el aviso desaparece.
    real_page.locator("#fileInput").set_input_files(str(DEMO_SAMPLE_CSV))
    wait_for_model(real_page, "Random Forest")
    assert real_page.locator("#modelSlot").inner_text() == ""
    assert real_page.locator("#h-summary").text_content() == "Resumen del análisis"


# Memoria de los análisis: respuesta JSON directa, guardado compacto y predicción por bloques

ANALYSIS_ADAPTER = TypeAdapter(AnalysisResponse)
# Diferencia permitida en la probabilidad (Random Forest ya la tiene de una predicción a otra).
PROBABILITY_NOISE = 1e-15


def validated_json(analysis):
    """El JSON que daba FastAPI al validar con response_model, como antes del cambio; falla si no cumple el esquema."""
    return ANALYSIS_ADAPTER.dump_json(ANALYSIS_ADAPTER.validate_python(analysis.response()), by_alias=True)


def messy_flows(sample_flows):
    """La muestra con celdas que la app acepta: categóricas vacías y un id escrito como decimal."""
    flows = sample_flows.astype({ID_COL: object})
    flows.loc[3, "service"] = np.nan
    flows.loc[7, "state"] = np.nan
    flows.loc[0, ID_COL] = f"{flows.loc[0, ID_COL]}.0"
    return flows


def test_analysis_json_is_the_same_as_with_validation(client, sample_flows):
    responses = [
        client.post("/api/predict", data={"use_sample": "true"}),
        client.post("/api/predict", data={"use_sample": "true", "use_labels": "false"}),
        upload(client, csv_bytes(messy_flows(sample_flows))),
        upload(client, csv_bytes(messy_flows(sample_flows)), use_labels="false"),
    ]
    for response in responses:
        assert response.status_code == 200 and response.headers["content-type"] == "application/json"
        analysis_id = response.json()["analysis_id"]
        expected = validated_json(client.app.state.analyses.get(analysis_id))
        assert response.content == expected
        assert client.get(f"/api/analysis/{analysis_id}").content == expected


@pytest.mark.parametrize("name", [*EXPLAINING_MODELS, "mlp"])
def test_project_models_json_is_the_same_as_with_validation(name, real_client, sample_flows):
    for data in ({"use_sample": "true"}, {"use_sample": "true", "use_labels": "false"}):
        response = real_client.post("/api/predict", data={**data, "model": name})
        analysis = real_client.app.state.analyses.get(response.json()["analysis_id"])
        assert response.content == validated_json(analysis)
    response = upload(real_client, csv_bytes(messy_flows(sample_flows)), model=name)
    assert response.content == validated_json(real_client.app.state.analyses.get(response.json()["analysis_id"]))


def test_openapi_documents_the_analysis_responses(client):
    # Las rutas devuelven el JSON directamente, pero su response_model sigue en la documentación.
    paths = client.get("/openapi.json").json()["paths"]
    for path, method in (("/api/predict", "post"), ("/api/analysis/{analysis_id}", "get")):
        schema = paths[path][method]["responses"]["200"]["content"]["application/json"]["schema"]
        assert schema == {"$ref": "#/components/schemas/AnalysisResponse"}


def test_compact_flows_keep_the_values(sample_flows):
    flows = messy_flows(sample_flows).infer_objects()
    flows["sbytes"] = flows["sbytes"].astype(np.int64)
    flows.loc[1, "sbytes"] = 2**31  # no cabe en int32: la columna queda en int64
    compact = compact_flows(flows)
    for column in flows.columns:
        assert compact[column].astype(object).where(compact[column].notna(), None).tolist() == \
            flows[column].astype(object).where(flows[column].notna(), None).tolist(), column
    assert compact["sbytes"].dtype == np.int64 and compact["dbytes"].dtype == np.int32
    assert all(compact[column].dtype == "category" for column in ["proto", "service", "state", ATTACK_CAT])
    # Es una tabla nueva: no comparte memoria con la leída.
    for column in flows.columns:
        if flows[column].dtype.kind in "if":
            assert not np.shares_memory(compact[column].to_numpy(), flows[column].to_numpy()), column
    assert compact_flows(flows).memory_usage(deep=True).sum() < flows.memory_usage(deep=True).sum()


def test_analysis_finds_flows_by_id(mock, sample_flows):
    analysis = run_analysis("x", sample_flows, mock, has_labels=True)
    ids = sample_flows[ID_COL].tolist()
    assert [analysis.position(flow_id) for flow_id in ids] == list(range(len(ids)))
    for missing in (max(ids) + 1, -1, 2**63, -(2**63) - 1, 10**30):
        assert analysis.position(missing) is None


def test_batch_prediction_gives_the_same_results(real_client, sample_flows, monkeypatch):
    # Por bloques de 64 flujos, como los de 10.000 con un archivo grande.
    monkeypatch.setattr(predictors_module, "PREDICTION_BATCH_ROWS", 64)
    for name, predictor in real_client.app.state.predictors.items():
        whole = predict_flows(predictor.model, predictor.info, sample_flows)
        batched = predictor.predict(sample_flows)
        np.testing.assert_array_equal(batched[1], whole[1])
        np.testing.assert_array_equal(batched[2], whole[2])
        assert np.abs(batched[0] - whole[0]).max() <= PROBABILITY_NOISE, name
        if name == "hist_gradient_boosting":
            np.testing.assert_array_equal(batched[0], whole[0])


@pytest.mark.parametrize("name", ["hist_gradient_boosting", "random_forest", "logistic_regression"])
def test_compact_rows_explain_the_same(name, real_client, sample_flows):
    predictor = real_client.app.state.predictors[name]
    flows = messy_flows(sample_flows).infer_objects()
    compact = compact_flows(flows)
    for position in range(0, len(flows), 25):
        assert predictor.explain(compact.iloc[position]) == predictor.explain(flows.iloc[position]), position


@pytest.mark.parametrize("kind", ["hist_gradient_boosting", "random_forest", "logistic_regression"])
def test_global_importance_uses_the_app_explanation(kind, sample_flows):
    # La importancia global del artículo se calcula con la misma explicación que muestra la app.
    from threat_detector.ml.evaluation import flow_contributions

    predictor = explained_predictor(kind, sample_flows)
    rows = sample_flows.iloc[[0, 3, 250, 499]]
    table = flow_contributions(predictor.model, {"name": kind, **predictor.info}, rows)
    for position, (_, flow) in enumerate(rows.iterrows()):
        explained = {c["feature"]: c["contribution"] for c in predictor.explain(flow)}
        assert table.iloc[position].to_dict() == pytest.approx(explained, abs=1e-12)

