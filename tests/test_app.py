"""Pruebas de la app: predictores, análisis en memoria y rutas de la API (con TestClient)."""

import json
import logging
import re
import time

import numpy as np
import pandas as pd
import pytest
from conftest import structure, write_json
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from threat_detector.app.analyses import (
    AnalysisStore,
    parse_sample_id,
    read_flows,
    run_analysis,
    sample_id,
    validate_upload,
)
from threat_detector.app import routes
from threat_detector.app.main import create_app
from threat_detector.app.mock import MockPredictor
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
from threat_detector.config import DEMO_SAMPLE_CSV, MAX_STORED_ANALYSES, MAX_UPLOAD_MB, REGISTRY_PATH
from threat_detector.dataset import (
    ATTACK_CAT,
    ATTACK_TYPES,
    ID_COL,
    NORMAL_CAT,
    TARGET,
    TARGET_COLS,
    FlowValidationError,
)


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


def test_project_artifacts_give_only_the_mock_predictor():
    predictors = build_predictors(load_artifacts()[1])
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


def test_pipeline_explanation_is_not_defined_yet(exported, sample_flows):
    models = load_artifacts(exported)[1]
    predictor = PipelinePredictor({**models["model_a"]["info"], "can_explain": True}, models["model_a"]["model"])
    with pytest.raises(NotImplementedError):
        predictor.explain(sample_flows.iloc[0])


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
def client():
    """La app con el artifacts/ real (solo el modelo simulado); with hace que corra el lifespan."""
    with TestClient(create_app()) as test_client:
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


def test_get_analysis_returns_what_predict_returned(client, sample_flows):
    created = upload(client, csv_bytes(sample_flows), use_labels="false").json()
    assert client.get(f"/api/analysis/{created['analysis_id']}").json() == created
    sample = client.post("/api/predict", data={"use_sample": "true"}).json()
    # Un servidor recién iniciado regenera la muestra.
    with TestClient(create_app()) as fresh:
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


def test_damaged_form_is_an_invalid_request(client):
    response = client.post("/api/predict", content=b"not multipart",
                           headers={"content-type": "multipart/form-data; boundary=xyz"})
    assert error_of(response, 400) == {"code": "invalid_request", "details": {"field": None},
                                       "message": "El pedido no es válido."}


def test_unexpected_errors_hide_the_python_error(sample_flows):
    def broken_predict(flows):
        raise RuntimeError("detalle interno")

    with TestClient(create_app(), raise_server_exceptions=False) as test_client:
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
