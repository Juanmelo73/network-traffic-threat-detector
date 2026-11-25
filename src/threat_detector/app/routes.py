"""Rutas de la API: las HTTP (contrato, secciones 4 a 7) y la simulación por WebSocket (sección 8).

Las rutas que leen archivos o predicen se definen con def: FastAPI las ejecuta en un threadpool,
así no detienen al servidor mientras trabajan.
"""

import asyncio
import json
import logging
import re
from typing import Annotated

from fastapi import APIRouter, File, Form, Request, Response, UploadFile, WebSocket, WebSocketDisconnect
from pydantic_core import to_json
from starlette.concurrency import run_in_threadpool

from threat_detector.app.analyses import read_flows, run_analysis, validate_upload
from threat_detector.app.schemas import (
    AnalysisResponse,
    ApiError,
    ExplainResponse,
    MetricsResponse,
    ModelsResponse,
)
from threat_detector.config import BYTES_PER_MB, MAX_UPLOAD_MB, SIMULATION_INTERVAL_SECONDS, SIMULATION_SPEEDS
from threat_detector.dataset import FlowValidationError

MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * BYTES_PER_MB

# Un id de flujo es un número entero escrito sin decimales.
INTEGER_PATTERN = re.compile(r"-?\d+")

# Tipos de mensaje que el navegador puede enviar a la simulación.
CONTROL_TYPES = ("start", "pause", "resume", "set_speed")
# Velocidad de la simulación si "start" no trae speed.
DEFAULT_SPEED = 1

logger = logging.getLogger(__name__)

router = APIRouter()


def find_analysis(request, analysis_id):
    """El análisis guardado (o la muestra regenerada); si no existe, ApiError analysis_not_found."""
    state = request.app.state
    analysis = state.analyses.find(analysis_id, state.predictors)
    if analysis is None:
        raise ApiError("analysis_not_found", {"analysis_id": analysis_id})
    return analysis


def analysis_response(analysis):
    """La respuesta JSON de un análisis (sección 4), sin validarla flujo por flujo.

    Si la ruta devolviera el diccionario, FastAPI validaría cada flujo con AnalysisResponse antes
    de pasarlo a JSON: con un archivo de 25 MB, unos 190 MB temporales. Analysis.response() ya arma
    la respuesta con el formato del contrato, y to_json es el mismo serializador de Pydantic:
    tests/test_app.py comprueba que los bytes son los mismos que con la validación y que cumplen el
    esquema. response_model sigue en la ruta para la documentación (/openapi.json).
    """
    return Response(to_json(analysis.response()), media_type="application/json")


@router.post("/api/predict", response_model=AnalysisResponse)
def predict(
    request: Request,
    file: Annotated[UploadFile | None, File()] = None,
    use_sample: Annotated[bool, Form()] = False,
    model: Annotated[str | None, Form()] = None,
    use_labels: Annotated[bool, Form()] = True,
):
    """Analiza un CSV subido, o la muestra de demostración, con un modelo (sección 4)."""
    # Los errores se revisan en el orden de la sección 9.
    if file is None and not use_sample:
        raise ApiError("no_file")
    if file is not None and use_sample:
        raise ApiError("file_and_sample")
    if file is not None and file.size > MAX_UPLOAD_BYTES:
        raise ApiError("file_too_large", {"max_mb": MAX_UPLOAD_MB})

    state = request.app.state
    try:
        flows = None if use_sample else read_flows(file.file.read())
        model_name = state.registry["default_model"] if model is None else model
        predictor = state.predictors.get(model_name)
        if predictor is None:
            raise ApiError("unknown_model", {"model": model_name})
        if use_sample:
            return analysis_response(state.analyses.sample(predictor, use_labels))
        has_labels = validate_upload(flows, predictor.info, use_labels)
        analysis = run_analysis(state.analyses.new_id(), flows, predictor, has_labels)
    except FlowValidationError as error:
        raise ApiError(error.code, error.details, str(error)) from error
    # El análisis guarda su propia copia compacta: la tabla leída se libera antes de armar la respuesta.
    del flows
    state.analyses.add(analysis)
    return analysis_response(analysis)


@router.get("/api/analysis/{analysis_id}", response_model=AnalysisResponse)
def get_analysis(request: Request, analysis_id: str):
    """Devuelve un análisis ya hecho, sin recalcular nada (sección 4)."""
    return analysis_response(find_analysis(request, analysis_id))


@router.get("/api/explain/{id}", response_model=ExplainResponse)
def explain(request: Request, id: str, analysis_id: str | None = None):
    """Explica la probabilidad de ataque de un flujo de un análisis (sección 5)."""
    if not analysis_id:
        raise ApiError("missing_analysis_id")
    analysis = find_analysis(request, analysis_id)
    flow_id = int(id) if INTEGER_PATTERN.fullmatch(id) else None
    explained = None if flow_id is None else analysis.explain(flow_id)
    if explained is None:
        raise ApiError("flow_not_found", {"id": id if flow_id is None else flow_id})
    flow, contributions = explained
    return {
        "analysis_id": analysis_id,
        "flow": flow,
        "can_explain": analysis.predictor.info["can_explain"],
        "contributions": contributions,
    }


@router.get("/api/models", response_model=ModelsResponse)
def models(request: Request):
    """Los modelos disponibles y el modelo por defecto (sección 6)."""
    state = request.app.state
    fields = ("name", "display_name", "is_mock", "can_explain", "use_ttl", "threshold")
    return {
        "default_model": state.registry["default_model"],
        "models": [{field: p.info[field] for field in fields} for p in state.predictors.values()],
    }


@router.get("/api/metrics", response_model=MetricsResponse)
def metrics(request: Request):
    """Las métricas oficiales de cada modelo, guardadas en su model.json (sección 7)."""
    return {
        "models": [
            {
                "name": p.info["name"],
                "display_name": p.info["display_name"],
                "is_mock": p.info["is_mock"],
                **p.info["test_metrics"],
                "complexity": p.info["complexity"],
            }
            for p in request.app.state.predictors.values()
        ]
    }


# Simulación (sección 8)


async def receive_message(websocket):
    """El siguiente mensaje del navegador, como diccionario; ApiError invalid_message si no se entiende."""
    message = await websocket.receive()
    if message["type"] == "websocket.disconnect":
        raise WebSocketDisconnect(message.get("code", 1000))
    try:
        # Un mensaje binario no trae "text": tampoco se entiende.
        data = json.loads(message.get("text") or "")
    except json.JSONDecodeError:
        raise ApiError("invalid_message") from None
    if not isinstance(data, dict) or data.get("type") not in CONTROL_TYPES:
        raise ApiError("invalid_message")
    return data


def read_speed(message, required):
    """La velocidad de un mensaje; ApiError invalid_speed si no está en SIMULATION_SPEEDS.

    Debe ser un entero de verdad: True no vale como 1, aunque en Python True == 1, ni 2.0 como 2.
    """
    if "speed" not in message:
        if required:
            raise ApiError("invalid_message")
        return DEFAULT_SPEED
    speed = message["speed"]
    if type(speed) is not int or speed not in SIMULATION_SPEEDS:
        raise ApiError("invalid_speed", {"speed": speed})
    return speed


async def play(websocket):
    """Recibe "start" y reproduce el análisis hasta el final; lanza ApiError si algo falla."""
    start = await receive_message(websocket)
    if start["type"] != "start" or not isinstance(start.get("analysis_id"), str):
        raise ApiError("invalid_message")
    speed = read_speed(start, required=False)
    # La simulación guarda su propia referencia al análisis: si se borra de la memoria mientras
    # tanto (por ejemplo, al subir otros archivos), la reproducción sigue hasta el final.
    analysis = await run_in_threadpool(find_analysis, websocket, start["analysis_id"])
    total = len(analysis.ids)
    await websocket.send_json({
        "type": "started", "analysis_id": analysis.analysis_id, "model": analysis.model_response(),
        "has_labels": analysis.has_labels, "total_flows": total, "speed": speed,
    })

    playback = {"speed": speed}
    playing = asyncio.Event()
    playing.set()

    async def send_flows():
        for position in range(total):
            await playing.wait()
            flow = analysis.flow_responses([position])[0]
            await websocket.send_json({"type": "flow", "position": position + 1, "total_flows": total, "flow": flow})
            if position + 1 < total:
                await asyncio.sleep(SIMULATION_INTERVAL_SECONDS / playback["speed"])
        await websocket.send_json({"type": "end", "total_flows": total})

    async def receive_controls():
        while True:
            message = await receive_message(websocket)
            if message["type"] == "pause":
                playing.clear()
            elif message["type"] == "resume":
                # Sin pausa no hace nada.
                playing.set()
            elif message["type"] == "set_speed":
                playback["speed"] = read_speed(message, required=True)
            else:
                # Un segundo "start": para reiniciar se abre otra conexión.
                raise ApiError("invalid_message")

    # Las dos tareas corren a la vez; cuando una termina (fin, error o desconexión), se cancela la otra.
    tasks = {asyncio.create_task(send_flows()), asyncio.create_task(receive_controls())}
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    for task in done:
        task.result()


@router.websocket("/ws/simulate")
async def simulate(websocket: WebSocket):
    """Reproduce un análisis flujo por flujo; un error llega como mensaje "error" y cierra la conexión."""
    await websocket.accept()
    try:
        await play(websocket)
    except WebSocketDisconnect:
        return
    except ApiError as error:
        await websocket.send_json({"type": "error", **error.content()})
    except Exception:
        # Aquí no hay manejador de errores HTTP: el detalle queda en el log y el usuario no lo ve.
        logger.exception("Error inesperado en la simulación")
        await websocket.send_json({"type": "error", **ApiError("internal_error").content()})
    await websocket.close()
