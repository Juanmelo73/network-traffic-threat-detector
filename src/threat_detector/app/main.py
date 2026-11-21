"""Aplicación FastAPI: carga los modelos al arrancar, registra las rutas, sirve el frontend y da formato a los errores."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from threat_detector.app.analyses import AnalysisStore
from threat_detector.app.predictors import build_predictors
from threat_detector.app.routes import router
from threat_detector.app.schemas import INVALID_REQUEST_WITHOUT_FIELD, ApiError
from threat_detector.artifacts import ArtifactError, load_artifacts
from threat_detector.config import ARTIFACTS_DIR, STATIC_DIR

logger = logging.getLogger(__name__)


def error_response(error, headers=None):
    return JSONResponse(status_code=error.status_code, content=error.content(), headers=headers)


def create_app(artifacts_dir=ARTIFACTS_DIR):
    """Arma la app con los modelos de artifacts_dir; las pruebas la arman con una carpeta temporal."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Los modelos se cargan una sola vez. Si algo falla, la app no arranca (contrato, sección 10).
        try:
            registry, models = load_artifacts(artifacts_dir)
        except ArtifactError as error:
            logger.error("No se pudieron cargar los modelos: %s", error)
            raise
        app.state.registry = registry
        app.state.predictors = build_predictors(models)
        app.state.analyses = AnalysisStore()
        yield

    app = FastAPI(title="Network Traffic Threat Detector", lifespan=lifespan)
    app.include_router(router)
    # Los archivos de static/ (páginas, estilos, scripts y sample_flows.csv). FastAPI revisa primero
    # las rutas de la API. Con fallback=None, una dirección que no existe da not_found en vez de
    # devolver index.html.
    app.frontend("/", directory=STATIC_DIR, fallback=None)

    @app.exception_handler(ApiError)
    async def api_error_handler(request: Request, error: ApiError):
        return error_response(error)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, error: RequestValidationError):
        # Se informa el primer campo con problemas, por su nombre (por ejemplo, use_labels).
        field = str(error.errors()[0]["loc"][-1])
        return error_response(ApiError("invalid_request", {"field": field}))

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(request: Request, error: StarletteHTTPException):
        if error.status_code == 404:
            api_error = ApiError("not_found")
        elif error.status_code == 405:
            api_error = ApiError("method_not_allowed")
        else:
            api_error = ApiError("invalid_request", {"field": None}, INVALID_REQUEST_WITHOUT_FIELD)
        # Conserva los encabezados del error, como Allow en un 405.
        return error_response(api_error, getattr(error, "headers", None))

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, error: Exception):
        # El usuario no ve el error de Python (contrato, sección 9).
        return error_response(ApiError("internal_error"))

    return app


app = create_app()
