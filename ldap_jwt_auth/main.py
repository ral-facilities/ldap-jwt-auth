"""
Main module contains the API entrypoint.
"""

import logging

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ldap_jwt_auth.core.config import config
from ldap_jwt_auth.core.logger_setup import setup_logger
from ldap_jwt_auth.routers import login, maintenance, refresh, verify

app = FastAPI(title=config.api.title, description=config.api.description, root_path=config.api.root_path)

setup_logger()
logger = logging.getLogger()
logger.info("Logging now setup")


@app.exception_handler(Exception)
async def custom_general_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    """
    Custom exception handler for FastAPI to handle uncaught exceptions. It logs the error and returns an appropriate
    response.

    :param _: Unused
    :param exc: The exception object that triggered this handler.
    :return: A JSON response indicating that something went wrong.
    """
    logger.exception(exc)
    return JSONResponse(content={"detail": "Something went wrong"}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.exception_handler(RequestValidationError)
async def custom_validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Custom exception handler for FastAPI to handle `RequestValidationError`.

    This method is used to handle validation errors that occur when processing incoming requests in FastAPI. When a
    `RequestValidationError` is raised during request parsing or validation, this handler will be triggered to log the
    error and call `request_validation_exception_handler` to return an appropriate response.

    :param _: Unused
    :param exc: The exception object representing the validation error.
    :return: A JSON response with validation error details.
    """
    # Exclude input as it may contain sensitive information which we do not want to log or return back to user
    detail = {"detail": jsonable_encoder(exc.errors(), exclude={"input"})}
    # The traceback here contains the exception message which includes the input hence why it is being excluded
    logger.exception(detail, exc_info=False)
    return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content=detail)


app.add_middleware(
    CORSMiddleware,
    allow_origins=config.api.allowed_cors_origins,
    allow_credentials=True,
    allow_methods=config.api.allowed_cors_methods,
    allow_headers=config.api.allowed_cors_headers,
)

app.include_router(login.router)
app.include_router(refresh.router)
app.include_router(verify.router)
app.include_router(maintenance.router)


@app.get("/")
def read_root():
    """
    Root endpoint for the API.
    """
    return {"title": config.api.title}
