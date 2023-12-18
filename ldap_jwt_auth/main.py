"""
Main module contains the API entrypoint.
"""
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ldap_jwt_auth.core.logger_setup import setup_logger

API_DESCRIPTION = "This is the API for the LDAP-JWT Authentication Service"
API_TITLE = "LDAP-JWT Authentication Service API"

app = FastAPI(title=API_TITLE, description=API_DESCRIPTION)

setup_logger()
logger = logging.getLogger()
logger.info("Logging now setup")

# Fixes CORS issues but should be updated before deploying to prod
ALLOWED_ORIGINS = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    """
    Root endpoint for the API.
    """
    return {"title": API_TITLE}
