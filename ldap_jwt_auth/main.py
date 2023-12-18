import logging

from fastapi import FastAPI

from ldap_jwt_auth.core.logger_setup import setup_logger

API_DESCRIPTION = "This is the API for the LDAP-JWT Authentication Service"
API_TITLE = "LDAP-JWT Authentication Service API"

app = FastAPI(title=API_TITLE, description=API_DESCRIPTION)

setup_logger()
logger = logging.getLogger()
logger.info("Logging now setup")


@app.get("/")
def read_root():
    return {"title": API_TITLE}
