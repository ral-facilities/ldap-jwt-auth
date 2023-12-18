from fastapi import FastAPI

API_DESCRIPTION = "This is the API for the LDAP-JWT Authentication Service"
API_TITLE = "LDAP-JWT Authentication Service API"

app = FastAPI(title=API_TITLE, description=API_DESCRIPTION)


@app.get("/")
def read_root():
    return {"title": API_TITLE}
