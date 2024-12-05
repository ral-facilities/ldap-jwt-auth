FROM python:3.12.8-alpine3.20@sha256:bb94273467caf397de28b4e6dd09ca4a2dd1b53fa9b130d5b2c7c82719258356

WORKDIR /ldap-jwt-auth-run

COPY pyproject.toml ./
COPY ldap_jwt_auth/ ldap_jwt_auth/

RUN --mount=type=cache,target=/root/.cache \
    set -eux; \
    \
    apk add --no-cache build-base openldap-dev; \
    python3 -m pip install .[dev];

CMD ["uvicorn", "ldap_jwt_auth.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
EXPOSE 8000
