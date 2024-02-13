FROM python:3.10-alpine3.19

WORKDIR /ldap-jwt-auth-run

COPY pyproject.toml ./
COPY ldap_jwt_auth/ ldap_jwt_auth/
COPY logs/ logs/

RUN --mount=type=cache,target=/root/.cache \
    set -eux; \
    \
    apk add --no-cache build-base openldap-dev; \
    python3 -m pip install .[dev];

CMD ["uvicorn", "ldap_jwt_auth.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
EXPOSE 8000
