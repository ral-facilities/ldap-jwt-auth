FROM python:3.12.2-alpine3.19@sha256:1a0501213b470de000d8432b3caab9d8de5489e9443c2cc7ccaa6b0aa5c3148e

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
