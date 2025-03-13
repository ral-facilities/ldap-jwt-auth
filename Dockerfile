FROM python:3.12.9-alpine3.20@sha256:4ce45e8acd11d49ee07aa736cd7ca2950df75033b946f3a5d9eca1cb4aae2ab7

WORKDIR /ldap-jwt-auth-run

COPY pyproject.toml ./
COPY ldap_jwt_auth/ ldap_jwt_auth/

RUN --mount=type=cache,target=/root/.cache \
    set -eux; \
    \
    apk add --no-cache build-base openldap-dev; \
    python3 -m pip install .[dev];

CMD ["fastapi", "dev", "ldap_jwt_auth/main.py", "--host", "0.0.0.0", "--port", "8000"]
EXPOSE 8000
