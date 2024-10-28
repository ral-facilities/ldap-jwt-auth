FROM python:3.12.7-alpine3.20@sha256:38e179a0f0436c97ecc76bcd378d7293ab3ee79e4b8c440fdc7113670cb6e204

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
