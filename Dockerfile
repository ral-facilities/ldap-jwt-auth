FROM python:3.12.9-alpine3.21@sha256:28b8a72c4e0704dd2048b79830e692e94ac2d43d30c914d54def6abf74448a4e

WORKDIR /ldap-jwt-auth-run

COPY pyproject.toml requirements.txt ./
COPY ldap_jwt_auth/ ldap_jwt_auth/

RUN --mount=type=cache,target=/root/.cache \
    set -eux; \
    \
    # Install python-ldap system dependencies \
    apk add --no-cache build-base openldap-dev; \
    \
    python -m pip install .[dev]; \
    # Ensure the pinned versions of the production dependencies and subdependencies are installed \
    python -m pip install --no-cache-dir --requirement requirements.txt;

CMD ["fastapi", "dev", "ldap_jwt_auth/main.py", "--host", "0.0.0.0", "--port", "8000"]
EXPOSE 8000
