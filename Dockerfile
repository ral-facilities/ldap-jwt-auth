FROM python:3.12.10-alpine3.21@sha256:9c51ecce261773a684c8345b2d4673700055c513b4d54bc0719337d3e4ee552e

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
