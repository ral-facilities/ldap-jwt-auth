FROM python:3.12.10-alpine3.21@sha256:9c51ecce261773a684c8345b2d4673700055c513b4d54bc0719337d3e4ee552e AS dev

WORKDIR /app

COPY pyproject.toml requirements.txt ./
COPY ldap_jwt_auth/ ldap_jwt_auth/

RUN --mount=type=cache,target=/root/.cache \
    set -eux; \
    \
    # Install python-ldap system dependencies \
    apk add --no-cache build-base openldap-dev; \
    \
    pip install --no-cache-dir .[dev]; \
    # Ensure the pinned versions of the production dependencies and subdependencies are installed \
    pip install --no-cache-dir --requirement requirements.txt;

CMD ["fastapi", "dev", "ldap_jwt_auth/main.py", "--host", "0.0.0.0", "--port", "8000"]

EXPOSE 8000


FROM dev AS test

WORKDIR /app

COPY test/ test/

CMD ["pytest",  "--config-file", "test/pytest.ini", "-v"]


FROM python:3.12.10-alpine3.21@sha256:9c51ecce261773a684c8345b2d4673700055c513b4d54bc0719337d3e4ee552e AS prod

WORKDIR /app

COPY requirements.txt ./
COPY ldap_jwt_auth/ ldap_jwt_auth/

RUN --mount=type=cache,target=/root/.cache \
    set -eux; \
    \
    # Install python-ldap system dependencies \
    apk add --no-cache build-base openldap-dev python3-dev; \
    \
    pip install --no-cache-dir --requirement requirements.txt; \
    \
    # Create a non-root user to run as \
    addgroup -g 500 -S ldap-jwt-auth; \
    adduser -S -D -G ldap-jwt-auth -H -u 500 -h /app ldap-jwt-auth;

USER ldap-jwt-auth

CMD ["fastapi", "run", "ldap_jwt_auth/main.py", "--host", "0.0.0.0", "--port", "8000"]

EXPOSE 8000
