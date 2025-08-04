FROM python:3.12.11-alpine3.22@sha256:9b8808206f4a956130546a32cbdd8633bc973b19db2923b7298e6f90cc26db08 AS base

# Install python-ldap system dependencies
RUN apk add --no-cache build-base openldap-dev

WORKDIR /app

COPY pyproject.toml requirements.txt ./
COPY ldap_jwt_auth/ ldap_jwt_auth/


FROM base AS dev

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache \
    set -eux; \
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


FROM base AS prod

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache \
    set -eux; \
    \
    # Ensure the package gets installed properly using the pyproject.toml file \
    pip install --no-cache-dir .; \
    # Ensure the pinned versions of the production dependencies and subdependencies are installed \
    pip install --no-cache-dir --requirement requirements.txt; \
    \
    # Create a non-root user to run as \
    addgroup -g 500 -S ldap-jwt-auth; \
    adduser -S -D -G ldap-jwt-auth -H -u 500 -h /app ldap-jwt-auth;

USER ldap-jwt-auth

CMD ["fastapi", "run", "ldap_jwt_auth/main.py", "--host", "0.0.0.0", "--port", "8000"]

EXPOSE 8000
