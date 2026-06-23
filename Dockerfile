########################################################################################################################
# Base stage, includes uv
########################################################################################################################
FROM python:3.13.14-alpine3.24@sha256:db66119d6609a3a941a9433b225f4e13d33c459cede097cf3ec2fc4d1bd314b2 AS base
COPY --from=ghcr.io/astral-sh/uv:0.11.21@sha256:ff07b86af50d4d9391d9daf4ff89ce427bc544f9aae87057e69a1cc0aa369946 /uv /uvx /bin/

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1
# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy
# Disable use of uv-managed Python versions
ENV UV_NO_MANAGED_PYTHON=1
# Disable Python downloads so that the system interpreter is used across images
ENV UV_PYTHON_DOWNLOADS=0

# Install python-ldap system dependencies
RUN apk add --no-cache build-base openldap-dev

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./


########################################################################################################################
# Stage for local development
########################################################################################################################
FROM base AS dev

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    set -eux; \
    \
    # Lock and install all dependencies but do not install the project \
    uv sync --locked --no-install-project;

COPY ldap_jwt_auth/ ldap_jwt_auth/

RUN --mount=type=cache,target=/root/.cache/uv \
    set -eux; \
    \
    # Install the project \
    uv sync --locked;

CMD ["/app/.venv/bin/fastapi", "dev", "ldap_jwt_auth/main.py", "--host", "0.0.0.0", "--port", "8000"]

EXPOSE 8000


########################################################################################################################
# Stage for running tests
########################################################################################################################
FROM dev AS test

WORKDIR /app

COPY test/ test/

CMD ["/app/.venv/bin/pytest",  "--config-file", "test/pytest.ini", "-v"]


########################################################################################################################
# Stage for production-ready build of the project
########################################################################################################################
FROM base AS prod-build

# Omit development dependencies
ENV UV_NO_DEV=1

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    set -eux; \
    \
    # Lock and install all dependencies but do not install the project \
    uv sync --locked --no-install-project;

COPY ldap_jwt_auth/ ldap_jwt_auth/

RUN --mount=type=cache,target=/root/.cache/uv \
    set -eux; \
    \
    # Install the project \
    uv sync --locked;


########################################################################################################################
# Minimal production-ready image
########################################################################################################################
# The same image that matches the build stage must be used as the path to the Python executable must be the same.
FROM python:3.13.14-alpine3.24@sha256:db66119d6609a3a941a9433b225f4e13d33c459cede097cf3ec2fc4d1bd314b2 AS prod

# Install python-ldap system dependencies
RUN apk add --no-cache build-base openldap-dev

WORKDIR /app

RUN set -eux; \
    \
    # Create a non-root user to run as \
    addgroup -g 500 -S ldap-jwt-auth; \
    adduser -S -D -G ldap-jwt-auth -H -u 500 -h /app ldap-jwt-auth;

# Copy the application from the prod-build stage
COPY --from=prod-build /app /app

USER ldap-jwt-auth

CMD ["/app/.venv/bin/fastapi", "run", "ldap_jwt_auth/main.py", "--host", "0.0.0.0", "--port", "8000"]

EXPOSE 8000
