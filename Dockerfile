FROM python:3.12.11-alpine3.21@sha256:690af2fd7f62e24289b28a397baa54eb6978340b4a3106df1015807706f1c7f2

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

CMD ["uvicorn", "ldap_jwt_auth.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
EXPOSE 8000
