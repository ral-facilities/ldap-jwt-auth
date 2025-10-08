# LDAP-JWT Authentication Service

This is a Python microservice created using FastAPI that provides user authentication against an LDAP server as well as
an SSO (Single Sign-On) OIDC provider, and returns a JSON Web Token (JWT).

## How to Run

This microservice requires an LDAP server to run against.

### Prerequisites

- Docker and Docker Compose installed (if you want to run the microservice inside Docker)
- Python 3.13 installed on your machine (if you are not using Docker)
- OIDC provider(s) to connect to for users authenticating using an SSO OIDC ID token
- LDAP server to connect to for users authenticating using LDAP credentials
- CA certificate PEM file containing all the trusted CA certificates (if LDAP certificate validation is enabled which is
  strongly recommended to be in production)
- Private and public key pair (must be OpenSSH encoded) for encrypting and decrypting the JWTs
- A list of active user emails for SSO OIDC authentication, defining who can use this service
- A list of active usernames for LDAP authentication, defining who can use this service
- This repository cloned

### Prerequisite Steps

1. Create a `.env` file alongside the `.env.example` file. Use the example file as a reference and modify the values
   accordingly.

   ```bash
   cp .env.example .env
   ```

2. Create a `logging.ini` file alongside the `logging.example.ini` file. Use the example file as a reference and modify
   it accordingly:

   ```bash
   cp logging.example.ini logging.ini
   ```

3. Navigate to the `keys` directory in the root of the project directory, and generate OpenSSH encoded private and
   public key pair:

   ```bash
   ssh-keygen -b 2048 -t rsa -f keys/jwt-key -q -N "" -C ""
   ```

4. (If LDAP certificate validation is enabled) Copy the `cacert.pem` file that contains all the trusted CA certificates
   to the `ldap_server_certs` directory in the root of the project.

5. Create a `users_config.yaml` file alongside the `users_config.example.yaml` file and add all the usernames
   (FederalIDs) and emails that can use this system (via LDAP authentication or SSO OIDC), and their role. The
   usernames are the Federal IDs and each one should be stored under `users` using correct yaml notation. You can also
   define the various roles in the system and if they are of the highest privilege.

   ```bash
   cp users_config.example.yaml users_config.yaml
   ```

### Inside of Docker

Ensure that Docker is installed and running on your machine before proceeding.

#### Using `docker-compose.yml`

The easiest way to run the application with Docker for local development is using the `docker-compose.yml` file. It is
configured to start:

- A keycloak instance for SSO authentication that can be accessed at `localhost:9004` using `admin` as the username and
  password to access the Admin Console. To get an ID token from the keycloak instance to then use for the
  `http://localhost:8004/oidc_login/keycloak` endpoint, run:

  ```bash
  curl -X POST http://localhost:9004/realms/testrealm/protocol/openid-connect/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=password" \
     -d "client_id=test-client-id" \
     -d "scope=openid profile email" \
     -d "username=test" \
     -d "password=password"
  ```

- The application in a reload mode which using the mounted `ldap_jwt_auth` directory means that FastAPI will watch for
  changes made to the code and automatically reload the application on the fly.

1. Build and start the Docker container:

   ```bash
   docker compose up
   ```

   The microservice should now be running inside Docker at http://localhost:8004 and its Swagger UI could be accessed
   at http://localhost:8004/docs.

#### Using `Dockerfile` for local development

Use the `Dockerfile`'s dev stage to run just the application itself in a container. Use this only for local development
(not production)! Mounting the `ldap_jwt_auth` directory to the container via a volume means that FastAPI will watch for
changes made to the code and automatically reload the application on the fly.

1. Build an image using the `Dockerfile`'s `dev` stage from the root of the project directory:

   ```bash
   docker build --file Dockerfile --target dev --tag ldap-jwt-auth:dev .
   ```

2. Start the container using the image built and map it to port `8004` locally:

   ```bash
   docker run \
    --publish 8004:8000 \
    --name ldap-jwt-auth \
    --env-file ./.env \
    --volume ./ldap_jwt_auth:/app/ldap_jwt_auth \
    --volume ./keys:/app/keys \
    --volume ./ldap_server_certs/cacert.pem:/app/ldap_server_certs/cacert.pem \
    --volume ./users_config.yaml:/app/users_config.yaml \
    --volume ./maintenance/maintenance.json:/app/maintenance/maintenance.json \
    --volume ./maintenance/scheduled_maintenance.json:/app/maintenance/scheduled_maintenance.json \
    --volume ./logging.ini:/app/logging.ini \
    ldap-jwt-auth:dev
   ```

   The microservice should now be running inside Docker at http://localhost:8004 and its Swagger UI could be accessed
   at http://localhost:8004/docs.

#### Using `Dockerfile` for running the unit tests

Use the `Dockerfile`'s `test` stage to run the unit tests in a container. Mounting the `ldap_jwt_auth` and `test`
directories to the container via volumes means that any changes made to the application or test code will automatically
be synced to the container next time you run the tests.

1. Build an image using the `Dockerfile`'s `test` stage from the root of the project directory:

   ```bash
   docker build --file Dockerfile --target test --tag ldap-jwt-auth:test .
   ```

2. Run the tests using:

   ```bash
   docker run \
    --rm \
    --name ldap-jwt-auth-test \
    --volume ./ldap_jwt_auth:/app/ldap_jwt_auth \
    --volume ./test:/app/test \
    --volume ./logging.ini:/app/logging.ini \
    ldap-jwt-auth:test \
    pytest --config-file test/pytest.ini --cov ldap_jwt_auth --cov-report term-missing test/unit -v
   ```

### Outside of Docker

### Local Setup

Ensure that Python is installed on your machine before proceeding.

1. Create a Python virtual environment and activate it in the root of the project directory:

   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

2. Install the software packages required to build `python-ldap` on your local system, more
   info [here](https://www.python-ldap.org/en/python-ldap-3.3.0/installing.html).

3. Install the required dependencies using pip:

   ```bash
   pip install .[dev]
   pip install -r requirements.txt
   ```

4. Start the application:

   ```bash
   fastapi dev ldap_jwt_auth/main.py --host 0.0.0.0 --port 8004
   ```

   The microservice should now be running locally at http://localhost:8004. The Swagger UI could be accessed
   at http://localhost:8004/docs.

## Notes

### Application Configuration

The configuration for the application is handled
using [Pydantic Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/). It allows for loading config
values from environment variables or the `.env` file. Please note that even when using the `.env` file, Pydantic will
still read environment variables as well as the `.env` file, environment variables will always take priority over
values loaded from the `.env` file.

Listed below are the environment variables supported by the application.

| Environment Variable                                       | Description                                                                                                                                                                                                                     | Mandatory                         | Default Value                                             |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- | --------------------------------------------------------- |
| `API__TITLE`                                               | The title of the API which is added to the generated OpenAPI.                                                                                                                                                                   | No                                | `LDAP-JWT Authentication Service API`                     |
| `API__DESCRIPTION`                                         | The description of the API which is added to the generated OpenAPI.                                                                                                                                                             | No                                | `This is the API for the LDAP-JWT Authentication Service` |
| `API__ROOT_PATH`                                           | (If using a proxy) The path prefix handled by a proxy that is not seen by the app.                                                                                                                                              | No                                | ` `                                                       |
| `API__ALLOWED_CORS_HEADERS`                                | The list of headers that are allowed to be included in cross-origin requests.                                                                                                                                                   | Yes                               |                                                           |
| `API__ALLOWED_CORS_ORIGINS`                                | The list of origins (domains) that are allowed to make cross-origin requests.                                                                                                                                                   | Yes                               |                                                           |
| `API__ALLOWED_CORS_METHODS`                                | The list of methods that are allowed to be used to make cross-origin requests.                                                                                                                                                  | Yes                               |                                                           |
| `AUTHENTICATION__PRIVATE_KEY_PATH`                         | The path to the private key to be used for encoding JWT access and refresh tokens.                                                                                                                                              | Yes                               |                                                           |
| `AUTHENTICATION__PUBLIC_KEY_PATH`                          | The path to the public key to be used for decoding JWT access and refresh tokens signed by the corresponding private key.                                                                                                       | Yes                               |                                                           |
| `AUTHENTICATION__JWT_ALGORITHM`                            | The algorithm to use to decode the JWT access and refresh tokens.                                                                                                                                                               | Yes                               |                                                           |
| `AUTHENTICATION__ACCESS_TOKEN_VALIDITY_MINUTES`            | Minutes after which the JWT access token expires.                                                                                                                                                                               | Yes                               |                                                           |
| `AUTHENTICATION__REFRESH_TOKEN_VALIDITY_DAYS`              | Days after which the JWT refresh token expires.                                                                                                                                                                                 | Yes                               |                                                           |
| `AUTHENTICATION__USERS_CONFIG_PATH`                        | The path to the `yaml` file containing the active usernames and defining who can use this service and their role.                                                                                                               | Yes                               |                                                           |
| `MAINTENANCE__MAINTENANCE_PATH`                            | The path to the `json` file containing the maintenance state.                                                                                                                                                                   | Yes                               |                                                           |
| `MAINTENANCE__SCHEDULED_MAINTENANCE_PATH`                  | The path to the `json` file containing the scheduled maintenance state.                                                                                                                                                         | Yes                               |                                                           |
| `LDAP_SERVER__URL`                                         | The URL to the LDAP server to connect to.                                                                                                                                                                                       | Yes                               |                                                           |
| `LDAP_SERVER__REALM`                                       | The realm for the LDAP server.                                                                                                                                                                                                  | Yes                               |                                                           |
| `LDAP_SERVER__CERTIFICATE_VALIDATION`                      | Whether to enforce TLS certificate validation when connecting to the LDAP server. Disabling this allows insecure connections and is not recommended for production.                                                             | Yes                               |                                                           |
| `LDAP_SERVER__CA_CERTIFICATE_FILE_PATH`                    | The path to the trusted Certificate Authority (CA) file used to verify the LDAP server’s TLS/SSL certificate.                                                                                                                   | If certificate validation enabled |                                                           |
| `OIDC_PROVIDERS__{provider_name}__DISPLAY_NAME`            | The display name (listed in the `GET` response of the `/oidc_providers` endpoint) for use by frontend web applications.                                                                                                         | Yes                               |                                                           |
| `OIDC_PROVIDERS__{provider_name}__CONFIGURATION_URL`       | The URL to the well known configuration for the OIDC provider.                                                                                                                                                                  | Yes                               |                                                           |
| `OIDC_PROVIDERS__{provider_name}__CLIENT_ID`               | The unique identifier for the registered service given by the OIDC provider.                                                                                                                                                    | Yes                               |                                                           |
| `OIDC_PROVIDERS__{provider_name}__VERIFY_CERT`             | Whether to verify the SSL certificate when making `GET` requests to the OIDC provider.                                                                                                                                          | No                                | `False`                                                   |
| `OIDC_PROVIDERS__{provider_name}__REQUEST_TIMEOUT_SECONDS` | The maximum number of seconds that the request should wait for a response from the OIDC provider before timing out.                                                                                                             | No                                | `10`                                                      |
| `OIDC_PROVIDERS__{provider_name}__SCOPE`                   | The claims (listed in the `GET` response of the `/oidc_providers` endpoint) the API client should request from the OIDC provider (i.e. email etc) when obtaining an OIDC ID token for the `/oidc_login/{provider_id}` endpoint. | No                                | `openid email`                                            |
| `OIDC_PROVIDERS__{provider_name}__USERNAME_CLAIM`          | The username claim to get from the OIDC ID token payload to check against the list of active user emails.                                                                                                                       | No                                | `email`                                                   |

### How to add or remove a user from the system

The `users_config.yaml` file at the root of the project directory contains the schema of users with access to the system
through SSO OIDC and/or LDAP authentication. This means that you can add or remove a user from the system by adding or
removing their username/email in the `users_config.yaml` file. You can also define a user's role in their schema, roles
can be defined at the top of the `users_config.yaml` file. See `users_config.example.yaml` for an example yaml
structure.

**PLEASE NOTE** Changes made to the `users_config.yaml` file using vim do not get synced in the Docker container
because it changes the inode index number of the file. A workaround is to create a new file using the
`users_config.yaml` file, apply your changes in the new file, and then overwrite the `users_config.yaml` file
with the content of the new file, see below.

```bash
cp users_config.yaml new_users_config.yaml
vim new_users_config.yaml
cat new_users_config.yaml > users_config.yaml
rm new_users_config.yaml
```

### How to update maintenance or scheduled maintenance state

The `maintenance` folder at the root of the project directory contains two json files which return the appropriate state
of the system. This means that you can edit the values in the files in accordance with the desired state of the system.

**_PLEASE NOTE_** Changes made to `maintenance.json` and `scheduled_maintenance.json` file using vim do not get synced
in the Docker container because it changes the inode index number of the file. A workaround is to create a new file
using the `maintenance.json` or `scheduled_maintenance.json` file, apply your changes in the new file, and then
overwrite the `maintenance.json` / `scheduled_maintenance.json` file with the content of the new file, see below an
example for `maintenance.json` file.

```bash
cp maintenance/maintenance.json new_maintenance.json
vim new_maintenance.json
cat new_maintenance.json > maintenance/maintenance.json
rm new_maintenance.json
```
