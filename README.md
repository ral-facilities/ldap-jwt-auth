# LDAP-JWT Authentication Service

This is a Python microservice created using FastAPI that provides user authentication against an LDAP server and returns
a JSON Web Token (JWT).

## How to Run

This microservice requires an LDAP server to run against.

### Prerequisites

- Docker and Docker Compose installed (if you want to run the microservice inside Docker)
- Python 3.12 installed on your machine (if you are not using Docker)
- LDAP server to connect to
- CA certificate PEM file containing all the trusted CA certificates (if LDAP certificate validation is enabled which is
  strongly recommended to be in production)
- Private and public key pair (must be OpenSSH encoded) for encrypting and decrypting the JWTs
- A list of active usernames, defining who can use this service
- This repository cloned

### Docker Setup

Ensure that Docker is installed and running on your machine before proceeding.

1. Create a `.env` file alongside the `.env.example` file. Use the example file as a reference and modify the values
   accordingly.

   ```bash
   cp ldap_jwt_auth/.env.example ldap_jwt_auth/.env
   ```

2. Create a `logging.ini` file alongside the `logging.example.ini` file. Use the example file as a reference and modify
   it accordingly:

   ```bash
   cp ldap_jwt_auth/logging.example.ini ldap_jwt_auth/logging.ini
   ```

3. Navigate to the `keys` directory in the root of the project directory, and generate OpenSSH encoded private and
   public key pair:

   ```bash
   ssh-keygen -b 2048 -t rsa -f keys/jwt-key -q -N "" -C ""
   ```

4. (If LDAP certificate validation is enabled) Copy the `cacert.pem` file that contains all the trusted CA certificates
   to the `ldap_server_certs` directory in the root of the project.

5. Create a `active_usernames.txt` file alongside the `active_usernames.example.txt` file and add all the usernames that
   can use this system. The usernames are the Federal IDs and each one should be stored on a separate line.
   ```bash
   cp active_usernames.example.txt active_usernames.txt
   ```

#### Using `docker-compose.yml`

The easiest way to run the application with Docker for local development is using the `docker-compose.yml` file. It is
configured to start the application in a reload mode using the `Dockerfile`.

1. Build and start the Docker container:
   ```bash
   docker-compose up
   ```
   The microservice should now be running inside Docker at http://localhost:8000 and its Swagger UI could be accessed
   at http://localhost:8000/docs.

#### Using `Dockerfile`

Use the `Dockerfile` to run just the application itself in a container. Use this only for local development (not
production)!

1. Build an image using the `Dockerfile` from the root of the project directory:

   ```bash
   docker build -f Dockerfile -t ldap_jwt_auth_api_image .
   ```

2. Start the container using the image built and map it to port `8000` locally:
   ```bash
   docker run -p 8000:8000 --name ldap_jwt_auth_api_container -v ./keys/jwt-key:/ldap-jwt-auth-run/keys/jwt-key -v ./keys/jwt-key.pub:/ldap-jwt-auth-run/keys/jwt-key.pub -v ./ldap_server_certs/cacert.pem:/ldap-jwt-auth-run/ldap_server_certs/cacert.pem -v ./active_usernames.txt:/ldap-jwt-auth-run/active_usernames.txt ldap_jwt_auth_api_image
   ```
   or with values for the environment variables:
   ```bash
   docker run -p 8000:8000 --name ldap_jwt_auth_api_container --env AUTHENTICATION__ACCESS_TOKEN_VALIDITY_MINUTES=10 -v ./keys/jwt-key:/ldap-jwt-auth-run/keys/jwt-key -v ./keys/jwt-key.pub:/ldap-jwt-auth-run/keys/jwt-key.pub -v ./ldap_server_certs/cacert.pem:/ldap-jwt-auth-run/ldap_server_certs/cacert.pem -v ./active_usernames.txt:/ldap-jwt-auth-run/active_usernames.txt ldap_jwt_auth_api_image
   ```
   The microservice should now be running inside Docker at http://localhost:8000 and its Swagger UI could be accessed
   at http://localhost:8000/docs.

#### Using `Dockerfile.prod`

Use the `Dockerfile.prod` to run just the application itself in a container. This can be used for production.

1. Private keys are only readable by the owner. Given that the private key is generated on the host machine and the
   container runs with a different user, it means that the key is not readable by the user in the container because the
   ownership belongs to the user on the host. This can be solved by transferring the ownership to the user in the
   container and setting the permissions.

   ```bash
   sudo chown 500:500 keys/jwt-key
   sudo chmod 0400 keys/jwt-key
   ```

2. Build an image using the `Dockerfile.prod` from the root of the project directory:

   ```bash
   docker build -f Dockerfile.prod -t ldap_jwt_auth_api_image .
   ```

3. Start the container using the image built and map it to port `8000` locally:
   ```bash
   docker run -p 8000:8000 --name ldap_jwt_auth_api_container -v ./keys/jwt-key:/ldap-jwt-auth-run/keys/jwt-key -v ./keys/jwt-key.pub:/ldap-jwt-auth-run/keys/jwt-key.pub -v ./ldap_server_certs/cacert.pem:/ldap-jwt-auth-run/ldap_server_certs/cacert.pem -v ./active_usernames.txt:/ldap-jwt-auth-run/active_usernames.txt ldap_jwt_auth_api_image
   ```
   or with values for the environment variables:
   ```bash
   docker run -p 8000:8000 --name ldap_jwt_auth_api_container --env AUTHENTICATION__ACCESS_TOKEN_VALIDITY_MINUTES=10 -v ./keys/jwt-key:/ldap-jwt-auth-run/keys/jwt-key -v ./keys/jwt-key.pub:/ldap-jwt-auth-run/keys/jwt-key.pub -v ./ldap_server_certs/cacert.pem:/ldap-jwt-auth-run/ldap_server_certs/cacert.pem -v ./active_usernames.txt:/ldap-jwt-auth-run/active_usernames.txt ldap_jwt_auth_api_image
   ```
   The microservice should now be running inside Docker at http://localhost:8000 and its Swagger UI could be accessed
   at http://localhost:8000/docs.

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
4. Create a `.env` file alongside the `.env.example` file. Use the example file as a reference and modify the values
   accordingly.

   ```bash
   cp ldap_jwt_auth/.env.example ldap_jwt_auth/.env
   ```

5. Create a `logging.ini` file alongside the `logging.example.ini` file. Use the example file as a reference and modify
   it accordingly:

   ```bash
   cp ldap_jwt_auth/logging.example.ini ldap_jwt_auth/logging.ini
   ```

6. Navigate to the `keys` directory in the root of the project directory, and generate OpenSSH encoded private and
   public key pair:

   ```bash
   ssh-keygen -b 2048 -t rsa -f keys/jwt-key -q -N "" -C ""
   ```

7. (If LDAP certificate validation is enabled) Copy the `cacert.pem` file that contains all the trusted CA certificates
   to the `ldap_server_certs` directory in the root of the project.

8. Create a `active_usernames.txt` file alongside the `active_usernames.example.txt` file and add all the usernames that
   can use this system. The usernames are the Federal IDs and each one should be stored on a separate line.

   ```bash
   cp active_usernames.example.txt active_usernames.txt
   ```

9. Start the microservice using FastAPI's CLI:

   ```bash
   fastapi dev ldap_jwt_auth/main.py --log-config ldap_jwt_auth/logging.ini
   ```

   The microservice should now be running locally at http://localhost:8000. The Swagger UI could be accessed
   at http://localhost:8000/docs.

10. To run the unit tests, run:

```bash
pytest -c test/pytest.ini test/unit/
```

## Notes

### Application Configuration

The configuration for the application is handled
using [Pydantic Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/). It allows for loading config
values from environment variables or the `.env` file. Please note that even when using the `.env` file, Pydantic will
still read environment variables as well as the `.env` file, environment variables will always take priority over
values loaded from the `.env` file.

Listed below are the environment variables supported by the application.

| Environment Variable                            | Description                                                                                                               | Mandatory | Default Value                                             |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | --------- | --------------------------------------------------------- |
| `API__TITLE`                                    | The title of the API which is added to the generated OpenAPI.                                                             | No        | `LDAP-JWT Authentication Service API`                     |
| `API__DESCRIPTION`                              | The description of the API which is added to the generated OpenAPI.                                                       | No        | `This is the API for the LDAP-JWT Authentication Service` |
| `API__ROOT_PATH`                                | (If using a proxy) The path prefix handled by a proxy that is not seen by the app.                                        | No        | ` `                                                       |
| `API__ALLOWED_CORS_HEADERS`                     | The list of headers that are allowed to be included in cross-origin requests.                                             | Yes       |                                                           |
| `API__ALLOWED_CORS_ORIGINS`                     | The list of origins (domains) that are allowed to make cross-origin requests.                                             | Yes       |                                                           |
| `API__ALLOWED_CORS_METHODS`                     | The list of methods that are allowed to be used to make cross-origin requests.                                            | Yes       |                                                           |
| `AUTHENTICATION__PRIVATE_KEY_PATH`              | The path to the private key to be used for encoding JWT access and refresh tokens.                                        | Yes       |                                                           |
| `AUTHENTICATION__PUBLIC_KEY_PATH`               | The path to the public key to be used for decoding JWT access and refresh tokens signed by the corresponding private key. | Yes       |                                                           |
| `AUTHENTICATION__JWT_ALGORITHM`                 | The algorithm to use to decode the JWT access and refresh tokens.                                                         | Yes       |                                                           |
| `AUTHENTICATION__ACCESS_TOKEN_VALIDITY_MINUTES` | Minutes after which the JWT access token expires.                                                                         | Yes       |                                                           |
| `AUTHENTICATION__REFRESH_TOKEN_VALIDITY_DAYS`   | Days after which the JWT refresh token expires.                                                                           | Yes       |                                                           |
| `AUTHENTICATION__ACTIVE_USERNAMES_PATH`         | The path to the `txt` file containing the active usernames and defining who can use this service.                         | Yes       |                                                           |
| `MAINTENANCE__MAINTENANCE_PATH`                 | The path to the `json` file containing the maintenance state.                                                             | Yes       |                                                           |
| `MAINTENANCE__SCHEDULED_MAINTENANCE_PATH`       | The path to the `json` file containing the scheduled maintenance state.                                                   | Yes       |                                                           |
| `LDAP_SERVER__URL`                              | The URL to the LDAP server to connect to.                                                                                 | Yes       |                                                           |
| `LDAP_SERVER__REALM`                            | The realm for the LDAP server.                                                                                            | Yes       |                                                           |

### How to add or remove user from system

The `active_usernames.txt` file at the root of the project directory contains the Federal IDs of the users with access
to the system. This means that you can add or remove a user from the system by adding or removing their Federal ID in
the `active_usernames.txt` file.

**PLEASE NOTE** Changes made to the `active_usernames.txt` file using vim do not get synced in the Docker container
because it changes the inode index number of the file. A workaround is to create a new file using
the `active_usernames.txt` file, apply your changes in the new file, and then overwrite the `active_usernames.txt` file
with the content of the new file, see below.

```bash
cp active_usernames.txt new_active_usernames.txt
vim new_active_usernames.txt
cat new_active_usernames.txt > active_usernames.txt
rm new_active_usernames.txt
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
