# LDAP-JWT Authentication Service
This is a Python microservice that provides user authentication against an LDAP server and returns a JSON Web Token
(JWT).

## How to Run
This microservice requires an LDAP server to run against.

### Prerequisites
- Docker installed (if you want to run the microservice inside Docker)
- Python 3.10 (or above) and an LDAP server to connect to
- Private and public key pair (must be OpenSSH encoded) for encrypting and decrypting the JWTs
- This repository cloned

### Docker Setup
The easiest way to run the application with Docker for local development is using the `docker-compose.yml` file. It is
configured to start the application in a reload mode using the `Dockerfile`. You can also use the `Dockerfile` directly
to run the application in a container. Please do not use the `Dockerfile` in production.

Ensure that Docker is installed and running on your machine before proceeding.

#### Using Docker Compose File
1. Create a `.env` file alongside the `.env.example` file. Use the example file as a reference and modify the values
   accordingly.

2. Create a `logging.ini` file alongside the `logging.example.ini` file. Use the example file as a reference and modify
   it accordingly.

3. Create a `keys` directory in the root of the project directory, navigate to it, and generate OpenSSH encoded private
   and public key pair:
   ```bash
   mkdir keys
   cd keys/
   ssh-keygen -b 2048 -t rsa -f jwt-key -q -N ""
   ```

4. Build and start the Docker container:
   ```bash
   docker-compose up
   ```
   The microservice should now be running inside Docker at http://localhost:8000 and its Swagger UI could be accessed
   at http://localhost:8000/docs.

#### Using Dockerfile
1. Build an image using the `Dockerfile` from the root of the project directory:
   ```bash
   docker build -f Dockerfile -t ldap_jwt_auth_image .
   ```

2. Start the container using the image built and map it to port `8000` locally:
   ```bash
   docker run -p 8000:8000 --name ldap_jwt_auth_container ldap_jwt_auth_image
   ```
   The microservice should now be running inside Docker at http://localhost:8000 and its Swagger UI could be accessed
   at http://localhost:8000/docs.

### Local Setup
Ensure that you have an LDAP server to connect to.

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
   ```

4. Create a `.env` file alongside the `.env.example` file. Use the example file as a reference and modify the values
   accordingly.

5. Create a `logging.ini` file alongside the `logging.example.ini` file. Use the example file as a reference and modify
   it accordingly.

6. Start the microservice using Uvicorn:
   ```bash
   uvicorn ldap_jwt_auth.main:app --log-config ldap_jwt_auth/logging.ini --reload
   ```
   The microservice should now be running locally at http://localhost:8000. The Swagger UI could be accessed
   at http://localhost:8000/docs.
