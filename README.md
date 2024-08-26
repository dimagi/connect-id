## Local Setup

- Clone this repo
- Copy `.env_example` to `docker.env`
- Run `docker-compose up --build -d`

This will start the django server on port 8000

### To setup users

Navigate to localhost:8000/users/register and make a 
POST request with a body similar to below

```
{"username": "sreddy_cc", "password": "1234", "phone_number": "<mobile-number-with-country-code>", "recovery_phone": "mobile-number-with-country-code", "name": "sreddy connect", "dob": "1990-04-16"}
```

## Production Deploy

### Initial Setup

- Create a `deploy.yml` file for the new server based on `config/deploy.yml`
- Install the SSH Key locally
- Install aws cli. This handles getting the aws docker registry password
- Follow https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user to add user to docker group
- Build a `.env` file based on `production.env_example` template
- Run `kamal setup`. This will perform first time setup on the server as well as do a deploy.

### Deploy

To deploy run `kamal deploy`
