# Local Setup

- Clone this repo
- Copy `.env_example` to `docker.env`
- Run `./docker-compose up --build -d`

This will start the django server on port 8000

## To setup users

Navigate to localhost:8000/users/register and make a 
POST request with a body similar to below

```
{"username": "sreddy_cc", "password": "1234", "phone_number": "<mobile-number-with-country-code>", "recovery_phone": "mobile-number-with-country-code", "name": "sreddy connect", "dob": "1990-04-16"}
```
