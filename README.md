# Connect-ID

## Steps to Set Up the Project Locally:

1. **Create and activate a Python virtual environment using Python 3.11:**

   ```bash
   python3.11 -m venv <virtual-env-path>
   source <virtual-env-path>/bin/activate  # On Windows, use <virtual-env-path>\Scripts\activate
   ```

2. **Install the required dependencies:**

   ```bash
   pip install -r requirements-dev.txt
   ```

3. **Install Git hooks:**

   ```bash
   pre-commit install
   pre-commit run -a
   ```

4. **Create an environment file and edit the settings as needed:**

   ```bash
   cp .env_template .env
   ```

5. **Set the following environment variables in the `.env` file:**

   ```env
   DATABASE_URL=
   DEBUG=True
   ```

````
6. **Run local services with docker-compose**
   ```bash
   docker compose up
````

7. **Run Django migrations and start the development server:**

   ```bash
   ./manage.py migrate
   ./manage.py runserver
   ```

## Production Deploy

### Setup

#### Kamal

(requires Ruby)

```bash
gem install kamal -v '~> 1.9.2'
```

#### 1Password CLI

See https://developer.1password.com/docs/cli/get-started/

Note: Do not use Flatpack or snap to install 1password CLI as these do not work with the SSH agent.

You will also need to update the 1Password configuration to allow it to access the SSH key:

_~/.config/1Password/ssh/agent.toml_

```toml
[[ssh-keys]]
vault = "Commcare Connect"
```

See https://developer.1password.com/docs/ssh/agent for more details.

To test that this is working you can run:

```bash
ssh connect@54.160.64.28
```

#### AWS CLI

```bash
aws configure sso --profile commcare-connect
aws sso login --profile commcare-connect
```

Note: If you used a different profile name you will need to set the `AWS_PROFILE` environment variable to the profile name.

### Deploy

To deploy run `kamal deploy` from within the `deploy` directory. Make sure you are on the `main` branch and have pulled the latest code.
