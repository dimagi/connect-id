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
   SECRET_KEY=None  # set None to use default secret key provided in settings.py
   APP_HASH=None    # set None to use default APP_HASH provided in settings.py
   ```

6. **Run Django migrations and start the development server:**

   ```bash
   ./manage.py migrate
   ./manage.py runserver
   
