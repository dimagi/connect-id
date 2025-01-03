# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "django-insecure-yofpqrszrdtv0ftihjd09cuim2al9^n9j^b85%-y0v*^_lj18d"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "connect",
        "USER": "connect",
        "PASSWORD": "connect",
        "HOST": "localhost",
        "PORT": "5433",
    }
}

ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

TWILIO_ACCOUNT_SID = None
TWILIO_AUTH_TOKEN = None
TWILIO_MESSAGING_SERVICE = None

FCM_CREDENTIALS = None
