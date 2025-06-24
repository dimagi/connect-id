import requests
from django.conf import settings


def check_number_for_existing_invites(phone_number):
    url = settings.CONNECT_INVITED_USER_URL
    auth = (settings.COMMCARE_CONNECT_CLIENT_ID, settings.COMMCARE_CONNECT_CLIENT_SECRET)
    response = requests.get(url, auth=auth, data={"phone_number": phone_number})
    data = response.json()
    return data.get("invited", False)
