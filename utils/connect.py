import requests
from django.conf import settings


def check_number_for_existing_invites(phone_number):
    url = settings.CONNECT_INVITED_USER_URL
    auth = (settings.COMMCARE_CONNECT_CLIENT_ID, settings.COMMCARE_CONNECT_CLIENT_SECRET)
    response = requests.get(url, auth=auth, params={"phone_number": phone_number})
    data = response.json()
    return data.get("invited", False)


def resend_connect_invite(user):
    url = settings.CONNECT_RESEND_INVITES_URL
    auth = (settings.COMMCARE_CONNECT_CLIENT_ID, settings.COMMCARE_CONNECT_CLIENT_SECRET)
    data = {
        "phone_number": user.phone_number.as_e164,
        "username": user.username,
        "name": user.name,
    }
    requests.post(url, auth=auth, data=data)


def get_connect_toggles(username=None, phone_number=None):
    url = settings.CONNECT_TOGGLES_URL
    auth = (settings.COMMCARE_CONNECT_CLIENT_ID, settings.COMMCARE_CONNECT_CLIENT_SECRET)
    params = {}
    if username is not None:
        params["username"] = username
    elif phone_number is not None:
        params["phone_number"] = phone_number
    response = requests.get(url, auth=auth, params=params)
    data = response.json()
    return {toggle["name"]: toggle["active"] for toggle in data.get("toggles", {})}
