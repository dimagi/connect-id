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
    requests.post(url, auth, data=data)
