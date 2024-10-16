import requests

from connectid import celery_app


class CommCareHQAPIException(Exception):
    pass


@celery_app.task()
def make_request_to_service(url, json_data):
    #: TO-DO add authorization.
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(url, json=json_data, headers=headers)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        return CommCareHQAPIException(
            {"status": "error", "message": str(e)},
        )
