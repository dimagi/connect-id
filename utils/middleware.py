from rest_framework.settings import api_settings


class CurrentVersionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        if request.versioning_scheme is not None:
            response.headers["X-CURRENT-API-VERSION"] = api_settings.DEFAULT_VERSION

        return response
