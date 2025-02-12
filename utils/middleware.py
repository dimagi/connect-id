import sentry_sdk
from rest_framework.settings import api_settings


class CurrentVersionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.include_version_headers = False
        response = self.get_response(request)
        if request.include_version_headers:
            response.headers["X-API-Current-Version"] = api_settings.DEFAULT_VERSION

        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        if hasattr(view_func, 'cls') and view_func.cls.versioning_class is not None:
            request.include_version_headers = True


class Log401ErrorsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Check if the response status code is 401
        if response.status_code == 401:
            sentry_sdk.capture_message(
                f"401 Unauthorized captured Error",
                level="error",
            )

        return response


