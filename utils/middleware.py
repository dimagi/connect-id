import base64
import logging

logger = logging.getLogger(__name__)

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

        if response.status_code == 401:
            auth_header = request.headers.get('AUTHORIZATION', '')
            username = None
            auth_error = None

            if auth_header.startswith('Basic '):
                try:
                    encoded_credentials = auth_header.split(' ')[1]
                    decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
                    username, _ = decoded_credentials.split(':')
                except ValueError as e:
                    auth_error = str(e)
                    username = None

            scope = sentry_sdk.get_current_scope()
            scope.set_user({'username': username, })

            error_msg = "401 Unauthorized captured Error."
            if auth_error:
                error_msg += f" Auth header error: {auth_error}"

            sentry_sdk.capture_message(
                message=error_msg,
                level="error",
            )

        return response
