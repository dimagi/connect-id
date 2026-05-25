import requests
from django.http import JsonResponse
from django.views import View

from .utils import get_user_toggles


class TogglesView(View):
    def get(self, request):
        username = None
        if request.user.is_authenticated:
            username = request.user.username
        try:
            toggles = get_user_toggles(username=username)
        except requests.exceptions.RequestException:
            return JsonResponse({"error": "Failed to fetch toggles"}, status=503)
        return JsonResponse({"toggles": toggles})
