from django.http import JsonResponse
from django.views import View

from .utils import get_user_toggles


class TogglesView(View):
    def get(self, request):
        username = None
        if request.user.is_authenticated:
            username = request.user.username
        toggles = get_user_toggles(username=username)
        return JsonResponse({"toggles": toggles})
