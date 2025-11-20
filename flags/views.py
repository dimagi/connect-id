from django.http import JsonResponse
from django.views import View
from waffle.models import Switch


class TogglesView(View):
    def get(self, request):
        switches = Switch.objects.all()
        toggles = {switch.name: switch.active for switch in switches}
        return JsonResponse({"toggles": toggles})
