import json

from django.core.exceptions import ValidationError
from django.shortcuts import render
from django.http import HttpResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import ConnectUser


# Create your views here.
@require_POST
@csrf_exempt
def register(request):
    print(request.body)
    print(type(request.body.decode('utf-8')))
    data = json.loads(request.body)
    u = ConnectUser(**data)
    try:
        u.full_clean()
    except ValidationError as e:
        print(e.message_dict)
        return HttpResponseBadRequest(e.message_dict)
    u.save()
    return HttpResponse()


def login(request):
    pass
