from waffle.models import Switch

from utils.connect import get_connect_toggles


def get_user_toggles(username=None, phone_number=None):
    switches = Switch.objects.all()
    connect_switches = get_connect_toggles(username=username, phone_number=phone_number)
    toggles = {
        switch.name: {"active": switch.active, "created_at": switch.created, "modified_at": switch.modified}
        for switch in switches
    }
    toggles.update(connect_switches)
    return toggles
