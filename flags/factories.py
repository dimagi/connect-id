import factory
from waffle.models import Switch


class SwitchFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Switch

    name = factory.Sequence(lambda n: f"TEST_SWITCH_{n}")
    active = True
