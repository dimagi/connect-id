import pytest

from users.factories import RecoveryStatusFactory
from users.models import RecoveryStatus


@pytest.fixture
def recovery_status():
    recovery_status = RecoveryStatusFactory(
        step=RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY,
    )
    recovery_status.user.set_recovery_pin("1234")
    recovery_status.user.save()
    return recovery_status
