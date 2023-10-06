import pytest

from users.models import ConnectUser


@pytest.mark.django_db
def test_registration(client):
    response = client.post('/users/register', {
        'username': 'testuser',
        'password': 'testpass',
        'phone_number': '+27734567657',
    })
    assert response.status_code == 200, response.content
    user = ConnectUser.objects.get(username='testuser')
    assert user.phone_number == '+27734567657'
