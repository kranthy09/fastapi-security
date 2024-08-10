"""Test to User amd Items"""

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_not_authenticated_read_user_me():
    """Test unauthorized user"""
    response = client.get("/users/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"


def test_authenticated_read_user_me():
    """Test user read profile information"""
    response = client.post(
        "/token", data={"username": "johndoe", "password": "secret"}
    )
    assert response.status_code == 200
    access_token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["username"] == "johndoe"


def test_authenticate_invalid_password_raise_exception():
    """Test raised exception when password is invalid"""
    response = client.post(
        "/token", data={"username": "johndoe", "password": "wrong"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_authenticate_none_username_raises_exception():
    """Test raise exeption when username is None"""

    response = client.post(
        "/token", data={"username": "", "password": "secret"}
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["msg"] == "Field required"
    assert response.json()["detail"][0]["type"] == "missing"
    assert response.json()["detail"][0]["loc"] == ["body", "username"]

def test_authenticate_with_invalid_username():
    """Test raise exception with invalid username"""
    response = client.post(
        "/token", data={"username": "invalid_user", "password": "secret"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"