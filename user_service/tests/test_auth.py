from fastapi.testclient import TestClient
from user_service.app.main import app

client = TestClient(app)

def test_register_and_login():
    username = "testuser"
    password = "testpass"

    response = client.post("/register", json={"username": username, "password": password})
    assert response.status_code == 200

    response = client.post("/token", data={"username": username, "password": password})
    assert response.status_code == 200
    assert "access_token" in response.json()