from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_root_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {"message": "Packet Analysis Tool API"}


def test_empty_session_list():
    response = client.get("/api/sessions")

    assert response.status_code == 200
    assert response.json() == {"sessions": []}


def test_missing_session_returns_not_found():
    response = client.get("/api/packet-details/missing")

    assert response.status_code == 404
    assert response.json()["detail"] == "Session not found"
