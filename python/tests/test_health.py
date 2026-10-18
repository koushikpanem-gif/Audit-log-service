from starlette.testclient import TestClient

from audit_log_service.app import create_app


def test_health_returns_up() -> None:
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "UP"}
