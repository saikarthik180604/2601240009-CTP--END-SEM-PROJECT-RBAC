"""Tests: Flask routes and JSON API (uses an in-memory database)."""

import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app(":memory:")
    app.config["TESTING"] = True
    return app.test_client()


@pytest.mark.parametrize(
    "path", ["/", "/dashboard", "/tenants", "/users", "/roles", "/permissions", "/hierarchy", "/audit"]
)
def test_pages_render(client, path):
    assert client.get(path).status_code == 200


def test_api_lists(client):
    assert len(client.get("/api/users").get_json()) == 4
    assert len(client.get("/api/roles").get_json()) == 8
    assert len(client.get("/api/permissions").get_json()) == 17


def test_api_check_permission_allow_and_deny(client):
    allow = client.post("/api/check-permission", json={"user_id": 1, "tenant_id": 1, "permission": "users:create"})
    deny = client.post("/api/check-permission", json={"user_id": 1, "tenant_id": 1, "permission": "billing:delete"})
    assert allow.get_json()["result"] == "ALLOW"
    assert deny.get_json()["result"] == "DENY"
    assert deny.get_json()["reason"] == "Explicit deny rule"


def test_api_cross_tenant_check_is_deny(client):
    reply = client.post("/api/check-permission", json={"user_id": 2, "tenant_id": 2, "permission": "products:read"})
    assert reply.status_code == 200
    assert reply.get_json()["result"] == "DENY"


def test_api_create_user_role_permission(client):
    assert client.post("/api/users", json={"username": "Zed", "email": "z@acme.com", "tenant_id": 1}).status_code == 201
    assert client.post("/api/permissions", json={"name": "invoices:approve"}).status_code == 201
    role = client.post("/api/roles", json={"role_name": "Auditor", "tenant_id": 1, "permissions": ["invoices:approve"]})
    assert role.status_code == 201
    assert role.get_json()["permissions"] == ["invoices:approve"]


def test_api_cycle_is_rejected_with_409(client):
    # ACME roles: Viewer=1, Editor=2, Manager=3, Admin=4
    reply = client.post("/api/hierarchy", json={"child_role_id": 1, "parent_role_id": 4})
    assert reply.status_code == 409
    assert "Circular" in reply.get_json()["error"]


def test_api_errors_are_clean_json(client):
    assert client.post("/api/users", json={"username": "x"}).status_code == 400
    assert client.post("/api/permissions", json={"name": "BAD NAME"}).status_code == 400
    assert client.post("/api/users", json={"username": "Alice", "email": "a@a.com", "tenant_id": 1}).status_code == 409
    assert client.get("/api/hierarchy?tenant_id=99").status_code == 404


def test_api_check_writes_audit_log(client):
    client.post("/api/check-permission", json={"user_id": 1, "tenant_id": 1, "permission": "users:create"})
    logs = client.get("/api/audit").get_json()
    assert logs[0]["username"] == "Alice" and logs[0]["permission"] == "users:create"
    assert client.get("/api/stats").get_json()["checks"] == 1
