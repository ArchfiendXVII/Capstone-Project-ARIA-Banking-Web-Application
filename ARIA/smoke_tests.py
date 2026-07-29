import os
import re
from io import BytesIO

from app import DATABASE, app, get_db, init_db

def csrf_token(client, path):
    response = client.get(path)
    match = re.search(
        rb'name="csrf_token"\s+value="([^"]+)"',
        response.data,
    )
    assert match, f"No CSRF token found on {path}"
    return match.group(1).decode()

def assert_ok(client, path):
    response = client.get(path, follow_redirects=True)
    assert response.status_code == 200, f"{path} returned {response.status_code}"
    return response


def assert_missing(client, path):
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 404, f"{path} should be removed, got {response.status_code}"


def assert_forbidden(client, path):
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 403, f"{path} should be forbidden, got {response.status_code}"


def login(client, email, password):
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token(client, "/login"),
            "email": email,
            "password": password,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"ARIA" in response.data


def extract_idempotency_key(html: bytes) -> str:
    match = re.search(rb'name="idempotency_key" value="([^"]+)"', html)
    assert match, "idempotency key hidden field missing from transfer form"
    return match.group(1).decode()


def run():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        for path in ["/", "/login", "/register"]:
            assert_ok(client, path)

        login(client, "john@aria.local", "password123")
        for path in [
            "/dashboard",
            "/transfer",
            "/transactions",
            "/profile",
            "/support",
            "/documents",
            "/statements",
        ]:
            assert_ok(client, path)
        for path in ["/employee-portal", "/admin"]:
            assert_forbidden(client, path)

        transfer_page = client.get("/transfer")
        idempotency_key = extract_idempotency_key(transfer_page.data)
        response = client.post(
            "/transfer",
            data={
                "csrf_token": csrf_token(client, "/transfer"),
                "recipient": "sara@aria.local",
                "amount": "10",
                "description": "Smoke test transfer",
                "idempotency_key": idempotency_key,
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

        response = client.post(
            "/support",
            data={
                "csrf_token": csrf_token(client, "/support"),
                "subject": "Smoke support",
                "message": "Please review my recent transfer question.",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

        response = client.post(
            "/documents",
            data={
                "csrf_token": csrf_token(client, "/documents"),
                "document_type": "Statement",
                "note": "smoke upload",
                "document": (BytesIO(b"statement payroll rent transfer"), "smoke_statement.txt"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert_ok(client, "/statements?q=payroll")

        for path in ["/privacy"]:
            assert_missing(client, path)

        client.get("/logout", follow_redirects=True)

        login(client, "admin@aria.local", "admin123")
        for path in [
            "/admin",
            "/admin/users",
            "/admin/transactions",
            "/admin/rejected-transfers",
            "/admin/audit-logs",
            "/admin/compliance",
            "/admin/compliance/findings",
            "/admin/compliance/reports",
            "/employee-portal",
        ]:
            assert_ok(client, path)

        client.post(
            "/logout",
            data={"csrf_token": csrf_token(client, "/dashboard")},
            follow_redirects=True,
        )
        login(client, "john@aria.local", "password123")
        for path in ["/admin/compliance", "/admin/compliance/findings", "/admin/compliance/reports"]:
            assert_forbidden(client, path)

        # negative security test:
        response = client.post(
            "/transfer",
            data={
                "recipient": "sara@aria.local",
                "amount": "10",
                "description": "Missing CSRF token",
            },
        )
        assert response.status_code == 400

if __name__ == "__main__":
    run()
    print("ARIA Bank smoke tests passed.")
