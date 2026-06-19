from io import BytesIO

from app import app


def assert_ok(client, path):
    response = client.get(path, follow_redirects=True)
    assert response.status_code == 200, f"{path} returned {response.status_code}"
    return response


def assert_missing(client, path):
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 404, f"{path} should be removed, got {response.status_code}"


def login(client, email, password):
    response = client.post(
        "/login",
        data={"email": email, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"ARIA" in response.data


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
            "/employee-portal",
            "/admin",
        ]:
            assert_ok(client, path)

        response = client.post(
            "/transfer",
            data={
                "recipient": "sara@aria.local",
                "amount": "10",
                "description": "Smoke test transfer",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

        response = client.post(
            "/support",
            data={
                "subject": "Smoke support",
                "message": "Please review my recent transfer question.",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

        response = client.post(
            "/documents",
            data={
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
            "/admin/audit-logs",
            "/employee-portal",
        ]:
            assert_ok(client, path)


if __name__ == "__main__":
    run()
    print("ARIA Bank smoke tests passed.")
