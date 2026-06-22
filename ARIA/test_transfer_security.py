import os
import re

from app import DATABASE, app, get_db, init_db


def _extract_idempotency_key(html: bytes) -> str:
    match = re.search(rb'name="idempotency_key" value="([^"]+)"', html)
    assert match, "idempotency key hidden field missing from transfer form"
    return match.group(1).decode()


def _reset_db() -> None:
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    with app.app_context():
        init_db()


def test_self_transfer_rejected():
    app.config.update(TESTING=True)
    _reset_db()
    with app.test_client() as client:
        client.post("/login", data={"email": "john@aria.local", "password": "password123"}, follow_redirects=True)
        transfer_page = client.get("/transfer")
        key = _extract_idempotency_key(transfer_page.data)

        response = client.post(
            "/transfer",
            data={
                "recipient": "john@aria.local",
                "amount": "25.00",
                "description": "self transfer test",
                "idempotency_key": key,
            },
            follow_redirects=True,
        )
        assert b"Transfers to your own account are not allowed." in response.data

        with app.app_context():
            row = get_db().execute(
                "SELECT reason_code FROM rejected_transfers ORDER BY id DESC LIMIT 1"
            ).fetchone()
            assert row["reason_code"] == "SELF_TRANSFER"


def test_idempotent_replay():
    app.config.update(TESTING=True)
    _reset_db()
    with app.test_client() as client:
        client.post("/login", data={"email": "john@aria.local", "password": "password123"}, follow_redirects=True)
        transfer_page = client.get("/transfer")
        key = _extract_idempotency_key(transfer_page.data)

        payload = {
            "recipient": "sara@aria.local",
            "amount": "10.00",
            "description": "idempotency test",
            "idempotency_key": key,
        }
        first = client.post("/transfer", data=payload, follow_redirects=True)
        assert b"Transfer completed." in first.data

        second = client.post("/transfer", data=payload, follow_redirects=True)
        assert b"Transfer already completed." in second.data

        with app.app_context():
            count = get_db().execute(
                """
                SELECT COUNT(*) AS count
                FROM transactions
                WHERE description = 'idempotency test'
                """
            ).fetchone()["count"]
            assert count == 1


if __name__ == "__main__":
    test_self_transfer_rejected()
    test_idempotent_replay()
    print("Transfer security tests passed.")
