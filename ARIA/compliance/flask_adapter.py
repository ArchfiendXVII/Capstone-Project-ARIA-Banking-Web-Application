from __future__ import annotations


def get_test_client():
    from app import app

    app.config.update(TESTING=True)
    return app.test_client()
