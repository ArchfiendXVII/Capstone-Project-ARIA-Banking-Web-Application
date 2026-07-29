"""ARIA Bank compliance monitoring package."""

__all__ = ["run_scan"]


def run_scan(*args, **kwargs):
    from compliance.scan_service import run_scan as _run_scan

    return _run_scan(*args, **kwargs)
