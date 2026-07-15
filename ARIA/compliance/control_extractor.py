from __future__ import annotations

from compliance.state import ControlDefinition

CONTROL_REGISTRY: list[ControlDefinition] = [
    ControlDefinition("F-01", "Weak passwords / plaintext storage", "High", "Passwords must be hashed and strong", ["OWASP A07", "NIST IA"], [], ["CF-01"], ["metrics"], "high"),
    ControlDefinition("F-02", "No MFA / lockout / throttling", "High", "Login must enforce MFA or lockout/throttling", ["OWASP A07", "NIST IA"], [], ["WC-02"], ["dast", "runtime"], "high"),
    ControlDefinition("F-03", "Dashboard IDOR", "High", "Dashboard must not expose other users via user_id", ["OWASP A01", "NIST AC"], ["GAP-04"], ["AC-04"], ["dast"], "high"),
    ControlDefinition("F-04", "Transaction history IDOR", "High", "Transactions must not expose other users via user_id", ["OWASP A01", "NIST AC"], [], ["AC-04"], ["dast"], "high"),
    ControlDefinition("F-05", "Profile role tampering", "Critical", "Profile route must ignore role parameter", ["OWASP A01", "NIST AC-3"], ["GAP-03"], ["AC-01", "AC-05"], ["dast"], "critical"),
    ControlDefinition("F-06", "Customer employee portal access", "High", "Employee portal must block customers", ["OWASP A01", "NIST AC"], [], ["AC-03"], ["dast"], "high"),
    ControlDefinition("F-07", "Customer admin dashboard access", "High", "Admin dashboard must block customers", ["OWASP A01", "NIST AC"], ["GAP-04"], ["AC-02"], ["dast"], "high"),
    ControlDefinition("F-08", "Missing CSRF", "Medium", "State-changing forms require CSRF tokens", ["OWASP A01", "NIST AC"], [], ["WC-01"], ["dast"], "medium"),
    ControlDefinition("F-09", "Unsafe SQL statements", "High", "Statements route must use parameterized queries", ["OWASP A03", "NIST SI"], [], ["SI-01", "SI-02"], ["dast", "metrics"], "high"),
    ControlDefinition("F-10", "Unsafe SQL transactions search", "Medium", "Transaction search must be parameterized", ["OWASP A03", "NIST SI"], [], ["SI-01", "SI-03"], ["dast"], "medium"),
    ControlDefinition("F-11", "Unsafe logging of raw input", "Medium", "Logs must not store unsanitized user input", ["OWASP A09", "NIST AU"], [], ["LM-01"], ["runtime"], "medium"),
    ControlDefinition("F-12", "Weak document upload", "Medium", "Document upload must validate file types", ["OWASP A05", "NIST SI"], [], ["WC-01"], ["dast"], "medium"),
    ControlDefinition("F-13", "Excessive data exposure", "High", "Sensitive data must be minimized", ["OWASP A02", "GDPR"], [], ["AC-04"], ["dast"], "high"),
    ControlDefinition("F-14", "Incomplete audit logging", "Medium", "Audit logs must include complete context", ["OWASP A09", "NIST AU"], ["GAP-05"], ["LM-01", "LM-02"], ["runtime"], "medium"),
    ControlDefinition("F-15", "Missing secure headers", "Medium", "HTTP security headers must be present", ["OWASP A05", "NIST CM"], [], ["CF-03", "WC-03"], ["dast"], "medium"),
    ControlDefinition("F-16", "Weak session / secret mgmt", "Medium", "Secrets must not be hardcoded", ["OWASP A05", "NIST CM"], [], ["CF-01", "CF-02"], ["metrics"], "medium"),
    ControlDefinition("F-17", "Missing privacy workflows", "High", "Privacy export/delete/consent routes required", ["GDPR"], [], ["KPI-10"], ["metrics"], "high"),
    ControlDefinition("F-18", "Weak transaction design", "Medium", "Transfers must be atomic with idempotency", ["OWASP A04", "NIST SI"], ["GAP-01", "GAP-02"], ["TC-01", "TC-02", "TC-03", "TC-04", "TC-05"], ["metrics", "dast", "runtime"], "medium"),
]


def load_controls() -> list[ControlDefinition]:
    return list(CONTROL_REGISTRY)


def build_routing_plan(controls: list[ControlDefinition]) -> list[dict]:
    plan: list[dict] = []
    for control in controls:
        for agent in control.assigned_agents:
            plan.append(
                {
                    "control_id": control.id,
                    "agent": agent,
                    "check_ids": control.check_ids,
                    "priority": control.priority,
                }
            )
    return plan
