# ARIA Bank

## Run

```powershell
.\.venv\Scripts\pip install -r requirements.txt
copy .env.example .env
# Set OPENAI_API_KEY in .env for compliance scans
.\.venv\Scripts\python run_server.py
```

Open `http://127.0.0.1:5000`.

## Compliance monitoring (Milestone 7)

Admin dashboard (admin login required):

- `/admin/compliance` — KPI cards, framework scores, run scan
- `/admin/compliance/findings` — F-01..F-18 verdicts
- `/admin/compliance/reports` — stored Judge reports

CLI scan (`OPENAI_API_KEY` required):

```powershell
.\.venv\Scripts\python -m compliance.run_scan
.\.venv\Scripts\python -m compliance.run_scan --type scheduled --json
```

Scripts:

- `scripts/export_siem_logs.py` — JSON Lines export for SIEM
- `scripts/schedule_compliance_scan.ps1` — Windows Task Scheduler helper

Reports are written to `reports/` and persisted in `compliance_reports`.

## Guides

- Milestone 7 plan: [MILESTONE_7_LLM_COMPLIANCE_MONITORING_PLAN.md](./MILESTONE_7_LLM_COMPLIANCE_MONITORING_PLAN.md)
- Initial compliance assessment guide: [INITIAL_COMPLIANCE_ASSESSMENT_GUIDE.md](./INITIAL_COMPLIANCE_ASSESSMENT_GUIDE.md)
- Internal app security and compliance reference: [APP_SECURITY_AND_COMPLIANCE_REFERENCE.md](./APP_SECURITY_AND_COMPLIANCE_REFERENCE.md)

