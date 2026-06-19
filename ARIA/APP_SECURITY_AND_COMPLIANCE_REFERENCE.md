# ARIA Bank Internal Security and Compliance Reference

This is the internal reference for the current ARIA Bank build. It describes how the app is wired today, what each area does, where the intentional weaknesses are, how to demonstrate them, and which compliance areas the current build fails to meet.

Use this document when you need to explain the app from the perspective of the people who built it.

## 1. What ARIA Bank Is Right Now

ARIA Bank is a multi-role banking web application with customer, staff, and admin surfaces. The current build is intentionally weak in several areas so it can be assessed later against OWASP, ISO 27001, NIST SP 800-53, and GDPR.

Important framing:

- The app itself is not an in-app compliance dashboard.
- Compliance analysis happens outside the app in your report, checklist, testing notes, and presentation.
- Several weaknesses are inspired by real-world CVE patterns, but the app does not literally embed vendor products such as F5 BIG-IP, Ivanti Connect Secure, MOVEit Transfer, or Log4j.
- The right way to describe it is: ARIA Bank contains vulnerabilities and design choices that model the same classes of failure seen in well-known incidents and CVEs.

## 2. Stack and Structure

### Backend

- Python
- Flask `3.0.3`
- SQLite
- Session-based authentication

### Frontend

- Jinja templates
- Bootstrap `5.3.3` from CDN
- Lucide icons from CDN
- Custom premium UI in `static/css/styles.css`

### Main files

- `app.py`: routes, auth, database helpers, seeded data, vulnerability behavior
- `run_server.py`: app launcher
- `templates/`: all screens
- `static/css/styles.css`: visual system
- `aria_bank.db`: local SQLite database

## 3. Current Route Map

### Public routes

| Route | Purpose | Current behavior |
| --- | --- | --- |
| `/` | Landing page | Premium public homepage |
| `/register` | New customer registration | Accepts weak passwords and stores them directly |
| `/login` | Sign in | No MFA, no lockout, no rate limiting |

### Authenticated customer routes

| Route | Purpose | Current behavior |
| --- | --- | --- |
| `/logout` | Sign out | Clears session |
| `/dashboard` | Customer account overview | Accepts `user_id` in query string and can show another user's account |
| `/transfer` | Money transfer | No CSRF, no confirmation step, no transfer cap, raw description logged |
| `/transactions` | Transaction history | Accepts `user_id` and unsafe search input |
| `/profile` | Customer profile | Hidden role field can be tampered with |
| `/support` | Support messages | Stores and logs raw user-controlled input |
| `/documents` | Document upload | Weak file validation, preview extraction, unsafe exposure patterns |
| `/statements` | Statement and document search | Unsafe SQL construction with `user_id` and `q` |

### Staff and admin routes

| Route | Intended audience | Current behavior |
| --- | --- | --- |
| `/employee-portal` | Staff/Admin | Customer can still access it |
| `/admin` | Staff/Admin dashboard | Customer can still access it |
| `/admin/users` | Admin only | Properly blocked unless user becomes admin |
| `/admin/transactions` | Staff/Admin | Protected by role check |
| `/admin/audit-logs` | Staff/Admin | Protected by role check |

### Removed routes

These are not part of the current app UI and should not be treated as in-app compliance features:

- `/privacy`
- `/admin/compliance`
- `/admin/findings`
- `/admin/compliance-checklist`

## 4. Seed Accounts and Known Local Data

### Baseline seeded users

| Name | Email | Password | Role |
| --- | --- | --- | --- |
| John Carter | `john@aria.local` | `password123` | customer |
| Sara Ahmed | `sara@aria.local` | `123456` | customer |
| Demo Business | `business@aria.local` | `business123` | customer |
| Teller User | `teller@aria.local` | `teller123` | staff |
| Admin User | `admin@aria.local` | `admin123` | admin |

### Current local instance snapshot

As of `2026-05-30`, the local database also contains:

- an extra customer account: `test@test.com`
- accumulated demo data from previous walkthroughs

Current record counts in the local instance:

- `users`: 6
- `transactions`: 33
- `support_messages`: 29
- `customer_documents`: 30
- `audit_logs`: 278

That means the app is already in a useful demo state, but counts may continue to drift as more testing is done.

## 5. Database Model

### `users`

- identity and login information
- stores `password` directly in plaintext
- contains `role` and `account_status`

### `accounts`

- mapped to customers
- includes full account number and balance

### `transactions`

- sender and recipient account references
- amount, description, status, flagged state

### `audit_logs`

- timestamp, user, event type, description, IP, severity
- coverage exists, but completeness is inconsistent

### `support_messages`

- customer support messages
- stores raw message content

### `customer_documents`

- uploaded filename
- document type
- content preview
- file size
- upload timestamp

## 6. What Each Major Area Is Doing

### Authentication

- Registration creates a customer user and a new account.
- Passwords are accepted with almost no quality controls.
- Passwords are stored and compared directly.
- Login redirects customers to `/dashboard` and staff/admin users to `/admin`.

### Customer dashboard

- Shows account number, balance, and recent transactions.
- If `user_id` is changed in the URL, the page will fetch a different account instead of blocking the request.

### Transfers

- Customer can transfer to another account by email or account number.
- Amount is only weakly validated.
- No secondary confirmation or approval flow exists.
- Transfer note is written into the audit log.

### Transactions

- Shows outgoing and incoming transfers.
- Search input is concatenated into SQL.
- `user_id` can be changed in the URL.

### Profile

- Lets the customer edit name, phone, and address.
- The form also contains a hidden `role` field.
- The backend trusts the role value and updates it.

### Support

- Customer can submit support requests.
- Subject and message are stored as entered.
- The audit log stores the full message text.

### Documents and statements

- Customer can upload a document with a type and note.
- Uploaded bytes are read directly.
- A preview is extracted from the first chunk of file content and stored.
- Statement search uses unsafe SQL and can be turned into a data exposure demo.

### Employee portal

- Shows user records, balances, account numbers, and recent documents.
- It looks like an employee workspace.
- A customer can still reach it.

### Admin dashboard

- Shows counts, high-value transfers, and recent logs.
- It is intended to feel like an operations dashboard.
- A customer can still reach it.

### User management

- Admin-only page for changing role and account status.
- Once a customer tampers their own role to `admin`, this page becomes reachable.

### Admin transactions

- Staff and admin can view all transactions.
- Transactions can be flagged for review.

### Audit logs

- Staff and admin can review recent activity.
- Logs exist, but not all records are equally detailed or safe.

## 7. Confirmed Vulnerability Inventory

This section is the most important one for your presentation. Each item below is confirmed by the current code and current app behavior.

### V-01. Weak password policy and plaintext password storage

**Where**

- `/register`
- `/login`
- `users.password`

**What is wrong**

- Weak passwords are accepted.
- Passwords are stored directly instead of being hashed.
- Login compares the stored password to the submitted password directly.

**How to demonstrate**

1. Register a new account with a password like `123456`.
2. Sign in successfully with that weak password.
3. Explain that the database stores passwords directly rather than storing a hash.

**Why it matters**

- Any database exposure becomes immediately worse.
- Password reuse risk becomes much more serious.
- This is a direct authentication and data-protection failure.

**Compliance impact**

- OWASP: Identification and Authentication Failures
- ISO 27001: access control, secure development
- NIST SP 800-53: `IA`, `AC`
- GDPR: security of personal data

### V-02. No MFA, no lockout, and no brute-force resistance

**Where**

- `/login`

**What is wrong**

- No MFA
- No account lockout
- No delay or throttling
- No captcha
- No suspicious-login workflow

**How to demonstrate**

1. Attempt several failed logins for the same user.
2. Observe that the account remains usable with no delay or lockout.
3. Log in correctly right after the failed attempts.

**Why it matters**

- Password attacks are easier.
- A weak password becomes much more exploitable.

**Compliance impact**

- OWASP: Identification and Authentication Failures
- ISO 27001: identity and access management weakness
- NIST SP 800-53: `IA`

### V-03. Broken access control on the customer dashboard

**Where**

- `/dashboard?user_id=<id>`

**What is wrong**

- The page accepts a `user_id` parameter and loads the matching account if it exists.
- It logs the access, but it does not prevent it.

**How to demonstrate**

1. Sign in as John.
2. Go to `/dashboard?user_id=2`.
3. Show that Sara's account details appear.

**Why it matters**

- A customer can view another customer's account information.

**Compliance impact**

- OWASP: Broken Access Control
- ISO 27001: least privilege and information access restriction
- NIST SP 800-53: `AC`
- GDPR: personal data exposure

### V-04. Broken access control on transaction history

**Where**

- `/transactions?user_id=<id>`

**What is wrong**

- The route accepts another user's account context.
- It records an `UNAUTHORIZED_ACCESS_ATTEMPT`, but still returns the data.

**How to demonstrate**

1. Sign in as John.
2. Go to `/transactions?user_id=3`.
3. Show Demo Business transaction history.

**Why it matters**

- Logging the abuse is not the same as preventing the abuse.

**Compliance impact**

- OWASP: Broken Access Control
- NIST SP 800-53: `AC`, `AU`
- GDPR: confidentiality failure

### V-05. Privilege escalation through profile tampering

**Where**

- `/profile`

**What is wrong**

- The profile form contains a hidden `role` field.
- The backend updates `users.role` from submitted form data.

**How to demonstrate**

1. Sign in as a customer.
2. Edit the hidden `role` field in browser developer tools or an intercepting proxy.
3. Change it from `customer` to `admin`.
4. Submit the profile form.
5. Visit `/admin/users`.

**Expected result**

- The customer becomes an admin and gains access to admin-only functionality.

**Why it matters**

- This is a direct privilege-escalation path.

**Compliance impact**

- OWASP: Broken Access Control
- ISO 27001: privileged access failure
- NIST SP 800-53: `AC`

### V-06. Customer access to employee-facing workspace

**Where**

- `/employee-portal`

**What is wrong**

- The route is protected only by login, not by staff/admin role.
- A customer can open it.

**How to demonstrate**

1. Sign in as John.
2. Browse to `/employee-portal`.
3. Show customer records, account numbers, balances, and recent document previews.

**Why it matters**

- This models an exposed management interface problem.

**Compliance impact**

- OWASP: Broken Access Control
- ISO 27001: access restriction and least privilege
- NIST SP 800-53: `AC`
- GDPR: unnecessary personal data exposure

### V-07. Customer access to admin dashboard

**Where**

- `/admin`

**What is wrong**

- A customer can still open the admin dashboard.
- The app logs the event as high severity, but still returns the page.

**How to demonstrate**

1. Sign in as a customer.
2. Browse to `/admin`.
3. Show admin metrics and recent operational activity.

**Why it matters**

- This exposes operational information to low-privilege users.

**Compliance impact**

- OWASP: Broken Access Control
- NIST SP 800-53: `AC`

### V-08. Missing CSRF protection across state-changing forms

**Where**

- `/register`
- `/login`
- `/transfer`
- `/profile`
- `/support`
- `/documents`
- `/admin/users`
- `/admin/transactions`

**What is wrong**

- Forms submit directly with no CSRF token and no server-side CSRF validation.

**How to demonstrate**

1. Show any of the forms in the browser.
2. Explain that no CSRF token is present in the form.
3. Use this as a design finding in the report even if you do not build a proof-of-concept page.

**Why it matters**

- Sensitive state changes can potentially be triggered from another site if the session is active.

**Compliance impact**

- OWASP: Broken Access Control, Insecure Design
- NIST SP 800-53: `AC`, `SC`

### V-09. Unsafe SQL construction in statement search

**Where**

- `/statements`

**What is wrong**

- `user_id` is inserted directly into the SQL string.
- `q` is concatenated directly into the SQL string.

**How to demonstrate**

1. Sign in as a customer.
2. Visit `/statements?user_id=1%20OR%201=1`.
3. Show that documents from multiple users appear.

**Why it matters**

- This is the clearest injection and data-exposure demo in the app.

**Compliance impact**

- OWASP: Injection, Broken Access Control
- ISO 27001: secure development failure
- NIST SP 800-53: `SI`, `SC`, `AC`
- GDPR: cross-user document exposure

### V-10. Unsafe SQL construction in transaction search

**Where**

- `/transactions?q=<search>`

**What is wrong**

- Search terms are concatenated into the SQL query.
- It is injection-prone and can break query execution.

**How to demonstrate**

1. Sign in as a customer.
2. Use a search value that contains a quote character.
3. Explain that the query is constructed directly from user input rather than parameterized safely.

**Why it matters**

- Even when the payload does not cleanly dump data, it still shows unsafe query building and unstable behavior.

**Compliance impact**

- OWASP: Injection
- ISO 27001: secure coding gap
- NIST SP 800-53: `SI`

### V-11. Unsafe logging pattern with raw user input

**Where**

- `/support`
- `/transfer`
- `/documents`
- `/admin/audit-logs`

**What is wrong**

- Support messages are logged with full raw subject and message.
- Transfer notes are logged as entered.
- Upload events log raw filename and note.

**How to demonstrate**

1. Submit a support message with a distinct string.
2. Sign in as staff or admin and open `/admin/audit-logs`.
3. Show that the raw input is stored directly in the log description.

**Why it matters**

- This models unsafe logging and log injection risk.
- It also means sensitive user-entered data can spread into operational records.

**Compliance impact**

- OWASP: Security Logging and Monitoring Failures
- ISO 27001: logging and monitoring weakness
- NIST SP 800-53: `AU`
- GDPR: excessive personal data propagation into logs

### V-12. Weak document upload handling and preview exposure

**Where**

- `/documents`
- `/statements`
- `/employee-portal`

**What is wrong**

- No strict type validation
- No content scanning
- No extension restrictions of substance
- First bytes of uploaded content are stored as preview text
- Recent document previews are visible in broad operational views

**How to demonstrate**

1. Upload a text file with obvious business or identity content.
2. Go to `/statements` and show the stored preview.
3. Go to `/employee-portal` and show the preview again in a broader workspace.

**Why it matters**

- File content becomes searchable and visible more broadly than it should.
- This works well as a data-exposure and insecure-file-handling demo.

**Compliance impact**

- OWASP: Injection-related exposure, Security Misconfiguration, Sensitive Data Exposure
- ISO 27001: information handling weakness
- NIST SP 800-53: `SI`, `SC`, `AC`
- GDPR: unnecessary processing and exposure of personal data

### V-13. Excessive personal and financial data exposure

**Where**

- `/dashboard`
- `/profile`
- `/transactions`
- `/employee-portal`
- `/admin/users`
- `/statements`

**What is wrong**

- Full account numbers are displayed.
- Balances and personal details are broadly visible.
- Document previews reveal identity and business content.

**How to demonstrate**

1. Open profile and show the full account number.
2. Open employee portal and show multiple users' balances and account details.
3. Open statements and show document preview content.

**Why it matters**

- The app exposes more data than is necessary for many views.

**Compliance impact**

- OWASP: Sensitive Data Exposure / Cryptographic Failures class of issue
- ISO 27001: information classification and access restriction weakness
- NIST SP 800-53: `AC`, `SC`
- GDPR: data minimization gap

### V-14. Incomplete and inconsistent audit logging

**Where**

- `/login`
- `/admin/audit-logs`
- seeded event history

**What is wrong**

- Failed login events omit IP address.
- Failed login events also omit severity.
- Logging exists, but it is inconsistent in completeness and quality.
- There is no alerting or incident workflow.

**How to demonstrate**

1. Attempt a failed login using an existing account email.
2. Sign in as staff or admin.
3. Open `/admin/audit-logs`.
4. Show the failed-login entry and explain what metadata is missing.

**Why it matters**

- Investigations become weaker.
- Monitoring becomes less reliable.

**Compliance impact**

- OWASP: Security Logging and Monitoring Failures
- ISO 27001: logging and monitoring weakness
- NIST SP 800-53: `AU`, `IR`

### V-15. Missing secure headers and configuration hardening

**Where**

- whole app

**What is wrong**

- No `Content-Security-Policy`
- No `X-Frame-Options`
- No `Strict-Transport-Security`
- No `X-Content-Type-Options`
- Session cookie is not explicitly marked `Secure`
- Session cookie is not explicitly marked `SameSite`
- Secret key is hardcoded in the app
- Server signature reveals Werkzeug and Python

**How to demonstrate**

1. Open the browser network panel or use a header inspection tool.
2. Inspect the `/login` response headers.
3. Show the missing headers and server disclosure.
4. Show the session cookie attributes after login.

**Why it matters**

- This is classic security misconfiguration territory.

**Compliance impact**

- OWASP: Security Misconfiguration
- ISO 27001: secure configuration weakness
- NIST SP 800-53: `CM`, `SC`

### V-16. Weak session and secret management

**Where**

- application configuration
- login/session flow

**What is wrong**

- Static secret key in code
- No session timeout policy
- No device/session review
- No binding to stronger auth context

**How to demonstrate**

1. Show the authentication flow and describe the cookie behavior.
2. Explain that sessions persist without a visible timeout control.
3. Point out that the app secret is fixed in source code.

**Why it matters**

- Session theft or misuse becomes easier to sustain.

**Compliance impact**

- OWASP: Identification and Authentication Failures, Security Misconfiguration
- NIST SP 800-53: `IA`, `SC`, `CM`

### V-17. Missing privacy management workflows

**Where**

- feature set overall

**What is wrong**

- No privacy center
- No export workflow
- No deletion workflow
- No visible consent management
- No retention controls

**How to demonstrate**

1. Show that the customer navigation has no privacy center.
2. Confirm that `/privacy` is not part of the current build.
3. Use the existing data exposure examples to explain why this matters.

**Why it matters**

- The app handles personal and financial data without giving the user meaningful privacy controls.

**Compliance impact**

- GDPR: data subject rights, data minimization, security of processing, accountability
- ISO 27001: information governance and protection gaps

### V-18. Weak transaction control design

**Where**

- `/transfer`

**What is wrong**

- No step-up verification
- No dual confirmation
- No transfer cap
- No friction for high-risk transfers

**How to demonstrate**

1. Sign in as a customer.
2. Make a transfer with a large amount if funds allow.
3. Show that the app completes the transfer immediately.

**Why it matters**

- Business logic is too permissive for a banking flow.

**Compliance impact**

- OWASP: Insecure Design
- ISO 27001: secure development and operational control weakness
- NIST SP 800-53: `SI`, `SC`, `AU`

## 8. CVE-Inspired Mapping

This is the safest and most accurate way to talk about the CVE side of the app.

### 1. Unsafe logging pattern

**ARIA area**

- support messages
- transfer notes
- upload notes
- audit log descriptions

**How to describe it**

- Inspired by unsafe logging and attacker-controlled log content problems
- Best discussed as analogous to well-known log abuse classes such as Log4Shell-era concerns

**What not to claim**

- Do not claim ARIA Bank contains Log4j or executes `${jndi:...}` payloads
- Do not claim remote code execution exists in this app

### 2. Document search and data exposure pattern

**ARIA area**

- `/documents`
- `/statements`

**How to describe it**

- Inspired by file-handling, unsafe query construction, and cross-tenant exposure problems seen in document-transfer incidents
- Best discussed as analogous to MOVEit-style data exposure and SQL injection classes

**What not to claim**

- Do not claim ARIA Bank is literally MOVEit or reproduces the exact vendor exploit chain

### 3. Exposed management interface pattern

**ARIA area**

- `/employee-portal`
- `/admin`

**How to describe it**

- Inspired by exposed admin or employee surfaces, weak authorization boundaries, and management-plane overexposure
- Best discussed as analogous to F5 BIG-IP or Ivanti-style management-interface failures

**What not to claim**

- Do not claim the app contains those appliances or their specific authentication-bypass bugs

### 4. Weak auth and session pattern

**ARIA area**

- `/login`
- session cookie handling
- secret management

**How to describe it**

- Inspired by weak authentication, poor session hardening, and configuration risk

## 9. Where the App Does Not Follow Compliance Expectations

This section is for the exact answer to: "Which parts are not following the standards?"

### OWASP Top 10 alignment gaps

| OWASP area | Where ARIA fails |
| --- | --- |
| Broken Access Control | `/dashboard`, `/transactions`, `/statements`, `/employee-portal`, `/admin`, `/profile` role tampering |
| Cryptographic Failures / sensitive data protection weakness | plaintext passwords, full account numbers, broad document preview exposure |
| Injection | `/transactions` search, `/statements` search and `user_id` handling |
| Insecure Design | weak transfer controls, no MFA, no step-up approval, role exposure in profile |
| Security Misconfiguration | missing headers, hardcoded secret, weak cookie settings, server disclosure |
| Identification and Authentication Failures | weak passwords, no MFA, no lockout, weak session management |
| Security Logging and Monitoring Failures | inconsistent log detail, missing failed-login context, no alerting workflow |

### ISO 27001 control-theme gaps

| Theme | Where ARIA fails |
| --- | --- |
| Access control | customers can reach privileged views and can escalate role |
| Privileged access management | employee and admin views are not properly restricted |
| Information protection | full account numbers, balances, and document previews are overexposed |
| Secure development | unsafe SQL construction and hidden-role trust |
| Logging and monitoring | incomplete event detail and no alerting |
| Incident management readiness | no incident workflow or response handling inside operations surface |
| Secure configuration | no response hardening headers, hardcoded secret, weak session cookie settings |

### NIST SP 800-53 family gaps

| Family | Where ARIA fails |
| --- | --- |
| `AC` Access Control | IDORs, exposed admin and employee surfaces, self-escalation |
| `IA` Identification and Authentication | weak passwords, no MFA, no lockout, weak session posture |
| `AU` Audit and Accountability | incomplete failed-login logging, inconsistent severity and IP capture |
| `SI` System and Information Integrity | unsafe SQL construction, weak file handling, unsafe input use |
| `SC` System and Communications Protection | missing headers, weak cookie handling, sensitive data overexposure |
| `IR` Incident Response | no operational incident workflow or alert-driven escalation |
| `CM` Configuration Management | hardcoded secret, default-style server disclosure, unpinned `latest` icon dependency |

### GDPR-relevant gaps

| GDPR concern | Where ARIA fails |
| --- | --- |
| Data minimization | full account numbers, broad balance exposure, document preview leakage |
| Security of processing | plaintext passwords, weak auth, poor access control, unsafe SQL |
| Accountability | incomplete logs and weak incident traceability |
| Privacy rights workflows | no user-facing export, deletion, or consent management flow |
| Confidentiality of personal data | customers can see other users' records and documents in several places |

## 10. Best Demo Flows

### Demo flow A: Customer-side weaknesses

1. Sign in as `john@aria.local / password123`
2. Show `/dashboard`
3. Change URL to `/dashboard?user_id=2`
4. Open `/transactions?user_id=3`
5. Open `/profile` and explain hidden role tampering
6. Open `/documents`, upload a text file, then go to `/statements`
7. Use `/statements?user_id=1%20OR%201=1`

### Demo flow B: Privileged area exposure

1. Stay signed in as a customer
2. Open `/employee-portal`
3. Open `/admin`
4. Explain what should have been blocked but is not

### Demo flow C: Logging and operational weakness

1. Submit a support message with a unique phrase
2. Sign in as admin
3. Open `/admin/audit-logs`
4. Show raw message content in the log trail
5. Show failed-login entries and explain missing IP and severity detail

### Demo flow D: Privilege escalation

1. Sign in as a customer
2. Tamper `role=admin` in the profile form submission
3. Refresh profile if needed
4. Open `/admin/users`
5. Explain that the escalation came from trusting a hidden client-side field

## 11. How to Talk About the App in the Report

When describing the app, the cleanest explanation is:

> ARIA Bank is the target web application that our team built for assessment. It includes customer, staff, and admin workflows, but it intentionally contains weaknesses in authentication, authorization, query handling, file handling, logging, session security, and data protection. Those weaknesses give us a realistic system to evaluate against OWASP, ISO 27001, NIST SP 800-53, and GDPR.

When describing the CVE angle, the cleanest explanation is:

> The app does not reproduce vendor CVEs one-to-one. Instead, it models the same categories of failure seen in real incidents, such as unsafe logging, exposed management interfaces, weak authentication and session controls, unsafe search and document handling, and overbroad data exposure.

## 12. How This Document Pairs With the Existing Assessment Guide

Use this file for:

- the exact technical truth of the app
- route-by-route weakness explanation
- demo walkthroughs
- internal team alignment

Use `INITIAL_COMPLIANCE_ASSESSMENT_GUIDE.md` for:

- how to perform the external compliance assessment
- how to organize evidence
- how to use LLMs to compare policies and practices against the standards

## 13. Short Version You Can Say Out Loud

If someone asks for the one-minute summary:

- ARIA Bank is a working banking app with customer, staff, and admin views.
- We intentionally built in weaknesses around weak passwords, no MFA, broken access control, unsafe SQL, unsafe logging, weak file handling, poor session hardening, and excessive data exposure.
- Some weaknesses are inspired by the same failure classes seen in real CVEs, especially around admin surface exposure, document/data exposure, and logging misuse.
- The app does not claim to be compliant. It is the system we assess for current-state gaps against OWASP, ISO 27001, NIST SP 800-53, and GDPR.
