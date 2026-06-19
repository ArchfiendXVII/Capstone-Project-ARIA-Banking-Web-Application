# Initial Compliance Assessment Guide for ARIA Bank

## Objective

Use ARIA Bank as the target web application for the initial compliance assessment. The goal is to assess the current state of the application against the selected standards by observing how the app actually behaves, documenting evidence, identifying gaps, and using LLMs to accelerate analysis of existing security policies and practices.

This app should be treated as the system under review. The compliance assessment happens outside the app in your report, checklist, findings register, and LLM-assisted analysis workflow.

## Standards in Scope

- OWASP Top 10
- ISO 27001
- NIST SP 800-53
- GDPR

## What ARIA Bank Gives You as Assessment Evidence

The app already provides a useful assessment surface:

- Public entry points: home, login, register
- Customer flows: dashboard, transfer, transactions, profile, support, documents, statements
- Staff and admin flows: employee portal, admin dashboard, user management, transactions, audit logs
- Data handling examples: account numbers, profile data, uploaded documents, transaction notes
- Operational visibility: audit logs, suspicious transaction flags, staff access views

That is enough to assess current practices such as authentication, access control, logging, data exposure, session handling, transaction handling, and operational oversight.

## Recommended Assessment Workflow

1. Define scope and evidence folder.
   Create a folder for screenshots, test notes, ZAP or Burp output, LLM outputs, and final tables.

2. Perform a role-based walkthrough.
   Log in as a customer, staff user, and admin user. Visit each major route and capture what the application allows each role to do.

3. Test baseline security behaviors.
   Focus on weak passwords, authorization boundaries, file upload handling, search behavior, logging coverage, transaction controls, and exposed operational views.

4. Record evidence as you go.
   For every finding, keep a screenshot, route, test action, observed result, and the date and account used.

5. Map each observation to standards.
   Do not start by scoring the app. Start by collecting observed facts, then map those facts to relevant controls or requirements.

6. Produce a current-state compliance picture.
   Classify each mapped item as compliant, partially compliant, or non-compliant, then summarize the major risks.

## Suggested Demonstration Flow

Use this sequence during the demo or while capturing report evidence:

1. Show the public home page and sign-in flow.
   Explain that the app is the target system being assessed.

2. Sign in as a customer.
   Demonstrate dashboard access, transaction history, profile data visibility, transfer flow, and document upload.

3. Demonstrate customer-facing risk areas.
   Show weak password acceptance, transaction handling, file upload behavior, statement search, support messages, or profile exposure.

4. Sign in as staff or admin.
   Demonstrate employee portal visibility, access to customer records, document previews, transaction review, and audit logs.

5. Show collected evidence outside the app.
   Present the checklist, findings register, or control-mapping table alongside screenshots from the app.

6. Show LLM-assisted analysis outputs.
   Present a policy-to-practice gap matrix or a draft findings summary generated from your policies, screenshots, and test notes.

## High-Value App Areas to Assess

| Area | App routes | What to look for | Likely standards impact |
| --- | --- | --- | --- |
| Authentication | `/login`, `/register` | Weak passwords, lack of MFA, poor failed-login handling, weak session behavior | OWASP A07, ISO access control, NIST IA/AC, GDPR security of processing |
| Access control | `/employee-portal`, `/admin`, `/admin/users`, `/admin/transactions` | Whether low-privilege users can reach privileged views or see too much data | OWASP A01, ISO privileged access, NIST AC, GDPR access restriction |
| Data exposure | `/profile`, `/dashboard`, `/transactions`, `/documents`, `/statements` | Full account numbers, excessive personal data, broad document visibility | OWASP A02, ISO information protection, NIST SC/AC, GDPR minimization |
| Transaction handling | `/transfer`, `/transactions` | Missing confirmation, no limits, weak validation, suspicious transaction handling | OWASP A04/A05, ISO secure development, NIST SI/SC/AU |
| Logging and monitoring | `/admin/audit-logs` | Missing events, missing context, inconsistent severity, incomplete evidence trail | OWASP A09, ISO logging and monitoring, NIST AU/IR |
| File and search behavior | `/documents`, `/statements` | Weak upload controls, unsafe previews, overly broad search access | OWASP A03/A05, ISO secure development, NIST SI/SC |

## Evidence Capture Template

For each observation, capture:

- `Feature or route`
- `User role used`
- `Test action performed`
- `Observed result`
- `Screenshot or evidence reference`
- `Relevant standard/control`
- `Status`
- `Risk level`

A simple evidence row can look like this:

| Feature | Observation | Evidence | Standards mapping | Status |
| --- | --- | --- | --- | --- |
| `/transfer` | Transfer action proceeds without an extra approval step | Screenshot `TX-03`, test note `TN-07` | OWASP Insecure Design, ISO secure development, NIST SI/SC | Partially compliant |

## How to Assess Current Compliance Against the Standards

### OWASP Top 10

Use the app to identify observable security weaknesses and map them to OWASP categories. Examples include:

- Broken access control
- Cryptographic or sensitive data exposure issues
- Injection-style or weak validation issues
- Insecure design in transaction flow
- Security misconfiguration
- Identification and authentication failures
- Logging and monitoring failures

### ISO 27001

Treat ISO 27001 as a control and governance lens. Ask:

- Is access controlled appropriately?
- Is sensitive information protected and minimized?
- Is there evidence of logging and monitoring?
- Does the application reflect secure development practices?
- Is there any visible incident-readiness or operational review process?

### NIST SP 800-53

Map findings into control families rather than trying to force a clause-by-clause assessment:

- `AC` Access Control
- `IA` Identification and Authentication
- `AU` Audit and Accountability
- `SI` System and Information Integrity
- `SC` System and Communications Protection
- `IR` Incident Response
- `CM` Configuration Management

### GDPR

Focus on personal data handling:

- Is unnecessary personal data visible?
- Can users access data related to them?
- Are deletion, export, or privacy-related practices documented or absent?
- Are logs and records sufficient for investigating misuse or exposure?

## How to Use LLMs to Analyze Existing Security Policies and Practices

The strongest use of LLMs here is not "tell me if we are compliant." The stronger use is:

1. Extract what the policies claim.
2. Extract what the app and current practices actually show.
3. Compare those two views against the standards.
4. Draft gaps, evidence summaries, and remediation recommendations for human review.

## Recommended LLM Inputs

Provide the LLM with:

- Security policy documents
- Access control policy
- Password or authentication policy
- Logging and monitoring policy
- Incident response procedure
- Secure development or SDLC documentation
- Privacy notice or data handling policy
- Your app screenshots and test notes
- Optional scanner output from ZAP or Burp

If a policy does not exist, that absence is itself a finding. The LLM should be told explicitly when documentation is missing.

## Practical LLM Workflow

1. Extract policy statements.
   Ask the LLM to list the security controls or commitments stated in each policy.

2. Summarize observed app practices.
   Give the LLM screenshots, route notes, and manual test results. Ask it to summarize what the system currently appears to do.

3. Compare policy versus practice.
   Ask the LLM to identify where the documented control and the observed application behavior match, partially match, or conflict.

4. Map gaps to standards.
   Ask the LLM to map each gap to OWASP, ISO 27001, NIST SP 800-53, and GDPR where relevant.

5. Draft findings.
   Ask the LLM to write concise findings with title, description, evidence, affected feature, risk, and suggested remediation.

6. Human validation.
   Review every LLM output manually. The final compliance judgement should be made by your team, not the model.

## Good Prompt Patterns

### Prompt 1: Extract policy controls

```text
You are helping with an initial compliance assessment.

Read the following security policy text and extract:
1. The security controls or commitments stated in the document
2. Any required practices related to authentication, logging, access control, privacy, or incident response
3. Any statements that can be mapped to OWASP, ISO 27001, NIST SP 800-53, or GDPR

Return the results as a table with:
- Policy statement
- Control theme
- Possible standards mapping
- Notes
```

### Prompt 2: Summarize observed app practices

```text
You are reviewing evidence from a banking web application.

Using the following screenshots, route notes, and test observations:
1. Summarize what the application currently does
2. Identify visible security practices and visible weaknesses
3. Separate facts from assumptions

Return:
- Observed fact
- Evidence reference
- Potential risk area
```

### Prompt 3: Compare policy against practice

```text
Compare the documented policy controls with the observed application behavior.

For each control:
1. State whether the app appears compliant, partially compliant, or non-compliant
2. Explain why
3. Reference the evidence used
4. Map the gap to OWASP, ISO 27001, NIST SP 800-53, and GDPR if relevant

Do not invent evidence. If evidence is missing, say so clearly.
```

### Prompt 4: Draft findings register entries

```text
Using the control gaps below, draft findings register entries with:
- Finding title
- Description
- Affected feature
- Evidence reference
- Risk level
- Standards mapping
- Recommended remediation
```

## Guardrails for LLM Use

Use these rules so the LLM stays useful:

- Always require evidence references
- Ask it to separate facts, inferences, and recommendations
- Do not let it claim a control is compliant unless evidence supports it
- Treat missing policy documentation as a possible governance gap
- Keep a human reviewer in the loop for final scoring and conclusions

## Suggested Deliverables for the Milestone

Using this app and the workflow above, you can produce:

- Initial compliance checklist
- Findings register
- Current-state gap analysis
- Standards mapping table
- Baseline risk summary
- LLM-assisted policy versus practice comparison

## Short Demo Script You Can Use

1. Introduce ARIA Bank as the target application being assessed.
2. Walk through customer features and identify current security-relevant behaviors.
3. Walk through staff and admin views and identify governance and access-control concerns.
4. Show screenshots, test notes, and audit-log evidence.
5. Show the checklist or findings table created from that evidence.
6. Show how the LLM was used to compare policy statements and observed practices against the standards.
7. Close with the current-state conclusion: what appears compliant, what appears partially compliant, and what appears non-compliant.

## Final Advice

The best demonstration is simple:

- Use the app to show what the system does now
- Use evidence to document current practices and weaknesses
- Use the standards to judge those practices
- Use LLMs to speed up policy extraction, mapping, and gap drafting
- Keep the final compliance interpretation with your team
