# Security Policy

## Reporting a vulnerability

Open a private security advisory on this repository. Do not open a public issue for
anything that could expose credentials, personal data, or a bypass of the masking
pipeline.

## Scope

This project sits between AI agents and production databases. The following are
security issues, not feature requests:

- Any way to obtain a value of a column listed in the masking registry (in a result,
  an error, a log, an audit record, or an echoed query).
- Any way for an agent to reach connection settings, the registry, user records or
  vault contents.
- Capability forgery, replay, audience confusion, or use after revocation.
- Any SQL that is not read-only reaching a driver.

## Non-issues (documented and accepted)

These are known limits, recorded in the plan's accepted-risk register. They are not
vulnerabilities under this policy:

- **Aggregate and inference leakage.** `AVG(salary)`, `COUNT(*) WHERE name='X'`,
  `ORDER BY` / `LIMIT` discrimination, and re-identification from unmasked columns are
  not prevented. Preventing them would require blocking results, which this gateway
  deliberately does not do.
- **Registry completeness.** A personal-data column that is not in the registry is
  returned to the agent. The detector writes an audit flag; it does not mask and does
  not block.
- **Unmapped databases.** Only MySQL/MariaDB is supported in v1.

## Handling

Fixture data in this repository is synthetic. No real employee, payroll, or client
data may be committed — including in test output, screenshots, or CI artefacts.
