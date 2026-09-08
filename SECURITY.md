# Security policy

ArchiveWeaver is an operations framework and does not receive production
credentials or archive content. Never open a public issue containing secrets,
private keys, tokens, customer data, or controller output with sensitive
values.

## Reporting

Use the repository host's private vulnerability-reporting channel or contact
the project security maintainers privately. Include the affected commit or
release, reproducible steps, impact, and a sanitized proof. Do not test against
production systems without written authorization.

## Operational response

Treat a leaked credential, unsigned release, failed fixity check, evidence
tamper event, or unsafe playbook change as a security incident. Freeze
promotion, revoke or rotate the affected credential, preserve the evidence
index and controller job record, and follow the incident sequence in
`docs/operations/service-management.md`. The service owner must set response
targets and disclosure timelines for each operated deployment.
