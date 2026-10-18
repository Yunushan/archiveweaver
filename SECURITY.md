# Security policy

ArchiveWeaver is an operations framework and does not receive production
credentials or archive content. Never open a public issue containing secrets,
private keys, tokens, customer data, or controller output with sensitive
values.

## Reporting

Use [GitHub's private vulnerability-reporting form][private-report] or contact
the project security maintainers privately. Include the affected commit or
release, reproducible steps, impact, and a sanitized proof. Do not test against
production systems without written authorization. If the private form is not
available, do not fall back to a public issue; use the private contact recorded
for the deployment's named security owner.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.0 (unreleased, alpha) | No security fixes until a 1.0 release is published |

Until 1.0, only the default branch receives security fixes. Deployment owners
may set their own support policy for artifacts they operate.

## Response targets

- Acknowledgement of a private report: within 2 business days.
- Coordinated disclosure: 90 days from acknowledgement, unless the parties agree
  otherwise in writing.

## Operational response

Treat a leaked credential, unsigned release, failed fixity check, evidence
tamper event, or unsafe playbook change as a security incident. Freeze
promotion, revoke or rotate the affected credential, preserve the evidence
index and controller job record, and follow the incident sequence in
`docs/operations/service-management.md`. The service owner must set response
targets and disclosure timelines for each operated deployment.

[private-report]: https://github.com/Yunushan/archiveweaver/security/advisories/new
