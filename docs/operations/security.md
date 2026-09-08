# Security baseline

## Supply chain

- pin upstream release versions and image digests;
- verify checksums and signatures when the upstream project publishes them;
- scan images, packages, and converter binaries before promotion;
- keep SBOMs and license notices with the release manifest;
- do not run arbitrary shell text from a catalog field;
- use protected CI variables and short-lived credentials;
- run the Ansible edition from a pinned execution environment; verify signed/reviewed content and keep controller, inventory, Vault, and evidence permissions separate.

## Host and runtime

- minimal OS installation and timely security updates;
- SELinux enforcing on Enterprise Linux where product compatibility permits;
- AppArmor and systemd hardening on Ubuntu/Debian where compatible;
- rootless containers when the product supports them; otherwise use a dedicated service identity;
- separate data, logs, temporary conversion, and backup paths;
- restrict ingress, database, search, queue, cluster, and storage ports to required networks;
- encrypt backups and object storage; test key recovery;
- keep Ansible host-key verification enabled, use an explicitly reviewed become policy, and run stateful changes with serial execution and fail-closed approval gates.

## Archive integrity

- immutable original bitstreams;
- cryptographic fixity at ingest and scheduled verification;
- event logs for every transformation and failed transformation;
- versioned metadata and access-policy changes;
- malware scanning before public access;
- quarantine failed or suspicious objects without deleting the original evidence;
- preserve chain-of-custody and retention decisions.

## Authentication and authorization

Use each product's documented LDAP, Active Directory, OIDC, SAML, or local-admin integration. Do not place passwords in URLs, shell history, manifests, or reports. Health checks should use a dedicated low-privilege endpoint or a pre-authenticated probe mechanism approved by the product owner. Ansible Vault or an approved external secret manager must supply credentials; do not pass secrets through `-e`, expose them in diffs, or write them to the evidence bundle.

