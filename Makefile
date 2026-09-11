.PHONY: help generate validate test lint quality smoke upstream-audit github-audit yaml-validate ansible-lock ansible-sbom release-tools-lock release-tools-check ansible-validate controller-validate

help:
	@printf '%s\n' 'make generate  - regenerate catalog JSON and reference pages' \
	              'make validate  - validate catalog and compile Python' \
	              'make test      - run validation, runner, contract, and unit tests' \
	              'make quality   - run Ruff and strict mypy checks' \
	              'make upstream-audit - verify cataloged GitHub repositories online' \
	              'make github-audit - read and verify hosted production controls' \
	              'make yaml-validate - strictly parse all repository YAML' \
	              'make ansible-lock - regenerate the complete controller dependency lock' \
	              'make ansible-sbom - generate its SPDX SBOM (requires SOURCE_DATE_EPOCH)' \
	              'make release-tools-lock - regenerate the release validation dependency lock' \
	              'make controller-validate - validate the Ansible controller contract' \
	              'make ansible-validate - run pinned Ansible lint and syntax checks' \
	              'make smoke     - exercise CLI planning/checking commands'

generate:
	python3 scripts/generate_catalog.py

validate: generate
	PYTHONPATH=src python3 -m archiveweaver validate-catalog --json
	python3 -m compileall -q src scripts tests

test: validate controller-validate yaml-validate release-tools-check
	bash -n scripts/*.sh tests/*.sh
	bash tests/test-operational-runner.sh
	bash tests/test-execution-environment.sh
	PYTHONPATH=src python3 -m unittest discover -s tests -v

lint:
	python3 -m compileall -q src scripts tests

quality:
	python3 -m ruff check src tests scripts setup.py
	PYTHONPATH=src python3 -m mypy --strict src/archiveweaver scripts

upstream-audit:
	python3 scripts/validate-upstream-repositories.py

github-audit:
	@python3 scripts/audit-github-production-controls.py --repository "$${GITHUB_REPOSITORY}" --source-revision "$$(git rev-parse --verify HEAD)" --json

yaml-validate:
	python3 scripts/validate-yaml.py

ansible-lock:
	python3 scripts/compile-ansible-lock.py

ansible-sbom:
	python3 scripts/generate-ansible-sbom.py

release-tools-lock:
	python3 scripts/compile-release-tools-lock.py

release-tools-check:
	python3 scripts/compile-release-tools-lock.py --check

controller-validate:
	python3 scripts/validate-controller-contract.py

ansible-validate:
	bash scripts/validate-ansible.sh

smoke:
	PYTHONPATH=src python3 -m archiveweaver list-solutions
	PYTHONPATH=src python3 -m archiveweaver plan --solution paperless-ngx --mode rke2 --nodes 3 --os ubuntu-24.04
	PYTHONPATH=src python3 -m archiveweaver repair --solution paperless-ngx --mode docker

