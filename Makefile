.PHONY: help generate validate test lint smoke ansible-validate controller-validate

help:
	@printf '%s\n' 'make generate  - regenerate catalog JSON and reference pages' \
	              'make validate  - validate catalog and compile Python' \
	              'make test      - run validation, runner, contract, and unit tests' \
	              'make controller-validate - validate the Ansible controller contract' \
	              'make ansible-validate - run pinned Ansible lint and syntax checks' \
	              'make smoke     - exercise CLI planning/checking commands'

generate:
	python3 scripts/generate_catalog.py

validate: generate
	PYTHONPATH=src python3 -m archiveweaver validate-catalog --json
	python3 -m compileall -q src scripts tests

test: validate controller-validate
	bash -n scripts/*.sh tests/*.sh
	bash tests/test-operational-runner.sh
	bash tests/test-execution-environment.sh
	PYTHONPATH=src python3 -m unittest discover -s tests -v

lint:
	python3 -m compileall -q src scripts tests

controller-validate:
	python3 scripts/validate-controller-contract.py

ansible-validate:
	bash scripts/validate-ansible.sh

smoke:
	PYTHONPATH=src python3 -m archiveweaver list-solutions
	PYTHONPATH=src python3 -m archiveweaver plan --solution paperless-ngx --mode rke2 --nodes 3 --os ubuntu-24.04
	PYTHONPATH=src python3 -m archiveweaver repair --solution paperless-ngx --mode docker

