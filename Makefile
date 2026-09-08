.PHONY: help generate validate test lint smoke

help:
	@printf '%s\n' 'make generate  - regenerate catalog JSON and reference pages' \
	              'make validate  - validate catalog and compile Python' \
	              'make test      - run stdlib unit tests' \
	              'make smoke     - exercise CLI planning/checking commands'

generate:
	python3 scripts/generate_catalog.py

validate: generate
	PYTHONPATH=src python3 -m archiveweaver validate-catalog --json
	python3 -m compileall -q src scripts tests

test: validate
	PYTHONPATH=src python3 -m unittest discover -s tests -v

lint:
	python3 -m compileall -q src scripts tests

smoke:
	PYTHONPATH=src python3 -m archiveweaver list-solutions
	PYTHONPATH=src python3 -m archiveweaver plan --solution paperless-ngx --mode rke2 --nodes 3 --os ubuntu-24.04
	PYTHONPATH=src python3 -m archiveweaver repair --solution paperless-ngx --mode docker

