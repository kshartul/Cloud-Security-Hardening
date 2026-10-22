SHELL := /bin/bash
STACKS := $(shell find . -path '*/terraform/stacks/*' -name main.tf -not -path '*/.terraform/*' -exec dirname {} \;)
MODULES := $(shell find . -path '*/terraform/modules/*' -name '*.tf' -not -path '*/.terraform/*' -exec dirname {} \; | sort -u)

.PHONY: help fmt validate scan test hooks clean

help:
	@echo "make fmt       - terraform fmt -recursive"
	@echo "make validate  - terraform init -backend=false && validate for every stack and module"
	@echo "make scan      - checkov + gitleaks + semgrep on this repo"
	@echo "make test      - pytest (authz, risk scoring, playbooks)"
	@echo "make hooks     - install pre-commit hooks"

fmt:
	terraform fmt -recursive

validate:
	@set -e; for d in $(MODULES) $(STACKS); do \
	  echo "== $$d"; \
	  (cd $$d && terraform init -backend=false -input=false >/dev/null && terraform validate); \
	done

scan:
	checkov -d . --framework terraform --config-file phase-2-secure-sdlc/configs/.checkov.yaml --skip-path phase-3-dast-api/serverless
	gitleaks git . --config phase-2-secure-sdlc/configs/.gitleaks.toml --redact
	semgrep scan --config p/python --config phase-2-secure-sdlc/configs/semgrep/ --error --metrics=off

test:
	python -m pytest -q phase-3-dast-api/serverless/tests phase-4-vuln-mgmt/tests phase-6-integration/tests

hooks:
	cp phase-2-secure-sdlc/configs/.pre-commit-config.yaml .pre-commit-config.yaml
	pre-commit install

clean:
	find . -name .terraform -type d -prune -exec rm -rf {} + ; find . -name '.build' -type d -prune -exec rm -rf {} +
