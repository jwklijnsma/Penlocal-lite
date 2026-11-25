PYTHON ?= python3
BUMP ?= patch

.PHONY: help install test serve demo web web-dev web-test version release release-patch release-minor release-major release-dry-run

help: ## show this list
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-16s %s\n", $$1, $$2}'
	@echo
	@echo "  release examples: make release | make release BUMP=minor | make release VERSION=1.0.0"

install: ## install for development (editable, with pytest)
	$(PYTHON) -m pip install -e ".[dev]"

test: ## run the offline test suite (no model server needed)
	$(PYTHON) -m pytest -q tests/

serve: ## start the web UI for ./scopes
	$(PYTHON) -m penlocal serve --scopes ./scopes --open

demo: ## start the web UI with the mock brain (no model server)
	$(PYTHON) -m penlocal serve --backend mock --scopes ./scopes --open

web: ## build the React UI into penlocal/web/static (commit the result)
	cd web && npm ci && npm run build

web-dev: ## Vite dev server on :5173, proxying /api to `penlocal serve --port 8770`
	cd web && npm run dev

web-test: ## typecheck and unit-test the UI
	cd web && npm run typecheck && npm test

version: ## print the current version
	@sed -n 's/^__version__ = "\(.*\)"$$/\1/p' penlocal/__init__.py

release: ## start the release workflow on GitHub (BUMP=patch|minor|major or VERSION=X.Y.Z)
	@command -v gh >/dev/null || { echo "make release needs the GitHub CLI: https://cli.github.com"; exit 1; }
	gh workflow run release.yml --ref main -f bump=$(BUMP) $(if $(VERSION),-f version=$(VERSION)) $(if $(DRY_RUN),-f dry_run=true)
	@echo "Started. Following the run (Ctrl-C stops watching, not the release)…"
	@sleep 5
	@gh run watch --exit-status "$$(gh run list --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"

release-patch: ## release X.Y.Z+1
	@$(MAKE) --no-print-directory release BUMP=patch

release-minor: ## release X.Y+1.0
	@$(MAKE) --no-print-directory release BUMP=minor

release-major: ## release X+1.0.0
	@$(MAKE) --no-print-directory release BUMP=major

release-dry-run: ## rehearse the release on GitHub: test and build everything, publish nothing
	@$(MAKE) --no-print-directory release DRY_RUN=1
