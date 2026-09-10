.PHONY: test up down logs clean

VENV := .venv
PY := $(VENV)/bin/python
PYTHON ?= python3   # project targets 3.11; override if `python3` is older

# Offline unit tests for the crypto/OIDC layer — no Keycloak or Docker needed.
test:
	@test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	@$(PY) -m pip install --quiet "python-jose[cryptography]==3.3.0" \
		"cryptography==41.0.7" "httpx==0.27.0" pytest
	@$(PY) -m pytest -q tests/

up:
	docker compose up -d

down:
	docker compose down -v

logs:
	docker compose logs -f keycloak

clean:
	rm -rf $(VENV) .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
