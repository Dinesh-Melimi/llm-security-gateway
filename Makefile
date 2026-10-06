.PHONY: install run test lint security eval report docker clean

install:
	pip install -r requirements-dev.txt

run:
	uvicorn --factory gateway.main:create_app --host 127.0.0.1 --port 8080 --reload

test:
	python -m pytest -q

lint:
	ruff check .

security:
	bandit -q -c pyproject.toml -r gateway scripts
	pip-audit -r requirements.txt

eval:
	python -m scripts.evaluate

report:
	python -m scripts.usage_report logs/audit.jsonl

docker:
	docker build -t llm-security-gateway .

clean:
	rm -rf .pytest_cache .ruff_cache logs __pycache__ */__pycache__
