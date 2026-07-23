.PHONY: validate analyze test report lint all

validate:
	python -m soclab validate

analyze:
	python -m soclab analyze

test:
	python -m soclab test-detections
	pytest

report:
	python -m soclab build-report

lint:
	ruff check .

all: lint validate analyze test report
