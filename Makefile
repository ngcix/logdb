PYTHON ?= python
PIP := $(PYTHON) -m pip
DB ?= case.duckdb
LOG ?=
TYPE ?= dumpstate
SQL ?=
ROWS ?= 100

.PHONY: help install-dev test wheel build make-db query

help:
	@echo "Development"
	@echo "  make install-dev"
	@echo "  make test"
	@echo "  make wheel"
	@echo "  make build          Build executable with Nuitka"
	@echo ""
	@echo "LogDB"
	@echo "  make make-db LOG=path/to/dumpstate [DB=case.duckdb] [TYPE=dumpstate]"
	@echo "  make query DB=case.duckdb SQL='SELECT ...' [ROWS=100]"

install-dev:
	$(PIP) install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

wheel:
	$(PYTHON) -m build --wheel

build:
	$(PIP) install nuitka -q
	python -m nuitka --onefile --output-dir=dist --output-filename=logdb src/logdb/__main__.py

make-db:
ifndef LOG
	$(error Set LOG=path/to/input-log)
endif
	$(PYTHON) -m logdb make -i "$(LOG)" -t "$(TYPE)" -o "$(DB)"

query:
ifndef SQL
	$(error Set SQL='SELECT ...')
endif
	$(PYTHON) -m logdb query "$(DB)" "$(SQL)" --rows "$(ROWS)"
