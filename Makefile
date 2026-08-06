PYTHON ?= python
PIP := $(PYTHON) -m pip
DB ?= case.duckdb
LOG ?=
TYPE ?= dumpstate
SQL ?=
ROWS ?= 100

REPO ?= https://github.sec.samsung.net/cuong-nguyen/logdb
RAW ?= $(REPO)/raw/main
SKILLS_DIR ?= $(HOME)/.agents/skills
CURL ?= curl

.PHONY: help setup install install-skills install-dev test wheel build make-db query

help:
	@echo "Install"
	@echo "  make setup                Install module, skills, and default configs"
	@echo "  make install              Install module from git"
	@echo "  make install-skills       Download skills to $(SKILLS_DIR)"
	@echo "                            Override with SKILLS_DIR=path/to/skills"
	@echo ""
	@echo "Development"
	@echo "  make install-dev"
	@echo "  make test"
	@echo "  make wheel"
	@echo "  make build          Build executable with Nuitka"
	@echo ""
	@echo "LogDB"
	@echo "  make make-db LOG=path/to/dumpstate [DB=case.duckdb] [TYPE=dumpstate]"
	@echo "  make query DB=case.duckdb SQL='SELECT ...' [ROWS=100]"

setup: install install-skills
	$(PYTHON) -m logdb config init

install:
	$(PIP) install git+$(REPO).git

install-skills:
	$(CURL) -fL --create-dirs -o "$(SKILLS_DIR)/logdb-make/SKILL.md" "$(RAW)/skills/logdb-make/SKILL.md"
	$(CURL) -fL --create-dirs -o "$(SKILLS_DIR)/logdb-query/SKILL.md" "$(RAW)/skills/logdb-query/SKILL.md"
	@echo "Skills saved to $(SKILLS_DIR)"

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
