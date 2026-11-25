#!/usr/bin/env bash
set -e

echo "============================================================"
echo "  Initializing Graph-ADAPT Project Repository Structure"
echo "============================================================"

mkdir -p src/agents
mkdir -p src/gatekeeper
mkdir -p src/graph
mkdir -p src/testing
mkdir -p src/utils
mkdir -p data/raw_logs
mkdir -p data/atomic_payloads
mkdir -p rules/stock_unrefined
mkdir -p rules/refined_output
mkdir -p docs/evaluation_report
mkdir -p docker

touch src/__init__.py
touch src/agents/__init__.py
touch src/gatekeeper/__init__.py
touch src/graph/__init__.py
touch src/testing/__init__.py
touch src/utils/__init__.py

echo "Directory structure created successfully!"