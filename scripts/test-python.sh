#!/bin/bash
# ==============================================================================
# test-python.sh
# 
# Description:
#   Runs the Python test suite for all existing applications.
# ==============================================================================
set -e

echo "Running Python tests for all services..."

SERVICES=(
  "auth-service"
  "ms1-profile-aggregator"
  "ms2-employee-details"
  "ms3-hardware-assets"
  "ms4-holiday-calendar"
  "ms5-office-locations"
  "ui-dashboard"
)

for SERVICE in "${SERVICES[@]}"; do
  echo "----------------------------------------"
  echo "Testing $SERVICE..."
  echo "----------------------------------------"
  cd "apps/$SERVICE"
  
  # Create a virtual environment if it doesn't exist to ensure isolated testing
  if [ ! -d "venv" ]; then
    python3 -m venv venv
  fi
  
  source venv/bin/activate
  pip install -r requirements.txt -q
  
  # Tell Python requests to trust the mkcert local CA if available
  if command -v mkcert &> /dev/null; then
    export REQUESTS_CA_BUNDLE="$(mkcert -CAROOT)/rootCA.pem"
  fi
  
  # Root at apps/ so shared apps/conftest.py is loaded for all services
  pytest --rootdir="$(cd .. && pwd)" tests
  deactivate
  
  cd ../..
done

echo "All tests passed successfully!"
