#!/usr/bin/env bash
set -euo pipefail

APPS=(
  "auth-service"
  "ms1-profile-aggregator"
  "ms2-employee-details"
  "ms3-hardware-assets"
  "ms4-holiday-calendar"
  "ms5-office-locations"
  "db-seeder"
)

if [[ $# -gt 0 ]]; then
  APPS=("$@")
fi

for APP in "${APPS[@]}"; do
  echo "Building image for $APP..."
  docker build -t "local/$APP:latest" "apps/$APP"
  echo "Build complete for $APP."
done
