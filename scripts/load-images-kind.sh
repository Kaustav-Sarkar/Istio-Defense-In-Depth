#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="istio-security"
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
  echo "Loading image local/$APP:latest into Kind cluster $CLUSTER_NAME..."
  kind load docker-image "local/$APP:latest" --name "$CLUSTER_NAME"
  echo "Load complete for $APP."
done
