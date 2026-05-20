#!/usr/bin/env bash
set -euo pipefail

kubectl apply -f deployment/apps/
kubectl rollout status deployment/auth-service -n zt-apps --timeout=180s
kubectl rollout status deployment/ms1-profile-aggregator -n zt-apps --timeout=180s
kubectl rollout status deployment/ms2-employee-details -n zt-apps --timeout=180s
kubectl rollout status deployment/ms3-hardware-assets -n zt-apps --timeout=180s
kubectl rollout status deployment/ms4-holiday-calendar -n zt-apps --timeout=180s
kubectl rollout status deployment/ms5-office-locations -n zt-apps --timeout=180s
