#!/usr/bin/env bash
set -euo pipefail

echo "Checking required tools..."
for tool in python3 docker kind kubectl istioctl mkcert; do
    if ! command -v "$tool" &> /dev/null; then
        echo "Error: $tool is not installed or not in PATH."
        exit 1
    fi
done
echo "All required tools are installed."
