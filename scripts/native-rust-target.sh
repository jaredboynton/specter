#!/usr/bin/env bash
set -euo pipefail

case "$(uname -s):$(uname -m)" in
    Darwin:arm64)
        echo "aarch64-apple-darwin"
        ;;
    Darwin:x86_64)
        echo "x86_64-apple-darwin"
        ;;
    Linux:aarch64 | Linux:arm64)
        echo "aarch64-unknown-linux-gnu"
        ;;
    Linux:x86_64)
        echo "x86_64-unknown-linux-gnu"
        ;;
    *)
        echo "Unsupported native target: $(uname -s) $(uname -m)" >&2
        exit 1
        ;;
esac
