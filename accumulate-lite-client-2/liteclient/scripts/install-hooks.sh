#!/bin/bash
# install-hooks.sh
# Install pre-commit hooks for the Accumulate Lite Client

set -e

echo "Installing pre-commit hooks for Accumulate Lite Client..."

# Check if pre-commit is installed
if ! command -v pre-commit &> /dev/null; then
    echo "pre-commit is not installed. Installing..."
    if command -v pip &> /dev/null; then
        pip install pre-commit
    elif command -v pip3 &> /dev/null; then
        pip3 install pre-commit
    else
        echo "Error: pip is not installed. Please install pip first."
        echo "Visit: https://pip.pypa.io/en/stable/installation/"
        exit 1
    fi
fi

# Install the pre-commit hooks
pre-commit install

# Install commit-msg hook for conventional commits
pre-commit install --hook-type commit-msg

echo "✅ Pre-commit hooks installed successfully!"
echo ""
echo "The following checks will run on every commit:"
echo "  - Code formatting (gofmt, goimports)"
echo "  - Mock detection (no new mocks allowed)"
echo "  - Build tag verification"
echo "  - Crystal Step 1 verification"
echo "  - Linting (golangci-lint)"
echo ""
echo "To run hooks manually: pre-commit run --all-files"
echo "To skip hooks (emergency only): git commit --no-verify"