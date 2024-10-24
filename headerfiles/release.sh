#!/bin/bash

# release.sh - A script to build and upload Python packages to PyPI

# Exit immediately if a command exits with a non-zero status
set -e

# Ensure required tools are installed
echo "Checking for required tools..."
REQUIRED_TOOLS=(python3 pip twine)
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v $tool &> /dev/null; then
        echo "$tool is not installed. Installing..."
        pip install $tool
    else
        echo "$tool is already installed."
    fi
done

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf build/ dist/ *.egg-info

# Build the package
echo "Building the package..."
python3 setup.py sdist bdist_wheel

# Upload the package to PyPI
echo "Uploading the package to PyPI..."
twine upload dist/*

echo "Package uploaded successfully!"

# Note: You might need to add --verbose flag to see more details
# Example: twine upload --verbose dist/*
