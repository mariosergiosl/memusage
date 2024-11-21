#!/bin/bash
#===============================================================================
#
# FILE: run_python_tests.sh
#
# USAGE: run_python_tests.sh
#
# DESCRIPTION: This script runs Pylint and flake8 tests on all Python files
#              in the current directory and its subdirectories.
#
# OPTIONS:
#    -h, --help       Display this help message
#    -v, --version    Display script version
#
# REQUIREMENTS: pylint, flake8
#
# BUGS:
#
# NOTES:
#
# AUTHOR:
#   Mario Luz (ml), mario.mssl@gmail.com
#
# COMPANY:
#
# VERSION: 1.0
# CREATED: 2024-11-21 17:00:00
# REVISION:
#===============================================================================

# Set script version
SCRIPT_VERSION="1.0"

# Display help message
show_help() {
  cat << EOF
Usage: $0 [OPTIONS]

This script runs Pylint and flake8 tests on all Python files.

OPTIONS:
  -h, --help       Display this help message
  -v, --version    Display script version

Examples:
  $0
  $0 -h
  $0 --version
EOF
}

# Display script version
show_version() {
  echo "$0 version $SCRIPT_VERSION"
}

# Get the commit message from the command line argument or prompt for one
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help
      exit 0
      ;;
    -v|--version)
      show_version
      exit 0
      ;;
    *)
      echo "Invalid option: $1"
      show_help
      exit 1
      ;;
  esac
done

# Check if pylint is installed
if ! command -v pylint &> /dev/null; then
    echo "Pylint is not installed. Install it with 'pip install pylint'."
    exit 1
fi

# Check if flake8 is installed
if ! command -v flake8 &> /dev/null; then
    echo "Flake8 is not installed. Install it with 'pip install flake8'."
    exit 1
fi

# Execute pylint and flake8 on all .py files
echo "Running tests..."
for file in $(find . -name "*.py"); do
    echo "Testing file: $file"
    echo "********************************************************************"
    # Execute pylint on all .py files
    echo "Running Pylint..."
    pylint --rcfile=.pylintrc --init-hook="import sys; sys.path.append('.')" "$file"

    # Execute flake8 on all .py files
    echo "Running Flake8..."
    flake8 --config=.flake8 "$file"
done
