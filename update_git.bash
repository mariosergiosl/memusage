#!/bin/bash
#===============================================================================
#
# FILE: update_git.sh
#
# USAGE: update_git.sh [commit message]
#
# DESCRIPTION: This script updates a Git repository with the latest changes.
#              If a commit message is provided as an argument, it uses that.
#              Otherwise, it prompts the user for a commit message.
#
# OPTIONS:
#    -h, --help       Display this help message
#    -v, --version    Display script version
#
# REQUIREMENTS: git
#
# BUGS:
#
# NOTES:
#
# AUTHOR:
#   Mario Sergio (ms), mariosergiosl@gmail.com
#
# COMPANY:
#
# VERSION: 1.1
# CREATED: 2024-11-20 17:00:00
# REVISION: 2024-11-21 14:00:00
#===============================================================================

# Set script version
SCRIPT_VERSION="1.1"

# Display help message
show_help() {
  cat << EOF
Usage: $0 [OPTIONS] [commit message]

This script updates a Git repository with the latest changes.

OPTIONS:
  -h, --help       Display this help message
  -v, --version    Display script version

Examples:
  $0 "My commit message"
  $0 -m "My commit message"
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
      commit_message="$1"
      shift
      ;;
  esac
done

if [[ -z "$commit_message" ]]; then
  read -p "Enter the commit message: " commit_message
fi

# Check if there are uncommitted changes
if ! git diff-index --quiet HEAD --; then
  # Add all changes to the staging area
  git add .

  # Get the list of updated files
  updated_files=$(git diff --cached --name-only)

  # Commit the changes with the updated files list as the comment
  git commit -m "$commit_message" -m "Updating the following files: $updated_files"

  # Pull the latest changes from the remote repository
  git pull origin main

  # Push the changes to the remote repository
  git push origin main
else
  echo "No changes to commit."
fi
