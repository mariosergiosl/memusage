#!/bin/bash
#===============================================================================
#
# FILE: update_git.sh
#
# USAGE: update_git.sh [commit message]
#
# DESCRIPTION: This script updates a Git repository with the latest changes.
#              If a commit message is provided as an argument, it uses that.
#              Otherwise, it shows the list of changed files and prompts 
#              the user for a commit message (optional). If no message is 
#              entered, it uses a default message with the files list.
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
#   Mario Luz (ml), mario.mssl[at]gmail.com
#
# COMPANY:
#
# VERSION: 1.2
# CREATED: 2024-11-18 17:00:00
# REVISION: 2024-11-21 15:00:00
#===============================================================================

# Set script version
SCRIPT_VERSION="1.2"

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
  $0 
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

# Check if there are uncommitted changes
if ! git diff-index --quiet HEAD --; then
  # Add all changes to the staging area
  git add .

  # Get the list of updated files
  updated_files=$(git diff --cached --name-only)

  # Display the list of updated files and prompt for a commit message
  echo "Updating the following files:"
  echo "$updated_files"
  echo "Press Enter to use the default commit message or type a custom message:"
  read -r -p "Commit message: " commit_message

  # Use the default commit message if none is provided
  if [[ -z "$commit_message" ]]; then
    commit_message="Updating files: $updated_files"
  fi

  # Commit the changes with the updated files list as the comment
  git commit -m "$commit_message"

  # Pull the latest changes from the remote repository
  git pull origin main

  # Push the changes to the remote repository
  git push origin main
else
  echo "No changes to commit."
fi
